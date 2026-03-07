from collections.abc import AsyncIterator
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from datetime import timedelta
import re

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from adapters.base import BaseAdapter
from adapters.sqlalchemy import SQLAlchemyAdapter
from core.auth import PyAuth
from core.config import JwtSettings, PyAuthSettings, VerificationSettings
from core.errors import AuthenticationError, ValidationError
from core.mailer import MailMessage, Mailer
from core.types import RequestContext
from providers.base import SocialIdentity


def build_settings() -> PyAuthSettings:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    return PyAuthSettings(
        jwt=JwtSettings(
            issuer="https://auth.example.com",
            audience="pyauth-clients",
            private_key_pem=private_pem,
            public_key_pem=public_pem,
        ),
        verification=VerificationSettings(
            email_verification_ttl_seconds=900,
            password_reset_ttl_seconds=900,
        ),
    )


def test_pyauth_wires_core_services() -> None:
    auth = PyAuth(settings=build_settings())

    assert auth.settings.jwt.algorithm == "EdDSA"
    assert auth.passwords is not None
    assert auth.tokens is not None


class DummyAdapter(BaseAdapter):
    async def create_user(self, user):
        return user

    async def update_user(self, user):
        return user

    async def get_user_by_id(self, user_id):
        return None

    async def get_user_by_email(self, email):
        return None

    async def create_account(self, account):
        return account

    async def get_account_by_provider_account_id(self, provider, provider_account_id):
        return None

    async def get_accounts_by_user_id(self, user_id):
        return []

    async def get_account_by_user_id_and_provider(self, user_id, provider):
        return None

    async def update_account(self, account):
        return account

    async def delete_account(self, account_id):
        return True

    async def create_session(self, session):
        return session

    async def get_session_by_token_hash(self, token_hash):
        return None

    async def delete_session(self, session_id):
        return True

    async def delete_sessions_by_user_id(self, user_id):
        return 0

    async def create_verification(self, verification):
        return verification

    async def get_verification_by_token_hash(self, token_hash):
        return None

    async def consume_verification(self, verification_id):
        return None

    async def delete_verifications_by_identifier_and_purpose(self, *, identifier, purpose):
        return 0

    async def delete_expired_verifications(self):
        return 0


def test_pyauth_accepts_injected_adapter() -> None:
    adapter = DummyAdapter()
    auth = PyAuth(settings=build_settings(), adapter=adapter)

    assert auth.adapter is adapter


class MemoryMailer(Mailer):
    def __init__(self) -> None:
        self.outbox: list[MailMessage] = []

    async def send(self, message: MailMessage) -> None:
        self.outbox.append(message)


@pytest.fixture
async def sqlite_adapter() -> AsyncIterator[SQLAlchemyAdapter]:
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    await SQLAlchemyAdapter.create_schema(engine)
    adapter = SQLAlchemyAdapter(session_factory=session_factory)
    try:
        yield adapter
    finally:
        await engine.dispose()


@pytest.fixture
def memory_mailer() -> MemoryMailer:
    return MemoryMailer()


def extract_token(message: MailMessage) -> str:
    match = re.search(r"token=([-A-Za-z0-9_.]+)", message.text_body)
    assert match is not None
    return match.group(1)


@pytest.mark.asyncio
async def test_sign_up_creates_local_account_session_and_verification_message(
    sqlite_adapter: SQLAlchemyAdapter,
    memory_mailer: MemoryMailer,
) -> None:
    auth = PyAuth(settings=build_settings(), adapter=sqlite_adapter, mailer=memory_mailer)

    result = await auth.sign_up(
        email="sami@example.com",
        password="very-secure-password",
        name="Sami",
        context=RequestContext(ip_address="127.0.0.1", user_agent="pytest"),
    )

    local_account = await sqlite_adapter.get_account_by_user_id_and_provider(
        result.user.id,
        "credentials",
    )

    assert result.user.email_normalized == "sami@example.com"
    assert result.session.user_id == result.user.id
    assert result.session.ip_address == "127.0.0.1"
    assert result.session_token != result.session.token_hash
    assert result.access_token is not None
    assert local_account is not None
    assert local_account.password_hash is not None
    assert len(memory_mailer.outbox) == 1
    assert memory_mailer.outbox[0].subject == "Verify your email"
    assert "https://example.com" not in memory_mailer.outbox[0].text_body


@pytest.mark.asyncio
async def test_sign_up_rejects_duplicate_email(
    sqlite_adapter: SQLAlchemyAdapter,
    memory_mailer: MemoryMailer,
) -> None:
    auth = PyAuth(settings=build_settings(), adapter=sqlite_adapter, mailer=memory_mailer)
    await auth.sign_up(email="sami@example.com", password="very-secure-password")

    with pytest.raises(ValidationError) as exc_info:
        await auth.sign_up(email="sami@example.com", password="another-secure-password")

    assert exc_info.value.code == "email_already_registered"


@pytest.mark.asyncio
async def test_sign_in_creates_new_session_and_rejects_bad_password(
    sqlite_adapter: SQLAlchemyAdapter,
    memory_mailer: MemoryMailer,
) -> None:
    auth = PyAuth(settings=build_settings(), adapter=sqlite_adapter, mailer=memory_mailer)
    await auth.sign_up(email="sami@example.com", password="very-secure-password")

    with pytest.raises(AuthenticationError):
        await auth.sign_in(
            email="sami@example.com",
            password="wrong-password",
            context=RequestContext(user_agent="pytest"),
        )

    result = await auth.sign_in(
        email="sami@example.com",
        password="very-secure-password",
        context=RequestContext(ip_address="10.0.0.1", user_agent="pytest"),
    )

    assert result.session.user_id == result.user.id
    assert result.session.ip_address == "10.0.0.1"
    assert result.access_token is not None


@pytest.mark.asyncio
async def test_password_reset_rotates_credentials_and_invalidates_existing_sessions(
    sqlite_adapter: SQLAlchemyAdapter,
    memory_mailer: MemoryMailer,
) -> None:
    auth = PyAuth(settings=build_settings(), adapter=sqlite_adapter, mailer=memory_mailer)
    sign_up_result = await auth.sign_up(
        email="sami@example.com",
        password="very-secure-password",
    )

    await auth.request_password_reset(email="sami@example.com")
    reset_token = extract_token(memory_mailer.outbox[-1])

    updated_user = await auth.reset_password(
        token=reset_token,
        new_password="new-very-secure-password",
    )

    with pytest.raises(AuthenticationError):
        await auth.authenticate_session(session_token=sign_up_result.session_token)

    with pytest.raises(AuthenticationError):
        await auth.sign_in(email="sami@example.com", password="very-secure-password")

    next_result = await auth.sign_in(
        email="sami@example.com",
        password="new-very-secure-password",
    )

    assert updated_user.id == next_result.user.id


@pytest.mark.asyncio
async def test_verify_email_marks_user_as_verified_and_token_is_single_use(
    sqlite_adapter: SQLAlchemyAdapter,
    memory_mailer: MemoryMailer,
) -> None:
    auth = PyAuth(settings=build_settings(), adapter=sqlite_adapter, mailer=memory_mailer)
    result = await auth.sign_up(email="sami@example.com", password="very-secure-password")
    verification_token = extract_token(memory_mailer.outbox[-1])

    verified_user = await auth.verify_email(token=verification_token)

    assert verified_user.id == result.user.id
    assert verified_user.email_verified is True

    with pytest.raises(ValidationError):
        await auth.verify_email(token=verification_token)


@pytest.mark.asyncio
async def test_request_email_verification_replaces_the_previous_token(
    sqlite_adapter: SQLAlchemyAdapter,
    memory_mailer: MemoryMailer,
) -> None:
    auth = PyAuth(settings=build_settings(), adapter=sqlite_adapter, mailer=memory_mailer)
    result = await auth.sign_up(email="sami@example.com", password="very-secure-password")
    first_token = extract_token(memory_mailer.outbox[-1])

    await auth.request_email_verification(user_id=result.user.id)
    second_token = extract_token(memory_mailer.outbox[-1])

    assert second_token != first_token

    with pytest.raises(ValidationError):
        await auth.verify_email(token=first_token)

    verified_user = await auth.verify_email(token=second_token)
    assert verified_user.email_verified is True


class UnsafeOAuthProvider:
    provider_name = "github"

    async def exchange_code(self, *, code: str, code_verifier: str) -> SocialIdentity:
        return SocialIdentity(
            provider="github",
            provider_account_id="github-user-123",
            email="sami@example.com",
            email_verified=True,
            safe_for_email_linking=False,
            name="Sami",
            image=None,
            access_token="github-access-token",
            refresh_token=None,
            expires_at=None,
        )


@pytest.mark.asyncio
async def test_complete_oauth_sign_in_rejects_unsafe_email_auto_linking(
    sqlite_adapter: SQLAlchemyAdapter,
    memory_mailer: MemoryMailer,
) -> None:
    auth = PyAuth(settings=build_settings(), adapter=sqlite_adapter, mailer=memory_mailer)
    await auth.sign_up(email="sami@example.com", password="very-secure-password")
    social_auth = PyAuth(
        settings=build_settings(),
        adapter=sqlite_adapter,
        mailer=memory_mailer,
        providers={"github": UnsafeOAuthProvider()},
    )

    with pytest.raises(ValidationError) as exc_info:
        await social_auth.complete_oauth_sign_in(
            provider_name="github",
            code="oauth-code",
            code_verifier="oauth-code-verifier",
        )

    assert exc_info.value.code == "unsafe_oauth_link"


class NoEmailOAuthProvider:
    provider_name = "github"

    async def exchange_code(self, *, code: str, code_verifier: str) -> SocialIdentity:
        return SocialIdentity(
            provider="github",
            provider_account_id="github-user-456",
            email=None,
            email_verified=False,
            safe_for_email_linking=False,
            name="Octo User",
            image=None,
            access_token="github-access-token",
            refresh_token=None,
            expires_at=None,
        )


@pytest.mark.asyncio
async def test_complete_oauth_sign_in_creates_subject_backed_user_when_email_missing(
    sqlite_adapter: SQLAlchemyAdapter,
    memory_mailer: MemoryMailer,
) -> None:
    social_auth = PyAuth(
        settings=build_settings(),
        adapter=sqlite_adapter,
        mailer=memory_mailer,
        providers={"github": NoEmailOAuthProvider()},
    )

    result = await social_auth.complete_oauth_sign_in(
        provider_name="github",
        code="oauth-code",
        code_verifier="oauth-code-verifier",
    )

    linked_account = await sqlite_adapter.get_account_by_provider_account_id(
        "github",
        "github-user-456",
    )

    assert result.user.email.endswith("@oauth.local")
    assert result.user.email_verified is False
    assert linked_account is not None
    assert linked_account.user_id == result.user.id
