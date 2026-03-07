from collections.abc import AsyncIterator
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from adapters.sqlalchemy import SQLAlchemyAdapter
from core.auth import PyAuth
from core.config import JwtSettings, PyAuthSettings, SessionSettings
from core.errors import AuthenticationError
from core.mailer import MailMessage, Mailer
from core.types import RequestContext
from schema.models import Session


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
        session=SessionSettings(ttl_seconds=1800),
    )


class MemoryMailer(Mailer):
    async def send(self, message: MailMessage) -> None:
        return None


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


@pytest.mark.asyncio
async def test_authenticate_session_returns_session_and_user(
    sqlite_adapter: SQLAlchemyAdapter,
) -> None:
    auth = PyAuth(settings=build_settings(), adapter=sqlite_adapter, mailer=MemoryMailer())
    sign_up_result = await auth.sign_up(
        email="sami@example.com",
        password="very-secure-password",
        context=RequestContext(ip_address="127.0.0.1", user_agent="pytest"),
    )

    authenticated = await auth.authenticate_session(session_token=sign_up_result.session_token)

    assert authenticated.user.id == sign_up_result.user.id
    assert authenticated.session.id == sign_up_result.session.id


@pytest.mark.asyncio
async def test_sign_out_invalidates_existing_session(
    sqlite_adapter: SQLAlchemyAdapter,
) -> None:
    auth = PyAuth(settings=build_settings(), adapter=sqlite_adapter, mailer=MemoryMailer())
    sign_up_result = await auth.sign_up(
        email="sami@example.com",
        password="very-secure-password",
    )

    deleted = await auth.sign_out(session_token=sign_up_result.session_token)

    assert deleted is True

    with pytest.raises(AuthenticationError):
        await auth.authenticate_session(session_token=sign_up_result.session_token)


@pytest.mark.asyncio
async def test_authenticate_session_rejects_expired_session(
    sqlite_adapter: SQLAlchemyAdapter,
) -> None:
    auth = PyAuth(settings=build_settings(), adapter=sqlite_adapter, mailer=MemoryMailer())
    sign_up_result = await auth.sign_up(
        email="sami@example.com",
        password="very-secure-password",
    )

    expired_session = sign_up_result.session.model_copy(
        update={"expires_at": datetime.now(timezone.utc) - timedelta(minutes=1)}
    )
    await sqlite_adapter.delete_session(sign_up_result.session.id)
    await sqlite_adapter.create_session(
        Session(
            user_id=expired_session.user_id,
            token_hash=expired_session.token_hash,
            expires_at=expired_session.expires_at,
            ip_address=expired_session.ip_address,
            user_agent=expired_session.user_agent,
        )
    )

    with pytest.raises(AuthenticationError) as exc_info:
        await auth.authenticate_session(session_token=sign_up_result.session_token)

    assert exc_info.value.code == "session_expired"
