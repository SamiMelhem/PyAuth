from __future__ import annotations

from collections.abc import AsyncIterator
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from adapters.sqlalchemy import SQLAlchemyAdapter
from core.auth import PyAuth
from core.config import GoogleProviderSettings, JwtSettings, PyAuthSettings, SocialAuthSettings
from core.mailer import MailMessage, Mailer
from framework.fastapi import create_auth_router, get_current_user
from providers.base import AuthorizationRequest, SocialIdentity


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
        social=SocialAuthSettings(
            google=GoogleProviderSettings(
                enabled=True,
                client_id="google-client-id",
                client_secret="google-client-secret",
                redirect_uri="https://auth.example.com/api/auth/callback/google",
            ),
        ),
    )


class MemoryMailer(Mailer):
    def __init__(self) -> None:
        self.outbox: list[MailMessage] = []

    async def send(self, message: MailMessage) -> None:
        self.outbox.append(message)


class FakeGoogleProvider:
    provider_name = "google"
    expected_issuer = "https://accounts.google.com"

    def get_authorization_url(self, *, state: str, code_verifier: str) -> AuthorizationRequest:
        assert code_verifier
        return AuthorizationRequest(
            url=f"https://accounts.example.com/auth?state={state}",
            state=state,
        )

    async def exchange_code(self, *, code: str, code_verifier: str) -> SocialIdentity:
        assert code == "oauth-code"
        assert code_verifier
        return SocialIdentity(
            provider="google",
            provider_account_id="google-user-123",
            email="sami@example.com",
            email_verified=True,
            safe_for_email_linking=True,
            name="Sami",
            image="https://example.com/sami.png",
            access_token="google-access-token",
            refresh_token="google-refresh-token",
            expires_at=None,
        )


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


def build_app(auth: PyAuth) -> FastAPI:
    app = FastAPI()
    app.include_router(create_auth_router(auth))

    @app.get("/me")
    async def read_me(current_user=Depends(get_current_user(auth))):  # type: ignore[name-defined]
        return {"id": current_user.id, "email": current_user.email}

    return app


@pytest.mark.asyncio
async def test_fastapi_sign_up_sets_session_cookie_and_exposes_current_user(
    sqlite_adapter: SQLAlchemyAdapter,
) -> None:
    auth = PyAuth(
        settings=build_settings(),
        adapter=sqlite_adapter,
        mailer=MemoryMailer(),
    )
    app = build_app(auth)

    with TestClient(app, base_url="https://testserver") as client:
        response = client.post(
            "/api/auth/sign-up",
            json={"email": "sami@example.com", "password": "very-secure-password"},
        )

        assert response.status_code == 200
        assert build_settings().session.cookie_name in response.cookies

        me_response = client.get("/me")
        assert me_response.status_code == 200
        assert me_response.json()["email"] == "sami@example.com"


@pytest.mark.asyncio
async def test_fastapi_oauth_start_sets_signed_state_cookie_and_redirects(
    sqlite_adapter: SQLAlchemyAdapter,
) -> None:
    auth = PyAuth(
        settings=build_settings(),
        adapter=sqlite_adapter,
        mailer=MemoryMailer(),
        providers={"google": FakeGoogleProvider()},
    )
    app = build_app(auth)

    with TestClient(app, base_url="https://testserver") as client:
        response = client.get("/api/auth/oauth/google", follow_redirects=False)

        assert response.status_code == 307
        assert response.headers["location"].startswith("https://accounts.example.com/auth")
        assert build_settings().oauth.state_cookie_name in response.cookies


@pytest.mark.asyncio
async def test_fastapi_oauth_callback_validates_state_and_sets_session_cookie(
    sqlite_adapter: SQLAlchemyAdapter,
) -> None:
    auth = PyAuth(
        settings=build_settings(),
        adapter=sqlite_adapter,
        mailer=MemoryMailer(),
        providers={"google": FakeGoogleProvider()},
    )
    app = build_app(auth)

    with TestClient(app, base_url="https://testserver") as client:
        start_response = client.get("/api/auth/oauth/google", follow_redirects=False)
        redirected_state = start_response.headers["location"].split("state=")[-1]

        callback_response = client.get(
            f"/api/auth/callback/google?code=oauth-code&state={redirected_state}",
            follow_redirects=False,
        )

        assert callback_response.status_code == 200
        assert build_settings().session.cookie_name in callback_response.cookies

        me_response = client.get("/me")
        assert me_response.status_code == 200
        assert me_response.json()["email"] == "sami@example.com"


@pytest.mark.asyncio
async def test_fastapi_oauth_callback_rejects_state_mismatch(
    sqlite_adapter: SQLAlchemyAdapter,
) -> None:
    auth = PyAuth(
        settings=build_settings(),
        adapter=sqlite_adapter,
        mailer=MemoryMailer(),
        providers={"google": FakeGoogleProvider()},
    )
    app = build_app(auth)

    with TestClient(app, base_url="https://testserver") as client:
        client.get("/api/auth/oauth/google", follow_redirects=False)
        callback_response = client.get(
            "/api/auth/callback/google?code=oauth-code&state=wrong-state",
            follow_redirects=False,
        )

        assert callback_response.status_code == 400
        assert callback_response.json()["error"]["code"] == "invalid_oauth_state"


@pytest.mark.asyncio
async def test_fastapi_oauth_callback_rejects_invalid_issuer_and_clears_state_cookie(
    sqlite_adapter: SQLAlchemyAdapter,
) -> None:
    auth = PyAuth(
        settings=build_settings(),
        adapter=sqlite_adapter,
        mailer=MemoryMailer(),
        providers={"google": FakeGoogleProvider()},
    )
    app = build_app(auth)

    with TestClient(app, base_url="https://testserver") as client:
        start_response = client.get("/api/auth/oauth/google", follow_redirects=False)
        redirected_state = start_response.headers["location"].split("state=")[-1]

        bad_callback = client.get(
            f"/api/auth/callback/google?code=oauth-code&state={redirected_state}&iss=https://bad-issuer.example.com",
            follow_redirects=False,
        )

        assert bad_callback.status_code == 400
        assert bad_callback.json()["error"]["code"] == "invalid_oauth_issuer"

        repeated_callback = client.get(
            f"/api/auth/callback/google?code=oauth-code&state={redirected_state}",
            follow_redirects=False,
        )

        assert repeated_callback.status_code == 400
        assert repeated_callback.json()["error"]["code"] == "invalid_oauth_state"
