from __future__ import annotations

from collections.abc import AsyncIterator
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
import re
import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from adapters.sqlalchemy import SQLAlchemyAdapter
from core.auth import PyAuth
from core.config import GoogleProviderSettings, JwtSettings, PyAuthSettings, SocialAuthSettings
from framework.fastapi import PyAuthRouter
from providers.base import AuthorizationRequest, SocialIdentity
from utils.mailer import InMemoryMailer


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


class FakeGoogleProvider:
    provider_name = "google"
    expected_issuer = "https://accounts.google.com"

    def get_authorization_url(self, *, state: str, code_verifier: str) -> AuthorizationRequest:
        return AuthorizationRequest(
            url=f"https://accounts.example.com/auth?state={state}",
            state=state,
        )

    async def exchange_code(self, *, code: str, code_verifier: str) -> SocialIdentity:
        return SocialIdentity(
            provider="google",
            provider_account_id="google-user-123",
            email="oauth@example.com",
            email_verified=True,
            safe_for_email_linking=True,
            name="OAuth User",
            image=None,
            access_token="google-access-token",
            refresh_token=None,
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
    router = PyAuthRouter(auth)
    router.mount_fastapi(app)

    @app.get("/me")
    async def read_me(current_user=Depends(router.get_current_user())):  # type: ignore[name-defined]
        return {"id": current_user.id, "email": current_user.email}

    return app


def extract_token(body: str) -> str:
    match = re.search(r"token=([-A-Za-z0-9_.]+)", body)
    assert match is not None
    return match.group(1)


@pytest.mark.asyncio
async def test_end_to_end_credentials_verification_reset_and_oauth_flow(
    sqlite_adapter: SQLAlchemyAdapter,
) -> None:
    mailer = InMemoryMailer()
    auth = PyAuth(
        settings=build_settings(),
        adapter=sqlite_adapter,
        mailer=mailer,
        providers={"google": FakeGoogleProvider()},
    )
    app = build_app(auth)

    with TestClient(app, base_url="https://testserver") as client:
        sign_up_response = client.post(
            "/api/auth/sign-up",
            json={"email": "sami@example.com", "password": "very-secure-password"},
        )
        assert sign_up_response.status_code == 200
        assert len(mailer.outbox) == 1

        verification_token = extract_token(mailer.outbox[-1].text_body)
        verification_response = client.post(
            "/api/auth/email-verification/confirm",
            json={"token": verification_token},
        )
        assert verification_response.status_code == 200
        assert verification_response.json()["user"]["email_verified"] is True

        missing_reset_response = client.post(
            "/api/auth/password-reset/request",
            json={"email": "missing@example.com"},
        )
        assert missing_reset_response.status_code == 200
        assert missing_reset_response.json() == {"requested": True}

        reset_request_response = client.post(
            "/api/auth/password-reset/request",
            json={"email": "sami@example.com"},
        )
        assert reset_request_response.status_code == 200

        reset_token = extract_token(mailer.outbox[-1].text_body)
        reset_confirm_response = client.post(
            "/api/auth/password-reset/confirm",
            json={"token": reset_token, "new_password": "new-very-secure-password"},
        )
        assert reset_confirm_response.status_code == 200

        bad_sign_in_response = client.post(
            "/api/auth/sign-in",
            json={"email": "sami@example.com", "password": "very-secure-password"},
        )
        assert bad_sign_in_response.status_code == 401
        assert bad_sign_in_response.json()["error"]["code"] == "invalid_credentials"

        good_sign_in_response = client.post(
            "/api/auth/sign-in",
            json={"email": "sami@example.com", "password": "new-very-secure-password"},
        )
        assert good_sign_in_response.status_code == 200

        me_response = client.get("/me")
        assert me_response.status_code == 200
        assert me_response.json()["email"] == "sami@example.com"

        sign_out_response = client.post("/api/auth/sign-out")
        assert sign_out_response.status_code == 200

        me_after_sign_out = client.get("/me")
        assert me_after_sign_out.status_code == 401

        oauth_start_response = client.get("/api/auth/oauth/google", follow_redirects=False)
        redirected_state = oauth_start_response.headers["location"].split("state=")[-1]
        oauth_callback_response = client.get(
            f"/api/auth/callback/google?code=oauth-code&state={redirected_state}"
        )
        assert oauth_callback_response.status_code == 200

        oauth_me_response = client.get("/me")
        assert oauth_me_response.status_code == 200
        assert oauth_me_response.json()["email"] == "oauth@example.com"
