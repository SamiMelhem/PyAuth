from __future__ import annotations

from collections.abc import AsyncIterator
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient
import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from adapters.sqlalchemy import SQLAlchemyAdapter
from core.auth import PyAuth
from core.config import (
    GoogleProviderSettings,
    JwtSettings,
    PyAuthSettings,
    SecuritySettings,
    SocialAuthSettings,
)
from core.mailer import MailMessage, Mailer
from framework.fastapi import PyAuthRouter, create_auth_router, get_current_user
from framework.request import PyAuthRequest
from providers.base import AuthorizationRequest, SocialIdentity


def build_settings(*, security: SecuritySettings | None = None) -> PyAuthSettings:
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
        security=security or SecuritySettings(),
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

    @app.get("/request-context")
    async def request_context(request: Request):
        pyauth_request = PyAuthRequest.from_fastapi(request)
        return {
            "ip_address": pyauth_request.ip_address,
            "user_agent": pyauth_request.user_agent,
            "headers": pyauth_request.headers,
            "cookies": pyauth_request.cookies,
        }

    return app


def _route_paths(routes: list) -> set[tuple[str, tuple[str, ...]]]:
    return {
        (path, tuple(sorted(methods or set())))
        for route in routes
        if (path := getattr(route, "path", None)) is not None
        and (methods := getattr(route, "methods", None)) is not None
    }


def test_pyauth_router_fastapi_adapter_matches_compatibility_wrapper() -> None:
    auth = PyAuth(settings=build_settings())

    router = PyAuthRouter(auth)
    adapter_paths = _route_paths(router.for_fastapi().routes)
    compatibility_paths = _route_paths(create_auth_router(auth).routes)

    assert adapter_paths == compatibility_paths
    assert router.prefix == "/api/auth"
    assert {path for path, _ in adapter_paths} == {
        "/api/auth/sign-up",
        "/api/auth/sign-in",
        "/api/auth/sign-out",
        "/api/auth/password-reset/request",
        "/api/auth/password-reset/confirm",
        "/api/auth/email-verification/request",
        "/api/auth/email-verification/confirm",
        "/api/auth/oauth/{provider_name}",
        "/api/auth/callback/{provider_name}",
    }


@pytest.mark.asyncio
async def test_pyauth_router_current_user_dependency_matches_compatibility_helper(
    sqlite_adapter: SQLAlchemyAdapter,
) -> None:
    auth = PyAuth(
        settings=build_settings(),
        adapter=sqlite_adapter,
        mailer=MemoryMailer(),
    )
    router = PyAuthRouter(auth)
    app = FastAPI()
    app.include_router(router.for_fastapi())

    @app.get("/me")
    async def read_me(current_user=Depends(router.get_current_user())):  # type: ignore[name-defined]
        return {"email": current_user.email}

    with TestClient(app, base_url="https://testserver") as client:
        client.post(
            "/api/auth/sign-up",
            json={"email": "router@example.com", "password": "very-secure-password"},
        )

        response = client.get("/me")

    assert response.status_code == 200
    assert response.json()["email"] == "router@example.com"


@pytest.mark.asyncio
async def test_pyauth_router_build_request_hook_controls_request_context(
    sqlite_adapter: SQLAlchemyAdapter,
) -> None:
    class CustomPyAuthRouter(PyAuthRouter):
        def build_request(self, request: Request) -> PyAuthRequest:
            built = super().build_request(request)
            return PyAuthRequest(
                ip_address="203.0.113.10",
                user_agent="CustomAgent/1.0",
                headers=built.headers,
                cookies=built.cookies,
            )

    auth = PyAuth(
        settings=build_settings(),
        adapter=sqlite_adapter,
        mailer=MemoryMailer(),
    )
    router = CustomPyAuthRouter(auth)
    app = FastAPI()
    router.mount_fastapi(app)

    with TestClient(app, base_url="https://testserver") as client:
        response = client.post(
            "/api/auth/sign-up",
            json={"email": "custom-context@example.com", "password": "very-secure-password"},
        )

    session_token = response.cookies[auth.settings.session.cookie_name]
    authenticated = await auth.authenticate_session(session_token=session_token)

    assert authenticated.session.ip_address == "203.0.113.10"
    assert authenticated.session.user_agent == "CustomAgent/1.0"


def test_pyauth_router_can_mount_itself_into_fastapi_app() -> None:
    auth = PyAuth(settings=build_settings())
    router = PyAuthRouter(auth)
    app = FastAPI()

    mounted_app = router.mount_fastapi(app)

    assert mounted_app is app
    mounted_paths = {getattr(route, "path", "") for route in app.routes}
    assert "/api/auth/sign-in" in mounted_paths
    assert "/api/auth/sign-up" in mounted_paths


@pytest.mark.asyncio
async def test_pyauth_router_bearer_dependency_authenticates_access_token(
    sqlite_adapter: SQLAlchemyAdapter,
) -> None:
    auth = PyAuth(
        settings=build_settings(),
        adapter=sqlite_adapter,
        mailer=MemoryMailer(),
    )
    router = PyAuthRouter(auth)
    app = FastAPI()
    app.include_router(router.for_fastapi())

    @app.get("/api-me")
    async def api_me(current_user=Depends(router.get_current_user_bearer())):  # type: ignore[name-defined]
        return {"email": current_user.email}

    with TestClient(app, base_url="https://testserver") as client:
        sign_up_response = client.post(
            "/api/auth/sign-up",
            json={"email": "bearer@example.com", "password": "very-secure-password"},
        )
        access_token = sign_up_response.json()["access_token"]
        response = client.get("/api-me", headers={"Authorization": f"Bearer {access_token}"})

    assert response.status_code == 200
    assert response.json()["email"] == "bearer@example.com"


@pytest.mark.asyncio
async def test_pyauth_router_bearer_dependency_respects_disabled_bearer_transport(
    sqlite_adapter: SQLAlchemyAdapter,
) -> None:
    auth = PyAuth(
        settings=build_settings(security=SecuritySettings(enable_bearer_tokens=False)),
        adapter=sqlite_adapter,
        mailer=MemoryMailer(),
    )
    router = PyAuthRouter(auth)
    app = FastAPI()
    app.include_router(router.for_fastapi())

    @app.get("/api-me")
    async def api_me(current_user=Depends(router.get_current_user_bearer())):  # type: ignore[name-defined]
        return {"email": current_user.email}

    with TestClient(app, base_url="https://testserver") as client:
        client.post(
            "/api/auth/sign-up",
            json={"email": "disabled-bearer@example.com", "password": "very-secure-password"},
        )
        created_user = await sqlite_adapter.get_user_by_email("disabled-bearer@example.com")
        assert created_user is not None
        token = auth.tokens.issue_access_token(subject=created_user.id)
        response = client.get("/api-me", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401
    assert response.json()["detail"]["error"]["code"] == "bearer_transport_disabled"


@pytest.mark.asyncio
async def test_pyauth_router_cookie_dependency_respects_disabled_cookie_transport(
    sqlite_adapter: SQLAlchemyAdapter,
) -> None:
    auth = PyAuth(
        settings=build_settings(security=SecuritySettings(enable_cookie_sessions=False)),
        adapter=sqlite_adapter,
        mailer=MemoryMailer(),
    )
    router = PyAuthRouter(auth)
    app = FastAPI()
    router.mount_fastapi(app)

    @app.get("/me")
    async def read_me(current_user=Depends(router.get_current_user())):  # type: ignore[name-defined]
        return {"email": current_user.email}

    with TestClient(app, base_url="https://testserver") as client:
        sign_up_response = client.post(
            "/api/auth/sign-up",
            json={"email": "cookie-disabled@example.com", "password": "very-secure-password"},
        )
        me_response = client.get("/me")

    assert auth.settings.session.cookie_name not in sign_up_response.cookies
    assert me_response.status_code == 401
    assert me_response.json()["detail"]["error"]["code"] == "cookie_transport_disabled"


@pytest.mark.asyncio
async def test_fastapi_current_user_dependency_returns_structured_missing_session_error(
    sqlite_adapter: SQLAlchemyAdapter,
) -> None:
    auth = PyAuth(
        settings=build_settings(),
        adapter=sqlite_adapter,
        mailer=MemoryMailer(),
    )
    app = build_app(auth)

    with TestClient(app, base_url="https://testserver") as client:
        response = client.get("/me")

    assert response.status_code == 401
    assert response.json()["detail"]["error"]["code"] == "missing_session"


def test_pyauth_request_from_fastapi_normalizes_request_metadata() -> None:
    app = FastAPI()

    @app.get("/request-context")
    async def request_context(request: Request):
        pyauth_request = PyAuthRequest.from_fastapi(request)
        return {
            "ip_address": pyauth_request.ip_address,
            "user_agent": pyauth_request.user_agent,
            "headers": pyauth_request.headers,
            "cookies": pyauth_request.cookies,
        }

    with TestClient(app, base_url="https://testserver") as client:
        client.cookies.set("example_cookie", "cookie-value")
        response = client.get(
            "/request-context",
            headers={"user-agent": "PyAuthTest/1.0", "x-trace-id": "trace-123"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["ip_address"] == "testclient"
    assert body["user_agent"] == "PyAuthTest/1.0"
    assert body["headers"]["x-trace-id"] == "trace-123"
    assert body["cookies"]["example_cookie"] == "cookie-value"


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
