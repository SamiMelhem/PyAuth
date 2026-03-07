from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

import pytest

from core.config import GoogleProviderSettings, JwtSettings, PyAuthSettings, SocialAuthSettings
from providers.google import GoogleProvider


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
                scopes=["openid", "email", "profile"],
            ),
        ),
    )


class FakeOAuthClient:
    def __init__(self) -> None:
        self.created_args: dict[str, str] = {}
        self.fetch_args: dict[str, str] = {}

    def create_authorization_url(self, url: str, **kwargs: str) -> tuple[str, str]:
        self.created_args = {"url": url, **kwargs}
        query = "&".join(f"{key}={value}" for key, value in kwargs.items())
        return f"{url}?{query}", kwargs["state"]

    async def fetch_token(self, url: str, **kwargs: str) -> dict[str, object]:
        self.fetch_args = {"url": url, **kwargs}
        return {
            "access_token": "google-access-token",
            "refresh_token": "google-refresh-token",
            "expires_at": int(datetime(2030, 1, 1, tzinfo=timezone.utc).timestamp()),
        }


class FakeResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, object]:
        return self.payload


class FakeHTTPClient:
    async def get(self, url: str, headers: dict[str, str]) -> FakeResponse:
        assert url.endswith("/userinfo")
        assert headers["Authorization"] == "Bearer google-access-token"
        return FakeResponse(
            {
                "sub": "google-user-123",
                "email": "sami@example.com",
                "email_verified": True,
                "name": "Sami",
                "picture": "https://example.com/sami.png",
            }
        )


@pytest.mark.asyncio
async def test_google_provider_builds_authorization_url_with_pkce() -> None:
    client = FakeOAuthClient()
    provider = GoogleProvider(
        settings=build_settings().social.google,
        oauth_client_factory=lambda **_: client,
        http_client_factory=lambda: FakeHTTPClient(),
    )

    authorization = provider.get_authorization_url(
        state="oauth-state",
        code_verifier="very-long-code-verifier",
    )

    parsed = urlparse(authorization.url)
    query = parse_qs(parsed.query)

    assert parsed.scheme == "https"
    assert query["state"] == ["oauth-state"]
    assert query["code_challenge_method"] == ["S256"]
    assert "code_challenge" in query


@pytest.mark.asyncio
async def test_google_provider_exchanges_code_and_maps_identity() -> None:
    client = FakeOAuthClient()
    provider = GoogleProvider(
        settings=build_settings().social.google,
        oauth_client_factory=lambda **_: client,
        http_client_factory=lambda: FakeHTTPClient(),
    )

    identity = await provider.exchange_code(
        code="google-code",
        code_verifier="very-long-code-verifier",
    )

    assert identity.provider == "google"
    assert identity.provider_account_id == "google-user-123"
    assert identity.email == "sami@example.com"
    assert identity.email_verified is True
    assert identity.safe_for_email_linking is True
    assert identity.name == "Sami"
    assert identity.access_token == "google-access-token"
