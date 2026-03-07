from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from urllib.parse import parse_qs, urlparse

import pytest

from core.config import GitHubProviderSettings, JwtSettings, PyAuthSettings, SocialAuthSettings
from providers.github import GitHubProvider


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
            github=GitHubProviderSettings(
                enabled=True,
                client_id="github-client-id",
                client_secret="github-client-secret",
                redirect_uri="https://auth.example.com/api/auth/callback/github",
                scopes=["read:user", "user:email"],
            ),
        ),
    )


class FakeOAuthClient:
    def create_authorization_url(self, url: str, **kwargs: str) -> tuple[str, str]:
        query = "&".join(f"{key}={value}" for key, value in kwargs.items())
        return f"{url}?{query}", kwargs["state"]

    async def fetch_token(self, url: str, **kwargs: str) -> dict[str, object]:
        return {
            "access_token": "github-access-token",
            "refresh_token": None,
            "expires_at": None,
        }


class FakeResponse:
    def __init__(self, payload: object) -> None:
        self.payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> object:
        return self.payload


class FakeHTTPClient:
    async def get(self, url: str, headers: dict[str, str]) -> FakeResponse:
        assert headers["Authorization"] == "Bearer github-access-token"
        if url.endswith("/user"):
            return FakeResponse(
                {
                    "id": 42,
                    "name": "Sami",
                    "avatar_url": "https://example.com/sami.png",
                }
            )
        if url.endswith("/user/emails"):
            return FakeResponse(
                [
                    {
                        "email": "sami@example.com",
                        "primary": True,
                        "verified": True,
                    }
                ]
            )
        raise AssertionError(f"Unexpected URL: {url}")


@pytest.mark.asyncio
async def test_github_provider_builds_authorization_url_with_pkce() -> None:
    provider = GitHubProvider(
        settings=build_settings().social.github,
        oauth_client_factory=lambda **_: FakeOAuthClient(),
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
async def test_github_provider_exchanges_code_and_maps_identity() -> None:
    provider = GitHubProvider(
        settings=build_settings().social.github,
        oauth_client_factory=lambda **_: FakeOAuthClient(),
        http_client_factory=lambda: FakeHTTPClient(),
    )

    identity = await provider.exchange_code(
        code="github-code",
        code_verifier="very-long-code-verifier",
    )

    assert identity.provider == "github"
    assert identity.provider_account_id == "42"
    assert identity.email == "sami@example.com"
    assert identity.email_verified is True
    assert identity.safe_for_email_linking is True
    assert identity.name == "Sami"
    assert identity.access_token == "github-access-token"
