from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import rsa
from typing import Any
import pytest
from pydantic import ValidationError

from core.config import (
    GitHubProviderSettings,
    GoogleProviderSettings,
    JwtSettings,
    MailerSettings,
    OAuthSettings,
    PyAuthSettings,
    SessionSettings,
    SocialAuthSettings,
    VerificationSettings,
)


def build_ed25519_key_pair() -> tuple[str, str]:
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
    return private_pem, public_pem


def test_pyauth_settings_default_secure_options() -> None:
    private_pem, public_pem = build_ed25519_key_pair()

    settings = PyAuthSettings(
        jwt=JwtSettings(
            issuer="https://auth.example.com",
            audience="pyauth-clients",
            private_key_pem=private_pem,
            public_key_pem=public_pem,
        )
    )

    assert settings.password_hash.algorithm == "argon2id"
    assert settings.jwt.algorithm == "EdDSA"
    assert settings.refresh_token.rotation_enabled is True
    assert settings.cookie.secure is True
    assert settings.cookie.http_only is True
    assert settings.session.cookie_name == "pyauth_session"
    assert settings.verification.password_reset_ttl_seconds == 3600
    assert settings.oauth.state_cookie_name == "pyauth_oauth_state"
    assert settings.social.google.enabled is False
    assert settings.mailer.from_email == "no-reply@example.com"


def test_pyauth_settings_require_key_material_for_eddsa() -> None:
    with pytest.raises(ValidationError):
        PyAuthSettings(
            jwt=JwtSettings(
                issuer="https://auth.example.com",
                audience="pyauth-clients",
            )
        )


def test_pyauth_settings_reject_non_ed25519_keys_for_eddsa() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
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

    with pytest.raises(ValidationError):
        PyAuthSettings(
            jwt=JwtSettings(
                issuer="https://auth.example.com",
                audience="pyauth-clients",
                private_key_pem=private_pem,
                public_key_pem=public_pem,
            )
        )


def test_pyauth_settings_reject_mismatched_ed25519_key_pairs() -> None:
    first_private_pem, _ = build_ed25519_key_pair()
    _, second_public_pem = build_ed25519_key_pair()

    with pytest.raises(ValidationError):
        PyAuthSettings(
            jwt=JwtSettings(
                issuer="https://auth.example.com",
                audience="pyauth-clients",
                private_key_pem=first_private_pem,
                public_key_pem=second_public_pem,
            )
        )


def test_pyauth_settings_reject_non_positive_access_token_ttl() -> None:
    private_pem, public_pem = build_ed25519_key_pair()

    with pytest.raises(ValidationError):
        PyAuthSettings(
            jwt=JwtSettings(
                issuer="https://auth.example.com",
                audience="pyauth-clients",
                private_key_pem=private_pem,
                public_key_pem=public_pem,
                access_token_ttl_seconds=0,
            ),
        )


@pytest.mark.parametrize(
    ("kwargs", "field_name"),
    [
        ({"password_hash": {"memory_cost_kib": -1}}, "password_hash"),
        ({"refresh_token": {"token_bytes": 0}}, "refresh_token"),
    ],
)
def test_pyauth_settings_reject_other_invalid_security_numbers(
    kwargs: dict[str, Any],
    field_name: str,
) -> None:
    private_pem, public_pem = build_ed25519_key_pair()

    with pytest.raises(ValidationError) as exc_info:
        PyAuthSettings(
            jwt=JwtSettings(
                issuer="https://auth.example.com",
                audience="pyauth-clients",
                private_key_pem=private_pem,
                public_key_pem=public_pem,
            ),
            **kwargs,
        )

    assert field_name in str(exc_info.value)


def test_pyauth_settings_accept_phase3_provider_and_session_settings() -> None:
    private_pem, public_pem = build_ed25519_key_pair()

    settings = PyAuthSettings(
        jwt=JwtSettings(
            issuer="https://auth.example.com",
            audience="pyauth-clients",
            private_key_pem=private_pem,
            public_key_pem=public_pem,
        ),
        session=SessionSettings(
            ttl_seconds=86_400,
            cookie_name="__Host-pyauth_session",
        ),
        verification=VerificationSettings(
            email_verification_ttl_seconds=900,
            password_reset_ttl_seconds=1800,
        ),
        oauth=OAuthSettings(
            state_cookie_name="__Host-pyauth_oauth_state",
            state_ttl_seconds=600,
        ),
        social=SocialAuthSettings(
            google=GoogleProviderSettings(
                enabled=True,
                client_id="google-client-id",
                client_secret="google-client-secret",
                redirect_uri="https://auth.example.com/api/auth/callback/google",
                scopes=["openid", "email", "profile"],
            ),
            github=GitHubProviderSettings(
                enabled=True,
                client_id="github-client-id",
                client_secret="github-client-secret",
                redirect_uri="https://auth.example.com/api/auth/callback/github",
            ),
        ),
        mailer=MailerSettings(
            from_email="auth@example.com",
            from_name="PyAuth",
        ),
    )

    assert settings.session.ttl_seconds == 86_400
    assert settings.verification.email_verification_ttl_seconds == 900
    assert settings.oauth.state_ttl_seconds == 600
    assert settings.social.google.enabled is True
    assert settings.social.google.scopes == ["openid", "email", "profile"]
    assert settings.social.github.redirect_uri is not None
    assert settings.social.github.redirect_uri.endswith("/github")
    assert settings.mailer.from_name == "PyAuth"


@pytest.mark.parametrize(
    ("kwargs", "field_name"),
    [
        ({"session": {"ttl_seconds": 0}}, "session"),
        ({"verification": {"password_reset_ttl_seconds": 0}}, "verification"),
        ({"oauth": {"state_ttl_seconds": 0}}, "oauth"),
    ],
)
def test_pyauth_settings_reject_invalid_phase3_ttls(
    kwargs: dict[str, Any],
    field_name: str,
) -> None:
    private_pem, public_pem = build_ed25519_key_pair()

    with pytest.raises(ValidationError) as exc_info:
        PyAuthSettings(
            jwt=JwtSettings(
                issuer="https://auth.example.com",
                audience="pyauth-clients",
                private_key_pem=private_pem,
                public_key_pem=public_pem,
            ),
            **kwargs,
        )

    assert field_name in str(exc_info.value)


def test_pyauth_settings_require_provider_credentials_when_provider_enabled() -> None:
    private_pem, public_pem = build_ed25519_key_pair()

    with pytest.raises(ValidationError) as exc_info:
        PyAuthSettings(
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
                    redirect_uri="https://auth.example.com/api/auth/callback/google",
                ),
            ),
        )

    assert "client_secret" in str(exc_info.value)
