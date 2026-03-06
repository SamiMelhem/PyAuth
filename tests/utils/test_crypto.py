from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from core.config import JwtSettings, PasswordHashSettings, PyAuthSettings
from core.errors import TokenError
from utils.crypto import PasswordService, TokenService


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
        )
    )


def test_password_service_hashes_and_verifies_password() -> None:
    service = PasswordService(settings=build_settings().password_hash)

    password_hash = service.hash_password("super-secret-password")

    assert password_hash != "super-secret-password"
    assert service.verify_password("super-secret-password", password_hash) is True
    assert service.verify_password("wrong-password", password_hash) is False


def test_password_service_detects_rehash_requirement() -> None:
    original_service = PasswordService(settings=build_settings().password_hash)
    password_hash = original_service.hash_password("super-secret-password")

    stronger_settings = PasswordHashSettings(
        memory_cost_kib=original_service.settings.memory_cost_kib * 2
    )
    stronger_service = PasswordService(settings=stronger_settings)

    assert stronger_service.needs_rehash(password_hash) is True


def test_token_service_issues_and_decodes_access_tokens() -> None:
    settings = build_settings()
    service = TokenService(settings=settings.jwt)

    token = service.issue_access_token(subject="user_123")
    claims = service.decode_access_token(token)

    assert claims["sub"] == "user_123"
    assert claims["iss"] == settings.jwt.issuer
    assert claims["aud"] == settings.jwt.audience
    assert claims["token_type"] == "access"


def test_token_service_generates_and_hashes_refresh_tokens() -> None:
    service = TokenService(settings=build_settings().jwt)

    token = service.generate_refresh_token()
    token_hash = service.hash_opaque_token(token)

    assert isinstance(token, str)
    assert len(token) >= 43
    assert token_hash != token
    assert service.hash_opaque_token(token) == token_hash


def test_token_service_wraps_bad_signature_errors() -> None:
    issuer = build_settings()
    verifier = build_settings()

    token = TokenService(settings=issuer.jwt).issue_access_token(subject="user_123")

    with pytest.raises(TokenError) as exc_info:
        TokenService(settings=verifier.jwt).decode_access_token(token)

    assert exc_info.value.code == "invalid_token"
    assert exc_info.value.status_code == 401
