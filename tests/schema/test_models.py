from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from schema.models import Account, Session, User, Verification, VerificationPurpose


def test_user_normalizes_email_and_sets_timestamps() -> None:
    user = User(email="  Sami@Example.COM  ")

    assert user.email == "Sami@Example.COM"
    assert user.email_normalized == "sami@example.com"
    assert isinstance(user.created_at, datetime)
    assert isinstance(user.updated_at, datetime)


def test_account_supports_credentials_provider_defaults() -> None:
    account = Account(
        user_id="user_123",
        provider="credentials",
        provider_account_id="sami@example.com",
        password_hash="hashed-password",
    )

    assert account.password_hash == "hashed-password"
    assert account.access_token is None
    assert account.refresh_token is None


def test_session_and_verification_have_portable_shapes() -> None:
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

    session = Session(
        user_id="user_123",
        token_hash="hashed-session-token",
        expires_at=expires_at,
    )
    verification = Verification(
        identifier="sami@example.com",
        purpose=VerificationPurpose.EMAIL_VERIFICATION,
        token_hash="hashed-verification-token",
        expires_at=expires_at,
    )

    assert session.token_hash == "hashed-session-token"
    assert verification.purpose is VerificationPurpose.EMAIL_VERIFICATION
    assert verification.consumed_at is None


def test_account_rejects_blank_provider_fields() -> None:
    with pytest.raises(ValidationError):
        Account(
            user_id="user_123",
            provider="   ",
            provider_account_id="   ",
        )


def test_session_rejects_naive_expiration_datetimes() -> None:
    with pytest.raises(ValidationError):
        Session(
            user_id="user_123",
            token_hash="hashed-session-token",
            expires_at=datetime.now(),
        )
