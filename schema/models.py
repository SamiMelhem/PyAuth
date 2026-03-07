from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator, model_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class VerificationPurpose(str, Enum):
    EMAIL_VERIFICATION = "email_verification"
    PASSWORD_RESET = "password_reset"


class EntityModel(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("id must not be blank")
        return trimmed

    @field_validator("created_at", "updated_at")
    @classmethod
    def validate_timestamps(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamps must be timezone-aware")
        return value


class User(EntityModel):
    email: str
    email_normalized: str | None = None
    email_verified: bool = False
    name: str | None = None
    image: str | None = None

    @field_validator("email", mode="before")
    @classmethod
    def strip_email(cls, value: str) -> str:
        return value.strip()

    @model_validator(mode="after")
    def populate_normalized_email(self) -> "User":
        self.email_normalized = self.email.strip().lower()
        return self


class Account(EntityModel):
    user_id: str
    provider: str
    provider_account_id: str
    password_hash: str | None = None
    access_token: str | None = None
    refresh_token: str | None = None
    expires_at: datetime | None = None

    @field_validator("user_id", "provider", "provider_account_id", mode="before")
    @classmethod
    def validate_required_strings(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("value must not be blank")
        return trimmed

    @field_validator("expires_at")
    @classmethod
    def validate_optional_expiration(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("expires_at must be timezone-aware")
        return value


class Session(EntityModel):
    user_id: str
    token_hash: str
    expires_at: datetime
    ip_address: str | None = None
    user_agent: str | None = None

    @field_validator("user_id", "token_hash", mode="before")
    @classmethod
    def validate_session_strings(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("value must not be blank")
        return trimmed

    @field_validator("expires_at")
    @classmethod
    def validate_expiration(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("expires_at must be timezone-aware")
        return value


class Verification(EntityModel):
    identifier: str
    purpose: VerificationPurpose
    token_hash: str
    expires_at: datetime
    consumed_at: datetime | None = None

    @field_validator("identifier", "token_hash", mode="before")
    @classmethod
    def validate_verification_strings(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("value must not be blank")
        return trimmed

    @field_validator("expires_at", "consumed_at")
    @classmethod
    def validate_verification_datetimes(
        cls,
        value: datetime | None,
    ) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("verification datetimes must be timezone-aware")
        return value
