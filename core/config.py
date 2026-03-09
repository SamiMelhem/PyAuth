from __future__ import annotations

from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class PasswordHashSettings(BaseModel):
    algorithm: Literal["argon2id"] = "argon2id"
    memory_cost_kib: int = Field(default=65_536, gt=0)
    time_cost: int = Field(default=3, gt=0)
    parallelism: int = Field(default=4, gt=0)
    salt_length: int = Field(default=16, gt=0)
    hash_length: int = Field(default=32, gt=0)


class JwtSettings(BaseModel):
    algorithm: Literal["EdDSA"] = "EdDSA"
    issuer: str
    audience: str
    access_token_ttl_seconds: int = Field(default=900, gt=0)
    leeway_seconds: int = Field(default=30, ge=0)
    private_key_pem: str | None = None
    public_key_pem: str | None = None
    key_id: str | None = None

    @model_validator(mode="after")
    def validate_key_material(self) -> "JwtSettings":
        if self.algorithm == "EdDSA":
            if not self.private_key_pem or not self.public_key_pem:
                raise ValueError(
                    "EdDSA access tokens require both private_key_pem and public_key_pem."
                )
            private_key = serialization.load_pem_private_key(
                self.private_key_pem.encode(),
                password=None,
            )
            public_key = serialization.load_pem_public_key(self.public_key_pem.encode())

            if not isinstance(private_key, Ed25519PrivateKey):
                raise ValueError("EdDSA access tokens require an Ed25519 private key.")
            if not isinstance(public_key, Ed25519PublicKey):
                raise ValueError("EdDSA access tokens require an Ed25519 public key.")

            derived_public_pem = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            provided_public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            if derived_public_pem != provided_public_pem:
                raise ValueError("EdDSA key material must use a matching Ed25519 key pair.")
        return self

    @classmethod
    def generate(cls, *, issuer: str, audience: str, key_id: str | None = None) -> "JwtSettings":
        private_key = Ed25519PrivateKey.generate()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        return cls(
            issuer=issuer,
            audience=audience,
            private_key_pem=private_pem,
            public_key_pem=public_pem,
            key_id=key_id,
        )


class RefreshTokenSettings(BaseModel):
    token_bytes: int = Field(default=32, gt=0)
    rotation_enabled: bool = True
    digest_algorithm: Literal["sha256"] = "sha256"


class SessionSettings(BaseModel):
    ttl_seconds: int = Field(default=1_209_600, gt=0)
    cookie_name: str = "pyauth_session"

    @field_validator("cookie_name")
    @classmethod
    def validate_cookie_name(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("cookie_name must not be blank")
        return trimmed

class CookieSettings(BaseModel):
    secure: bool = True
    http_only: bool = True
    same_site: Literal["lax", "strict", "none"] = "lax"
    path: str = "/"
    domain: str | None = None
    max_age_seconds: int = Field(default=1_209_600, gt=0)


class SecuritySettings(BaseModel):
    require_https: bool = True
    enable_bearer_tokens: bool = True
    enable_cookie_sessions: bool = True


class VerificationSettings(BaseModel):
    email_verification_ttl_seconds: int = Field(default=86_400, gt=0)
    password_reset_ttl_seconds: int = Field(default=3_600, gt=0)


class OAuthSettings(BaseModel):
    state_cookie_name: str = "pyauth_oauth_state"
    state_ttl_seconds: int = Field(default=600, gt=0)

    @field_validator("state_cookie_name")
    @classmethod
    def validate_state_cookie_name(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("state_cookie_name must not be blank")
        return trimmed


class SocialProviderSettings(BaseModel):
    enabled: bool = False
    client_id: str | None = None
    client_secret: str | None = None
    redirect_uri: str | None = None
    scopes: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_enabled_provider(self) -> "SocialProviderSettings":
        if self.enabled:
            missing = [
                field_name
                for field_name in ("client_id", "client_secret", "redirect_uri")
                if not getattr(self, field_name)
            ]
            if missing:
                raise ValueError(
                    f"Enabled social providers require values for: {', '.join(missing)}"
                )
        return self


class GoogleProviderSettings(SocialProviderSettings):
    scopes: list[str] = Field(default_factory=lambda: ["openid", "email", "profile"])


class GitHubProviderSettings(SocialProviderSettings):
    scopes: list[str] = Field(default_factory=lambda: ["read:user", "user:email"])


class SocialAuthSettings(BaseModel):
    google: GoogleProviderSettings = Field(default_factory=GoogleProviderSettings)
    github: GitHubProviderSettings = Field(default_factory=GitHubProviderSettings)


class MailerSettings(BaseModel):
    from_email: str = "no-reply@example.com"
    from_name: str | None = None

    @field_validator("from_email")
    @classmethod
    def validate_from_email(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("from_email must not be blank")
        return trimmed


class PyAuthSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PYAUTH_",
        env_nested_delimiter="__",
        extra="ignore",
        validate_default=True,
    )

    password_hash: PasswordHashSettings = Field(default_factory=PasswordHashSettings)
    jwt: JwtSettings
    refresh_token: RefreshTokenSettings = Field(default_factory=RefreshTokenSettings)
    session: SessionSettings = Field(default_factory=SessionSettings)
    cookie: CookieSettings = Field(default_factory=CookieSettings)
    verification: VerificationSettings = Field(default_factory=VerificationSettings)
    oauth: OAuthSettings = Field(default_factory=OAuthSettings)
    social: SocialAuthSettings = Field(default_factory=SocialAuthSettings)
    mailer: MailerSettings = Field(default_factory=MailerSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)

    @classmethod
    def for_development(
        cls,
        *,
        issuer: str,
        audience: str,
        password_hash: PasswordHashSettings | None = None,
        refresh_token: RefreshTokenSettings | None = None,
        session: SessionSettings | None = None,
        cookie: CookieSettings | None = None,
        verification: VerificationSettings | None = None,
        oauth: OAuthSettings | None = None,
        social: SocialAuthSettings | None = None,
        mailer: MailerSettings | None = None,
        security: SecuritySettings | None = None,
        key_id: str | None = None,
    ) -> "PyAuthSettings":
        dev_cookie = cookie or CookieSettings(secure=False)
        dev_security = security or SecuritySettings(require_https=False)
        return cls(
            password_hash=password_hash or PasswordHashSettings(),
            jwt=JwtSettings.generate(issuer=issuer, audience=audience, key_id=key_id),
            refresh_token=refresh_token or RefreshTokenSettings(),
            session=session or SessionSettings(),
            cookie=dev_cookie,
            verification=verification or VerificationSettings(),
            oauth=oauth or OAuthSettings(),
            social=social or SocialAuthSettings(),
            mailer=mailer or MailerSettings(),
            security=dev_security,
        )
