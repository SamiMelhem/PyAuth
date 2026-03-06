from __future__ import annotations

from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from pydantic import BaseModel, Field, model_validator
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


class RefreshTokenSettings(BaseModel):
    token_bytes: int = Field(default=32, gt=0)
    rotation_enabled: bool = True
    digest_algorithm: Literal["sha256"] = "sha256"


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
    cookie: CookieSettings = Field(default_factory=CookieSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
