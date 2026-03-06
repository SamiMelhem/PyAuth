from __future__ import annotations

import hashlib
import secrets
import time
import uuid
import warnings
from typing import Any

from joserfc import jwk, jwt
from joserfc.jws import JWSRegistry
from pwdlib.hashers.argon2 import Argon2Hasher

from core.config import JwtSettings, PasswordHashSettings, RefreshTokenSettings
from core.errors import TokenError


class PasswordService:
    def __init__(self, settings: PasswordHashSettings) -> None:
        self.settings = settings
        self._hasher = Argon2Hasher(
            time_cost=settings.time_cost,
            memory_cost=settings.memory_cost_kib,
            parallelism=settings.parallelism,
            hash_len=settings.hash_length,
            salt_len=settings.salt_length,
        )

    def hash_password(self, password: str) -> str:
        return self._hasher.hash(password)

    def verify_password(self, password: str, password_hash: str) -> bool:
        return self._hasher.verify(password, password_hash)

    def needs_rehash(self, password_hash: str) -> bool:
        return self._hasher.check_needs_rehash(password_hash)


class TokenService:
    def __init__(
        self,
        settings: JwtSettings,
        refresh_settings: RefreshTokenSettings | None = None,
    ) -> None:
        self.settings = settings
        self.refresh_settings = refresh_settings or RefreshTokenSettings()
        self._registry = JWSRegistry(algorithms=[settings.algorithm])
        self._private_key = jwk.import_key(settings.private_key_pem, "OKP")
        self._public_key = jwk.import_key(settings.public_key_pem, "OKP")

    def issue_access_token(
        self,
        *,
        subject: str,
        additional_claims: dict[str, Any] | None = None,
    ) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": self.settings.issuer,
            "aud": self.settings.audience,
            "sub": subject,
            "iat": now,
            "nbf": now,
            "exp": now + self.settings.access_token_ttl_seconds,
            "jti": str(uuid.uuid4()),
            "token_type": "access",
        }
        if additional_claims:
            claims.update(additional_claims)

        header = {"alg": self.settings.algorithm, "typ": "JWT"}
        if self.settings.key_id:
            header["kid"] = self.settings.key_id

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return jwt.encode(
                header,
                claims,
                self._private_key,
                registry=self._registry,
            )

    def decode_access_token(self, token: str) -> dict[str, Any]:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                decoded = jwt.decode(
                    token,
                    self._public_key,
                    algorithms=[self.settings.algorithm],
                    registry=self._registry,
                )
        except TokenError:
            raise
        except Exception as exc:
            raise TokenError("Token signature is invalid", code="invalid_token") from exc

        claims = dict(decoded.claims)
        now = int(time.time())
        leeway = self.settings.leeway_seconds

        if claims.get("iss") != self.settings.issuer:
            raise TokenError("Token issuer is invalid", code="invalid_token_issuer")
        if claims.get("aud") != self.settings.audience:
            raise TokenError("Token audience is invalid", code="invalid_token_audience")
        if claims.get("token_type") != "access":
            raise TokenError("Token type is invalid", code="invalid_token_type")
        if int(claims.get("nbf", now)) > now + leeway:
            raise TokenError("Token is not active yet", code="token_not_active")
        if int(claims.get("exp", now)) <= now - leeway:
            raise TokenError("Token has expired", code="token_expired")

        return claims

    def generate_refresh_token(self) -> str:
        return secrets.token_urlsafe(self.refresh_settings.token_bytes)

    def hash_opaque_token(self, token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()
