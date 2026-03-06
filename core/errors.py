from __future__ import annotations

from typing import Any


class PyAuthError(Exception):
    default_code = "pyauth_error"
    default_status_code = 500

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        status_code: int | None = None,
        detail: dict[str, Any] | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code or self.default_code
        self.status_code = status_code or self.default_status_code
        self.detail = detail
        self.cause = cause

    def to_dict(self) -> dict[str, Any]:
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "detail": self.detail,
            }
        }


class ConfigurationError(PyAuthError):
    default_code = "configuration_error"
    default_status_code = 500


class AuthenticationError(PyAuthError):
    default_code = "authentication_error"
    default_status_code = 401


class AuthorizationError(PyAuthError):
    default_code = "authorization_error"
    default_status_code = 403


class TokenError(PyAuthError):
    default_code = "token_error"
    default_status_code = 401


class ValidationError(PyAuthError):
    default_code = "validation_error"
    default_status_code = 400


class RateLimitError(PyAuthError):
    default_code = "rate_limit_error"
    default_status_code = 429


class AdapterError(PyAuthError):
    default_code = "adapter_error"
    default_status_code = 500
