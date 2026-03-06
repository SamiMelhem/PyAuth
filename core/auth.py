from __future__ import annotations

from core.config import PyAuthSettings
from utils.crypto import PasswordService, TokenService


class PyAuth:
    def __init__(self, *, settings: PyAuthSettings) -> None:
        self.settings = settings
        self.passwords = PasswordService(settings=settings.password_hash)
        self.tokens = TokenService(
            settings=settings.jwt,
            refresh_settings=settings.refresh_token,
        )
