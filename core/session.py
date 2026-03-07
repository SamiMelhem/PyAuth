from __future__ import annotations

from datetime import timedelta

from core.config import PyAuthSettings
from core.types import RequestContext
from schema.models import Session, utc_now
from utils.crypto import TokenService


class SessionService:
    def __init__(self, *, settings: PyAuthSettings, tokens: TokenService) -> None:
        self.settings = settings
        self.tokens = tokens

    def create_session(
        self,
        *,
        user_id: str,
        context: RequestContext | None = None,
    ) -> tuple[Session, str]:
        raw_token = self.tokens.generate_refresh_token()
        session = Session(
            user_id=user_id,
            token_hash=self.tokens.hash_opaque_token(raw_token),
            expires_at=utc_now() + timedelta(seconds=self.settings.session.ttl_seconds),
            ip_address=context.ip_address if context is not None else None,
            user_agent=context.user_agent if context is not None else None,
        )
        return session, raw_token

    def issue_access_token(self, *, user_id: str) -> str | None:
        if not self.settings.security.enable_bearer_tokens:
            return None
        return self.tokens.issue_access_token(subject=user_id)
