from __future__ import annotations

import base64
import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, cast

from authlib.integrations.httpx_client import AsyncOAuth2Client
import httpx

from core.config import SocialProviderSettings


@dataclass(frozen=True)
class AuthorizationRequest:
    url: str
    state: str


@dataclass(frozen=True)
class SocialIdentity:
    provider: str
    provider_account_id: str
    email: str | None
    email_verified: bool
    name: str | None
    image: str | None
    access_token: str | None
    refresh_token: str | None
    expires_at: datetime | None
    safe_for_email_linking: bool = False


def build_pkce_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


class BaseOAuthProvider(ABC):
    provider_name: str
    authorize_url: str
    token_url: str
    expected_issuer: str | None = None

    def __init__(
        self,
        *,
        settings: SocialProviderSettings,
        oauth_client_factory: Callable[..., Any] | None = None,
        http_client_factory: Callable[[], Any] | None = None,
    ) -> None:
        self.settings = settings
        self.oauth_client_factory = oauth_client_factory or self._default_oauth_client_factory
        self.http_client_factory = http_client_factory or self._default_http_client_factory

    def _default_oauth_client_factory(self, **kwargs: Any) -> AsyncOAuth2Client:
        return AsyncOAuth2Client(**kwargs)

    def _default_http_client_factory(self) -> httpx.AsyncClient:
        return httpx.AsyncClient()

    def get_authorization_url(self, *, state: str, code_verifier: str) -> AuthorizationRequest:
        client = self.oauth_client_factory(
            client_id=self.settings.client_id,
            client_secret=self.settings.client_secret,
            redirect_uri=self.settings.redirect_uri,
            scope=" ".join(self.settings.scopes),
        )
        url, returned_state = client.create_authorization_url(
            self.authorize_url,
            state=state,
            code_challenge=build_pkce_challenge(code_verifier),
            code_challenge_method="S256",
        )
        return AuthorizationRequest(url=url, state=returned_state)

    async def exchange_code(self, *, code: str, code_verifier: str) -> SocialIdentity:
        client = self.oauth_client_factory(
            client_id=self.settings.client_id,
            client_secret=self.settings.client_secret,
            redirect_uri=self.settings.redirect_uri,
        )
        token_data = await client.fetch_token(
            self.token_url,
            code=code,
            code_verifier=code_verifier,
        )
        return await self._build_identity(token_data)

    @staticmethod
    def _expires_at_datetime(expires_at: object) -> datetime | None:
        if expires_at is None:
            return None
        if isinstance(expires_at, datetime):
            return expires_at
        if isinstance(expires_at, (int, float)):
            return datetime.fromtimestamp(int(expires_at), tz=timezone.utc)
        try:
            return datetime.fromtimestamp(int(cast(int | float | str, expires_at)), tz=timezone.utc)
        except (TypeError, ValueError):
            return None

    @abstractmethod
    async def _build_identity(self, token_data: dict[str, Any]) -> SocialIdentity:
        raise NotImplementedError
