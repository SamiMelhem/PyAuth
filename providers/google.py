from __future__ import annotations

from typing import Any

from core.config import GoogleProviderSettings
from providers.base import BaseOAuthProvider, SocialIdentity


class GoogleProvider(BaseOAuthProvider):
    provider_name = "google"
    authorize_url = "https://accounts.google.com/o/oauth2/v2/auth"
    token_url = "https://oauth2.googleapis.com/token"
    userinfo_url = "https://openidconnect.googleapis.com/v1/userinfo"
    expected_issuer = "https://accounts.google.com"

    def __init__(self, *, settings: GoogleProviderSettings, **kwargs: Any) -> None:
        super().__init__(settings=settings, **kwargs)

    async def _build_identity(self, token_data: dict[str, Any]) -> SocialIdentity:
        client = self.http_client_factory()
        response = await client.get(
            self.userinfo_url,
            headers={"Authorization": f"Bearer {token_data['access_token']}"},
        )
        response.raise_for_status()
        payload = response.json()
        return SocialIdentity(
            provider=self.provider_name,
            provider_account_id=str(payload["sub"]),
            email=payload.get("email"),
            email_verified=bool(payload.get("email_verified")),
            name=payload.get("name"),
            image=payload.get("picture"),
            access_token=token_data.get("access_token"),
            refresh_token=token_data.get("refresh_token"),
            expires_at=self._expires_at_datetime(token_data.get("expires_at")),
            safe_for_email_linking=bool(payload.get("email_verified") and payload.get("email")),
        )
