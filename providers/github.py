from __future__ import annotations

from typing import Any

from core.config import GitHubProviderSettings
from providers.base import BaseOAuthProvider, SocialIdentity


class GitHubProvider(BaseOAuthProvider):
    provider_name = "github"
    authorize_url = "https://github.com/login/oauth/authorize"
    token_url = "https://github.com/login/oauth/access_token"
    user_url = "https://api.github.com/user"
    emails_url = "https://api.github.com/user/emails"

    def __init__(self, *, settings: GitHubProviderSettings, **kwargs: Any) -> None:
        super().__init__(settings=settings, **kwargs)

    async def _build_identity(self, token_data: dict[str, Any]) -> SocialIdentity:
        client = self.http_client_factory()
        headers = {"Authorization": f"Bearer {token_data['access_token']}"}

        user_response = await client.get(self.user_url, headers=headers)
        user_response.raise_for_status()
        user_payload = user_response.json()

        emails_response = await client.get(self.emails_url, headers=headers)
        emails_response.raise_for_status()
        emails_payload = emails_response.json()

        primary_email = next(
            (
                item
                for item in emails_payload
                if item.get("primary") or item.get("verified")
            ),
            None,
        )

        return SocialIdentity(
            provider=self.provider_name,
            provider_account_id=str(user_payload["id"]),
            email=primary_email.get("email") if primary_email is not None else None,
            email_verified=bool(primary_email and primary_email.get("verified")),
            name=user_payload.get("name"),
            image=user_payload.get("avatar_url"),
            access_token=token_data.get("access_token"),
            refresh_token=token_data.get("refresh_token"),
            expires_at=self._expires_at_datetime(token_data.get("expires_at")),
            safe_for_email_linking=bool(
                primary_email
                and primary_email.get("verified")
                and primary_email.get("primary")
            ),
        )
