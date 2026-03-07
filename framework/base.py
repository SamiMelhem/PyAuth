from __future__ import annotations

from itsdangerous import BadSignature, BadTimeSignature, URLSafeTimedSerializer

from core.config import PyAuthSettings
from core.errors import ValidationError


class OAuthStateCookieManager:
    def __init__(self, settings: PyAuthSettings) -> None:
        self.settings = settings
        self.serializer = URLSafeTimedSerializer(
            settings.jwt.private_key_pem or settings.jwt.issuer,
            salt="pyauth-oauth-state",
        )

    def dumps(self, payload: dict[str, str]) -> str:
        return self.serializer.dumps(payload)

    def loads(self, value: str) -> dict[str, str]:
        try:
            payload = self.serializer.loads(
                value,
                max_age=self.settings.oauth.state_ttl_seconds,
            )
        except (BadSignature, BadTimeSignature) as exc:
            raise ValidationError("OAuth state is invalid", code="invalid_oauth_state") from exc
        return payload
