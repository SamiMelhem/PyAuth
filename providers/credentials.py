from __future__ import annotations

from schema.models import Account


CREDENTIALS_PROVIDER = "credentials"


class CredentialsProvider:
    provider_name: str = CREDENTIALS_PROVIDER

    def build_account(self, *, user_id: str, password_hash: str) -> Account:
        return Account(
            user_id=user_id,
            provider=self.provider_name,
            provider_account_id=user_id,
            password_hash=password_hash,
        )
