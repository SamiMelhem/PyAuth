from __future__ import annotations

from abc import ABC, abstractmethod

from schema.models import Account, Session, User, Verification, VerificationPurpose


class BaseAdapter(ABC):
    @abstractmethod
    async def create_user(self, user: User) -> User:
        raise NotImplementedError

    @abstractmethod
    async def update_user(self, user: User) -> User:
        raise NotImplementedError

    @abstractmethod
    async def get_user_by_id(self, user_id: str) -> User | None:
        raise NotImplementedError

    @abstractmethod
    async def get_user_by_email(self, email: str) -> User | None:
        raise NotImplementedError

    @abstractmethod
    async def create_account(self, account: Account) -> Account:
        raise NotImplementedError

    @abstractmethod
    async def get_account_by_provider_account_id(
        self,
        provider: str,
        provider_account_id: str,
    ) -> Account | None:
        raise NotImplementedError

    @abstractmethod
    async def get_accounts_by_user_id(self, user_id: str) -> list[Account]:
        raise NotImplementedError

    @abstractmethod
    async def get_account_by_user_id_and_provider(
        self,
        user_id: str,
        provider: str,
    ) -> Account | None:
        raise NotImplementedError

    @abstractmethod
    async def update_account(self, account: Account) -> Account:
        raise NotImplementedError

    @abstractmethod
    async def delete_account(self, account_id: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    async def create_session(self, session: Session) -> Session:
        raise NotImplementedError

    @abstractmethod
    async def get_session_by_token_hash(self, token_hash: str) -> Session | None:
        raise NotImplementedError

    @abstractmethod
    async def delete_session(self, session_id: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    async def delete_sessions_by_user_id(self, user_id: str) -> int:
        raise NotImplementedError

    @abstractmethod
    async def create_verification(self, verification: Verification) -> Verification:
        raise NotImplementedError

    @abstractmethod
    async def get_verification_by_token_hash(
        self,
        token_hash: str,
    ) -> Verification | None:
        raise NotImplementedError

    @abstractmethod
    async def consume_verification(self, verification_id: str) -> Verification | None:
        raise NotImplementedError

    @abstractmethod
    async def delete_verifications_by_identifier_and_purpose(
        self,
        *,
        identifier: str,
        purpose: VerificationPurpose,
    ) -> int:
        raise NotImplementedError

    @abstractmethod
    async def delete_expired_verifications(self) -> int:
        raise NotImplementedError