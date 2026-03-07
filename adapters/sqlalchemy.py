from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, cast

from sqlalchemy import Boolean, DateTime, String, Text, UniqueConstraint, delete, select
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from adapters.base import BaseAdapter
from core.errors import AdapterError
from schema.models import Account, Session, User, Verification, VerificationPurpose, utc_now


class Base(DeclarativeBase):
    pass


class UserRecord(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    email_normalized: Mapped[str] = mapped_column(String(320), unique=True, nullable=False)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    image: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AccountRecord(Base):
    __tablename__ = "accounts"
    __table_args__ = (
        UniqueConstraint("provider", "provider_account_id", name="uq_accounts_provider_identity"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    provider_account_id: Mapped[str] = mapped_column(String(255), nullable=False)
    password_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    access_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    refresh_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class SessionRecord(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(255), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class VerificationRecord(Base):
    __tablename__ = "verifications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    identifier: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    purpose: Mapped[str] = mapped_column(String(100), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class SQLAlchemyAdapter(BaseAdapter):
    def __init__(
        self,
        *,
        session: AsyncSession | None = None,
        session_factory: async_sessionmaker[AsyncSession] | None = None,
    ) -> None:
        if (session is None) == (session_factory is None):
            raise ValueError("Provide exactly one of session or session_factory.")
        self._session = session
        self._session_factory = session_factory

    @staticmethod
    async def create_schema(engine: AsyncEngine) -> None:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

    @asynccontextmanager
    async def _session_scope(self):
        if self._session is not None:
            yield self._session
            return

        assert self._session_factory is not None
        async with self._session_factory() as session:
            yield session

    def _owns_session(self, session: AsyncSession) -> bool:
        return self._session is None

    async def _finalize_write(
        self,
        session: AsyncSession,
        *,
        refresh_record: UserRecord | AccountRecord | SessionRecord | VerificationRecord | None = None,
    ) -> None:
        try:
            if self._owns_session(session):
                await session.commit()
                if refresh_record is not None:
                    await session.refresh(refresh_record)
            else:
                await session.flush()
        except IntegrityError as exc:
            await session.rollback()
            raise AdapterError(
                "Database integrity constraint failed",
                code="adapter_integrity_error",
            ) from exc
        except SQLAlchemyError as exc:
            await session.rollback()
            raise AdapterError("Database operation failed", code="adapter_error") from exc

    async def _ensure_user_exists(self, session: AsyncSession, user_id: str) -> None:
        record = await session.get(UserRecord, user_id)
        if record is None:
            raise AdapterError("User not found", code="user_not_found")

    @staticmethod
    def _aware_datetime(value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            return value.replace(tzinfo=timezone.utc)
        return value

    @staticmethod
    def _to_user(record: UserRecord) -> User:
        return User.model_validate(
            {
                "id": record.id,
                "email": record.email,
                "email_normalized": record.email_normalized,
                "email_verified": record.email_verified,
                "name": record.name,
                "image": record.image,
                "created_at": SQLAlchemyAdapter._aware_datetime(record.created_at),
                "updated_at": SQLAlchemyAdapter._aware_datetime(record.updated_at),
            }
        )

    @staticmethod
    def _to_account(record: AccountRecord) -> Account:
        return Account.model_validate(
            {
                "id": record.id,
                "user_id": record.user_id,
                "provider": record.provider,
                "provider_account_id": record.provider_account_id,
                "password_hash": record.password_hash,
                "access_token": record.access_token,
                "refresh_token": record.refresh_token,
                "expires_at": SQLAlchemyAdapter._aware_datetime(record.expires_at),
                "created_at": SQLAlchemyAdapter._aware_datetime(record.created_at),
                "updated_at": SQLAlchemyAdapter._aware_datetime(record.updated_at),
            }
        )

    @staticmethod
    def _to_session(record: SessionRecord) -> Session:
        return Session.model_validate(
            {
                "id": record.id,
                "user_id": record.user_id,
                "token_hash": record.token_hash,
                "expires_at": SQLAlchemyAdapter._aware_datetime(record.expires_at),
                "ip_address": record.ip_address,
                "user_agent": record.user_agent,
                "created_at": SQLAlchemyAdapter._aware_datetime(record.created_at),
                "updated_at": SQLAlchemyAdapter._aware_datetime(record.updated_at),
            }
        )

    @staticmethod
    def _to_verification(record: VerificationRecord) -> Verification:
        return Verification.model_validate(
            {
                "id": record.id,
                "identifier": record.identifier,
                "purpose": record.purpose,
                "token_hash": record.token_hash,
                "expires_at": SQLAlchemyAdapter._aware_datetime(record.expires_at),
                "consumed_at": SQLAlchemyAdapter._aware_datetime(record.consumed_at),
                "created_at": SQLAlchemyAdapter._aware_datetime(record.created_at),
                "updated_at": SQLAlchemyAdapter._aware_datetime(record.updated_at),
            }
        )

    async def create_user(self, user: User) -> User:
        async with self._session_scope() as session:
            record = UserRecord(
                id=user.id,
                email=user.email,
                email_normalized=user.email_normalized,
                email_verified=user.email_verified,
                name=user.name,
                image=user.image,
                created_at=user.created_at,
                updated_at=user.updated_at,
            )
            session.add(record)
            await self._finalize_write(session, refresh_record=record)
            return self._to_user(record)

    async def get_user_by_id(self, user_id: str) -> User | None:
        async with self._session_scope() as session:
            record = await session.get(UserRecord, user_id)
            return None if record is None else self._to_user(record)

    async def update_user(self, user: User) -> User:
        async with self._session_scope() as session:
            record = await session.get(UserRecord, user.id)
            if record is None:
                raise AdapterError("User not found", code="user_not_found")
            record.email = user.email
            record.email_normalized = user.email_normalized or user.email.strip().lower()
            record.email_verified = user.email_verified
            record.name = user.name
            record.image = user.image
            record.updated_at = utc_now()
            await self._finalize_write(session, refresh_record=record)
            return self._to_user(record)

    async def get_user_by_email(self, email: str) -> User | None:
        normalized_email = email.strip().lower()
        async with self._session_scope() as session:
            result = await session.execute(
                select(UserRecord).where(UserRecord.email_normalized == normalized_email)
            )
            record = result.scalar_one_or_none()
            return None if record is None else self._to_user(record)

    async def create_account(self, account: Account) -> Account:
        async with self._session_scope() as session:
            await self._ensure_user_exists(session, account.user_id)
            record = AccountRecord(
                id=account.id,
                user_id=account.user_id,
                provider=account.provider,
                provider_account_id=account.provider_account_id,
                password_hash=account.password_hash,
                access_token=account.access_token,
                refresh_token=account.refresh_token,
                expires_at=account.expires_at,
                created_at=account.created_at,
                updated_at=account.updated_at,
            )
            session.add(record)
            await self._finalize_write(session, refresh_record=record)
            return self._to_account(record)

    async def get_account_by_provider_account_id(
        self,
        provider: str,
        provider_account_id: str,
    ) -> Account | None:
        async with self._session_scope() as session:
            result = await session.execute(
                select(AccountRecord).where(
                    AccountRecord.provider == provider,
                    AccountRecord.provider_account_id == provider_account_id,
                )
            )
            record = result.scalar_one_or_none()
            return None if record is None else self._to_account(record)

    async def get_accounts_by_user_id(self, user_id: str) -> list[Account]:
        async with self._session_scope() as session:
            result = await session.execute(
                select(AccountRecord).where(AccountRecord.user_id == user_id)
            )
            return [self._to_account(record) for record in result.scalars().all()]

    async def get_account_by_user_id_and_provider(
        self,
        user_id: str,
        provider: str,
    ) -> Account | None:
        async with self._session_scope() as session:
            result = await session.execute(
                select(AccountRecord).where(
                    AccountRecord.user_id == user_id,
                    AccountRecord.provider == provider,
                )
            )
            record = result.scalar_one_or_none()
            return None if record is None else self._to_account(record)

    async def update_account(self, account: Account) -> Account:
        async with self._session_scope() as session:
            record = await session.get(AccountRecord, account.id)
            if record is None:
                raise AdapterError("Account not found", code="account_not_found")
            record.password_hash = account.password_hash
            record.access_token = account.access_token
            record.refresh_token = account.refresh_token
            record.expires_at = account.expires_at
            record.updated_at = utc_now()
            await self._finalize_write(session, refresh_record=record)
            return self._to_account(record)

    async def delete_account(self, account_id: str) -> bool:
        async with self._session_scope() as session:
            result = cast(
                CursorResult[Any],
                await session.execute(
                delete(AccountRecord).where(AccountRecord.id == account_id)
                ),
            )
            await self._finalize_write(session)
            return bool(result.rowcount)

    async def create_session(self, session: Session) -> Session:
        session_model = session
        async with self._session_scope() as db_session:
            await self._ensure_user_exists(db_session, session_model.user_id)
            record = SessionRecord(
                id=session_model.id,
                user_id=session_model.user_id,
                token_hash=session_model.token_hash,
                expires_at=session_model.expires_at,
                ip_address=session_model.ip_address,
                user_agent=session_model.user_agent,
                created_at=session_model.created_at,
                updated_at=session_model.updated_at,
            )
            db_session.add(record)
            await self._finalize_write(db_session, refresh_record=record)
            return self._to_session(record)

    async def get_session_by_token_hash(self, token_hash: str) -> Session | None:
        async with self._session_scope() as session:
            result = await session.execute(
                select(SessionRecord).where(SessionRecord.token_hash == token_hash)
            )
            record = result.scalar_one_or_none()
            return None if record is None else self._to_session(record)

    async def delete_session(self, session_id: str) -> bool:
        async with self._session_scope() as session:
            result = cast(
                CursorResult[Any],
                await session.execute(
                delete(SessionRecord).where(SessionRecord.id == session_id)
                ),
            )
            await self._finalize_write(session)
            return bool(result.rowcount)

    async def delete_sessions_by_user_id(self, user_id: str) -> int:
        async with self._session_scope() as session:
            result = cast(
                CursorResult[Any],
                await session.execute(
                delete(SessionRecord).where(SessionRecord.user_id == user_id)
                ),
            )
            await self._finalize_write(session)
            return int(result.rowcount or 0)

    async def create_verification(self, verification: Verification) -> Verification:
        async with self._session_scope() as session:
            record = VerificationRecord(
                id=verification.id,
                identifier=verification.identifier,
                purpose=verification.purpose.value,
                token_hash=verification.token_hash,
                expires_at=verification.expires_at,
                consumed_at=verification.consumed_at,
                created_at=verification.created_at,
                updated_at=verification.updated_at,
            )
            session.add(record)
            await self._finalize_write(session, refresh_record=record)
            return self._to_verification(record)

    async def get_verification_by_token_hash(
        self,
        token_hash: str,
    ) -> Verification | None:
        async with self._session_scope() as session:
            result = await session.execute(
                select(VerificationRecord).where(VerificationRecord.token_hash == token_hash)
            )
            record = result.scalar_one_or_none()
            return None if record is None else self._to_verification(record)

    async def consume_verification(self, verification_id: str) -> Verification | None:
        async with self._session_scope() as session:
            record = await session.get(VerificationRecord, verification_id)
            if record is None or record.consumed_at is not None:
                return None
            record.consumed_at = utc_now()
            record.updated_at = utc_now()
            await self._finalize_write(session, refresh_record=record)
            return self._to_verification(record)

    async def delete_verifications_by_identifier_and_purpose(
        self,
        *,
        identifier: str,
        purpose: VerificationPurpose,
    ) -> int:
        async with self._session_scope() as session:
            result = cast(
                CursorResult[Any],
                await session.execute(
                    delete(VerificationRecord).where(
                        VerificationRecord.identifier == identifier,
                        VerificationRecord.purpose == purpose.value,
                    )
                ),
            )
            await self._finalize_write(session)
            return int(result.rowcount or 0)

    async def delete_expired_verifications(self) -> int:
        async with self._session_scope() as session:
            result = cast(
                CursorResult[Any],
                await session.execute(
                delete(VerificationRecord).where(VerificationRecord.expires_at < utc_now())
                ),
            )
            await self._finalize_write(session)
            return int(result.rowcount or 0)
