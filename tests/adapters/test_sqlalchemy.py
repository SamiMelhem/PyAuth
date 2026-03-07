from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from adapters.sqlalchemy import SQLAlchemyAdapter
from core.errors import AdapterError
from schema.models import Account, Session, User, Verification, VerificationPurpose


@pytest.fixture
async def sqlite_adapter() -> AsyncIterator[SQLAlchemyAdapter]:
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    await SQLAlchemyAdapter.create_schema(engine)

    try:
        yield SQLAlchemyAdapter(session_factory=session_factory)
    finally:
        await engine.dispose()


@pytest.fixture
async def sqlite_session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    await SQLAlchemyAdapter.create_schema(engine)

    try:
        yield session_factory
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_sqlalchemy_adapter_creates_and_fetches_user_by_normalized_email(
    sqlite_adapter: SQLAlchemyAdapter,
) -> None:
    created = await sqlite_adapter.create_user(User(email="  Sami@Example.COM  "))
    fetched = await sqlite_adapter.get_user_by_email("sami@example.com")

    assert created.email_normalized == "sami@example.com"
    assert fetched is not None
    assert fetched.id == created.id


@pytest.mark.asyncio
async def test_sqlalchemy_adapter_manages_sessions_and_bulk_revocation(
    sqlite_adapter: SQLAlchemyAdapter,
) -> None:
    user = await sqlite_adapter.create_user(User(email="sami@example.com"))
    session = await sqlite_adapter.create_session(
        Session(
            user_id=user.id,
            token_hash="hashed-session-token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
    )

    fetched = await sqlite_adapter.get_session_by_token_hash("hashed-session-token")
    deleted_count = await sqlite_adapter.delete_sessions_by_user_id(user.id)
    after_delete = await sqlite_adapter.get_session_by_token_hash("hashed-session-token")

    assert fetched is not None
    assert fetched.id == session.id
    assert deleted_count == 1
    assert after_delete is None


@pytest.mark.asyncio
async def test_sqlalchemy_adapter_consumes_verifications_once(
    sqlite_adapter: SQLAlchemyAdapter,
) -> None:
    verification = await sqlite_adapter.create_verification(
        Verification(
            identifier="sami@example.com",
            purpose=VerificationPurpose.EMAIL_VERIFICATION,
            token_hash="hashed-verification-token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
    )

    consumed = await sqlite_adapter.consume_verification(verification.id)
    consumed_again = await sqlite_adapter.consume_verification(verification.id)

    assert consumed is not None
    assert consumed.consumed_at is not None
    assert consumed_again is None


@pytest.mark.asyncio
async def test_sqlalchemy_adapter_enforces_unique_provider_accounts(
    sqlite_adapter: SQLAlchemyAdapter,
) -> None:
    user = await sqlite_adapter.create_user(User(email="sami@example.com"))
    await sqlite_adapter.create_account(
        Account(
            user_id=user.id,
            provider="github",
            provider_account_id="github-123",
        )
    )

    with pytest.raises(AdapterError):
        await sqlite_adapter.create_account(
            Account(
                user_id=user.id,
                provider="github",
                provider_account_id="github-123",
            )
        )


@pytest.mark.asyncio
async def test_sqlalchemy_adapter_does_not_commit_injected_sessions(
    sqlite_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with sqlite_session_factory() as session:
        adapter = SQLAlchemyAdapter(session=session)

        async with session.begin():
            await adapter.create_user(User(email="sami@example.com"))
            assert session.in_transaction() is True


@pytest.mark.asyncio
async def test_sqlalchemy_adapter_rejects_orphan_accounts(
    sqlite_adapter: SQLAlchemyAdapter,
) -> None:
    with pytest.raises(AdapterError):
        await sqlite_adapter.create_account(
            Account(
                user_id="missing-user",
                provider="github",
                provider_account_id="github-123",
            )
        )


@pytest.mark.asyncio
async def test_sqlalchemy_adapter_deletes_expired_verifications(
    sqlite_adapter: SQLAlchemyAdapter,
) -> None:
    await sqlite_adapter.create_verification(
        Verification(
            identifier="sami@example.com",
            purpose=VerificationPurpose.PASSWORD_RESET,
            token_hash="expired-verification-token",
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        )
    )

    deleted_count = await sqlite_adapter.delete_expired_verifications()
    fetched = await sqlite_adapter.get_verification_by_token_hash("expired-verification-token")

    assert deleted_count == 1
    assert fetched is None
