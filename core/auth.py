from __future__ import annotations

from datetime import timedelta
from re import sub
from typing import Any

from adapters.base import BaseAdapter
from core.config import PyAuthSettings
from core.errors import AuthenticationError, ConfigurationError, ValidationError
from core.mailer import MailMessage, Mailer
from core.session import SessionService
from core.types import AuthenticatedSession, AuthResult, RequestContext
from providers.base import AuthorizationRequest, SocialIdentity
from providers.credentials import CREDENTIALS_PROVIDER, CredentialsProvider
from providers.github import GitHubProvider
from providers.google import GoogleProvider
from schema.models import User, Verification, VerificationPurpose, utc_now
from utils.crypto import PasswordService, TokenService


class PyAuth:
    def __init__(
        self,
        *,
        settings: PyAuthSettings,
        adapter: BaseAdapter | None = None,
        mailer: Mailer | None = None,
        providers: dict[str, Any] | None = None,
    ) -> None:
        self.settings = settings
        self.adapter = adapter
        self.mailer = mailer
        self.passwords = PasswordService(settings=settings.password_hash)
        self.tokens = TokenService(
            settings=settings.jwt,
            refresh_settings=settings.refresh_token,
        )
        self.sessions = SessionService(settings=settings, tokens=self.tokens)
        self.credentials = CredentialsProvider()
        self.providers = providers or self._build_provider_registry()

    def _build_provider_registry(self) -> dict[str, Any]:
        registry: dict[str, Any] = {}
        if self.settings.social.google.enabled:
            registry["google"] = GoogleProvider(settings=self.settings.social.google)
        if self.settings.social.github.enabled:
            registry["github"] = GitHubProvider(settings=self.settings.social.github)
        return registry

    def _require_adapter(self) -> BaseAdapter:
        if self.adapter is None:
            raise ConfigurationError("PyAuth adapter is required for auth flows")
        return self.adapter

    def _require_mailer(self) -> Mailer:
        if self.mailer is None:
            raise ConfigurationError("PyAuth mailer is required for email flows")
        return self.mailer

    def _require_provider(self, provider_name: str) -> Any:
        provider = self.providers.get(provider_name)
        if provider is None:
            raise ValidationError("OAuth provider is not configured", code="oauth_provider_not_found")
        return provider

    async def _create_session_result(
        self,
        *,
        user: User,
        context: RequestContext | None = None,
    ) -> AuthResult:
        adapter = self._require_adapter()
        session, session_token = self.sessions.create_session(user_id=user.id, context=context)
        created_session = await adapter.create_session(session)
        return AuthResult(
            user=user,
            session=created_session,
            session_token=session_token,
            access_token=self.sessions.issue_access_token(user_id=user.id),
        )

    async def _send_verification_message(
        self,
        *,
        user: User,
        purpose: VerificationPurpose,
    ) -> None:
        adapter = self._require_adapter()
        mailer = self._require_mailer()
        ttl_seconds = (
            self.settings.verification.email_verification_ttl_seconds
            if purpose is VerificationPurpose.EMAIL_VERIFICATION
            else self.settings.verification.password_reset_ttl_seconds
        )
        raw_token = self.tokens.generate_refresh_token()
        await adapter.delete_verifications_by_identifier_and_purpose(
            identifier=user.email_normalized or user.email.strip().lower(),
            purpose=purpose,
        )
        await adapter.create_verification(
            Verification(
                identifier=user.email_normalized or user.email.strip().lower(),
                purpose=purpose,
                token_hash=self.tokens.hash_opaque_token(raw_token),
                expires_at=utc_now() + timedelta(seconds=ttl_seconds),
            )
        )
        subject = (
            "Verify your email"
            if purpose is VerificationPurpose.EMAIL_VERIFICATION
            else "Reset your password"
        )
        await mailer.send(
            MailMessage(
                to_email=user.email,
                subject=subject,
                text_body=f"Use this token={raw_token} to continue your {purpose.value} flow.",
            )
        )

    async def sign_up(
        self,
        *,
        email: str,
        password: str,
        name: str | None = None,
        context: RequestContext | None = None,
        send_verification: bool = True,
    ) -> AuthResult:
        adapter = self._require_adapter()
        if await adapter.get_user_by_email(email) is not None:
            raise ValidationError(
                "A user with this email already exists",
                code="email_already_registered",
            )

        user = await adapter.create_user(User(email=email, name=name))
        account = self.credentials.build_account(
            user_id=user.id,
            password_hash=self.passwords.hash_password(password),
        )
        await adapter.create_account(account)
        if send_verification:
            await self._send_verification_message(
                user=user,
                purpose=VerificationPurpose.EMAIL_VERIFICATION,
            )
        return await self._create_session_result(user=user, context=context)

    async def sign_in(
        self,
        *,
        email: str,
        password: str,
        context: RequestContext | None = None,
    ) -> AuthResult:
        adapter = self._require_adapter()
        user = await adapter.get_user_by_email(email)
        if user is None:
            raise AuthenticationError("Invalid email or password", code="invalid_credentials")
        account = await adapter.get_account_by_user_id_and_provider(
            user.id,
            CREDENTIALS_PROVIDER,
        )
        if account is None or account.password_hash is None:
            raise AuthenticationError("Invalid email or password", code="invalid_credentials")
        if not self.passwords.verify_password(password, account.password_hash):
            raise AuthenticationError("Invalid email or password", code="invalid_credentials")
        if self.passwords.needs_rehash(account.password_hash):
            account = account.model_copy(
                update={"password_hash": self.passwords.hash_password(password)}
            )
            await adapter.update_account(account)
        return await self._create_session_result(user=user, context=context)

    async def authenticate_session(self, *, session_token: str) -> AuthenticatedSession:
        adapter = self._require_adapter()
        token_hash = self.tokens.hash_opaque_token(session_token)
        session = await adapter.get_session_by_token_hash(token_hash)
        if session is None:
            raise AuthenticationError("Session is invalid", code="invalid_session")
        if session.expires_at <= utc_now():
            await adapter.delete_session(session.id)
            raise AuthenticationError("Session has expired", code="session_expired")
        user = await adapter.get_user_by_id(session.user_id)
        if user is None:
            raise AuthenticationError("Session user no longer exists", code="invalid_session")
        return AuthenticatedSession(user=user, session=session)

    async def sign_out(self, *, session_token: str) -> bool:
        adapter = self._require_adapter()
        token_hash = self.tokens.hash_opaque_token(session_token)
        session = await adapter.get_session_by_token_hash(token_hash)
        if session is None:
            return False
        return await adapter.delete_session(session.id)

    async def request_password_reset(self, *, email: str) -> None:
        adapter = self._require_adapter()
        user = await adapter.get_user_by_email(email)
        if user is None:
            return
        await self._send_verification_message(
            user=user,
            purpose=VerificationPurpose.PASSWORD_RESET,
        )

    async def reset_password(self, *, token: str, new_password: str) -> User:
        adapter = self._require_adapter()
        token_hash = self.tokens.hash_opaque_token(token)
        verification = await adapter.get_verification_by_token_hash(token_hash)
        if (
            verification is None
            or verification.purpose is not VerificationPurpose.PASSWORD_RESET
            or verification.consumed_at is not None
            or verification.expires_at <= utc_now()
        ):
            raise ValidationError(
                "Reset token is invalid or expired",
                code="invalid_reset_token",
            )
        user = await adapter.get_user_by_email(verification.identifier)
        if user is None:
            raise ValidationError("User not found for reset token", code="user_not_found")
        account = await adapter.get_account_by_user_id_and_provider(
            user.id,
            CREDENTIALS_PROVIDER,
        )
        if account is None:
            raise ValidationError("Credentials account not found", code="credentials_not_found")
        await adapter.update_account(
            account.model_copy(update={"password_hash": self.passwords.hash_password(new_password)})
        )
        await adapter.consume_verification(verification.id)
        await adapter.delete_sessions_by_user_id(user.id)
        refreshed_user = await adapter.get_user_by_id(user.id)
        assert refreshed_user is not None
        return refreshed_user

    async def request_email_verification(self, *, user_id: str) -> None:
        adapter = self._require_adapter()
        user = await adapter.get_user_by_id(user_id)
        if user is None:
            raise ValidationError("User not found", code="user_not_found")
        await self._send_verification_message(
            user=user,
            purpose=VerificationPurpose.EMAIL_VERIFICATION,
        )

    async def verify_email(self, *, token: str) -> User:
        adapter = self._require_adapter()
        token_hash = self.tokens.hash_opaque_token(token)
        verification = await adapter.get_verification_by_token_hash(token_hash)
        if (
            verification is None
            or verification.purpose is not VerificationPurpose.EMAIL_VERIFICATION
            or verification.consumed_at is not None
            or verification.expires_at <= utc_now()
        ):
            raise ValidationError(
                "Verification token is invalid or expired",
                code="invalid_verification_token",
            )
        user = await adapter.get_user_by_email(verification.identifier)
        if user is None:
            raise ValidationError("User not found", code="user_not_found")
        updated_user = await adapter.update_user(
            user.model_copy(update={"email_verified": True})
        )
        await adapter.consume_verification(verification.id)
        return updated_user

    def begin_oauth_sign_in(
        self,
        *,
        provider_name: str,
        state: str,
        code_verifier: str,
    ) -> AuthorizationRequest:
        provider = self._require_provider(provider_name)
        return provider.get_authorization_url(state=state, code_verifier=code_verifier)

    async def complete_oauth_sign_in(
        self,
        *,
        provider_name: str,
        code: str,
        code_verifier: str,
        context: RequestContext | None = None,
    ) -> AuthResult:
        adapter = self._require_adapter()
        provider = self._require_provider(provider_name)
        identity: SocialIdentity = await provider.exchange_code(
            code=code,
            code_verifier=code_verifier,
        )

        account = await adapter.get_account_by_provider_account_id(
            identity.provider,
            identity.provider_account_id,
        )
        if account is not None:
            updated_account = await adapter.update_account(
                account.model_copy(
                    update={
                        "access_token": identity.access_token,
                        "refresh_token": identity.refresh_token,
                        "expires_at": identity.expires_at,
                    }
                )
            )
            user = await adapter.get_user_by_id(updated_account.user_id)
            if user is None:
                raise ValidationError("OAuth user not found", code="user_not_found")
            return await self._create_session_result(user=user, context=context)

        user = await adapter.get_user_by_email(identity.email) if identity.email else None
        if user is None:
            user = await adapter.create_user(
                User(
                    email=identity.email
                    or self._build_placeholder_email(
                        provider=identity.provider,
                        provider_account_id=identity.provider_account_id,
                    ),
                    email_verified=identity.safe_for_email_linking,
                    name=identity.name,
                    image=identity.image,
                )
            )
        elif not identity.safe_for_email_linking:
            raise ValidationError(
                "Verified email is required before linking an OAuth account",
                code="unsafe_oauth_link",
            )
        elif identity.safe_for_email_linking and not user.email_verified:
            user = await adapter.update_user(user.model_copy(update={"email_verified": True}))

        await adapter.create_account(
            self._build_social_account(user_id=user.id, identity=identity)
        )
        return await self._create_session_result(user=user, context=context)

    @staticmethod
    def _build_social_account(*, user_id: str, identity: SocialIdentity):
        from schema.models import Account

        return Account(
            user_id=user_id,
            provider=identity.provider,
            provider_account_id=identity.provider_account_id,
            access_token=identity.access_token,
            refresh_token=identity.refresh_token,
            expires_at=identity.expires_at,
        )

    @staticmethod
    def _build_placeholder_email(*, provider: str, provider_account_id: str) -> str:
        normalized_provider = sub(r"[^a-z0-9]+", "-", provider.lower()).strip("-")
        normalized_subject = sub(
            r"[^a-z0-9]+",
            "-",
            provider_account_id.lower(),
        ).strip("-")
        return f"{normalized_provider}-{normalized_subject}@oauth.local"
