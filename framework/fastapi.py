from __future__ import annotations

import secrets
from typing import Any, Callable

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse

from core.auth import PyAuth
from core.errors import AuthenticationError, PyAuthError, ValidationError
from framework.base import OAuthStateCookieManager
from framework.request import build_request_context
from framework.schemas import (
    EmailVerificationConfirmBody,
    EmailVerificationRequestBody,
    PasswordResetConfirmBody,
    PasswordResetRequestBody,
    SignInRequest,
    SignUpRequest,
)


def _error_response(error: PyAuthError) -> JSONResponse:
    return JSONResponse(status_code=error.status_code, content=error.to_dict())


def _set_session_cookie(auth: PyAuth, response: Response, session_token: str) -> None:
    response.set_cookie(
        key=auth.settings.session.cookie_name,
        value=session_token,
        max_age=auth.settings.session.ttl_seconds,
        secure=auth.settings.cookie.secure,
        httponly=auth.settings.cookie.http_only,
        samesite=auth.settings.cookie.same_site,
        path=auth.settings.cookie.path,
        domain=auth.settings.cookie.domain,
    )


def _clear_session_cookie(auth: PyAuth, response: Response) -> None:
    response.delete_cookie(
        key=auth.settings.session.cookie_name,
        path=auth.settings.cookie.path,
        domain=auth.settings.cookie.domain,
    )


def get_current_user(auth: PyAuth) -> Callable[..., Any]:
    async def dependency(request: Request):
        session_token = request.cookies.get(auth.settings.session.cookie_name)
        if not session_token:
            error = AuthenticationError("Session cookie is missing", code="missing_session")
            raise HTTPException(status_code=error.status_code, detail=error.to_dict())
        try:
            authenticated = await auth.authenticate_session(session_token=session_token)
        except PyAuthError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.to_dict()) from exc
        return authenticated.user

    return dependency


def create_auth_router(auth: PyAuth) -> APIRouter:
    router = APIRouter(prefix="/api/auth")
    oauth_cookie = OAuthStateCookieManager(auth.settings)

    @router.post("/sign-up")
    async def sign_up(payload: SignUpRequest, request: Request):
        try:
            result = await auth.sign_up(
                email=payload.email,
                password=payload.password,
                name=payload.name,
                context=build_request_context(request),
            )
        except PyAuthError as exc:
            return _error_response(exc)

        response = JSONResponse(
            {
                "user": result.user.model_dump(mode="json"),
                "access_token": result.access_token,
            }
        )
        _set_session_cookie(auth, response, result.session_token)
        return response

    @router.post("/sign-in")
    async def sign_in(payload: SignInRequest, request: Request):
        try:
            result = await auth.sign_in(
                email=payload.email,
                password=payload.password,
                context=build_request_context(request),
            )
        except PyAuthError as exc:
            return _error_response(exc)

        response = JSONResponse(
            {
                "user": result.user.model_dump(mode="json"),
                "access_token": result.access_token,
            }
        )
        _set_session_cookie(auth, response, result.session_token)
        return response

    @router.post("/sign-out")
    async def sign_out(request: Request):
        session_token = request.cookies.get(auth.settings.session.cookie_name)
        response = JSONResponse({"signed_out": True})
        _clear_session_cookie(auth, response)
        if not session_token:
            return response
        try:
            await auth.sign_out(session_token=session_token)
        except PyAuthError as exc:
            return _error_response(exc)
        return response

    @router.post("/password-reset/request")
    async def request_password_reset(payload: PasswordResetRequestBody):
        try:
            await auth.request_password_reset(email=payload.email)
        except PyAuthError as exc:
            return _error_response(exc)
        return JSONResponse({"requested": True})

    @router.post("/password-reset/confirm")
    async def confirm_password_reset(payload: PasswordResetConfirmBody):
        try:
            user = await auth.reset_password(
                token=payload.token,
                new_password=payload.new_password,
            )
        except PyAuthError as exc:
            return _error_response(exc)
        return JSONResponse({"user": user.model_dump(mode="json")})

    @router.post("/email-verification/request")
    async def request_email_verification(payload: EmailVerificationRequestBody):
        try:
            await auth.request_email_verification(user_id=payload.user_id)
        except PyAuthError as exc:
            return _error_response(exc)
        return JSONResponse({"requested": True})

    @router.post("/email-verification/confirm")
    async def confirm_email_verification(payload: EmailVerificationConfirmBody):
        try:
            user = await auth.verify_email(token=payload.token)
        except PyAuthError as exc:
            return _error_response(exc)
        return JSONResponse({"user": user.model_dump(mode="json")})

    @router.get("/oauth/{provider_name}")
    async def start_oauth(provider_name: str):
        state = secrets.token_urlsafe(24)
        code_verifier = secrets.token_urlsafe(48)
        try:
            authorization = auth.begin_oauth_sign_in(
                provider_name=provider_name,
                state=state,
                code_verifier=code_verifier,
            )
        except PyAuthError as exc:
            return _error_response(exc)

        response = RedirectResponse(authorization.url)
        response.set_cookie(
            key=auth.settings.oauth.state_cookie_name,
            value=oauth_cookie.dumps(
                {
                    "provider": provider_name,
                    "state": state,
                    "code_verifier": code_verifier,
                }
            ),
            max_age=auth.settings.oauth.state_ttl_seconds,
            secure=auth.settings.cookie.secure,
            httponly=True,
            samesite=auth.settings.cookie.same_site,
            path=auth.settings.cookie.path,
            domain=auth.settings.cookie.domain,
        )
        return response

    @router.get("/callback/{provider_name}")
    async def oauth_callback(
        provider_name: str,
        code: str,
        state: str,
        request: Request,
        iss: str | None = None,
    ):
        state_cookie = request.cookies.get(auth.settings.oauth.state_cookie_name)
        if not state_cookie:
            return _error_response(
                ValidationError("OAuth state cookie is missing", code="invalid_oauth_state")
            )

        try:
            payload = oauth_cookie.loads(state_cookie)
            if payload.get("provider") != provider_name or payload.get("state") != state:
                raise ValidationError("OAuth state is invalid", code="invalid_oauth_state")
            provider = auth._require_provider(provider_name)
            expected_issuer = getattr(provider, "expected_issuer", None)
            if iss is not None and expected_issuer is not None and iss != expected_issuer:
                raise ValidationError("OAuth issuer is invalid", code="invalid_oauth_issuer")
            result = await auth.complete_oauth_sign_in(
                provider_name=provider_name,
                code=code,
                code_verifier=payload["code_verifier"],
                context=build_request_context(request),
            )
        except PyAuthError as exc:
            response = _error_response(exc)
            response.delete_cookie(
                auth.settings.oauth.state_cookie_name,
                path=auth.settings.cookie.path,
                domain=auth.settings.cookie.domain,
            )
            return response

        response = JSONResponse(
            {
                "user": result.user.model_dump(mode="json"),
                "access_token": result.access_token,
            }
        )
        _set_session_cookie(auth, response, result.session_token)
        response.delete_cookie(
            auth.settings.oauth.state_cookie_name,
            path=auth.settings.cookie.path,
            domain=auth.settings.cookie.domain,
        )
        return response

    return router
