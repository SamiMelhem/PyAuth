from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable

from core.auth import PyAuth
from framework.request import PyAuthRequest

if TYPE_CHECKING:
    from fastapi import APIRouter, FastAPI


class PyAuthRouter:
    def __init__(self, auth: PyAuth, *, prefix: str = "/api/auth") -> None:
        self.auth = auth
        self.prefix = prefix

    def build_request(self, request: Any) -> PyAuthRequest:
        return PyAuthRequest.from_fastapi(request)

    def for_fastapi(self) -> "APIRouter":
        from framework.fastapi import build_fastapi_auth_router

        return build_fastapi_auth_router(self)

    def mount_fastapi(self, app: "FastAPI") -> "FastAPI":
        app.include_router(self.for_fastapi())
        return app

    def get_current_user(self) -> Callable[..., Any]:
        from framework.fastapi import build_current_user_dependency

        return build_current_user_dependency(self.auth)

    def get_current_user_bearer(self) -> Callable[..., Any]:
        from framework.fastapi import build_current_user_bearer_dependency

        return build_current_user_bearer_dependency(self.auth)
