from __future__ import annotations

from typing import TYPE_CHECKING

from framework.request import PyAuthRequest, build_request_context
from framework.router import PyAuthRouter

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Any

    from core.auth import PyAuth
    from fastapi import APIRouter

    def create_auth_router(auth: PyAuth) -> APIRouter: ...
    def get_current_user(auth: PyAuth) -> Callable[..., Any]: ...
    def get_current_user_bearer(auth: PyAuth) -> Callable[..., Any]: ...

__all__ = [
    "PyAuthRequest",
    "PyAuthRouter",
    "build_request_context",
    "create_auth_router",
    "get_current_user",
    "get_current_user_bearer",
]


def __getattr__(name: str):
    if name in {"create_auth_router", "get_current_user", "get_current_user_bearer"}:
        from framework.fastapi import (
            create_auth_router,
            get_current_user,
            get_current_user_bearer,
        )

        return {
            "create_auth_router": create_auth_router,
            "get_current_user": get_current_user,
            "get_current_user_bearer": get_current_user_bearer,
        }[name]
    raise AttributeError(f"module 'framework' has no attribute {name!r}")
