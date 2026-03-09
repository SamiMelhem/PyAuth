from __future__ import annotations

from typing import TYPE_CHECKING

from core.auth import PyAuth
from core.config import PyAuthSettings
from core.mailer import ConsoleMailer

if TYPE_CHECKING:
    from framework.request import PyAuthRequest
    from framework.router import PyAuthRouter

__all__ = ["ConsoleMailer", "PyAuth", "PyAuthRequest", "PyAuthRouter", "PyAuthSettings"]


def __getattr__(name: str):
    if name in {"PyAuthRequest", "PyAuthRouter"}:
        from framework import PyAuthRequest, PyAuthRouter

        return {"PyAuthRequest": PyAuthRequest, "PyAuthRouter": PyAuthRouter}[name]
    raise AttributeError(f"module '__init__' has no attribute {name!r}")
