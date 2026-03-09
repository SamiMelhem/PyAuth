from __future__ import annotations

from typing import TYPE_CHECKING

from pyauth.core.auth import PyAuth
from pyauth.core.config import PyAuthSettings
from pyauth.core.mailer import ConsoleMailer

if TYPE_CHECKING:
    from pyauth.framework import PyAuthRequest, PyAuthRouter

__all__ = ["ConsoleMailer", "PyAuth", "PyAuthRequest", "PyAuthRouter", "PyAuthSettings"]


def __getattr__(name: str):
    if name in {"PyAuthRequest", "PyAuthRouter"}:
        from pyauth.framework import PyAuthRequest, PyAuthRouter

        return {"PyAuthRequest": PyAuthRequest, "PyAuthRouter": PyAuthRouter}[name]
    raise AttributeError(f"module 'pyauth' has no attribute {name!r}")
