from __future__ import annotations

from dataclasses import dataclass, field

from schema.models import Session, User


@dataclass(frozen=True)
class RequestContext:
    ip_address: str | None = None
    user_agent: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class AuthResult:
    user: User
    session: Session
    session_token: str
    access_token: str | None = None


@dataclass(frozen=True)
class AuthenticatedSession:
    user: User
    session: Session
