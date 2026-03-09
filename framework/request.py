from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.types import RequestContext


@dataclass(frozen=True)
class PyAuthRequest:
    ip_address: str | None = None
    user_agent: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_fastapi(cls, request: Any) -> "PyAuthRequest":
        return cls(
            ip_address=request.client.host if getattr(request, "client", None) is not None else None,
            user_agent=request.headers.get("user-agent"),
            headers=dict(request.headers),
            cookies=dict(request.cookies),
        )

    def to_context(self) -> RequestContext:
        return RequestContext(
            ip_address=self.ip_address,
            user_agent=self.user_agent,
            headers=self.headers,
            cookies=self.cookies,
        )


def build_request_context(request: Any) -> RequestContext:
    return PyAuthRequest.from_fastapi(request).to_context()
