from __future__ import annotations

from fastapi import Request

from core.types import RequestContext


def build_request_context(request: Request) -> RequestContext:
    return RequestContext(
        ip_address=request.client.host if request.client is not None else None,
        user_agent=request.headers.get("user-agent"),
        headers=dict(request.headers),
        cookies=dict(request.cookies),
    )
