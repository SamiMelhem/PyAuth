"""
Post-Phase 4 sample: FastAPI + SQLAlchemy + PyAuth

Run from project root:
  uv sync --extra fastapi --extra sqlalchemy
  uv run uvicorn examples.fastapi_sqlalchemy_app:app --reload

Then try:
  - POST /api/auth/sign-up   {"email": "you@example.com", "password": "SecurePass123"}
  - POST /api/auth/sign-in   {"email": "you@example.com", "password": "SecurePass123"}
  - GET  /me                (requires session cookie)
  - POST /api/auth/sign-out
  - GET  /api/auth/oauth/google   (redirects to Google sign-in)
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from adapters.sqlalchemy import SQLAlchemyAdapter
from core.config import (
    GoogleProviderSettings,
    GitHubProviderSettings,
    SocialAuthSettings,
)
from pyauth import ConsoleMailer, PyAuth, PyAuthRouter, PyAuthSettings


def build_settings() -> PyAuthSettings:
    return PyAuthSettings.for_development(
        issuer="http://localhost:8000",
        audience="pyauth-sample",
        social=SocialAuthSettings(
            google=GoogleProviderSettings(
                enabled=True,
                client_id="YOUR_GOOGLE_CLIENT_ID",
                client_secret="YOUR_GOOGLE_CLIENT_SECRET",
                redirect_uri="http://localhost:8000/api/auth/callback/google",
            ),
            github=GitHubProviderSettings(
                enabled=True,
                client_id="YOUR_GITHUB_CLIENT_ID",
                client_secret="YOUR_GITHUB_CLIENT_SECRET",
                redirect_uri="http://localhost:8000/api/auth/callback/github",
            ),
        ),
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    await SQLAlchemyAdapter.create_schema(engine)
    yield
    await engine.dispose()


# SQLite for local testing; use postgresql+asyncpg://... for production
engine = create_async_engine("sqlite+aiosqlite:///./pyauth_sample.db")
session_factory = async_sessionmaker(engine, expire_on_commit=False)
adapter = SQLAlchemyAdapter(session_factory=session_factory)

settings = build_settings()
auth = PyAuth(
    settings=settings,
    adapter=adapter,
    mailer=ConsoleMailer(),
)
auth_router = PyAuthRouter(auth)

app = FastAPI(
    title="PyAuth Sample",
    description="Phase 4 demo: FastAPI + SQLAlchemy + PyAuthRouter",
    lifespan=lifespan,
)

auth_router.mount_fastapi(app)


@app.get("/")
async def root():
    return {
        "message": "PyAuth sample app",
        "docs": "/docs",
        "auth_endpoints": [
            "POST /api/auth/sign-up",
            "POST /api/auth/sign-in",
            "POST /api/auth/sign-out",
            "POST /api/auth/password-reset/request",
            "POST /api/auth/password-reset/confirm",
            "POST /api/auth/email-verification/request",
            "POST /api/auth/email-verification/confirm",
            "GET  /api/auth/oauth/{google|github}",
            "GET  /api/auth/callback/{google|github}",
        ],
    }


@app.get("/me")
async def me(current_user=Depends(auth_router.get_current_user())):
    """Protected route: returns the current user when session cookie is valid."""
    return {"user": current_user.model_dump(mode="json")}

@app.get('/api-me')
async def api_me(current_user=Depends(auth_router.get_current_user_bearer())):
    return {"user": current_user.model_dump(mode="json")}