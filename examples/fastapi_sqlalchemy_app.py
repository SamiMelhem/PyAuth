"""
Post-Phase 3 sample: FastAPI + SQLAlchemy + PyAuth

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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, FastAPI
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from adapters.sqlalchemy import SQLAlchemyAdapter
from core.auth import PyAuth
from core.config import (
    GoogleProviderSettings,
    GitHubProviderSettings,
    JwtSettings,
    PyAuthSettings,
    SocialAuthSettings,
)
from core.mailer import MailMessage, Mailer
from framework.fastapi import create_auth_router, get_current_user


def _generate_jwt_keys() -> tuple[str, str]:
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


class ConsoleMailer(Mailer):
    """Prints verification and reset emails to stdout instead of sending."""

    async def send(self, message: MailMessage) -> None:
        print(f"\n[Mail] to={message.to_email} subject={message.subject}")
        print("-" * 60)
        print(message.text_body)
        print("-" * 60)


def build_settings() -> PyAuthSettings:
    private_pem, public_pem = _generate_jwt_keys()
    return PyAuthSettings(
        jwt=JwtSettings(
            issuer="http://localhost:8000",
            audience="pyauth-sample",
            private_key_pem=private_pem,
            public_key_pem=public_pem,
        ),
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
auth = PyAuth(settings=settings, adapter=adapter, mailer=ConsoleMailer())

app = FastAPI(
    title="PyAuth Sample",
    description="Post-Phase 3 demo: FastAPI + SQLAlchemy + PyAuth",
    lifespan=lifespan,
)

app.include_router(create_auth_router(auth))


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
async def me(current_user=Depends(get_current_user(auth))):
    """Protected route: returns the current user when session cookie is valid."""
    return {"user": current_user.model_dump(mode="json")}
