from __future__ import annotations

from pydantic import BaseModel


class SignUpRequest(BaseModel):
    email: str
    password: str
    name: str | None = None


class SignInRequest(BaseModel):
    email: str
    password: str


class PasswordResetRequestBody(BaseModel):
    email: str


class PasswordResetConfirmBody(BaseModel):
    token: str
    new_password: str


class EmailVerificationRequestBody(BaseModel):
    user_id: str


class EmailVerificationConfirmBody(BaseModel):
    token: str
