from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from adapters.base import BaseAdapter
from core.auth import PyAuth
from core.config import JwtSettings, PyAuthSettings


def build_settings() -> PyAuthSettings:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    return PyAuthSettings(
        jwt=JwtSettings(
            issuer="https://auth.example.com",
            audience="pyauth-clients",
            private_key_pem=private_pem,
            public_key_pem=public_pem,
        )
    )


def test_pyauth_wires_core_services() -> None:
    auth = PyAuth(settings=build_settings())

    assert auth.settings.jwt.algorithm == "EdDSA"
    assert auth.passwords is not None
    assert auth.tokens is not None


class DummyAdapter(BaseAdapter):
    async def create_user(self, user):
        return user

    async def get_user_by_id(self, user_id):
        return None

    async def get_user_by_email(self, email):
        return None

    async def create_account(self, account):
        return account

    async def get_account_by_provider_account_id(self, provider, provider_account_id):
        return None

    async def get_accounts_by_user_id(self, user_id):
        return []

    async def update_account(self, account):
        return account

    async def delete_account(self, account_id):
        return True

    async def create_session(self, session):
        return session

    async def get_session_by_token_hash(self, token_hash):
        return None

    async def delete_session(self, session_id):
        return True

    async def delete_sessions_by_user_id(self, user_id):
        return 0

    async def create_verification(self, verification):
        return verification

    async def get_verification_by_token_hash(self, token_hash):
        return None

    async def consume_verification(self, verification_id):
        return None

    async def delete_expired_verifications(self):
        return 0


def test_pyauth_accepts_injected_adapter() -> None:
    adapter = DummyAdapter()
    auth = PyAuth(settings=build_settings(), adapter=adapter)

    assert auth.adapter is adapter
