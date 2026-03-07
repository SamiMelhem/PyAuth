from providers.credentials import CREDENTIALS_PROVIDER, CredentialsProvider


def test_credentials_provider_builds_local_account() -> None:
    provider = CredentialsProvider()
    account = provider.build_account(
        user_id="user-123",
        password_hash="hashed-password",
    )

    assert account.provider == CREDENTIALS_PROVIDER
    assert account.provider_account_id == "user-123"
    assert account.password_hash == "hashed-password"


def test_credentials_provider_uses_the_expected_provider_name() -> None:
    provider = CredentialsProvider()

    assert provider.provider_name == CREDENTIALS_PROVIDER
