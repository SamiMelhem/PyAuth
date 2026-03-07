from adapters.base import BaseAdapter


def test_base_adapter_is_async_abstract_contract() -> None:
    required_methods = {
        "create_user",
        "get_user_by_id",
        "get_user_by_email",
        "create_account",
        "get_account_by_provider_account_id",
        "get_accounts_by_user_id",
        "update_account",
        "delete_account",
        "create_session",
        "get_session_by_token_hash",
        "delete_session",
        "delete_sessions_by_user_id",
        "create_verification",
        "get_verification_by_token_hash",
        "consume_verification",
        "delete_expired_verifications",
    }

    assert required_methods.issubset(BaseAdapter.__abstractmethods__)
