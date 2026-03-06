from core.errors import AuthenticationError, ConfigurationError


def test_authentication_error_uses_401_payload() -> None:
    error = AuthenticationError(
        message="Credentials are invalid",
        code="invalid_credentials",
        detail={"field": "password"},
    )

    assert error.status_code == 401
    assert error.to_dict() == {
        "error": {
            "code": "invalid_credentials",
            "message": "Credentials are invalid",
            "detail": {"field": "password"},
        }
    }


def test_configuration_error_defaults_to_internal_server_error() -> None:
    error = ConfigurationError(message="Signing keys are missing")

    assert error.status_code == 500
    assert error.code == "configuration_error"
