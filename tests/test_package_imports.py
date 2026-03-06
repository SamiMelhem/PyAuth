from pyauth import PyAuth
from pyauth.core.auth import PyAuth as CorePyAuth
from pyauth.core.config import PyAuthSettings


def test_pyauth_package_exports_are_importable() -> None:
    assert PyAuth is CorePyAuth
    assert PyAuthSettings.__name__ == "PyAuthSettings"
