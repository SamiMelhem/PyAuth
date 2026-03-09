import subprocess
import sys

from pyauth import ConsoleMailer, PyAuth, PyAuthRequest, PyAuthRouter, PyAuthSettings
from pyauth.core.auth import PyAuth as CorePyAuth
from pyauth.core.config import PyAuthSettings as CorePyAuthSettings
from pyauth.core.mailer import ConsoleMailer as CoreConsoleMailer
from pyauth.framework import PyAuthRequest as FrameworkPyAuthRequest
from pyauth.framework import PyAuthRouter as FrameworkPyAuthRouter


def test_pyauth_package_exports_are_importable() -> None:
    assert PyAuth is CorePyAuth
    assert PyAuthSettings is CorePyAuthSettings
    assert PyAuthRouter is FrameworkPyAuthRouter
    assert PyAuthRequest is FrameworkPyAuthRequest
    assert ConsoleMailer is CoreConsoleMailer


def test_importing_pyauth_does_not_eagerly_import_fastapi_adapter() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import pyauth; print('framework.fastapi' in sys.modules)",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.stdout.strip() == "False"
