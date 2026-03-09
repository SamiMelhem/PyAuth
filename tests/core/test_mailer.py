from __future__ import annotations

import pytest

from core.mailer import ConsoleMailer, MailMessage


@pytest.mark.asyncio
async def test_console_mailer_prints_message_to_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    mailer = ConsoleMailer()

    await mailer.send(
        MailMessage(
            to_email="dev@example.com",
            subject="Verify your email",
            text_body="Use this token=abc123 to continue.",
        )
    )

    captured = capsys.readouterr()
    assert "dev@example.com" in captured.out
    assert "Verify your email" in captured.out
    assert "token=abc123" in captured.out
