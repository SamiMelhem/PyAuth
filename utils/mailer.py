from __future__ import annotations

from core.mailer import MailMessage, Mailer


class InMemoryMailer(Mailer):
    def __init__(self) -> None:
        self.outbox: list[MailMessage] = []

    async def send(self, message: MailMessage) -> None:
        self.outbox.append(message)
