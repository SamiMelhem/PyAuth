from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class MailMessage:
    to_email: str
    subject: str
    text_body: str
    html_body: str | None = None


class Mailer(ABC):
    @abstractmethod
    async def send(self, message: MailMessage) -> None:
        raise NotImplementedError


class ConsoleMailer(Mailer):
    async def send(self, message: MailMessage) -> None:
        print(f"\n[PyAuth Mail] to={message.to_email} subject={message.subject}")
        print("-" * 60)
        print(message.text_body)
        if message.html_body:
            print("-" * 60)
            print(message.html_body)
        print("-" * 60)
