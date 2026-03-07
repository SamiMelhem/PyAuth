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
