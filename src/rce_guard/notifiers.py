from __future__ import annotations

import json
import logging
import os
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Optional

from .models import DetectionResult

logger = logging.getLogger(__name__)

DEFAULT_TELEGRAM_TOKEN = ""
DEFAULT_TELEGRAM_CHAT_ID = ""

TransportFn = Callable[[str, bytes, dict[str, str]], None]


def _build_ssl_context() -> ssl.SSLContext:
    if os.getenv("RCE_GUARD_TELEGRAM_INSECURE", "0") == "1":
        logger.warning("Telegram notifier is running with certificate verification disabled. Use only in trusted environments.")
        return ssl._create_unverified_context()  # type: ignore[arg-type]
    context = ssl.create_default_context()
    try:
        import certifi
    except ImportError:
        return context
    try:
        context.load_verify_locations(certifi.where())
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("Unable to load certifi CA bundle: %s", exc)
    return context


SSL_CONTEXT = _build_ssl_context()


def _default_transport(url: str, data: bytes, headers: dict[str, str]) -> None:
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=SSL_CONTEXT))
    with opener.open(request, timeout=5) as response:  # noqa: S310 (standard library usage)
        response.read()


@dataclass(slots=True)
class TelegramNotifier:
    token: Optional[str] = None
    chat_id: Optional[str] = None
    enabled: bool = True
    transport: TransportFn = field(default=_default_transport, repr=False)

    def __post_init__(self) -> None:
        if not self.token or not self.chat_id:
            self.enabled = False

    @classmethod
    def from_args(
        cls,
        token: Optional[str],
        chat_id: Optional[str],
        *,
        enabled: bool = True,
    ) -> "TelegramNotifier":
        if not token:
            token = os.getenv("RCE_GUARD_TELEGRAM_TOKEN") or DEFAULT_TELEGRAM_TOKEN
        if not chat_id:
            chat_id = os.getenv("RCE_GUARD_TELEGRAM_CHAT_ID") or DEFAULT_TELEGRAM_CHAT_ID
        return cls(token=token, chat_id=chat_id, enabled=enabled)

    def notify_detection(self, result: DetectionResult) -> None:
        if not self.enabled:
            return
        try:
            message = self._format_message(result)
            payload = json.dumps({"chat_id": self.chat_id, "text": message}).encode("utf-8")
            url = f"https://api.telegram.org/bot{self.token}/sendMessage"
            headers = {"Content-Type": "application/json"}
            self.transport(url, payload, headers)
        except urllib.error.URLError as exc:
            logger.warning("Failed to deliver Telegram notification: %s", exc)
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Unexpected error sending Telegram notification", exc_info=exc)

    def _format_message(self, result: DetectionResult) -> str:
        request = result.request
        lines = [
            "[RCE-Guard] Malicious payload detected!",
            f"Summary: {result.summary()}",
            f"Request: {request.method} {request.path}",
        ]
        if request.remote_addr:
            lines.append(f"Source IP: {request.remote_addr}")
        if request.query_string:
            lines.append(f"Query: {request.query_string}")
        lines.append("")
        lines.append("Matches:")
        for match in result.matches:
            lines.append(f"- {match.rule_id} [{match.severity}] {match.description}")
        return "\n".join(lines)


class DummyNotifier:
    """No-op notifier used when messaging is disabled."""

    def notify_detection(self, result: DetectionResult) -> None:  # pragma: no cover - simple noop
        return
