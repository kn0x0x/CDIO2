import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from rce_guard.models import DetectionResult, HTTPRequest, RuleMatch
from rce_guard.notifiers import TelegramNotifier


class TelegramNotifierTestCase(unittest.TestCase):
    def _malicious_result(self) -> DetectionResult:
        request = HTTPRequest(
            method="POST",
            path="/upload",
            query_string=None,
            headers={},
            body="cmd=system('id')",
            remote_addr="192.0.2.10",
        )
        match = RuleMatch(
            rule_id="RCE-003",
            description="PHP command execution",
            severity="HIGH",
            evidence="system('id')",
            location="body",
            tags=("php",),
            span=(0, 5),
        )
        return DetectionResult(request=request, matches=[match])

    def test_notifier_uses_default_credentials(self) -> None:
        notifier = TelegramNotifier.from_args(None, None)
        self.assertTrue(notifier.enabled)
        self.assertIn("8129718611", notifier.token)
        self.assertEqual(notifier.chat_id, "6325753293")

    def test_notifier_uses_transport_when_enabled(self) -> None:
        events = []

        def fake_transport(url: str, data: bytes, headers: dict[str, str]) -> None:
            events.append((url, data, headers))

        notifier = TelegramNotifier(
            token="TOKEN",
            chat_id="CHAT",
            enabled=True,
            transport=fake_transport,
        )
        notifier.notify_detection(self._malicious_result())
        self.assertEqual(len(events), 1)
        url, data, headers = events[0]
        self.assertIn("TOKEN", url)
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertIn(b"Malicious payload detected", data)


if __name__ == "__main__":
    unittest.main()
