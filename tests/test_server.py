import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from rce_guard.server import EventLog


class EventLogTestCase(unittest.TestCase):
    def test_event_log_keeps_latest_entries(self) -> None:
        log = EventLog(max_items=2)
        log.add({"id": 1})
        log.add({"id": 2})
        log.add({"id": 3})
        snapshot = log.snapshot()
        self.assertEqual(len(snapshot), 2)
        self.assertEqual(snapshot[0]["id"], 3)
        self.assertEqual(snapshot[1]["id"], 2)

    def test_event_log_limit_parameter(self) -> None:
        log = EventLog(max_items=5)
        for idx in range(5):
            log.add({"id": idx})
        snapshot = log.snapshot(limit=3)
        self.assertEqual(len(snapshot), 3)
        self.assertTrue(all(isinstance(item, dict) for item in snapshot))


if __name__ == "__main__":
    unittest.main()
