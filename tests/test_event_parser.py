import unittest

from parser.event_parser import parse_log


class EventParserTests(unittest.TestCase):
    def test_parses_ssh_failed_password_event(self) -> None:
        event = parse_log(
            "2026-04-27T10:00:00Z SSH Failed password for root from 198.51.100.10 port 551",
            line_number=7,
        )

        self.assertEqual(event["line_number"], 7)
        self.assertEqual(event["timestamp"], "2026-04-27T10:00:00Z")
        self.assertEqual(event["category"], "ssh")
        self.assertEqual(event["action"], "login_failure")
        self.assertEqual(event["source"], "198.51.100.10")
        self.assertEqual(event["source_ip"], "198.51.100.10")
        self.assertEqual(event["user"], "root")

    def test_parses_api_admin_endpoint(self) -> None:
        event = parse_log(
            "2026-04-27T10:05:00Z API GET /api/admin from 203.0.113.20 status=403",
            line_number=1,
        )

        self.assertEqual(event["category"], "api")
        self.assertEqual(event["action"], "admin_access")
        self.assertEqual(event["endpoint"], "/api/admin")
        self.assertEqual(event["status"], "403")
        self.assertEqual(event["source_ip"], "203.0.113.20")

    def test_parses_system_process_anomaly(self) -> None:
        event = parse_log(
            "2026-04-27T10:15:00Z SYSTEM high CPU usage Process: miner cpu=97 host=web-01",
            line_number=3,
        )

        self.assertEqual(event["category"], "system")
        self.assertEqual(event["action"], "process_anomaly")
        self.assertEqual(event["process"], "miner")
        self.assertEqual(event["cpu"], 97)
        self.assertEqual(event["host"], "web-01")


if __name__ == "__main__":
    unittest.main()
