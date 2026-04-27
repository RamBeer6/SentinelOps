import unittest

from alerts import create_alerts
from config import load_config
from detector import run_detection
from parser import parse_logs


class DetectionPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = load_config()

    def _alerts_for(self, logs: list[str]) -> list[dict]:
        events = parse_logs(logs)
        detections = run_detection(events, self.config)
        return create_alerts(detections, self.config)

    def test_detects_bruteforce_over_threshold(self) -> None:
        logs = [
            f"2026-04-27T10:00:0{i}Z SSH Failed password for root from 198.51.100.10 port 55{i}"
            for i in range(6)
        ]

        alerts = self._alerts_for(logs)

        self.assertTrue(any(alert["type"] == "Brute Force" for alert in alerts))
        self.assertTrue(any(alert["severity"] == "CRITICAL" for alert in alerts))

    def test_detects_sensitive_file_access(self) -> None:
        alerts = self._alerts_for(
            ["2026-04-27T10:10:00Z SYSTEM File accessed: /etc/shadow user=www-data host=web-01"]
        )

        self.assertEqual(alerts[0]["type"], "Privilege Access")
        self.assertEqual(alerts[0]["metadata"]["asset"], "/etc/shadow")
        self.assertEqual(alerts[0]["enrichment"]["asset_criticality"], "HIGH")

    def test_trusted_ip_health_check_does_not_alert(self) -> None:
        alerts = self._alerts_for(["2026-04-27T10:20:00Z API GET /health from 10.0.0.8 status=200"])

        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
