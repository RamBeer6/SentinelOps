import unittest

from investigation import investigate


class InvestigationTests(unittest.TestCase):
    def test_privilege_access_finding_uses_alert_asset(self) -> None:
        alert = {
            "id": "ALERT-0001",
            "type": "Privilege Access",
            "source": "web-01",
            "evidence": ["2026-04-27T10:10:00Z SYSTEM File accessed: /etc/shadow user=www-data host=web-01"],
            "metadata": {"asset": "/etc/shadow"},
        }

        investigation = investigate(alert, logs=[])

        self.assertIn("/etc/shadow", investigation["finding"])
        self.assertNotIn("/etc/passwd", investigation["finding"])


if __name__ == "__main__":
    unittest.main()
