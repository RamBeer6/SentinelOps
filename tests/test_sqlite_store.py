import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from storage import save_run


class SQLiteStoreTests(unittest.TestCase):
    def test_save_run_persists_alert_and_investigation_payloads(self) -> None:
        alert = {
            "id": "ALERT-0001",
            "type": "Brute Force",
            "severity": "HIGH",
            "risk_score": 9,
            "timestamp": "2026-04-27T10:00:00Z",
            "source": "198.51.100.10",
            "source_ip": "198.51.100.10",
            "description": "Multiple failed login attempts detected",
            "evidence": ["failed login"],
            "metadata": {"failed_attempts": 6},
        }
        investigation = {
            "finding": "6 failed login attempts from 198.51.100.10",
            "impact": "Unauthorized access attempt",
            "risk": "Possible account compromise",
            "recommendations": ["Enable MFA"],
            "related_logs": ["failed login"],
            "event_count": 1,
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "sentinelops.db"
            run_id = save_run([alert], {alert["id"]: investigation}, "logs/system_logs.txt", str(db_path))

            connection = sqlite3.connect(db_path)
            try:
                run = connection.execute("SELECT id, log_path, alert_count FROM runs").fetchone()
                stored_alert = connection.execute("SELECT run_id, payload FROM alerts").fetchone()
                stored_investigation = connection.execute(
                    "SELECT alert_id, payload FROM investigations"
                ).fetchone()
            finally:
                connection.close()

        self.assertEqual(run, (run_id, "logs/system_logs.txt", 1))
        self.assertEqual(stored_alert[0], run_id)
        self.assertEqual(json.loads(stored_alert[1])["id"], "ALERT-0001")
        self.assertEqual(stored_investigation[0], "ALERT-0001")
        self.assertEqual(json.loads(stored_investigation[1])["finding"], investigation["finding"])


if __name__ == "__main__":
    unittest.main()
