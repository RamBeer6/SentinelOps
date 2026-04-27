import json
import sqlite3
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    log_path TEXT NOT NULL,
    alert_count INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    run_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    description TEXT NOT NULL,
    payload TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(id)
);

CREATE TABLE IF NOT EXISTS investigations (
    alert_id TEXT PRIMARY KEY,
    finding TEXT NOT NULL,
    impact TEXT NOT NULL,
    risk TEXT NOT NULL,
    payload TEXT NOT NULL,
    FOREIGN KEY (alert_id) REFERENCES alerts(id)
);
"""


def initialize_database(db_path: str = "data/sentinelops.db") -> Path:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(path) as connection:
        connection.executescript(SCHEMA)

    return path


def save_run(
    alerts: list[dict],
    investigations: dict[str, dict],
    log_path: str,
    db_path: str = "data/sentinelops.db",
) -> int:
    path = initialize_database(db_path)

    with sqlite3.connect(path) as connection:
        cursor = connection.cursor()
        cursor.execute(
            "INSERT INTO runs (created_at, log_path, alert_count) VALUES (datetime('now'), ?, ?)",
            (log_path, len(alerts)),
        )
        run_id = int(cursor.lastrowid)

        for alert in alerts:
            cursor.execute(
                """
                INSERT OR REPLACE INTO alerts (
                    id, run_id, type, severity, risk_score, timestamp, source,
                    source_ip, description, payload
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert["id"],
                    run_id,
                    alert["type"],
                    alert["severity"],
                    alert["risk_score"],
                    alert["timestamp"],
                    alert["source"],
                    alert.get("source_ip", "unknown"),
                    alert["description"],
                    json.dumps(alert, indent=2),
                ),
            )

            investigation = investigations[alert["id"]]
            cursor.execute(
                """
                INSERT OR REPLACE INTO investigations (
                    alert_id, finding, impact, risk, payload
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    alert["id"],
                    investigation["finding"],
                    investigation["impact"],
                    investigation["risk"],
                    json.dumps(investigation, indent=2),
                ),
            )

    return run_id
