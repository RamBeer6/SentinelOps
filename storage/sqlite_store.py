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
    id TEXT NOT NULL,
    run_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    description TEXT NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY (run_id, id),
    FOREIGN KEY (run_id) REFERENCES runs(id)
);

CREATE TABLE IF NOT EXISTS investigations (
    alert_id TEXT NOT NULL,
    run_id INTEGER NOT NULL,
    finding TEXT NOT NULL,
    impact TEXT NOT NULL,
    risk TEXT NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY (run_id, alert_id),
    FOREIGN KEY (run_id, alert_id) REFERENCES alerts(run_id, id)
);
"""


def _table_columns(connection: sqlite3.Connection, table_name: str) -> set[str]:
    return {row[1] for row in connection.execute(f"PRAGMA table_info({table_name})").fetchall()}


def _migrate_legacy_schema(connection: sqlite3.Connection) -> None:
    tables = {
        row[0]
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    }
    if not {"alerts", "investigations"}.issubset(tables):
        return
    if "run_id" in _table_columns(connection, "investigations"):
        return

    connection.executescript(
        """
        ALTER TABLE alerts RENAME TO alerts_legacy;
        ALTER TABLE investigations RENAME TO investigations_legacy;
        """
    )
    connection.executescript(SCHEMA)
    connection.executescript(
        """
        INSERT INTO alerts (
            id, run_id, type, severity, risk_score, timestamp, source,
            source_ip, description, payload
        )
        SELECT
            id, run_id, type, severity, risk_score, timestamp, source,
            source_ip, description, payload
        FROM alerts_legacy;

        INSERT INTO investigations (
            alert_id, run_id, finding, impact, risk, payload
        )
        SELECT
            investigations_legacy.alert_id,
            alerts.run_id,
            investigations_legacy.finding,
            investigations_legacy.impact,
            investigations_legacy.risk,
            investigations_legacy.payload
        FROM investigations_legacy
        JOIN alerts ON alerts.id = investigations_legacy.alert_id;

        DROP TABLE alerts_legacy;
        DROP TABLE investigations_legacy;
        """
    )


def initialize_database(db_path: str = "data/sentinelops.db") -> Path:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(path)
    try:
        connection.executescript(SCHEMA)
        _migrate_legacy_schema(connection)
        connection.commit()
    finally:
        connection.close()

    return path


def save_run(
    alerts: list[dict],
    investigations: dict[str, dict],
    log_path: str,
    db_path: str = "data/sentinelops.db",
) -> int:
    path = initialize_database(db_path)

    connection = sqlite3.connect(path)
    try:
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
                    alert_id, run_id, finding, impact, risk, payload
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    alert["id"],
                    run_id,
                    investigation["finding"],
                    investigation["impact"],
                    investigation["risk"],
                    json.dumps(investigation, indent=2),
                ),
            )

        connection.commit()
    finally:
        connection.close()

    return run_id
