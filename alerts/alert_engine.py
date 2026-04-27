import json
from pathlib import Path

from enrichment import enrich_alert


def create_alerts(detections: list[dict], config: dict | None = None) -> list[dict]:
    alerts = []

    for index, detection in enumerate(detections, start=1):
        alert = {
            "id": f"ALERT-{index:04d}",
            "type": detection["type"],
            "severity": detection["severity"],
            "risk_score": detection["risk_score"],
            "description": detection["description"],
            "timestamp": detection["timestamp"],
            "source": detection["source"],
            "source_ip": detection.get("source_ip", "unknown"),
            "evidence": detection["evidence"],
            "metadata": detection.get("metadata", {}),
        }
        if config is not None:
            alert = enrich_alert(alert, config)
        alerts.append(alert)

    return alerts


def save_alerts(alerts: list[dict], output_path: str = "alerts/alerts.json") -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(alerts, indent=2), encoding="utf-8")
