from collections import defaultdict
from datetime import datetime, timezone


def _raw_evidence(events: list[dict]) -> list[str]:
    return [event["raw"] for event in events]


def _primary_source_ip(events: list[dict]) -> str:
    for event in events:
        if event.get("source_ip") != "unknown":
            return event["source_ip"]
    return "unknown"


def detect_bruteforce(events: list[dict], config: dict) -> list[dict]:
    threshold = int(config.get("bruteforce_threshold", 5))
    failures_by_ip: dict[str, list[dict]] = defaultdict(list)

    for event in events:
        if event["action"] == "login_failure" and event["source_ip"] != "unknown":
            failures_by_ip[event["source_ip"]].append(event)

    detections = []
    for source_ip, source_events in failures_by_ip.items():
        if len(source_events) > threshold:
            users = sorted({event["user"] for event in source_events if event["user"] != "unknown"})
            detections.append(
                {
                    "type": "Brute Force",
                    "severity": "HIGH",
                    "description": "Multiple failed login attempts detected",
                    "source": source_ip,
                    "source_ip": source_ip,
                    "evidence": _raw_evidence(source_events),
                    "metadata": {
                        "failed_attempts": len(source_events),
                        "threshold": threshold,
                        "targeted_users": users,
                        "first_seen": source_events[0]["timestamp"],
                        "last_seen": source_events[-1]["timestamp"],
                    },
                }
            )

    return detections


def detect_suspicious_ip(events: list[dict], config: dict) -> list[dict]:
    trusted_ips = set(config.get("trusted_ips", []))
    admin_endpoints = set(config.get("untrusted_admin_endpoints", ["/admin"]))
    events_by_ip: dict[str, list[dict]] = defaultdict(list)

    for event in events:
        source_ip = event["source_ip"]
        if source_ip == "unknown" or source_ip in trusted_ips:
            continue

        is_admin_access = event["endpoint"] in admin_endpoints
        is_auth_activity = event["action"] in {"login_failure", "login_success"}
        if is_admin_access or is_auth_activity:
            events_by_ip[source_ip].append(event)

    return [
        {
            "type": "Suspicious IP",
            "severity": "MEDIUM",
            "description": "Activity from an untrusted source IP",
            "source": source_ip,
            "source_ip": source_ip,
            "evidence": _raw_evidence(source_events),
            "metadata": {
                "trusted_ips": sorted(trusted_ips),
                "event_count": len(source_events),
                "actions": sorted({event["action"] for event in source_events}),
            },
        }
        for source_ip, source_events in events_by_ip.items()
    ]


def detect_privilege_access(events: list[dict], config: dict) -> list[dict]:
    sensitive_files = set(config.get("sensitive_files", ["/etc/passwd"]))
    detections = []

    for event in events:
        if event["action"] == "file_access" and event["asset"] in sensitive_files:
            detections.append(
                {
                    "type": "Privilege Access",
                    "severity": "HIGH",
                    "description": "Sensitive system file access detected",
                    "source": event["source"],
                    "source_ip": event["source_ip"],
                    "evidence": [event["raw"]],
                    "metadata": {
                        "asset": event["asset"],
                        "host": event["host"],
                        "user": event["user"],
                    },
                }
            )

    return detections


def detect_abnormal_behavior(events: list[dict], config: dict) -> list[dict]:
    cpu_threshold = int(config.get("cpu_threshold", 90))
    detections = []

    for event in events:
        if event["action"] == "process_anomaly" and event["cpu"] >= cpu_threshold:
            detections.append(
                {
                    "type": "Abnormal Behavior",
                    "severity": "MEDIUM",
                    "description": "Process started with abnormal CPU usage",
                    "source": event["source"],
                    "source_ip": event["source_ip"],
                    "evidence": [event["raw"]],
                    "metadata": {
                        "behavior": "high CPU usage",
                        "host": event["host"],
                        "process": event["process"],
                        "cpu": event["cpu"],
                        "threshold": cpu_threshold,
                    },
                }
            )

    return detections


def correlate_alerts(detections: list[dict]) -> list[dict]:
    by_source: dict[str, set[str]] = defaultdict(set)
    evidence_by_source: dict[str, list[str]] = defaultdict(list)
    source_ip_by_source: dict[str, str] = {}

    for detection in detections:
        source = detection["source"]
        by_source[source].add(detection["type"])
        evidence_by_source[source].extend(detection["evidence"])
        source_ip_by_source[source] = detection.get("source_ip", "unknown")

    correlated = []
    for source, types in by_source.items():
        if {"Brute Force", "Suspicious IP"}.issubset(types):
            correlated.append(
                {
                    "type": "Correlated Attack",
                    "severity": "CRITICAL",
                    "description": "Brute-force activity from an untrusted IP requires escalation",
                    "source": source,
                    "source_ip": source_ip_by_source.get(source, "unknown"),
                    "evidence": sorted(set(evidence_by_source[source])),
                    "metadata": {"correlated_rules": sorted(types)},
                }
            )

    return correlated


def add_risk_score(detection: dict) -> dict:
    severity_score = {
        "LOW": 3,
        "MEDIUM": 5,
        "HIGH": 8,
        "CRITICAL": 10,
    }
    evidence_bonus = 1 if len(detection.get("evidence", [])) >= 6 else 0
    score = severity_score.get(detection["severity"], 4) + evidence_bonus
    detection["risk_score"] = min(score, 10)
    detection["timestamp"] = datetime.now(timezone.utc).isoformat()
    return detection


def run_detection(events: list[dict], config: dict) -> list[dict]:
    detections = []
    detections.extend(detect_bruteforce(events, config))
    detections.extend(detect_suspicious_ip(events, config))
    detections.extend(detect_privilege_access(events, config))
    detections.extend(detect_abnormal_behavior(events, config))
    detections.extend(correlate_alerts(detections))

    return [add_risk_score(detection) for detection in detections]
