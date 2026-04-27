from collections import Counter


def _common_context(alert: dict) -> dict:
    return {
        "related_logs": alert["evidence"],
        "event_count": len(alert["evidence"]),
    }


def investigate_bruteforce(alert: dict) -> dict:
    context = _common_context(alert)
    attempts = alert.get("metadata", {}).get("failed_attempts", context["event_count"])

    return {
        **context,
        "finding": f"{attempts} failed login attempts from {alert['source']}",
        "impact": "Unauthorized access attempt against authentication services",
        "risk": "Possible brute-force attack leading to account compromise",
        "recommendations": [
            "Block or rate-limit the source IP",
            "Enable MFA for exposed accounts",
            "Review successful logins after the failed attempts",
        ],
    }


def investigate_suspicious_ip(alert: dict) -> dict:
    context = _common_context(alert)

    return {
        **context,
        "finding": f"Untrusted IP activity detected from {alert['source']}",
        "impact": "Potential reconnaissance or unauthorized access attempt",
        "risk": "Unknown source interacting with sensitive endpoints",
        "recommendations": [
            "Validate IP ownership and geolocation",
            "Add the IP to a watchlist",
            "Restrict access to administrative endpoints",
        ],
    }


def investigate_privilege_access(alert: dict) -> dict:
    context = _common_context(alert)

    return {
        **context,
        "finding": "Sensitive file access to /etc/passwd was observed",
        "impact": "Possible credential discovery or privilege escalation preparation",
        "risk": "Attacker may be collecting local account information",
        "recommendations": [
            "Identify the process and user that accessed the file",
            "Review host telemetry around the same timestamp",
            "Validate file permissions and endpoint controls",
        ],
    }


def investigate_abnormal_behavior(alert: dict) -> dict:
    context = _common_context(alert)

    return {
        **context,
        "finding": "Process behavior showed abnormal CPU usage",
        "impact": "Possible runaway process, crypto-mining, or malicious execution",
        "risk": "Host performance degradation or active malicious workload",
        "recommendations": [
            "Inspect the process command line and parent process",
            "Collect endpoint telemetry for the affected host",
            "Terminate the process if malicious behavior is confirmed",
        ],
    }


def investigate_correlated_attack(alert: dict) -> dict:
    context = _common_context(alert)
    event_types = Counter()
    for log in alert["evidence"]:
        if "Failed password" in log or "POST /login failed" in log:
            event_types["login_failures"] += 1
        if "GET /admin" in log:
            event_types["admin_access"] += 1

    return {
        **context,
        "finding": f"Correlated brute-force and suspicious IP activity from {alert['source']}",
        "impact": "Authentication attack with elevated confidence due to source reputation",
        "risk": "High likelihood of active intrusion attempt",
        "recommendations": [
            "Escalate to incident response",
            "Block the IP at perimeter controls",
            "Search for successful authentication from the same source",
        ],
        "correlation_summary": dict(event_types),
    }


INVESTIGATORS = {
    "Brute Force": investigate_bruteforce,
    "Suspicious IP": investigate_suspicious_ip,
    "Privilege Access": investigate_privilege_access,
    "Abnormal Behavior": investigate_abnormal_behavior,
    "Correlated Attack": investigate_correlated_attack,
}


def investigate(alert: dict, logs: list[str]) -> dict:
    investigator = INVESTIGATORS.get(alert["type"])
    if investigator:
        return investigator(alert)

    return {
        "related_logs": logs,
        "event_count": len(logs),
        "finding": "Unknown alert type requires manual review",
        "impact": "Undetermined",
        "risk": "Unknown",
        "recommendations": ["Review the alert and related telemetry manually"],
    }
