import re
from datetime import datetime


IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
KEY_VALUE_PATTERN = re.compile(r"\b([A-Za-z_]+)=([A-Za-z0-9._/-]+)\b")
CPU_PATTERN = re.compile(r"\bcpu=(\d+)\b")
PROCESS_PATTERN = re.compile(r"Process:\s+([A-Za-z0-9._-]+)")
FILE_PATTERN = re.compile(r"File accessed:\s+(\S+)")
ENDPOINT_PATTERN = re.compile(r"\b(?:GET|POST|PUT|DELETE|PATCH)\s+(\S+)")
SSH_USER_PATTERN = re.compile(r"password for ([A-Za-z0-9._-]+) from")


def _extract_timestamp(raw_log: str) -> str:
    first_token = raw_log.split(maxsplit=1)[0]
    try:
        datetime.fromisoformat(first_token.replace("Z", "+00:00"))
        return first_token
    except ValueError:
        return "unknown"


def _extract_ip(raw_log: str) -> str:
    match = IP_PATTERN.search(raw_log)
    return match.group(0) if match else "unknown"


def _extract_key_values(raw_log: str) -> dict:
    return {key: value for key, value in KEY_VALUE_PATTERN.findall(raw_log)}


def _classify_event(raw_log: str) -> tuple[str, str]:
    if "Failed password" in raw_log:
        return "ssh", "login_failure"
    if "Accepted password" in raw_log:
        return "ssh", "login_success"
    if "POST /login failed" in raw_log:
        return "api", "login_failure"
    if "GET /admin" in raw_log or "GET /api/admin" in raw_log:
        return "api", "admin_access"
    if "File accessed:" in raw_log:
        return "system", "file_access"
    if "high CPU usage" in raw_log:
        return "system", "process_anomaly"
    return "unknown", "unknown"


def parse_log(raw_log: str, line_number: int) -> dict:
    key_values = _extract_key_values(raw_log)
    category, action = _classify_event(raw_log)
    source_ip = _extract_ip(raw_log)

    cpu_match = CPU_PATTERN.search(raw_log)
    process_match = PROCESS_PATTERN.search(raw_log)
    file_match = FILE_PATTERN.search(raw_log)
    endpoint_match = ENDPOINT_PATTERN.search(raw_log)
    ssh_user_match = SSH_USER_PATTERN.search(raw_log)

    host = key_values.get("host", "unknown")
    user = key_values.get("user") or (ssh_user_match.group(1) if ssh_user_match else "unknown")
    source = source_ip if source_ip != "unknown" else host

    return {
        "line_number": line_number,
        "timestamp": _extract_timestamp(raw_log),
        "category": category,
        "action": action,
        "source": source,
        "source_ip": source_ip,
        "user": user,
        "host": host,
        "endpoint": endpoint_match.group(1) if endpoint_match else "unknown",
        "status": key_values.get("status", "unknown"),
        "asset": file_match.group(1) if file_match else "unknown",
        "process": process_match.group(1) if process_match else "unknown",
        "cpu": int(cpu_match.group(1)) if cpu_match else 0,
        "raw": raw_log,
    }


def parse_logs(logs: list[str]) -> list[dict]:
    return [parse_log(log, line_number=index) for index, log in enumerate(logs, start=1)]
