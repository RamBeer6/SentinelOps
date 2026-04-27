# SentinelOps

SentinelOps is a lightweight SOC detection and investigation pipeline written in Python. It ingests raw security logs, normalizes them into structured events, applies detection rules, generates enriched alerts, stores findings in SQLite, and produces investigation reports.

The project is intended for learning, experimentation, and demonstrating how detection engineering workflows can be modeled with simple, inspectable code.

## Pipeline

```text
Raw Logs -> Parsed Events -> Detection Rules -> Alerts -> Investigation -> Reports -> SQLite
```

## Features

- Raw log ingestion from text files
- Structured event parsing for SSH, API, and system activity
- Configurable detection thresholds and trusted IP ranges
- Rule-based detections for authentication attacks, suspicious IP activity, sensitive file access, and abnormal process behavior
- Alert enrichment with IP reputation, asset criticality, and MITRE ATT&CK context
- Correlation logic for escalating related detections
- JSON alert output
- Text incident reports
- Executive summary generation
- Static HTML dashboard
- SQLite storage for alert and investigation history
- Sample attack scenarios
- Unit tests for detection behavior

## Detection Rules

| Rule | Description | Severity |
| --- | --- | --- |
| Brute Force | Detects more than the configured number of failed login attempts from one IP address | HIGH |
| Suspicious IP | Detects authentication or admin activity from an untrusted IP address | MEDIUM |
| Privilege Access | Detects access to configured sensitive files such as `/etc/passwd` or `/etc/shadow` | HIGH |
| Abnormal Behavior | Detects process activity above the configured CPU threshold | MEDIUM |
| Correlated Attack | Escalates cases where brute-force activity and suspicious IP activity are linked | CRITICAL |

Detection settings are defined in:

```text
config/detection_config.json
```

## Project Structure

```text
SentinelOps/
  alerts/              Alert creation and JSON export
  config/              Detection settings and MITRE mappings
  detector/            Detection and correlation rules
  enrichment/          Alert enrichment logic
  investigation/       Investigation summaries and recommendations
  logs/                Sample logs and scenarios
  parser/              Raw log normalization
  reports/             Report and dashboard generation
  storage/             SQLite persistence
  tests/               Unit tests
  loader.py            Log file loader
  main.py              Command-line runner
```

## Requirements

- Python 3.10 or newer
- No external Python packages are required

## Quick Start

Run the default pipeline:

```powershell
python main.py --clean
```

This reads:

```text
logs/system_logs.txt
```

And generates:

```text
alerts/alerts.json
reports/alert-*.txt
reports/executive_summary.md
reports/dashboard.html
data/sentinelops.db
```

## CLI Usage

```powershell
python main.py --help
```

Common options:

```powershell
python main.py --log-file logs/system_logs.txt
python main.py --config config/detection_config.json
python main.py --reports-dir reports
python main.py --alerts-file alerts/alerts.json
python main.py --db data/sentinelops.db
python main.py --no-db
python main.py --clean
```

## Sample Scenarios

Brute-force authentication attempt:

```powershell
python main.py --clean --log-file logs/scenario_bruteforce.log
```

Sensitive file access:

```powershell
python main.py --clean --log-file logs/scenario_sensitive_access.log
```

API abuse:

```powershell
python main.py --clean --log-file logs/scenario_api_abuse.log
```

## Example Alert

```json
{
  "id": "ALERT-0007",
  "type": "Correlated Attack",
  "severity": "CRITICAL",
  "risk_score": 10,
  "description": "Brute-force activity from an untrusted IP requires escalation",
  "source": "172.16.4.20",
  "source_ip": "172.16.4.20",
  "enrichment": {
    "ip_reputation": "internal_untrusted",
    "asset_criticality": "LOW",
    "mitre_tactic": "Multiple",
    "mitre_technique": "Correlated activity across detection rules"
  }
}
```

## Reports

SentinelOps produces several report formats:

- Per-alert incident reports in `reports/alert-*.txt`
- Executive summary in `reports/executive_summary.md`
- Static dashboard in `reports/dashboard.html`

The generated dashboard can be opened directly in a browser.

## Running Tests

```powershell
python -m unittest
```

## Data Storage

When SQLite persistence is enabled, SentinelOps writes run history, alerts, and investigations to:

```text
data/sentinelops.db
```

Use `--no-db` to run the pipeline without writing to SQLite.

## Notes

SentinelOps uses sample logs and deterministic detection rules. It is not a replacement for production SIEM, EDR, or SOAR tooling, but it provides a compact reference implementation of a detection and investigation workflow.
