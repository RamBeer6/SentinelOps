# SentinelOps - SOC Detection & Investigation System

SentinelOps is a Python-based SOC simulation that models a real analyst workflow:

```text
Raw Logs -> Parsed Events -> Detections -> Alerts -> Investigations -> Reports -> SQLite History
```

The project is designed as a portfolio-grade security engineering project. It shows log parsing, detection logic, alert enrichment, incident investigation, reporting, and persistence.

## What It Does

- Ingests raw SSH, API, and system logs
- Normalizes log lines into structured security events
- Runs configurable detection rules
- Generates enriched JSON alerts
- Maps detections to MITRE ATT&CK context
- Correlates related alerts into escalated incidents
- Produces analyst-style incident reports
- Produces an executive summary
- Produces a static HTML SOC dashboard
- Stores alerts and investigations in SQLite
- Includes repeatable scenarios and unit tests

## Detection Rules

| Rule | Logic | Severity |
| --- | --- | --- |
| Brute Force | More than 5 failed login attempts from one IP | HIGH |
| Suspicious IP | Auth or admin activity from an untrusted IP | MEDIUM |
| Privilege Access | Access to sensitive files such as `/etc/passwd` or `/etc/shadow` | HIGH |
| Abnormal Behavior | Process CPU usage above configured threshold | MEDIUM |
| Correlated Attack | Brute force combined with suspicious IP activity | CRITICAL |

Detection settings live in:

```text
config/detection_config.json
```

## Project Structure

```text
SentinelOps/
  alerts/              JSON alert generation
  config/              Detection thresholds, trusted IPs, MITRE mapping
  detector/            Detection and correlation engine
  enrichment/          IP reputation, asset criticality, MITRE enrichment
  investigation/       Alert investigation logic
  logs/                Sample logs and attack scenarios
  parser/              Raw log to normalized event parser
  reports/             Text reports, executive summary, HTML dashboard
  storage/             SQLite persistence
  tests/               Unit tests
  loader.py            Log file loader
  main.py              CLI runner
```

## Run The Full Pipeline

```powershell
python main.py --clean
```

Generated outputs:

- `alerts/alerts.json`
- `reports/alert-*.txt`
- `reports/executive_summary.md`
- `reports/dashboard.html`
- `data/sentinelops.db`

## Run Specific Scenarios

Brute force:

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

## Run Tests

```powershell
python -m unittest
```

## Example Alert

```json
{
  "id": "ALERT-0007",
  "type": "Correlated Attack",
  "severity": "CRITICAL",
  "risk_score": 10,
  "source": "172.16.4.20",
  "enrichment": {
    "ip_reputation": "internal_untrusted",
    "mitre_tactic": "Multiple",
    "mitre_technique": "Correlated activity across detection rules"
  }
}
```

## Interview Talking Points

- I built a full detection pipeline, not just isolated scripts.
- I normalized raw logs into structured events before applying detection rules.
- I separated configuration from code so thresholds and trusted IPs can be tuned.
- I added enrichment fields such as IP reputation, asset criticality, and MITRE mapping.
- I correlated multiple detections into a higher-severity incident.
- I persisted alerts and investigations into SQLite for historical review.
- I generated both analyst reports and an executive summary/dashboard.
- I added unit tests to validate detection behavior.

## Resume Description

```text
SOC Detection & Investigation System
* Built a Python SOC pipeline to parse logs, detect anomalies, and generate enriched security alerts
* Implemented configurable detection rules for brute force, suspicious IP activity, privilege access, and abnormal host behavior
* Added alert correlation, risk scoring, MITRE ATT&CK mapping, and SQLite persistence
* Automated incident investigation reports, executive summaries, and a static SOC dashboard
* Created repeatable attack scenarios and unit tests for detection validation
```
