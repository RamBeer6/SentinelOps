# Detection Rules

SentinelOps uses deterministic rules over normalized security events. Detection settings are stored in `config/detection_config.json`.

## Brute Force

Detects repeated login failures from the same source IP.

| Field | Value |
| --- | --- |
| Event action | `login_failure` |
| Grouping | `source_ip` |
| Default threshold | More than 5 failures |
| Severity | `HIGH` |
| Example source | SSH or API login failures |

## Suspicious IP

Detects authentication or administrative activity from an IP address that is not listed as trusted.

| Field | Value |
| --- | --- |
| Trusted source | `config.trusted_ips` |
| Event actions | `login_failure`, `login_success`, `admin_access` |
| Severity | `MEDIUM` |

## Privilege Access

Detects access to configured sensitive files.

| Field | Value |
| --- | --- |
| Event action | `file_access` |
| Sensitive files | `config.sensitive_files` |
| Severity | `HIGH` |
| Examples | `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` |

## Abnormal Behavior

Detects process behavior above the configured CPU threshold.

| Field | Value |
| --- | --- |
| Event action | `process_anomaly` |
| Threshold | `config.cpu_threshold` |
| Severity | `MEDIUM` |

## Correlated Attack

Escalates related detections when the same source is associated with both brute-force behavior and suspicious IP activity.

| Field | Value |
| --- | --- |
| Required detections | `Brute Force` and `Suspicious IP` |
| Grouping | `source` |
| Severity | `CRITICAL` |

## Risk Scoring

Each alert receives a score from 1 to 10 based on severity. Alerts with larger evidence sets receive a small bonus.

| Severity | Base Score |
| --- | --- |
| LOW | 3 |
| MEDIUM | 5 |
| HIGH | 8 |
| CRITICAL | 10 |
