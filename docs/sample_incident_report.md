# Sample Incident Report

## Summary

SentinelOps detected a correlated authentication attack from an untrusted source. The source generated multiple failed login attempts and matched suspicious IP criteria, causing the alert to be escalated to critical severity.

## Alert Details

| Field | Value |
| --- | --- |
| Alert ID | `ALERT-0009` |
| Type | `Correlated Attack` |
| Severity | `CRITICAL` |
| Risk Score | `10/10` |
| Source | `172.16.4.20` |
| MITRE Context | Correlated activity across detection rules |

## Findings

- Multiple failed API login attempts were observed from the same source IP.
- The source IP was not in the trusted IP list.
- The activity matched both brute-force and suspicious IP detection logic.

## Impact

The activity indicates a likely authentication attack. If successful, it could lead to account compromise or unauthorized access to protected systems.

## Recommendations

- Block or rate-limit the source IP.
- Review authentication logs for successful logins after the failed attempts.
- Enforce MFA for exposed accounts.
- Add the source IP to a watchlist.
- Search for related activity across other logs and hosts.

## Evidence

```text
2026-04-27T09:03:31Z API POST /login failed from 172.16.4.20 user=guest status=401
2026-04-27T09:03:36Z API POST /login failed from 172.16.4.20 user=guest status=401
2026-04-27T09:03:41Z API POST /login failed from 172.16.4.20 user=guest status=401
2026-04-27T09:03:46Z API POST /login failed from 172.16.4.20 user=guest status=401
2026-04-27T09:03:51Z API POST /login failed from 172.16.4.20 user=guest status=401
2026-04-27T09:03:56Z API POST /login failed from 172.16.4.20 user=guest status=401
```
