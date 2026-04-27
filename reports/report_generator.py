from collections import Counter
from html import escape
from pathlib import Path


def _format_list(title: str, items: list[str]) -> list[str]:
    lines = [f"{title}:"]
    lines.extend(f"- {item}" for item in items)
    return lines


def generate_report(alert: dict, investigation: dict, output_dir: str = "reports") -> Path:
    report_dir = Path(output_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / f"{alert['id'].lower()}_{alert['type'].lower().replace(' ', '_')}.txt"
    enrichment = alert.get("enrichment", {})

    lines = [
        "=== INCIDENT REPORT ===",
        "",
        f"Alert ID: {alert['id']}",
        f"Type: {alert['type']}",
        f"Severity: {alert['severity']}",
        f"Risk Score: {alert['risk_score']}/10",
        f"Timestamp: {alert['timestamp']}",
        f"Source: {alert['source']}",
        f"Source IP: {alert.get('source_ip', 'unknown')}",
        "",
        "Enrichment:",
        f"- IP reputation: {enrichment.get('ip_reputation', 'unknown')}",
        f"- Asset criticality: {enrichment.get('asset_criticality', 'unknown')}",
        f"- MITRE tactic: {enrichment.get('mitre_tactic', 'unknown')}",
        f"- MITRE technique: {enrichment.get('mitre_technique', 'unknown')}",
        "",
        "Findings:",
        f"- {investigation['finding']}",
        f"- Related events: {investigation['event_count']}",
        "",
        "Impact:",
        f"- {investigation['impact']}",
        "",
        "Risk:",
        f"- {investigation['risk']}",
        "",
        *_format_list("Recommendations", investigation["recommendations"]),
        "",
        "Evidence:",
        *[f"- {log}" for log in investigation["related_logs"]],
    ]

    if "correlation_summary" in investigation:
        lines.extend(["", "Correlation Summary:"])
        lines.extend(f"- {key}: {value}" for key, value in investigation["correlation_summary"].items())

    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report_path


def generate_summary(alerts: list[dict], output_dir: str = "reports") -> Path:
    report_dir = Path(output_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    summary_path = report_dir / "executive_summary.md"

    by_severity = Counter(alert["severity"] for alert in alerts)
    by_type = Counter(alert["type"] for alert in alerts)
    critical_alerts = [alert for alert in alerts if alert["severity"] == "CRITICAL"]

    lines = [
        "# SentinelOps Executive Summary",
        "",
        f"Total alerts: **{len(alerts)}**",
        f"Critical alerts: **{by_severity.get('CRITICAL', 0)}**",
        f"High alerts: **{by_severity.get('HIGH', 0)}**",
        f"Medium alerts: **{by_severity.get('MEDIUM', 0)}**",
        "",
        "## Alert Types",
        "",
    ]
    lines.extend(f"- {alert_type}: {count}" for alert_type, count in by_type.most_common())
    lines.extend(["", "## Highest Priority Findings", ""])

    if critical_alerts:
        lines.extend(
            f"- {alert['id']} {alert['type']} from {alert['source']} "
            f"(risk {alert['risk_score']}/10)"
            for alert in critical_alerts
        )
    else:
        lines.append("- No critical alerts detected.")

    lines.extend(["", "## Analyst Notes", ""])
    lines.append("- Review correlated alerts first.")
    lines.append("- Validate whether any failed authentication attempts were followed by successful logins.")
    lines.append("- Add confirmed malicious IPs to perimeter blocking controls.")

    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return summary_path


def generate_dashboard(alerts: list[dict], output_dir: str = "reports") -> Path:
    report_dir = Path(output_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    dashboard_path = report_dir / "dashboard.html"

    rows = []
    for alert in alerts:
        enrichment = alert.get("enrichment", {})
        rows.append(
            "<tr>"
            f"<td>{escape(alert['id'])}</td>"
            f"<td>{escape(alert['type'])}</td>"
            f"<td><span class=\"badge {escape(alert['severity'].lower())}\">{escape(alert['severity'])}</span></td>"
            f"<td>{alert['risk_score']}/10</td>"
            f"<td>{escape(alert['source'])}</td>"
            f"<td>{escape(enrichment.get('mitre_technique', 'Unknown'))}</td>"
            f"<td>{len(alert['evidence'])}</td>"
            "</tr>"
        )

    severity_counts = Counter(alert["severity"] for alert in alerts)
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SentinelOps SOC Dashboard</title>
  <style>
    body {{
      margin: 0;
      font-family: Arial, sans-serif;
      background: #f5f7fb;
      color: #172033;
    }}
    header {{
      background: #172033;
      color: white;
      padding: 24px 32px;
    }}
    main {{
      padding: 24px 32px;
    }}
    .metrics {{
      display: grid;
      grid-template-columns: repeat(4, minmax(120px, 1fr));
      gap: 12px;
      margin-bottom: 24px;
    }}
    .metric {{
      background: white;
      border: 1px solid #d8deea;
      border-radius: 8px;
      padding: 16px;
    }}
    .metric strong {{
      display: block;
      font-size: 28px;
      margin-top: 6px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: white;
      border: 1px solid #d8deea;
    }}
    th, td {{
      text-align: left;
      border-bottom: 1px solid #e8edf5;
      padding: 12px;
      font-size: 14px;
    }}
    th {{
      background: #eef2f8;
    }}
    .badge {{
      border-radius: 999px;
      color: white;
      display: inline-block;
      font-size: 12px;
      font-weight: bold;
      min-width: 72px;
      padding: 5px 8px;
      text-align: center;
    }}
    .critical {{ background: #9f1239; }}
    .high {{ background: #b45309; }}
    .medium {{ background: #2563eb; }}
    .low {{ background: #047857; }}
  </style>
</head>
<body>
  <header>
    <h1>SentinelOps SOC Dashboard</h1>
    <p>Detection, alerting, investigation, and reporting overview</p>
  </header>
  <main>
    <section class="metrics">
      <div class="metric">Total alerts<strong>{len(alerts)}</strong></div>
      <div class="metric">Critical<strong>{severity_counts.get("CRITICAL", 0)}</strong></div>
      <div class="metric">High<strong>{severity_counts.get("HIGH", 0)}</strong></div>
      <div class="metric">Medium<strong>{severity_counts.get("MEDIUM", 0)}</strong></div>
    </section>
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Type</th>
          <th>Severity</th>
          <th>Risk</th>
          <th>Source</th>
          <th>MITRE</th>
          <th>Events</th>
        </tr>
      </thead>
      <tbody>
        {''.join(rows)}
      </tbody>
    </table>
  </main>
</body>
</html>
"""

    dashboard_path.write_text(html, encoding="utf-8")
    return dashboard_path
