import argparse
from pathlib import Path

from alerts import create_alerts, save_alerts
from config import load_config
from detector import run_detection
from investigation import investigate
from loader import load_logs
from parser import parse_logs
from reports import generate_dashboard, generate_report, generate_summary
from storage import save_run


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run SentinelOps SOC detection pipeline.")
    parser.add_argument("--log-file", default="logs/system_logs.txt", help="Path to the log file to analyze.")
    parser.add_argument("--config", default="config/detection_config.json", help="Detection configuration path.")
    parser.add_argument("--alerts-file", default="alerts/alerts.json", help="Output path for JSON alerts.")
    parser.add_argument("--reports-dir", default="reports", help="Directory for generated reports.")
    parser.add_argument("--db", default="data/sentinelops.db", help="SQLite database path.")
    parser.add_argument("--no-db", action="store_true", help="Skip SQLite persistence.")
    parser.add_argument("--clean", action="store_true", help="Remove generated reports before running.")
    return parser.parse_args()


def clean_reports(reports_dir: str) -> None:
    path = Path(reports_dir)
    if not path.exists():
        return

    generated_patterns = ["alert-*.txt", "executive_summary.md", "dashboard.html"]
    for pattern in generated_patterns:
        for generated_file in path.glob(pattern):
            generated_file.unlink()


def run_pipeline(args: argparse.Namespace) -> dict:
    if args.clean:
        clean_reports(args.reports_dir)

    config = load_config(args.config)
    raw_logs = load_logs(args.log_file)
    events = parse_logs(raw_logs)
    detections = run_detection(events, config)
    alerts = create_alerts(detections, config)
    save_alerts(alerts, args.alerts_file)

    investigations = {}
    report_paths = []
    for alert in alerts:
        investigation = investigate(alert, raw_logs)
        investigations[alert["id"]] = investigation
        report_paths.append(generate_report(alert, investigation, args.reports_dir))

    summary_path = generate_summary(alerts, args.reports_dir)
    dashboard_path = generate_dashboard(alerts, args.reports_dir)

    run_id = None
    if not args.no_db:
        run_id = save_run(alerts, investigations, args.log_file, args.db)

    return {
        "log_count": len(raw_logs),
        "event_count": len(events),
        "alert_count": len(alerts),
        "report_paths": report_paths,
        "summary_path": summary_path,
        "dashboard_path": dashboard_path,
        "run_id": run_id,
    }


def main() -> None:
    results = run_pipeline(parse_args())

    print(f"Loaded logs: {results['log_count']}")
    print(f"Parsed events: {results['event_count']}")
    print(f"Generated alerts: {results['alert_count']}")
    if results["run_id"] is not None:
        print(f"SQLite run ID: {results['run_id']}")
    print(f"Executive summary: {results['summary_path']}")
    print(f"Dashboard: {results['dashboard_path']}")
    print("Reports:")
    for report_path in results["report_paths"]:
        print(f"- {report_path}")


if __name__ == "__main__":
    main()
