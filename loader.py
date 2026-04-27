from pathlib import Path


def load_logs(log_path: str = "logs/system_logs.txt") -> list[str]:
    """Load non-empty log lines from a text file."""
    path = Path(log_path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
