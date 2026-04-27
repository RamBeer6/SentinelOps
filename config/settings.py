import json
from pathlib import Path


DEFAULT_CONFIG_PATH = "config/detection_config.json"


def load_config(config_path: str = DEFAULT_CONFIG_PATH) -> dict:
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")

    return json.loads(path.read_text(encoding="utf-8"))
