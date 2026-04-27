import json
from pathlib import Path


DEFAULT_CONFIG_PATH = "config/detection_config.json"
REQUIRED_KEYS = {
    "trusted_ips",
    "bruteforce_threshold",
    "cpu_threshold",
    "sensitive_files",
    "untrusted_admin_endpoints",
    "asset_criticality",
    "mitre_mapping",
}


def validate_config(config: dict) -> dict:
    missing_keys = sorted(REQUIRED_KEYS.difference(config))
    if missing_keys:
        raise ValueError(f"Missing required configuration keys: {', '.join(missing_keys)}")

    list_keys = ["trusted_ips", "sensitive_files", "untrusted_admin_endpoints"]
    for key in list_keys:
        if not isinstance(config[key], list):
            raise ValueError(f"Configuration key '{key}' must be a list")

    for key in ["bruteforce_threshold", "cpu_threshold"]:
        if not isinstance(config[key], int) or config[key] <= 0:
            raise ValueError(f"Configuration key '{key}' must be a positive integer")

    for key in ["asset_criticality", "mitre_mapping"]:
        if not isinstance(config[key], dict):
            raise ValueError(f"Configuration key '{key}' must be an object")

    return config


def load_config(config_path: str = DEFAULT_CONFIG_PATH) -> dict:
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")

    return validate_config(json.loads(path.read_text(encoding="utf-8")))
