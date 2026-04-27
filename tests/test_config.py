import json
import tempfile
import unittest
from pathlib import Path

from config.settings import load_config, validate_config


VALID_CONFIG = {
    "trusted_ips": ["10.0.0.5"],
    "bruteforce_threshold": 5,
    "cpu_threshold": 90,
    "sensitive_files": ["/etc/shadow"],
    "untrusted_admin_endpoints": ["/admin"],
    "asset_criticality": {"unknown": "LOW"},
    "mitre_mapping": {},
}


class ConfigTests(unittest.TestCase):
    def test_validate_config_rejects_missing_required_key(self) -> None:
        config = dict(VALID_CONFIG)
        del config["mitre_mapping"]

        with self.assertRaisesRegex(ValueError, "mitre_mapping"):
            validate_config(config)

    def test_validate_config_rejects_invalid_threshold(self) -> None:
        config = dict(VALID_CONFIG)
        config["bruteforce_threshold"] = 0

        with self.assertRaisesRegex(ValueError, "positive integer"):
            validate_config(config)

    def test_load_config_returns_valid_json_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            config_path.write_text(json.dumps(VALID_CONFIG), encoding="utf-8")

            config = load_config(str(config_path))

        self.assertEqual(config["trusted_ips"], ["10.0.0.5"])


if __name__ == "__main__":
    unittest.main()
