import unittest

from enrichment import enrich_alert


class EnrichmentTests(unittest.TestCase):
    def _enriched_reputation(self, source_ip: str, trusted_ips: list[str] | None = None) -> str:
        alert = {
            "type": "Suspicious IP",
            "source": source_ip,
            "source_ip": source_ip,
        }
        config = {
            "trusted_ips": trusted_ips or [],
            "asset_criticality": {"unknown": "LOW"},
            "mitre_mapping": {},
        }

        return enrich_alert(alert, config)["enrichment"]["ip_reputation"]

    def test_trusted_ip_reputation_wins_over_private_range(self) -> None:
        self.assertEqual(self._enriched_reputation("10.0.0.5", ["10.0.0.5"]), "trusted")

    def test_private_ip_reputation_uses_full_private_ranges(self) -> None:
        self.assertEqual(self._enriched_reputation("172.20.10.5"), "internal_untrusted")

    def test_public_ip_reputation_is_external_untrusted(self) -> None:
        self.assertEqual(self._enriched_reputation("8.8.8.8"), "external_untrusted")

    def test_documentation_ip_reputation_is_external_untrusted(self) -> None:
        self.assertEqual(self._enriched_reputation("198.51.100.10"), "external_untrusted")

    def test_invalid_ip_reputation_is_not_applicable(self) -> None:
        self.assertEqual(self._enriched_reputation("unknown"), "not_applicable")


if __name__ == "__main__":
    unittest.main()
