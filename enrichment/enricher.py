PRIVATE_PREFIXES = ("10.", "172.16.", "192.168.")


def _ip_reputation(source_ip: str, trusted_ips: set[str]) -> str:
    if source_ip in trusted_ips:
        return "trusted"
    if source_ip == "unknown":
        return "not_applicable"
    if source_ip.startswith(PRIVATE_PREFIXES):
        return "internal_untrusted"
    return "external_untrusted"


def _asset_criticality(source: str, config: dict) -> str:
    asset_map = config.get("asset_criticality", {})
    return asset_map.get(source, asset_map.get("unknown", "LOW"))


def enrich_alert(alert: dict, config: dict) -> dict:
    trusted_ips = set(config.get("trusted_ips", []))
    source_ip = alert.get("source_ip", alert.get("source", "unknown"))
    mitre = config.get("mitre_mapping", {}).get(alert["type"], {})

    alert["enrichment"] = {
        "ip_reputation": _ip_reputation(source_ip, trusted_ips),
        "asset_criticality": _asset_criticality(alert.get("source", "unknown"), config),
        "mitre_tactic": mitre.get("tactic", "Unknown"),
        "mitre_technique": mitre.get("technique", "Unknown"),
    }
    return alert
