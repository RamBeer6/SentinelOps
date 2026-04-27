from ipaddress import ip_address, ip_network


PRIVATE_NETWORKS = (
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
)


def _ip_reputation(source_ip: str, trusted_ips: set[str]) -> str:
    if source_ip in trusted_ips:
        return "trusted"
    if source_ip == "unknown":
        return "not_applicable"

    try:
        parsed_ip = ip_address(source_ip)
    except ValueError:
        return "not_applicable"

    if any(parsed_ip in network for network in PRIVATE_NETWORKS):
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
