import httpx

KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"

_kev_cache = None


def load_kev_catalog() -> set[str]:
    """Fetch the CISA KEV catalog once and cache the set of CVE IDs it contains."""
    global _kev_cache

    if _kev_cache is not None:
        return _kev_cache

    try:
        response = httpx.get(KEV_URL, timeout=30.0, follow_redirects=True)
        response.raise_for_status()
        data = response.json()
        _kev_cache = {v["cveID"] for v in data.get("vulnerabilities", [])}
    except Exception:
        _kev_cache = set()

    return _kev_cache


def is_actively_exploited(cve_id: str | None) -> bool:
    """Check if a given CVE ID is in the CISA KEV catalog (actively exploited in the wild)."""
    if not cve_id:
        return False

    catalog = load_kev_catalog()
    return cve_id in catalog