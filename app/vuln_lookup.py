import httpx
from cvss import CVSS3
from kev_lookup import is_actively_exploited


def get_vulnerabilities(name: str, version: str | None, ecosystem: str) -> list[dict]:
    """Check OSV.dev for known vulnerabilities affecting this package version."""
    if not version:
        return []

    ecosystem_map = {
        "python": "PyPI",
        "node": "npm",
    }
    osv_ecosystem = ecosystem_map.get(ecosystem, ecosystem)

    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {"name": name, "ecosystem": osv_ecosystem},
        "version": version,
    }

    try:
        response = httpx.post(url, json=payload, timeout=5.0)
        response.raise_for_status()
        data = response.json()
    except Exception:
        return []

    vulns = data.get("vulns", [])

    results = []
    for v in vulns:
        cve_id = extract_cve_id(v)
        results.append({
            "id": v.get("id"),
            "cve_id": cve_id,
            "summary": v.get("summary"),
            "severity": extract_severity(v),
            "is_kev": is_actively_exploited(cve_id),
        })

    return results


def extract_cve_id(vuln: dict) -> str | None:
    """OSV entries sometimes use a GHSA ID as the main id, with the CVE listed as an alias."""
    if vuln.get("id", "").startswith("CVE-"):
        return vuln["id"]

    for alias in vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            return alias

    return None


def extract_severity(vuln: dict) -> str:
    """Convert OSV's severity data into a simple label: CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN."""
    severity_list = vuln.get("severity", [])

    for entry in severity_list:
        score_text = entry.get("score", "")

        if score_text.startswith("CVSS:3"):
            try:
                score = CVSS3(score_text).base_score
                return score_to_label(score)
            except Exception:
                continue

    return "UNKNOWN"


def score_to_label(score: float) -> str:
    """Turn a numeric CVSS score (0-10) into a standard severity label."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "UNKNOWN"