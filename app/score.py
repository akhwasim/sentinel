from project import ScanResult

SEVERITY_PENALTIES = {
    "CRITICAL": 15,
    "HIGH": 8,
    "MEDIUM": 3,
    "LOW": 1,
}

WARNING_PENALTY = 5
UNDECLARED_LICENSE_PENALTY = 2
MAX_LICENSE_PENALTY = 20


def calculate_score(scan_result: ScanResult) -> dict:
    """Calculate a deterministic supply-chain health score (0-100)."""
    score = 100
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    undeclared_license_count = 0

    for comp in scan_result.components:
        for vuln in comp.vulnerabilities:
            severity = vuln.get("severity", "UNKNOWN")
            penalty = SEVERITY_PENALTIES.get(severity, 0)
            score -= penalty

            if severity == "CRITICAL":
                critical_count += 1
            elif severity == "HIGH":
                high_count += 1
            elif severity == "MEDIUM":
                medium_count += 1
            elif severity == "LOW":
                low_count += 1

        if comp.license and comp.license.get("confidence") == "UNDECLARED":
            undeclared_license_count += 1

    score -= len(scan_result.warnings) * WARNING_PENALTY

    license_penalty = min(undeclared_license_count * UNDECLARED_LICENSE_PENALTY, MAX_LICENSE_PENALTY)
    score -= license_penalty

    score = max(0, min(100, score))

    return {
        "score": score,
        "critical_vulnerabilities": critical_count,
        "high_vulnerabilities": high_count,
        "medium_vulnerabilities": medium_count,
        "low_vulnerabilities": low_count,
        "undeclared_licenses": undeclared_license_count,
        "warnings": len(scan_result.warnings),
    }