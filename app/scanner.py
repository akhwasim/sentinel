from pathlib import Path
from detector import detect_ecosystem
from parsers.requirements_txt import parse_requirements_txt
from models import Component
from purl import build_purl
from license_lookup import get_license
from vuln_lookup import get_vulnerabilities
from project import ScanResult


def run_scan(path: str, show_progress: bool = True) -> ScanResult | None:
    """Detect ecosystem, parse dependencies, enrich with license/vuln data, return a ScanResult."""
    ecosystem = detect_ecosystem(path)

    if ecosystem != "python":
        print("Currently only Python projects are supported.")
        return None

    raw_dependencies, warnings = parse_requirements_txt(path)
    components = []
    total = len(raw_dependencies)

    for index, dep in enumerate(raw_dependencies, start=1):
        if show_progress:
            print(f"Checking {index}/{total}: {dep['name']}")

        component = Component(
            name=dep["name"],
            version=dep["version"],
            ecosystem=ecosystem,
            type="direct",
            purl=build_purl(ecosystem, dep["name"], dep["version"]),
            license=get_license(dep["name"], dep["version"]),
            vulnerabilities=get_vulnerabilities(dep["name"], dep["version"], ecosystem),
        )
        components.append(component)

    return ScanResult(
        project_name=Path(path).name,
        ecosystem=ecosystem,
        analysis_quality="DEGRADED",
        resolution_method="requirements.txt",
        components=components,
        warnings=warnings,
    )