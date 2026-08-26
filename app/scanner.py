from pathlib import Path
from detector import detect_ecosystem, detect_python_resolution_method
from parsers.requirements_txt import parse_requirements_txt
from parsers.poetry_lock import parse_poetry_lock
from parsers.pyproject_toml import get_direct_dependency_names
from graph import build_dependency_graph
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

    resolution_method = detect_python_resolution_method(path)

    if resolution_method == "poetry.lock":
        raw_items, warnings = build_poetry_dependencies(path)
        analysis_quality = "COMPLETE"
    elif resolution_method == "requirements.txt":
        parsed, warnings = parse_requirements_txt(path)
        raw_items = [{"name": d["name"], "version": d["version"], "type": "direct", "introduced_by": None} for d in parsed]
        analysis_quality = "DEGRADED"
    else:
        print("No supported dependency file found.")
        return None

    components = enrich_components(raw_items, ecosystem, show_progress)

    return ScanResult(
        project_name=Path(path).name,
        ecosystem=ecosystem,
        analysis_quality=analysis_quality,
        resolution_method=resolution_method,
        components=components,
        warnings=warnings,
    )


def build_poetry_dependencies(path: str) -> tuple[list[dict], list[str]]:
    """Build the full direct/transitive dependency list from poetry.lock + pyproject.toml."""
    packages = parse_poetry_lock(path)
    direct_names = get_direct_dependency_names(path)
    graph = build_dependency_graph(packages, direct_names)
    return graph, []


def enrich_components(raw_items: list[dict], ecosystem: str, show_progress: bool) -> list[Component]:
    """Add license and vulnerability data to each raw dependency item."""
    components = []
    total = len(raw_items)

    for index, item in enumerate(raw_items, start=1):
        if show_progress:
            print(f"Checking {index}/{total}: {item['name']}")

        component = Component(
            name=item["name"],
            version=item["version"],
            ecosystem=ecosystem,
            type=item["type"],
            purl=build_purl(ecosystem, item["name"], item["version"]),
            license=get_license(item["name"], item["version"]),
            vulnerabilities=get_vulnerabilities(item["name"], item["version"], ecosystem),
            introduced_by=item.get("introduced_by"),
        )
        components.append(component)

    return components