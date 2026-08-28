from pathlib import Path
from detector import detect_ecosystem, detect_python_resolution_method, detect_node_resolution_method
from parsers.requirements_txt import parse_requirements_txt
from parsers.poetry_lock import parse_poetry_lock
from parsers.pyproject_toml import get_direct_dependency_names
from graph import build_dependency_graph
from models import Component
from purl import build_purl
from license_lookup import get_license
from vuln_lookup import get_vulnerabilities
from project import ScanResult
from github_ingest import is_github_url, clone_repo, cleanup_repo, extract_repo_name
from parsers.package_lock import parse_package_lock


def run_scan(path: str, show_progress: bool = True) -> ScanResult | None:
    """Detect ecosystem, parse dependencies, enrich with license/vuln data, return a ScanResult."""
    project_name_override = None
    cloned_dir = None

    if is_github_url(path):
        print(f"Cloning {path}...")
        project_name_override = extract_repo_name(path)
        cloned_dir = clone_repo(path)
        path = cloned_dir

    ecosystem = detect_ecosystem(path)

    if ecosystem == "python":
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

    elif ecosystem == "node":
        resolution_method = detect_node_resolution_method(path)

        if resolution_method == "package-lock.json":
            raw_items, warnings = build_node_dependencies(path)
            analysis_quality = "COMPLETE"
        else:
            print("No supported dependency file found (package.json without lockfile not yet supported).")
            return None

    else:
        print("Unsupported ecosystem.")
        return None

    components = enrich_components(raw_items, ecosystem, show_progress)

    result = ScanResult(
        project_name=project_name_override or Path(path).name,
        ecosystem=ecosystem,
        analysis_quality=analysis_quality,
        resolution_method=resolution_method,
        components=components,
        warnings=warnings,
    )

    if cloned_dir:
        cleanup_repo(cloned_dir)

    return result


def build_poetry_dependencies(path: str) -> tuple[list[dict], list[str]]:
    """Build the full direct/transitive dependency list from poetry.lock + pyproject.toml."""
    packages = parse_poetry_lock(path)
    direct_names = get_direct_dependency_names(path)
    graph = build_dependency_graph(packages, direct_names)
    return graph, []

def build_node_dependencies(path: str) -> tuple[list[dict], list[str]]:
    """Build the full direct/transitive dependency list from package-lock.json."""
    packages, direct_names = parse_package_lock(path)
    graph = build_dependency_graph(packages, direct_names)
    return graph, []


def enrich_components(raw_items: list[dict], ecosystem: str, show_progress: bool) -> list[Component]:
    """Add license and vulnerability data to each raw dependency item."""
    components = []
    total = len(raw_items)

    for index, item in enumerate(raw_items, start=1):
        if show_progress:
            print(f"Checking {index}/{total}: {item['name']}")

        license_info = resolve_license(item, ecosystem)

        component = Component(
            name=item["name"],
            version=item["version"],
            ecosystem=ecosystem,
            type=item["type"],
            purl=build_purl(ecosystem, item["name"], item["version"]),
            license=license_info,
            vulnerabilities=get_vulnerabilities(item["name"], item["version"], ecosystem),
            introduced_by=item.get("introduced_by"),
        )
        components.append(component)

    return components


def resolve_license(item: dict, ecosystem: str) -> dict:
    """Get license info the right way depending on ecosystem."""
    if ecosystem == "node":
        license_id = item.get("license")
        if license_id:
            return {"id": license_id, "source": "package-lock.json", "confidence": "DECLARED"}
        return {"id": None, "source": None, "confidence": "UNDECLARED"}

    return get_license(item["name"], item["version"])