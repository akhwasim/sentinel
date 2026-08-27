import json
from pathlib import Path


def parse_package_lock(project_path: str) -> tuple[list[dict], set[str]]:
    """Read package-lock.json and return (packages, direct_names)."""
    file_path = Path(project_path) / "package-lock.json"
    data = json.loads(file_path.read_text())

    all_packages = data.get("packages", {})
    root_package = all_packages.get("", {})
    direct_names = set(root_package.get("dependencies", {}).keys())

    packages = []
    for path, info in all_packages.items():
        if path == "":
            continue

        name = path.split("node_modules/")[-1]
        depends_on = list(info.get("dependencies", {}).keys())

        packages.append({
            "name": name,
            "version": info.get("version"),
            "license": info.get("license"),
            "depends_on": depends_on,
        })

    return packages, direct_names