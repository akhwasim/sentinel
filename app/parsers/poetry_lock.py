import tomllib
from pathlib import Path


def parse_poetry_lock(project_path: str) -> list[dict]:
    """Read poetry.lock and return a list of {name, version, dependencies} dicts."""
    file_path = Path(project_path) / "poetry.lock"
    data = tomllib.loads(file_path.read_text())

    packages = data.get("package", [])
    dependencies = []

    for pkg in packages:
        deps_section = pkg.get("dependencies", {})
        depends_on = list(deps_section.keys())

        dependencies.append({
            "name": pkg["name"],
            "version": pkg["version"],
            "depends_on": depends_on,
        })

    return dependencies