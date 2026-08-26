import tomllib
from pathlib import Path


def get_direct_dependency_names(project_path: str) -> set[str]:
    """Read pyproject.toml and return the set of direct dependency names."""
    file_path = Path(project_path) / "pyproject.toml"
    data = tomllib.loads(file_path.read_text())

    raw_deps = data.get("project", {}).get("dependencies", [])
    names = set()

    for entry in raw_deps:
        name = entry.split(" ")[0].split("(")[0].strip()
        names.add(normalize_name(name))

    return names


def normalize_name(name: str) -> str:
    """Normalize a package name the same way PyPI does (lowercase, dashes)."""
    return name.lower().replace("_", "-")