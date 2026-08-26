from pathlib import Path


def detect_ecosystem(project_path: str) -> str | None:
    """Look at a folder and figure out what kind of project it is."""
    path = Path(project_path)

    if (path / "requirements.txt").exists() or (path / "pyproject.toml").exists():
        return "python"

    if (path / "package.json").exists():
        return "node"

    return None


def detect_python_resolution_method(project_path: str) -> str:
    """Figure out which file to use for resolving Python dependencies."""
    path = Path(project_path)

    if (path / "poetry.lock").exists():
        return "poetry.lock"

    if (path / "requirements.txt").exists():
        return "requirements.txt"

    return "unknown"