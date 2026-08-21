from pathlib import Path


def detect_ecosystem(project_path: str) -> str | None:
    """Look at a folder and figure out what kind of project it is."""
    path = Path(project_path)

    if (path / "requirements.txt").exists() or (path / "pyproject.toml").exists():
        return "python"

    if (path / "package.json").exists():
        return "node"

    return None