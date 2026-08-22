from pathlib import Path


def parse_requirements_txt(project_path: str) -> list[dict]:
    """Read requirements.txt and return a list of {name, version} dicts."""
    file_path = Path(project_path) / "requirements.txt"
    dependencies = []

    lines = file_path.read_text().splitlines()

    for line in lines:
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        if "==" in line:
            name, version = line.split("==", 1)
        else:
            name, version = line, None

        dependencies.append({"name": name.strip(), "version": version})

    return dependencies