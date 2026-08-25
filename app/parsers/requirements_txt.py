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

    deduplicated = {}
    warnings = []

    for dep in dependencies:
        name = dep["name"]
        existing = deduplicated.get(name)

        if existing and existing["version"] and dep["version"] and existing["version"] != dep["version"]:
            warnings.append(
                f"{name} pinned to conflicting versions: {existing['version']} and {dep['version']} "
                f"(using {existing['version']})"
            )

        if name not in deduplicated or deduplicated[name]["version"] is None:
            deduplicated[name] = dep

    return list(deduplicated.values()), warnings