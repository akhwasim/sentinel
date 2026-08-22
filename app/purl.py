def build_purl(ecosystem: str, name: str, version: str | None) -> str:
    """Build a Package URL (PURL) for a component."""
    ecosystem_map = {
        "python": "pypi",
        "node": "npm",
    }
    purl_type = ecosystem_map.get(ecosystem, ecosystem)

    normalized_name = name.lower().replace("_", "-")

    if version:
        return f"pkg:{purl_type}/{normalized_name}@{version}"
    return f"pkg:{purl_type}/{normalized_name}"