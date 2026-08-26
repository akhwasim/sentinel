def build_dependency_graph(packages: list[dict], direct_names: set[str]) -> list[dict]:
    """Combine poetry.lock packages + direct dependency names into a labeled component list."""
    name_to_package = {normalize(pkg["name"]): pkg for pkg in packages}

    result = []
    for pkg in packages:
        normalized_name = normalize(pkg["name"])

        if normalized_name in direct_names:
            dep_type = "direct"
            introduced_by = None
        else:
            dep_type = "transitive"
            introduced_by = find_introducer(normalized_name, packages, direct_names)

        result.append({
            "name": pkg["name"],
            "version": pkg["version"],
            "type": dep_type,
            "introduced_by": introduced_by,
        })

    return result


def find_introducer(target_name: str, packages: list[dict], direct_names: set[str], seen: set[str] | None = None) -> str | None:
    """Find which direct dependency (eventually) pulled in this transitive package."""
    if seen is None:
        seen = set()

    if target_name in seen:
        return None
    seen.add(target_name)

    for pkg in packages:
        depends_on_normalized = [normalize(d) for d in pkg.get("depends_on", [])]
        if target_name in depends_on_normalized:
            pkg_name_normalized = normalize(pkg["name"])

            if pkg_name_normalized in direct_names:
                return pkg["name"]

            result = find_introducer(pkg_name_normalized, packages, direct_names, seen)
            if result:
                return result

    return None


def normalize(name: str) -> str:
    return name.lower().replace("_", "-")