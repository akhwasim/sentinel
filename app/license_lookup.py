import httpx


def get_license(name: str, version: str | None) -> dict:
    """Look up a package's declared license from PyPI."""
    url = f"https://pypi.org/pypi/{name}/json"

    try:
        response = httpx.get(url, timeout=5.0)
        response.raise_for_status()
        data = response.json()
    except Exception:
        return {"id": None, "source": None, "confidence": "UNDECLARED"}

    info = data.get("info", {})

    license_expression = info.get("license_expression")
    if license_expression:
        return {"id": license_expression, "source": "license_expression", "confidence": "DECLARED"}

    classifiers = info.get("classifiers", [])
    license_classifiers = [c for c in classifiers if c.startswith("License ::")]
    if license_classifiers:
        license_name = license_classifiers[0].split("::")[-1].strip()
        return {"id": license_name, "source": "classifier", "confidence": "DECLARED"}

    license_text = info.get("license")
    if license_text:
        return {"id": license_text, "source": "metadata", "confidence": "DECLARED"}

    return {"id": None, "source": None, "confidence": "UNDECLARED"}