import ast
from pathlib import Path


def find_imported_packages(project_path: str) -> set[str]:
    """Walk all .py files in a project and collect the top-level package names actually imported."""
    imported = set()
    path = Path(project_path)

    skip_dirs = {"venv", ".venv", "node_modules", "__pycache__", ".git"}

    for py_file in path.rglob("*.py"):
        if any(part in skip_dirs for part in py_file.parts):
            continue

        try:
            source = py_file.read_text(errors="ignore")
            tree = ast.parse(source)
        except Exception:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top_level = alias.name.split(".")[0]
                    imported.add(normalize(top_level))

            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    top_level = node.module.split(".")[0]
                    imported.add(normalize(top_level))

    return imported


def normalize(name: str) -> str:
    return name.lower().replace("_", "-")