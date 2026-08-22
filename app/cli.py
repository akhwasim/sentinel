import typer
from detector import detect_ecosystem
from parsers.requirements_txt import parse_requirements_txt

app = typer.Typer()


@app.command()
def scan(path: str = typer.Argument(".")):
    """Scan a project and generate an SBOM."""
    print(f"Scanning: {path}")
    ecosystem = detect_ecosystem(path)
    print(f"Detected ecosystem: {ecosystem}")

    if ecosystem == "python":
        dependencies = parse_requirements_txt(path)
        print(f"Found {len(dependencies)} dependencies")


if __name__ == "__main__":
    app()