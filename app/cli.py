import typer
from detector import detect_ecosystem

app = typer.Typer()


@app.command()
def scan(path: str = typer.Argument(".")):
    """Scan a project and generate an SBOM."""
    print(f"Scanning: {path}")
    ecosystem = detect_ecosystem(path)
    print(f"Detected ecosystem: {ecosystem}")


if __name__ == "__main__":
    app()