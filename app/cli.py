import typer
from detector import detect_ecosystem
from parsers.requirements_txt import parse_requirements_txt
from models import Component
from purl import build_purl
from project import ScanResult
from pathlib import Path
from sbom import generate_sbom
from license_lookup import get_license
from vuln_lookup import get_vulnerabilities

app = typer.Typer()


@app.command()
def scan(path: str = typer.Argument(".")):
    """Scan a project and generate an SBOM."""
    print(f"Scanning: {path}")
    ecosystem = detect_ecosystem(path)
    print(f"Detected ecosystem: {ecosystem}")

    if ecosystem == "python":
        raw_dependencies = parse_requirements_txt(path)
        components = []
        total = len(raw_dependencies)
        for index, dep in enumerate(raw_dependencies, start=1):
            print(f"Checking {index}/{total}: {dep['name']}")
            component = Component(
                name=dep["name"],
                version=dep["version"],
                ecosystem=ecosystem,
                type="direct",
                purl=build_purl(ecosystem, dep["name"], dep["version"]),
                license=get_license(dep["name"], dep["version"]),
                vulnerabilities=get_vulnerabilities(dep["name"], dep["version"], ecosystem),
            )
            components.append(component)

        scan_result = ScanResult(
            project_name=Path(path).name,
            ecosystem=ecosystem,
            analysis_quality="DEGRADED",
            resolution_method="requirements.txt",
            components=components,
        )

        print(f"Found {len(scan_result.components)} dependencies")
        print(f"Analysis quality: {scan_result.analysis_quality}")
        print(f"Scanned at: {scan_result.scanned_at}")

        sbom_json = generate_sbom(scan_result)
        output_path = Path("output") / "sbom.cdx.json"
        output_path.write_text(sbom_json)
        print(f"SBOM written to: {output_path}")


if __name__ == "__main__":
    app()