import typer
from pathlib import Path
from sbom import generate_sbom
from score import calculate_score
from explain import explain_findings
from explain import ask_about_findings
from scanner import run_scan

app = typer.Typer()


@app.command()
def scan(path: str = typer.Argument(".")):
    """Scan a project and generate an SBOM."""
    print(f"Scanning: {path}")

    scan_result = run_scan(path)
    if scan_result is None:
        return

    print(f"Found {len(scan_result.components)} dependencies")
    print(f"Analysis quality: {scan_result.analysis_quality}")
    print(f"Scanned at: {scan_result.scanned_at}")

    if scan_result.warnings:
        print(f"\nWarnings ({len(scan_result.warnings)}):")
        for warning in scan_result.warnings:
            print(f"  ⚠ {warning}")

    unreachable_with_vulns = [
        c for c in scan_result.components
        if c.reachable == "NOT_REACHABLE" and c.vulnerabilities
    ]
    if unreachable_with_vulns:
        print(f"\nNote: {len(unreachable_with_vulns)} vulnerable package(s) are declared but not imported anywhere in your code:")
        for comp in unreachable_with_vulns:
            print(f"  - {comp.name} {comp.version}")

    summary = calculate_score(scan_result)
    print(f"\nSupply Chain Score: {summary['score']}/100")
    print(f"  Critical vulnerabilities: {summary['critical_vulnerabilities']}")
    print(f"  High vulnerabilities: {summary['high_vulnerabilities']}")
    print(f"  Medium vulnerabilities: {summary['medium_vulnerabilities']}")
    print(f"  Low vulnerabilities: {summary['low_vulnerabilities']}")
    print(f"  Undeclared licenses: {summary['undeclared_licenses']}")
    if summary['kev_vulnerabilities'] > 0:
        print(f"  🔴 Actively exploited (CISA KEV): {summary['kev_vulnerabilities']}")

    if summary['exploitable_vulnerabilities'] > 0:
        print(f"  🟠 Public exploit available: {summary['exploitable_vulnerabilities']}")    

    sbom_json = generate_sbom(scan_result)
    output_path = Path("output") / "sbom.cdx.json"
    output_path.write_text(sbom_json)
    print(f"SBOM written to: {output_path}")

@app.command()
def explain(path: str = typer.Argument(".")):
    """Explain the scan findings in plain English using AI."""
    scan_result = run_scan(path)
    if scan_result is None:
        return

    print("\nAnalyzing findings with AI...\n")
    explanation = explain_findings(scan_result)
    print(explanation)

@app.command()
def ask(question: str, path: str = typer.Option(".", "--path")):
    """Ask a question about the scan findings."""
    scan_result = run_scan(path)
    if scan_result is None:
        return

    print("\nThinking...\n")
    answer = ask_about_findings(scan_result, question)
    print(answer)


if __name__ == "__main__":
    app()