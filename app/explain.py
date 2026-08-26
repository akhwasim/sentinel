from project import ScanResult
from score import calculate_score
from ai import ask_ai

SYSTEM_PROMPT = """You are a security assistant for a software supply chain tool called Sentinel.
You will be given real scan findings (score, vulnerabilities, warnings, license data).
Explain them in plain, clear English for a developer.
Prioritize what to fix first, and explain WHY.
Do not invent any vulnerabilities, packages, or facts that are not in the data given to you.
Keep it concise: 3-4 short paragraphs maximum."""


def explain_findings(scan_result: ScanResult) -> str:
    """Generate a plain-English explanation of the scan findings."""
    summary = calculate_score(scan_result)

    vuln_lines = []
    for comp in scan_result.components:
        for vuln in comp.vulnerabilities:
            vuln_lines.append(
                f"- {comp.name} {comp.version}: {vuln.get('id')} "
                f"(severity: {vuln.get('severity')}) - {vuln.get('summary')}"
            )

    findings_text = f"""
Project: {scan_result.project_name}
Analysis quality: {scan_result.analysis_quality}
Score: {summary['score']}/100

Vulnerabilities found:
{chr(10).join(vuln_lines) if vuln_lines else "None"}

Warnings:
{chr(10).join(scan_result.warnings) if scan_result.warnings else "None"}

Undeclared licenses: {summary['undeclared_licenses']}
"""

    return ask_ai(SYSTEM_PROMPT, findings_text)