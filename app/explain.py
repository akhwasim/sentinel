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
    findings_text = build_findings_text(scan_result)
    return ask_ai(SYSTEM_PROMPT, findings_text)


ASK_SYSTEM_PROMPT = """You are a security assistant for a software supply chain tool called Sentinel.
You will be given real scan findings (score, vulnerabilities, warnings, license data) and a question from the user.
Answer ONLY using the data given to you. Do not invent vulnerabilities, packages, or facts not present in the data.
If the question cannot be answered from the given data, say so honestly.
Keep answers concise and direct."""


def build_findings_text(scan_result: ScanResult) -> str:
    """Build the plain-text findings block (shared by explain and ask)."""
    summary = calculate_score(scan_result)

    vuln_lines = []
    kev_lines = []
    exploit_lines = []
    for comp in scan_result.components:
        for vuln in comp.vulnerabilities:
            reachability_note = ""
            if comp.reachable == "NOT_REACHABLE":
                reachability_note = " [NOTE: this package is declared but never imported in the codebase - likely NOT actually exploitable in practice]"
            elif comp.reachable == "REACHABLE":
                reachability_note = " [this package is actively imported and used in the codebase]"

            line = (
                f"- {comp.name} {comp.version}: {vuln.get('id')} "
                f"(severity: {vuln.get('severity')}) - {vuln.get('summary')}{reachability_note}"
            )
            vuln_lines.append(line)

            if vuln.get("is_kev"):
                kev_lines.append(
                    f"- {comp.name} {comp.version}: {vuln.get('cve_id')} "
                    f"is CONFIRMED to be actively exploited in the wild (CISA KEV catalog)"
                )
            elif vuln.get("has_public_exploit"):
                exploit_lines.append(
                    f"- {comp.name} {comp.version}: {vuln.get('cve_id')} "
                    f"has a publicly available exploit (not yet confirmed as actively exploited)"
                )

    direct_deps = [c.name for c in scan_result.components if c.type == "direct"]

    transitive_lines = []
    for comp in scan_result.components:
        if comp.type == "transitive":
            transitive_lines.append(f"- {comp.name} (introduced by: {comp.introduced_by})")

    return f"""
Project: {scan_result.project_name}
Analysis quality: {scan_result.analysis_quality}
Score: {summary['score']}/100

Direct dependencies: {', '.join(direct_deps) if direct_deps else "None (analysis was degraded, direct/transitive not distinguished)"}

Transitive dependencies and what introduced them:
{chr(10).join(transitive_lines) if transitive_lines else "None (not available for this analysis quality)"}

Vulnerabilities found:
{chr(10).join(vuln_lines) if vuln_lines else "None"}

ACTIVELY EXPLOITED VULNERABILITIES (CISA KEV catalog - highest priority):
{chr(10).join(kev_lines) if kev_lines else "None"}

VULNERABILITIES WITH PUBLIC EXPLOITS AVAILABLE (elevated risk, second priority):
{chr(10).join(exploit_lines) if exploit_lines else "None"}

Warnings:
{chr(10).join(scan_result.warnings) if scan_result.warnings else "None"}

Undeclared licenses: {summary['undeclared_licenses']}
"""


def ask_about_findings(scan_result: ScanResult, question: str) -> str:
    """Answer a user's question grounded in the real scan findings."""
    findings_text = build_findings_text(scan_result)
    full_prompt = f"{findings_text}\n\nQuestion: {question}"
    return ask_ai(ASK_SYSTEM_PROMPT, full_prompt)