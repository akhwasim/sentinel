# Sentinel

Sentinel is an AI-assisted Software Bill of Materials (SBOM) generator and supply-chain security analysis tool.

It scans a project's dependencies, generates a standard CycloneDX SBOM, checks for known vulnerabilities and license issues, and uses AI to explain the findings in plain English.

## Current features

- Detects Python projects (`requirements.txt` or `poetry.lock`)
- Parses dependencies, including full dependency graphs when a lockfile is available
- Generates a CycloneDX SBOM
- Checks dependencies against known vulnerabilities (via OSV.dev)
- Extracts license information (deterministic, no AI involved)
- Calculates a deterministic supply-chain health score
- AI-powered `explain` and `ask` commands for plain-English analysis of real findings

## Design principle

The core scanning, SBOM generation, license detection, and vulnerability checks are fully deterministic. AI is only used to explain and prioritize findings that already exist — it never invents dependencies, licenses, or vulnerabilities.

## Requirements

- Python 3.12+
- A Groq API key (free) for the AI features — get one at https://console.groq.com

## Setup

\`\`\`bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
\`\`\`

Create a `.env` file in the project root:
\`\`\`
GROQ_API_KEY=your_key_here
\`\`\`

## Usage

\`\`\`bash
python app/cli.py scan <path-to-project>
python app/cli.py explain <path-to-project>
python app/cli.py ask "your question" --path <path-to-project>
\`\`\`

## Status

This project is under active development. Currently supports local Python projects. Node.js support, GitHub URL scanning, and a web report view are planned next.