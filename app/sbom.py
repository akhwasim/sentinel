from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component as CycloneComponent, ComponentType
from cyclonedx.output.json import JsonV1Dot5
from project import ScanResult
from packageurl import PackageURL
from cyclonedx.model.license import DisjunctiveLicense, LicenseExpression
from cyclonedx.model.vulnerability import Vulnerability, VulnerabilityRating, VulnerabilitySeverity
from cyclonedx.model.bom_ref import BomRef


def generate_sbom(scan_result: ScanResult) -> str:
    """Build a CycloneDX SBOM (as a JSON string) from our ScanResult."""
    bom = Bom()
    name_to_cyclone_comp = {}

    for comp in scan_result.components:
        cyclone_comp = CycloneComponent(
            name=comp.name,
            version=comp.version or "",
            type=ComponentType.LIBRARY,
            purl=PackageURL.from_string(comp.purl),
        )

        if comp.license and comp.license.get("id"):
            license_id = comp.license["id"]
            cyclone_comp.licenses.add(LicenseExpression(license_id))

        bom.components.add(cyclone_comp)
        name_to_cyclone_comp[normalize(comp.name)] = cyclone_comp

        for vuln in comp.vulnerabilities:
            cyclone_vuln = Vulnerability(
                id=vuln.get("id"),
                description=vuln.get("summary") or "",
            )
            cyclone_vuln.affects.add(cyclone_comp.bom_ref)

            severity_label = vuln.get("severity")
            if severity_label and severity_label != "UNKNOWN":
                rating = VulnerabilityRating(severity=VulnerabilitySeverity[severity_label])
                cyclone_vuln.ratings.add(rating)

            bom.vulnerabilities.add(cyclone_vuln)

    for comp in scan_result.components:
        if comp.introduced_by:
            parent = name_to_cyclone_comp.get(normalize(comp.introduced_by))
            child = name_to_cyclone_comp.get(normalize(comp.name))
            if parent and child:
                bom.register_dependency(parent, [child])

    output = JsonV1Dot5(bom)
    return output.output_as_string(indent=2)


def normalize(name: str) -> str:
    return name.lower().replace("_", "-")