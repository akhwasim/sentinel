from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component as CycloneComponent, ComponentType
from cyclonedx.output.json import JsonV1Dot5
from project import ScanResult
from packageurl import PackageURL

def generate_sbom(scan_result: ScanResult) -> str:
    """Build a CycloneDX SBOM (as a JSON string) from our ScanResult."""
    bom = Bom()

    for comp in scan_result.components:
        cyclone_comp = CycloneComponent(
            name=comp.name,
            version=comp.version or "",
            type=ComponentType.LIBRARY,
            purl=PackageURL.from_string(comp.purl),
        )
        bom.components.add(cyclone_comp)

    output = JsonV1Dot5(bom)
    return output.output_as_string(indent=2)