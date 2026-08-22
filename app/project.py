from dataclasses import dataclass, field
from datetime import datetime, timezone
from models import Component


@dataclass
class ScanResult:
    project_name: str
    ecosystem: str
    analysis_quality: str
    resolution_method: str
    scanned_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    components: list[Component] = field(default_factory=list)