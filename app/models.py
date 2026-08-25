from dataclasses import dataclass, field


@dataclass
class Component:
    name: str
    version: str | None
    ecosystem: str
    type: str
    purl: str
    license: dict | None = None
    vulnerabilities: list[dict] = field(default_factory=list)