from dataclasses import dataclass


@dataclass
class Component:
    name: str
    version: str | None
    ecosystem: str
    type: str
    purl: str