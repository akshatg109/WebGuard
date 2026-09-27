"""Passive technology indicators, independent of database persistence."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Mapping


class TechnologyCategory(StrEnum):
    WEB_SERVER = "web_server"
    FRAMEWORK = "framework"
    CMS = "cms"
    RUNTIME = "runtime"
    PLATFORM = "platform"
    LIBRARY = "library"


class TechnologyConfidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True, slots=True)
class Technology:
    name: str
    category: TechnologyCategory
    confidence: TechnologyConfidence
    evidence: tuple[str, ...]
    metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.name or not self.evidence:
            raise ValueError("Technology observations require a name and evidence.")
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "category": self.category.value,
            "confidence": self.confidence.value,
            "evidence": list(self.evidence),
            "metadata": dict(self.metadata),
        }
