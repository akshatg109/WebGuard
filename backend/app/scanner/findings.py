"""Typed, stable finding vocabulary for deterministic scanner checks."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import re
from types import MappingProxyType
from typing import Mapping
from urllib.parse import urlsplit, urlunsplit


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class FindingStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


class FindingCategory(StrEnum):
    TRANSPORT = "transport"
    HEADERS = "headers"
    EXPOSURE = "exposure"
    COOKIES = "cookies"
    CONTENT = "content"
    TECHNOLOGY = "technology"


Evidence = Mapping[str, object]
_CHECK_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_.]*$")


@dataclass(frozen=True, slots=True)
class Finding:
    check_id: str
    title: str
    severity: Severity
    category: FindingCategory
    status: FindingStatus
    summary: str
    why_it_matters: str
    evidence: Evidence
    remediation: str
    affected_url: str
    metadata: Evidence = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not _CHECK_ID_PATTERN.fullmatch(self.check_id):
            raise ValueError("Finding check_id must be a stable lowercase identifier.")
        if not isinstance(self.severity, Severity):
            raise TypeError("Finding severity must use the controlled Severity enum.")
        if not isinstance(self.status, FindingStatus):
            raise TypeError("Finding status must use the controlled FindingStatus enum.")
        if not isinstance(self.category, FindingCategory):
            raise TypeError("Finding category must use the controlled FindingCategory enum.")
        if (
            not self.check_id
            or not self.title
            or not self.summary
            or not self.why_it_matters
            or not self.remediation
        ):
            raise ValueError("Findings require stable identifiers and non-empty descriptions.")
        object.__setattr__(self, "evidence", _freeze_mapping(self.evidence))
        object.__setattr__(self, "metadata", _freeze_mapping(self.metadata))

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly shape with controlled enum values."""
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "status": self.status.value,
            "summary": self.summary,
            "why_it_matters": self.why_it_matters,
            "evidence": _json_value(self.evidence),
            "remediation": self.remediation,
            "affected_url": self.affected_url,
            "metadata": _json_value(self.metadata),
        }


def affected_url_for_context(context: object) -> str:
    """Use the final URL without query parameters to avoid carrying query secrets."""
    current = getattr(context, "current_url", None)
    normalized = getattr(context, "normalized_url", None)
    # Never fall back to the raw requested URL: on a validation failure it could
    # contain userinfo. Current/normalized values are set only after validation.
    candidate = current or normalized or ""
    try:
        parts = urlsplit(candidate)
        if (
            parts.scheme not in {"http", "https"}
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
        ):
            return ""
        return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    except (TypeError, ValueError):
        return ""


def _json_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    if isinstance(value, StrEnum):
        return value.value
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"Unsupported finding evidence value type: {type(value).__name__}")


def _freeze_mapping(value: Mapping[str, object]) -> Mapping[str, object]:
    return MappingProxyType({key: _freeze_value(item) for key, item in value.items()})


def _freeze_value(value: object) -> object:
    if isinstance(value, Mapping):
        return _freeze_mapping(value)
    if isinstance(value, (tuple, list)):
        return tuple(_freeze_value(item) for item in value)
    if isinstance(value, StrEnum):
        return value
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"Unsupported finding evidence value type: {type(value).__name__}")
