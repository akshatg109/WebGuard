"""JSON-safe persistence and API serialization for scanner results."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from app.scanner.findings import Finding
from app.scanner.scoring import CHECKS_BY_ID, ScoreResult

_URL_TOKEN = re.compile(r"https?://[^\s\"'<>),]+", re.IGNORECASE)
_OMIT_EVIDENCE_KEYS = frozenset({"server_values", "x_powered_by_values"})
_NON_PUBLIC_HOSTS = frozenset({"localhost", "metadata", "metadata.google.internal", "instance-data.ec2.internal"})
_NON_PUBLIC_SUFFIXES = (".localhost", ".local", ".localdomain", ".internal", ".home.arpa")
_TECH_CONFIDENCE_NUMERIC = {"low": 0.4, "medium": 0.7, "high": 0.9}


def safe_url(value: str | None) -> str:
    """Remove query/userinfo and never return a non-public literal/host URL."""
    if not value:
        return ""
    try:
        parts = urlsplit(value)
        hostname = parts.hostname
        if parts.scheme not in {"http", "https"} or not hostname:
            return ""
        host = hostname.casefold().rstrip(".")
        if _is_non_public_host(host):
            return "[non-public destination redacted]"
        try:
            port = parts.port
        except ValueError:
            return ""
        rendered_host = f"[{host}]" if ":" in host else host
        netloc = rendered_host + (f":{port}" if port is not None else "")
        return urlunsplit((parts.scheme.casefold(), netloc, parts.path, "", ""))
    except (TypeError, ValueError):
        return ""


def _is_non_public_host(host: str) -> bool:
    if host in _NON_PUBLIC_HOSTS or host.endswith(_NON_PUBLIC_SUFFIXES):
        return True
    try:
        return not ipaddress.ip_address(host).is_global
    except ValueError:
        return False


def safe_value(value: object, *, key: str | None = None) -> object:
    """Recursively sanitize finding evidence/metadata before persistence/return."""
    if key is not None and key.casefold() in _OMIT_EVIDENCE_KEYS:
        return None
    if isinstance(value, Mapping):
        return {
            str(name): safe_value(item, key=str(name))
            for name, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            if str(name).casefold() not in _OMIT_EVIDENCE_KEYS
        }
    if isinstance(value, (tuple, list)):
        return [safe_value(item) for item in value]
    if isinstance(value, str):
        return _URL_TOKEN.sub(lambda match: safe_url(match.group(0).rstrip(".")), value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    raise TypeError(f"Unsupported scan result value: {type(value).__name__}")


def finding_dict(finding: Finding) -> dict[str, object]:
    data = finding.to_dict()
    data["affected_url"] = safe_url(finding.affected_url)
    data["evidence"] = safe_value(data["evidence"])
    data["metadata"] = safe_value(data["metadata"])
    return data


def finding_persistence_row(finding: Finding) -> dict[str, object]:
    data = finding_dict(finding)
    return {
        "check_id": data["check_id"],
        "title": data["title"],
        "severity": data["severity"],
        "status": data["status"],
        # The Phase 2 description/recommendation fields retain these meanings.
        "summary": data["summary"],
        "why_it_matters": data["why_it_matters"],
        "evidence": data["evidence"],
        "remediation": data["remediation"],
        "affected_url": data["affected_url"],
        "metadata": data["metadata"],
    }


def technology_persistence_rows(findings: tuple[Finding, ...]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    technology_finding = next(
        (finding for finding in findings if finding.check_id == "technology.passive_indicators"),
        None,
    )
    if technology_finding is None:
        return result
    raw_technologies = technology_finding.to_dict()["metadata"].get("technologies", [])
    if not isinstance(raw_technologies, list):
        return result
    for raw in raw_technologies:
        if not isinstance(raw, dict):
            continue
        confidence = raw.get("confidence")
        evidence = raw.get("evidence")
        if (
            not isinstance(raw.get("name"), str)
            or not isinstance(raw.get("category"), str)
            or confidence not in _TECH_CONFIDENCE_NUMERIC
            or not isinstance(evidence, list)
        ):
            continue
        result.append(
            {
                "name": raw["name"],
                "category": raw["category"],
                "confidence": _TECH_CONFIDENCE_NUMERIC[confidence],
                "confidence_label": confidence,
                "evidence": safe_value(evidence),
                "metadata": safe_value(raw.get("metadata", {})),
            }
        )
    return result


def score_persistence_fields(score: ScoreResult) -> dict[str, object]:
    details = score.to_dict()
    # Keep the scalar/availability/version fields and per-check explanations in
    # their dedicated columns/table rather than duplicate them in score_details.
    for key in ("score", "available", "scoring_version", "confidence", "checks"):
        details.pop(key, None)
    return {
        "score": score.score,
        "score_available": score.available,
        "scoring_version": score.scoring_version,
        "score_confidence": score.confidence.value,
        "score_details": details,
    }


def check_result_persistence_rows(
    findings: tuple[Finding, ...], score: ScoreResult
) -> list[dict[str, object]]:
    explanations = {item.check_id: item.to_dict() for item in score.checks}
    rows: list[dict[str, object]] = []
    for finding in findings:
        explanation = explanations.get(finding.check_id)
        if explanation is None:
            raise ValueError("The scoring result omitted a canonical scanner check.")
        rows.append(
            {
                "check_id": finding.check_id,
                "status": finding.status.value,
                "severity": finding.severity.value,
                "scoring_relevant": CHECKS_BY_ID[finding.check_id].is_score_bearing,
                "scoring_version": score.scoring_version,
                "check_version": CHECKS_BY_ID[finding.check_id].check_version,
                "reason": finding.summary,
                "evidence": safe_value(finding.to_dict()["evidence"]),
                "score_explanation": explanation,
            }
        )
    return rows


def api_check_result(row: Mapping[str, Any]) -> dict[str, object]:
    check_id = str(row.get("check_id", ""))
    return {
        "check_id": check_id,
        "status": row.get("status"),
        "severity": row.get("severity"),
        "scoring_relevant": bool(row.get("scoring_relevant", CHECKS_BY_ID.get(check_id).is_score_bearing if check_id in CHECKS_BY_ID else False)),
        "scoring_version": row.get("scoring_version"),
        "check_version": row.get("check_version"),
        "reason": row.get("reason", ""),
        "evidence": safe_value(row.get("evidence", {})),
        "score_explanation": safe_value(row.get("score_explanation", {})),
    }


def api_finding_from_row(row: Mapping[str, Any]) -> dict[str, object]:
    check_id = str(row.get("check_id", ""))
    return {
        "id": str(row["id"]) if row.get("id") is not None else None,
        "check_id": check_id,
        "title": row.get("title", ""),
        "category": CHECKS_BY_ID[check_id].category.value if check_id in CHECKS_BY_ID else "informational",
        "severity": row.get("severity"),
        "status": row.get("status"),
        "summary": row.get("description", ""),
        "why_it_matters": row.get("why_it_matters", ""),
        "evidence": safe_value(row.get("evidence") or {}),
        "remediation": row.get("recommendation", ""),
        "affected_url": safe_url(row.get("affected_url")),
        "metadata": safe_value(row.get("metadata") or {}),
    }


def api_technology_from_row(row: Mapping[str, Any]) -> dict[str, object]:
    return {
        "name": row.get("name", ""),
        "category": row.get("category", ""),
        "confidence": row.get("confidence_label") or _confidence_label(row.get("confidence")),
        "evidence": safe_value(row.get("evidence") or []),
    }


def _confidence_label(value: object) -> str | None:
    if not isinstance(value, (float, int)):
        return None
    if value >= 0.8:
        return "high"
    if value >= 0.5:
        return "medium"
    return "low"
