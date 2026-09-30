"""Bounded, defensive projection of persisted scanner findings for AI prompts."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from typing import Any

from app.ai.contracts import AiFindingInput
from app.scanner.scoring import CHECKS_BY_ID, LEGACY_CATALOG_RECONCILIATION

_DENIED_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "authorization",
        "auth_header",
        "body",
        "body_text",
        "cookie_value",
        "cookie_values",
        "cookies",
        "headers",
        "html",
        "internal_ip",
        "ip_address",
        "password",
        "raw_body",
        "raw_response_body",
        "raw_response_headers",
        "refresh_token",
        "response_body",
        "resolved_ip",
        "scanner_token",
        "secret",
        "server_values",
        "set_cookie",
        "set_cookie_values",
        "target_url",
        "token",
        "value",
        "values",
        "x_powered_by_values",
        "header_value",
        "header_values",
        "raw",
        "url",
        "urls",
        "affected_url",
        "normalized_url",
        "requested_url",
        "final_url",
        "source_url",
        "hostname",
        "host",
        "origin",
        "origins",
        "sanitized_reference_origins",
        "resource_origins",
        "http_origins",
        "redirect_chain",
        "redirect_destinations",
    }
)
_IPV4_CANDIDATE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6_CANDIDATE = re.compile(r"(?<![\w:])(?:[0-9a-f]{0,4}:){2,}[0-9a-f:]{0,}(?![\w:])", re.IGNORECASE)
_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_CREDENTIAL = re.compile(
    r"(?i)(\b(?:bearer|basic)\s+)[A-Za-z0-9._~+/=-]+|"
    r"\b(?:token|secret|password|api[_-]?key)\s*[:=]\s*[^\s,;]+"
)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")
_MAX_EVIDENCE_NODES = 100
_MAX_EVIDENCE_DEPTH = 4


def finding_input(
    row: Mapping[str, Any],
    score_explanation: Mapping[str, Any] | None = None,
) -> AiFindingInput:
    """Create a strict provider input without URLs, bodies, headers, or secrets."""
    check_id = _clean_text(row.get("check_id"), 80)
    canonical_check_id = LEGACY_CATALOG_RECONCILIATION.get(check_id, check_id)
    check = CHECKS_BY_ID.get(canonical_check_id)
    category = check.category.value if check is not None else "technology"
    scoring = _scoring_projection(score_explanation or {})
    return AiFindingInput.model_validate(
        {
            # The stable scanner check ID identifies the observation; the DB UUID,
            # target URL, owner ID, and scan ID are not needed by the model.
            "finding_id": check_id,
            "title": _clean_text(row.get("title"), 160),
            "category": category,
            "severity": row.get("severity"),
            "status": row.get("status"),
            "summary": _clean_text(row.get("description", row.get("summary")), 600),
            "why_it_matters": _clean_text(row.get("why_it_matters"), 600),
            "evidence": _safe_evidence(row.get("evidence") or {}),
            "remediation_hints": _clean_text(
                row.get("recommendation", row.get("remediation")), 800
            ),
            "scoring_impact": scoring,
        }
    )


def scan_finding_inputs(
    findings: list[Mapping[str, Any]],
    check_results: list[Mapping[str, Any]],
) -> list[AiFindingInput]:
    explanations = {
        str(result.get("check_id", "")): result.get("score_explanation")
        for result in check_results
        if isinstance(result.get("score_explanation"), Mapping)
    }
    return [finding_input(row, explanations.get(str(row.get("check_id", "")))) for row in findings]


def _scoring_projection(value: Mapping[str, Any]) -> dict[str, object]:
    allowed = ("state", "points_available", "deduction", "reason_code")
    return {
        key: cleaned
        for key in allowed
        if (cleaned := _safe_value(value.get(key), key=key, depth=0, budget=[_MAX_EVIDENCE_NODES])) is not None
    }


def _safe_evidence(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        return {}
    budget = [_MAX_EVIDENCE_NODES]
    result = _safe_value(value, key=None, depth=0, budget=budget)
    return result if isinstance(result, dict) else {}


def _safe_value(
    value: object,
    *,
    key: str | None,
    depth: int,
    budget: list[int],
) -> object | None:
    if budget[0] <= 0 or depth > _MAX_EVIDENCE_DEPTH:
        return None
    budget[0] -= 1
    normalized_key = key.casefold().replace("-", "_") if key else None
    if normalized_key in _DENIED_KEYS:
        return None
    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        for raw_key, child in list(value.items())[:40]:
            clean_key = _clean_text(raw_key, 80)
            if not clean_key:
                continue
            sanitized = _safe_value(child, key=clean_key, depth=depth + 1, budget=budget)
            if sanitized is not None:
                result[clean_key] = sanitized
        return result
    if isinstance(value, (list, tuple)):
        items: list[object] = []
        for child in value[:20]:
            sanitized = _safe_value(child, key=key, depth=depth + 1, budget=budget)
            if sanitized is not None:
                items.append(sanitized)
        return items
    if isinstance(value, str):
        return _clean_text(value, 240)
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return max(-1_000_000, min(value, 1_000_000))
    if isinstance(value, float):
        return value if value == value and abs(value) <= 1_000_000 else None
    return None


def _clean_text(value: object, max_length: int) -> str:
    if not isinstance(value, str):
        return ""
    text = " ".join("".join(char if char >= " " else " " for char in value).split())
    text = _URL.sub("[URL omitted]", text)
    text = _JWT.sub("[credential omitted]", text)
    text = _CREDENTIAL.sub("[credential omitted]", text)
    text = _IPV4_CANDIDATE.sub(_redact_ip, text)
    text = _IPV6_CANDIDATE.sub(_redact_ip, text)
    return text[:max_length]


def _redact_ip(match: re.Match[str]) -> str:
    candidate = match.group(0).strip("[]")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return match.group(0)
    return "[IP omitted]"
