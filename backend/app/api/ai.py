"""Authenticated, opt-in AI summaries and finding explanations."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from pydantic import ValidationError

from app.ai import AI_PROMPT_VERSION
from app.ai.contracts import (
    AiGenerationRequest,
    AiFindingInput,
    FindingAiOutput,
    ScanSummaryAiOutput,
)
from app.ai.provider import AiProvider, AiProviderError
from app.ai.sanitize import finding_input, scan_finding_inputs
from app.api.auth import AuthenticatedUser, get_authenticated_user
from app.api.errors import ApiError
from app.api.rate_limit import InMemoryPerUserRateLimiter
from app.api.schemas import AiExplanationResponse, AiSummaryResponse
from app.api.service_auth import require_scanner_service_token
from app.persistence.ai import AiRepository

router = APIRouter(
    prefix="/api/scans",
    tags=["AI guidance"],
    dependencies=[Depends(require_scanner_service_token)],
)

_MAX_AI_FINDINGS = 50
_MAX_AI_INPUT_BYTES = 64 * 1024


@router.post(
    "/{scan_id}/ai/summary",
    response_model=AiSummaryResponse,
    responses={
        401: {"description": "Valid scanner service credential and Supabase access token required."},
        404: {"description": "The scan was not found in this account."},
        409: {"description": "AI guidance is available only after a completed scan."},
        429: {"description": "The per-user AI generation limit was exceeded."},
        503: {"description": "AI provider or AI persistence is unavailable."},
    },
)
async def generate_scan_summary(
    scan_id: UUID,
    payload: AiGenerationRequest,
    request: Request,
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> AiSummaryResponse:
    repository: AiRepository = request.app.state.ai_repository
    context = await _get_owned_context(repository, str(scan_id), user.id)
    inputs = _completed_scan_inputs(context)
    data = [item.model_dump(mode="json") for item in inputs]
    evidence_hash = _input_hash(data)

    cached = await _read_summary_cache(repository, str(scan_id))
    if not payload.regenerate and _cache_matches(cached, evidence_hash):
        result = _summary_response(cached, cached=True)
        if result is not None:
            return result

    provider: AiProvider | None = request.app.state.ai_provider
    if provider is None:
        raise ApiError(503, "ai_unavailable", "AI guidance is not configured for this WebGuard instance.")
    await _consume_ai_budget_async(request, user.id)

    try:
        generated = await provider.generate_json(task="scan_summary", data={"findings": data})
        content = ScanSummaryAiOutput.model_validate(generated)
    except AiProviderError:
        raise ApiError(502, "ai_provider_failure", "AI guidance could not be generated right now.") from None
    except (ValidationError, ValueError, TypeError):
        raise ApiError(502, "ai_invalid_response", "AI guidance returned an invalid response.") from None

    try:
        row = await repository.save_summary(
            scan_id=str(scan_id),
            evidence_hash=evidence_hash,
            prompt_version=AI_PROMPT_VERSION,
            content=content.model_dump(mode="json"),
            provider=provider.name,
            model=provider.model,
        )
    except Exception:
        raise ApiError(503, "ai_persistence_failure", "AI guidance could not be saved right now.") from None
    result = _summary_response(row, cached=False)
    if result is None:
        raise ApiError(503, "ai_persistence_failure", "AI guidance could not be saved right now.")
    return result


@router.post(
    "/{scan_id}/findings/{finding_id}/ai/explanation",
    response_model=AiExplanationResponse,
    responses={
        401: {"description": "Valid scanner service credential and Supabase access token required."},
        404: {"description": "The scan or finding was not found in this account."},
        409: {"description": "AI guidance is available only after a completed scan."},
        429: {"description": "The per-user AI generation limit was exceeded."},
        503: {"description": "AI provider or AI persistence is unavailable."},
    },
)
async def explain_finding(
    scan_id: UUID,
    finding_id: UUID,
    payload: AiGenerationRequest,
    request: Request,
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> AiExplanationResponse:
    repository: AiRepository = request.app.state.ai_repository
    context = await _get_owned_context(repository, str(scan_id), user.id)
    finding, check_result = _owned_finding(context, str(finding_id))
    prompt_input = finding_input(finding, check_result)
    data = prompt_input.model_dump(mode="json")
    evidence_hash = _input_hash(data)

    cached = await _read_explanation_cache(repository, str(scan_id), str(finding_id))
    if not payload.regenerate and _cache_matches(cached, evidence_hash):
        result = _explanation_response(cached, str(finding_id), cached=True)
        if result is not None:
            return result

    provider: AiProvider | None = request.app.state.ai_provider
    if provider is None:
        raise ApiError(503, "ai_unavailable", "AI guidance is not configured for this WebGuard instance.")
    await _consume_ai_budget_async(request, user.id)

    try:
        generated = await provider.generate_json(task="finding_explanation", data={"finding": data})
        content = FindingAiOutput.model_validate(generated)
    except AiProviderError:
        raise ApiError(502, "ai_provider_failure", "AI guidance could not be generated right now.") from None
    except (ValidationError, ValueError, TypeError):
        raise ApiError(502, "ai_invalid_response", "AI guidance returned an invalid response.") from None

    # The observed-evidence section remains deterministic and comes directly
    # from the scanner, never from generated model text.
    deterministic_content = content.model_dump(mode="json")
    deterministic_content["observed_evidence"] = _deterministic_evidence_text(prompt_input)
    try:
        row = await repository.save_explanation(
            scan_id=str(scan_id),
            finding_id=str(finding_id),
            evidence_hash=evidence_hash,
            prompt_version=AI_PROMPT_VERSION,
            content=deterministic_content,
            provider=provider.name,
            model=provider.model,
        )
    except Exception:
        raise ApiError(503, "ai_persistence_failure", "AI guidance could not be saved right now.") from None
    result = _explanation_response(row, str(finding_id), cached=False)
    if result is None:
        raise ApiError(503, "ai_persistence_failure", "AI guidance could not be saved right now.")
    return result


async def cached_ai_response(
    repository: AiRepository,
    scan_id: str,
    user_id: str,
) -> dict[str, object]:
    """Read generated content for a report without making a provider call."""
    try:
        bundle = await repository.get_cached_bundle(scan_id, user_id)
    except Exception:
        # An unapplied optional AI migration must not break deterministic reports.
        return {"ai_summary": None, "ai_explanations": []}
    if bundle is None:
        return {"ai_summary": None, "ai_explanations": []}

    summary = _summary_response(bundle.get("summary"), cached=True)
    if summary is not None and summary.prompt_version != AI_PROMPT_VERSION:
        summary = None
    explanations: list[dict[str, object]] = []
    for row in bundle.get("explanations", []):
        if not isinstance(row, Mapping):
            continue
        finding_id = str(row.get("finding_id", ""))
        result = _explanation_response(row, finding_id, cached=True)
        if result is not None and result.prompt_version == AI_PROMPT_VERSION:
            explanations.append(result.model_dump(mode="json"))
    return {
        "ai_summary": summary.model_dump(mode="json") if summary is not None else None,
        "ai_explanations": explanations,
    }


async def _get_owned_context(
    repository: AiRepository,
    scan_id: str,
    user_id: str,
) -> Mapping[str, Any]:
    try:
        context = await repository.get_owned_scan_context(scan_id, user_id)
    except Exception:
        raise ApiError(503, "persistence_failure", "Scan findings are temporarily unavailable.") from None
    if context is None:
        raise ApiError(404, "scan_not_found", "The requested scan was not found.")
    if context.get("scan", {}).get("status") != "completed":
        raise ApiError(409, "ai_scan_not_complete", "AI guidance is available only after a completed scan.")
    return context


def _completed_scan_inputs(context: Mapping[str, Any]):
    findings = context.get("findings")
    checks = context.get("check_results")
    if not isinstance(findings, list) or not findings:
        raise ApiError(503, "persistence_failure", "Scan findings are temporarily unavailable.")
    if len(findings) > _MAX_AI_FINDINGS:
        raise ApiError(503, "ai_input_too_large", "AI guidance is unavailable for this scan's finding set.")
    if not isinstance(checks, list):
        checks = []
    try:
        return scan_finding_inputs(findings, checks)
    except (ValidationError, ValueError, TypeError):
        raise ApiError(503, "persistence_failure", "Scan findings are temporarily unavailable.") from None


def _owned_finding(
    context: Mapping[str, Any],
    finding_id: str,
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    findings = context.get("findings", [])
    finding = next(
        (row for row in findings if isinstance(row, Mapping) and str(row.get("id")) == finding_id),
        None,
    )
    if finding is None:
        raise ApiError(404, "ai_finding_not_found", "The requested finding was not found in this scan.")
    checks = context.get("check_results", [])
    result = next(
        (
            row for row in checks
            if isinstance(row, Mapping) and row.get("check_id") == finding.get("check_id")
        ),
        {},
    )
    explanation = result.get("score_explanation") if isinstance(result, Mapping) else None
    return finding, explanation if isinstance(explanation, Mapping) else {}


async def _consume_ai_budget_async(request: Request, user_id: str) -> None:
    limiter: InMemoryPerUserRateLimiter = request.app.state.ai_rate_limiter
    retry_after = await limiter.consume(user_id)
    if retry_after is not None:
        raise ApiError(
            429,
            "ai_rate_limit_exceeded",
            "The AI guidance limit has been reached. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )


def _input_hash(data: object) -> str:
    encoded = json.dumps(data, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > _MAX_AI_INPUT_BYTES:
        raise ApiError(503, "ai_input_too_large", "AI guidance is unavailable for this finding data.")
    versioned = f"{AI_PROMPT_VERSION}\n{encoded}".encode("utf-8")
    return hashlib.sha256(versioned).hexdigest()


def _deterministic_evidence_text(finding: AiFindingInput) -> str:
    """Serialize safe scanner evidence without cutting a JSON value mid-stream."""
    data: dict[str, object] = {"summary": finding.summary, "evidence": {}}
    safe_evidence = finding.evidence
    output = data["evidence"]
    assert isinstance(output, dict)
    for key, value in sorted(safe_evidence.items()):
        output[key] = value
        candidate = json.dumps(data, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        if len(candidate) > 1_000:
            del output[key]
            data["evidence_truncated"] = True
            break
    return json.dumps(data, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


async def _read_summary_cache(repository: AiRepository, scan_id: str) -> Mapping[str, Any] | None:
    try:
        return await repository.get_cached_summary(scan_id)
    except Exception:
        raise ApiError(503, "ai_persistence_failure", "AI guidance storage is unavailable.") from None


async def _read_explanation_cache(
    repository: AiRepository, scan_id: str, finding_id: str
) -> Mapping[str, Any] | None:
    try:
        return await repository.get_cached_explanation(scan_id, finding_id)
    except Exception:
        raise ApiError(503, "ai_persistence_failure", "AI guidance storage is unavailable.") from None


def _cache_matches(row: Mapping[str, Any] | None, evidence_hash: str) -> bool:
    return bool(
        row
        and row.get("evidence_hash") == evidence_hash
        and row.get("prompt_version") == AI_PROMPT_VERSION
    )


def _summary_response(row: object, *, cached: bool) -> AiSummaryResponse | None:
    if not isinstance(row, Mapping):
        return None
    try:
        content = ScanSummaryAiOutput.model_validate(row.get("summary"))
        return AiSummaryResponse(
            generated_at=str(row["generated_at"]),
            provider=str(row["provider"]),
            model=str(row["model"]),
            prompt_version=str(row["prompt_version"]),
            cached=cached,
            content=content.model_dump(mode="json"),
        )
    except (KeyError, ValidationError, ValueError, TypeError):
        return None


def _explanation_response(
    row: object,
    finding_id: str,
    *,
    cached: bool,
) -> AiExplanationResponse | None:
    if not isinstance(row, Mapping):
        return None
    try:
        canonical_finding_id = str(UUID(finding_id))
        content = FindingAiOutput.model_validate(row.get("explanation"))
        return AiExplanationResponse(
            finding_id=canonical_finding_id,
            generated_at=str(row["generated_at"]),
            provider=str(row["provider"]),
            model=str(row["model"]),
            prompt_version=str(row["prompt_version"]),
            cached=cached,
            content=content.model_dump(mode="json"),
        )
    except (KeyError, ValidationError, ValueError, TypeError):
        return None
