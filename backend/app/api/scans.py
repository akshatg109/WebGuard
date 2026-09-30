"""Authenticated synchronous scan creation and owned-result retrieval."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from app.api.ai import cached_ai_response
from app.api.auth import AuthenticatedUser, get_authenticated_user
from app.api.errors import ApiError
from app.api.rate_limit import InMemoryScanRateLimiter
from app.api.schemas import (
    ScanCreateRequest,
    ScanFailureResponse,
    ScanListResponse,
    ScanResponse,
    ScanSummaryResponse,
    SeverityCounts,
)
from app.api.service_auth import require_scanner_service_token
from app.api.serialization import (
    api_check_result,
    api_finding_from_row,
    api_technology_from_row,
    finding_dict,
    score_persistence_fields,
    safe_url,
)
from app.persistence.scans import ScanRepository
from app.scanner.checks.registry import run_security_checks
from app.scanner.errors import ScannerError, ScannerErrorCode
from app.scanner.models import ScanStatus
from app.scanner.scoring import score_findings
from app.scanner.url_validator import validate_target_url

router = APIRouter(
    prefix="/api/scans",
    tags=["scans"],
    dependencies=[Depends(require_scanner_service_token)],
    responses={
        401: {"description": "Valid scanner service credential and Supabase access token required."},
        503: {"description": "Scanner service is not configured or temporarily unavailable."},
    },
)

_SCANNER_FAILURES: dict[ScannerErrorCode, tuple[int, str]] = {
    ScannerErrorCode.BLOCKED_DESTINATION: (422, "blocked_target"),
    ScannerErrorCode.UNSAFE_REDIRECT: (422, "blocked_target"),
    ScannerErrorCode.DNS_RESOLUTION_FAILED: (502, "network_failure"),
    ScannerErrorCode.CONNECTION_FAILED: (502, "network_failure"),
    ScannerErrorCode.TIMEOUT: (504, "timeout"),
}
_SAFE_FAILURE_MESSAGES = {
    "invalid_target": "The target URL is invalid or not allowed.",
    "blocked_target": "The target is not allowed by scanner policy.",
    "network_failure": "The target could not be reached safely.",
    "timeout": "The target request exceeded a configured time limit.",
    "scanner_error": "The scanner could not complete this request safely.",
    "persistence_failure": "Scan results could not be saved.",
}


@router.get("", response_model=ScanListResponse)
async def list_scans(
    request: Request,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=100_000),
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> ScanListResponse:
    """Return a bounded, verified-user-only scan history page."""
    repository: ScanRepository = request.app.state.scan_repository
    try:
        result = await repository.list_owned_summaries(user.id, limit=limit, offset=offset)
    except Exception:
        raise ApiError(503, "persistence_failure", "Scan history is temporarily unavailable.") from None

    items = [
        ScanSummaryResponse(
            id=str(row["id"]),
            target_url=safe_url(str(row.get("target_url", ""))),
            normalized_url=(
                safe_url(str(row["normalized_url"]))
                if row.get("normalized_url")
                else None
            ),
            status=row["status"],
            score=row.get("score"),
            score_available=bool(row.get("score_available", False)),
            confidence=row.get("confidence"),
            created_at=str(row.get("created_at") or ""),
            completed_at=(str(row["completed_at"]) if row.get("completed_at") else None),
            duration_ms=row.get("duration_ms"),
            finding_count=row.get("finding_count"),
            severity_counts=(
                SeverityCounts(**row["severity_counts"])
                if row.get("severity_counts") is not None
                else None
            ),
        )
        for row in result.get("items", [])
    ]
    return ScanListResponse(
        items=items,
        total=int(result.get("total", 0)),
        limit=limit,
        offset=offset,
    )


@router.post(
    "",
    response_model=ScanResponse | ScanFailureResponse,
    status_code=201,
    responses={
        401: {"description": "Valid Supabase access token required."},
        422: {"description": "Invalid or blocked target."},
        429: {"description": "Per-user scan creation limit exceeded."},
    },
)
async def create_scan(
    payload: ScanCreateRequest,
    request: Request,
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> ScanResponse | JSONResponse:
    limiter: InMemoryScanRateLimiter = request.app.state.scan_rate_limiter
    retry_after = await limiter.consume(user.id)
    if retry_after is not None:
        raise ApiError(
            429,
            "rate_limit_exceeded",
            "The scan creation limit has been reached. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )

    scanner = request.app.state.scanner_service
    try:
        target = validate_target_url(payload.url, scanner.settings)
    except ScannerError as exc:
        status, code = (
            (422, "blocked_target")
            if exc.code == ScannerErrorCode.BLOCKED_DESTINATION
            else (422, "invalid_target")
        )
        message = (
            "The target is not allowed by scanner policy."
            if code == "blocked_target"
            else "The target URL is invalid or not allowed."
        )
        raise ApiError(status, code, message) from None

    repository: ScanRepository = request.app.state.scan_repository
    display_url = safe_url(target.normalized_url)
    try:
        scan_row = await repository.create_pending(user.id, display_url)
        scan_id = str(UUID(str(scan_row["id"])))
    except Exception:
        raise ApiError(503, "persistence_failure", "The scan could not be started right now.") from None

    started = time.monotonic()
    try:
        await repository.mark_running(scan_id, user.id, target.normalized_url)
    except Exception:
        return await _persist_failure_response(
            repository,
            scan_id,
            user.id,
            display_url,
            started,
        )

    try:
        context = await scanner.fetch(payload.url)
    except ScannerError as exc:
        status_code, code = _SCANNER_FAILURES.get(exc.code, (500, "scanner_error"))
        return await _failure_response(
            repository, scan_id, user.id, display_url, started,
            status_code=status_code, code=code,
        )
    except (asyncio.TimeoutError, TimeoutError):
        return await _failure_response(
            repository, scan_id, user.id, display_url, started,
            status_code=504, code="timeout",
        )
    except Exception:
        return await _failure_response(
            repository, scan_id, user.id, display_url, started,
            status_code=500, code="scanner_error",
        )

    context.scan_id = scan_id
    if context.error is not None:
        status_code, code = _SCANNER_FAILURES.get(context.error.code, (500, "scanner_error"))
        return await _failure_response(
            repository, scan_id, user.id, display_url, started,
            status_code=status_code, code=code,
        )
    if context.status != ScanStatus.COMPLETED or context.http_status is None:
        return await _failure_response(
            repository, scan_id, user.id, display_url, started,
            status_code=500, code="scanner_error",
        )

    try:
        findings = run_security_checks(context)
        score = score_findings(findings)
        response = _build_response(
            scan={
                "id": scan_id,
                "target_url": display_url,
                "normalized_url": safe_url(context.normalized_url or target.normalized_url),
                "status": "completed",
                "created_at": scan_row.get("created_at"),
                "completed_at": None,
                **score_persistence_fields(score),
                "error_code": None,
                "error_message": None,
            },
            findings=[finding_dict(finding) for finding in findings],
            technologies=_technologies_from_findings(findings),
            check_results=_checks_from_findings(findings, score),
        )
        response.ai_available = request.app.state.ai_provider is not None
    except Exception:
        return await _failure_response(
            repository, scan_id, user.id, display_url, started,
            status_code=500, code="scanner_error",
        )

    duration_ms = max(0, int((time.monotonic() - started) * 1_000))
    response.duration_ms = duration_ms
    try:
        await repository.persist_completed(
            scan_id=scan_id,
            user_id=user.id,
            normalized_url=context.normalized_url or target.normalized_url,
            duration_ms=duration_ms,
            findings=findings,
            score=score,
        )
    except Exception:
        # The restricted RPC is atomic; a persistence error cannot publish a
        # partially written result or falsely claim completion.
        return await _persist_failure_response(
            repository, scan_id, user.id, display_url, started
        )
    response.completed_at = datetime.now(UTC).isoformat()
    return response


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    request: Request,
    scan_id: UUID,
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> ScanResponse:
    repository: ScanRepository = request.app.state.scan_repository
    try:
        bundle = await repository.get_owned_bundle(str(scan_id), user.id)
    except Exception:
        raise ApiError(503, "persistence_failure", "Scan results are temporarily unavailable.") from None
    if bundle is None:
        raise ApiError(404, "scan_not_found", "The requested scan was not found.")
    response = _response_from_bundle(bundle)
    response.ai_available = request.app.state.ai_provider is not None
    ai_content = await cached_ai_response(request.app.state.ai_repository, str(scan_id), user.id)
    response.ai_summary = ai_content["ai_summary"]
    response.ai_explanations = ai_content["ai_explanations"]
    return response


async def _persist_failure_response(
    repository: ScanRepository,
    scan_id: str,
    user_id: str,
    target_url: str,
    started: float,
) -> JSONResponse:
    code = "persistence_failure"
    message = "Scan results could not be saved."
    try:
        await _mark_failed(
            repository,
            scan_id,
            user_id,
            code=code,
            message=message,
            started=started,
        )
    except Exception:
        # The original failure is intentionally not logged or returned. The row
        # can remain pending/running only if Supabase itself is unreachable.
        pass
    return JSONResponse(
        status_code=500,
        content={
            "id": scan_id,
            "target_url": target_url,
            "status": "failed",
            "error": {"code": code, "message": message},
        },
    )


async def _mark_failed(
    repository: ScanRepository,
    scan_id: str,
    user_id: str,
    *,
    code: str,
    message: str,
    started: float,
) -> None:
    await repository.mark_failed(
        scan_id,
        user_id,
        error_code=code,
        error_message=message,
        duration_ms=max(0, int((time.monotonic() - started) * 1_000)),
    )


async def _failure_response(
    repository: ScanRepository,
    scan_id: str,
    user_id: str,
    target_url: str,
    started: float,
    *,
    status_code: int,
    code: str,
) -> JSONResponse:
    message = _SAFE_FAILURE_MESSAGES[code]
    try:
        await _mark_failed(
            repository,
            scan_id,
            user_id,
            code=code,
            message=message,
            started=started,
        )
    except Exception:
        return await _persist_failure_response(
            repository, scan_id, user_id, target_url, started
        )
    return JSONResponse(
        status_code=status_code,
        content={
            "id": scan_id,
            "target_url": target_url,
            "status": "failed",
            "error": {"code": code, "message": message},
        },
    )


def _build_response(
    *,
    scan: Mapping[str, Any],
    findings: list[Mapping[str, Any]],
    technologies: list[Mapping[str, Any]],
    check_results: list[Mapping[str, Any]],
) -> ScanResponse:
    status = str(scan.get("status", "failed"))
    safe_findings = [dict(item) for item in findings]
    score_available = bool(scan.get("score_available", False))
    score = scan.get("score")
    if status == "completed":
        summary = (
            f"{len(safe_findings)} security checks completed; WebGuard configuration score: "
            f"{score}/100. This is not a guarantee of security."
            if score_available
            else "Scan completed; the score is unavailable because evidence coverage requirements were not met."
        )
    elif status == "failed":
        summary = "The scan failed; no score is available."
    elif status == "running":
        summary = "The scan is running."
    else:
        summary = "The scan is pending."

    error_code = scan.get("error_code")
    # Never echo persisted error text. Older rows may predate the safe failure
    # vocabulary and could contain implementation details.
    error_message = _SAFE_FAILURE_MESSAGES.get(str(error_code))
    return ScanResponse(
        id=str(scan["id"]),
        target_url=safe_url(str(scan.get("target_url", ""))),
        normalized_url=(
            safe_url(str(scan["normalized_url"]))
            if scan.get("normalized_url")
            else None
        ),
        status=status,  # validated by the response model
        created_at=(str(scan["created_at"]) if scan.get("created_at") else None),
        completed_at=(str(scan["completed_at"]) if scan.get("completed_at") else None),
        duration_ms=scan.get("duration_ms"),
        score=score,
        score_available=score_available,
        confidence=scan.get("score_confidence"),
        scoring_version=scan.get("scoring_version"),
        score_unavailability_reasons=list(
            (scan.get("score_details") or {}).get("unavailability_reasons", [])
        ),
        score_details=dict(scan.get("score_details") or {}),
        summary=summary,
        findings=safe_findings,
        technologies=[dict(item) for item in technologies],
        check_results=[dict(item) for item in check_results],
        error=(
            {"code": error_code, "message": error_message}
            if error_code and error_message
            else None
        ),
    )


def _response_from_bundle(bundle: Mapping[str, Any]) -> ScanResponse:
    scan = dict(bundle["scan"])
    details = scan.get("score_details") or {}
    check_rows = [api_check_result(row) for row in bundle.get("check_results", [])]
    return _build_response(
        scan={**scan, "score_details": details},
        findings=[api_finding_from_row(row) for row in bundle.get("findings", [])],
        technologies=[api_technology_from_row(row) for row in bundle.get("technologies", [])],
        check_results=check_rows,
    )


def _checks_from_findings(findings: tuple[Any, ...], score: Any) -> list[dict[str, object]]:
    from app.api.serialization import check_result_persistence_rows

    return [api_check_result(row) for row in check_result_persistence_rows(findings, score)]


def _technologies_from_findings(findings: tuple[Any, ...]) -> list[dict[str, object]]:
    from app.api.serialization import technology_persistence_rows

    return [
        {
            "name": row["name"],
            "category": row["category"],
            "confidence": row["confidence_label"],
            "evidence": row["evidence"],
        }
        for row in technology_persistence_rows(findings)
    ]
