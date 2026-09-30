"""Supabase persistence adapter for owned scans and atomic result completion."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID

from app.api.serialization import (
    check_result_persistence_rows,
    finding_persistence_row,
    safe_url,
    score_persistence_fields,
    technology_persistence_rows,
)
from app.scanner.findings import Finding
from app.scanner.scoring import ScoreResult


class ScanRepository(Protocol):
    async def create_pending(self, user_id: str, target_url: str) -> Mapping[str, Any]: ...

    async def mark_running(self, scan_id: str, user_id: str, normalized_url: str) -> None: ...

    async def persist_completed(
        self,
        *,
        scan_id: str,
        user_id: str,
        normalized_url: str,
        duration_ms: int,
        findings: tuple[Finding, ...],
        score: ScoreResult,
    ) -> None: ...

    async def mark_failed(
        self,
        scan_id: str,
        user_id: str,
        *,
        error_code: str,
        error_message: str,
        duration_ms: int,
    ) -> None: ...

    async def get_owned_bundle(self, scan_id: str, user_id: str) -> Mapping[str, Any] | None: ...

    async def list_owned_summaries(
        self, user_id: str, *, limit: int, offset: int
    ) -> Mapping[str, Any]: ...


class PersistenceUnavailable(RuntimeError):
    """Raised when the backend has no privileged Supabase client configured."""


class SupabaseScanRepository:
    """Use the server-only service client; caller IDs come from verified Auth."""

    def __init__(self, supabase_client: object | None) -> None:
        self._client = supabase_client

    def _require_client(self) -> Any:
        if self._client is None:
            raise PersistenceUnavailable()
        return self._client

    async def create_pending(self, user_id: str, target_url: str) -> Mapping[str, Any]:
        client = self._require_client()
        response = await (
            client.table("scans")
            .insert(
                {
                    "user_id": str(UUID(user_id)),
                    "target_url": safe_url(target_url),
                    "status": "pending",
                    "score_available": False,
                    "score_details": {},
                }
            )
            .select("id,user_id,target_url,status,created_at")
            .single()
            .execute()
        )
        if not isinstance(response.data, Mapping):
            raise RuntimeError("Scan creation returned no row.")
        return response.data

    async def mark_running(self, scan_id: str, user_id: str, normalized_url: str) -> None:
        client = self._require_client()
        response = await (
            client.table("scans")
            .update(
                {
                    "status": "running",
                    "normalized_url": safe_url(normalized_url),
                    "started_at": datetime.now(UTC).isoformat(),
                }
            )
            .eq("id", str(UUID(scan_id)))
            .eq("user_id", str(UUID(user_id)))
            .eq("status", "pending")
            .select("id")
            .execute()
        )
        if not response.data:
            raise RuntimeError("Scan lifecycle update returned no row.")

    async def persist_completed(
        self,
        *,
        scan_id: str,
        user_id: str,
        normalized_url: str,
        duration_ms: int,
        findings: tuple[Finding, ...],
        score: ScoreResult,
    ) -> None:
        client = self._require_client()
        score_fields = score_persistence_fields(score)
        params = {
            "p_scan_id": str(UUID(scan_id)),
            "p_user_id": str(UUID(user_id)),
            "p_normalized_url": safe_url(normalized_url),
            "p_score": score_fields["score"],
            "p_score_available": score_fields["score_available"],
            "p_scoring_version": score_fields["scoring_version"],
            "p_score_confidence": score_fields["score_confidence"],
            "p_score_details": score_fields["score_details"],
            "p_completed_at": datetime.now(UTC).isoformat(),
            "p_duration_ms": max(0, duration_ms),
            "p_findings": [finding_persistence_row(finding) for finding in findings],
            "p_technologies": technology_persistence_rows(findings),
            "p_check_results": check_result_persistence_rows(findings, score),
        }
        # This restricted Postgres RPC inserts children and changes state to
        # completed in one transaction. A failure leaves the scan running so the
        # caller can safely mark it failed without publishing partial results.
        await client.rpc("persist_completed_scan", params).execute()

    async def mark_failed(
        self,
        scan_id: str,
        user_id: str,
        *,
        error_code: str,
        error_message: str,
        duration_ms: int,
    ) -> None:
        client = self._require_client()
        response = await (
            client.table("scans")
            .update(
                {
                    "status": "failed",
                    "completed_at": datetime.now(UTC).isoformat(),
                    "duration_ms": max(0, duration_ms),
                    "error_code": error_code,
                    "error_message": error_message,
                    "score": None,
                    "score_available": False,
                    "scoring_version": None,
                    "score_confidence": None,
                    "score_details": {},
                }
            )
            .eq("id", str(UUID(scan_id)))
            .eq("user_id", str(UUID(user_id)))
            .neq("status", "completed")
            .select("id")
            .execute()
        )
        if not response.data:
            raise RuntimeError("Scan failure state was not persisted.")

    async def get_owned_bundle(self, scan_id: str, user_id: str) -> Mapping[str, Any] | None:
        client = self._require_client()
        canonical_scan_id = str(UUID(scan_id))
        canonical_user_id = str(UUID(user_id))
        scan_response = await (
            client.table("scans")
            .select("*")
            .eq("id", canonical_scan_id)
            .eq("user_id", canonical_user_id)
            .limit(1)
            .execute()
        )
        scan_rows = scan_response.data or []
        if not scan_rows:
            return None
        scan = scan_rows[0]

        # The ownership predicate above is deliberately performed before reading
        # any child table, even though RLS independently protects these rows.
        findings_response, technologies_response, checks_response = await _execute_children(
            client, canonical_scan_id
        )
        return {
            "scan": scan,
            "findings": findings_response.data or [],
            "technologies": technologies_response.data or [],
            "check_results": checks_response.data or [],
        }

    async def list_owned_summaries(
        self, user_id: str, *, limit: int, offset: int
    ) -> Mapping[str, Any]:
        """Return a bounded list of summaries after applying the verified owner filter."""
        client = self._require_client()
        canonical_user_id = str(UUID(user_id))
        response = await (
            client.table("scans")
            .select(
                "id,target_url,normalized_url,status,score,score_available,score_confidence,"
                "created_at,completed_at,duration_ms",
                count="exact",
            )
            .eq("user_id", canonical_user_id)
            .order("created_at", desc=True)
            .range(offset, offset + limit - 1)
            .execute()
        )
        scans = response.data or []
        scan_ids = [str(UUID(str(row["id"]))) for row in scans]
        findings_by_scan: dict[str, list[Mapping[str, Any]]] = {
            scan_id: [] for scan_id in scan_ids
        }
        if scan_ids:
            finding_response = await (
                client.table("findings")
                .select("scan_id,severity,status")
                .in_("scan_id", scan_ids)
                .execute()
            )
            for finding in finding_response.data or []:
                scan_id = str(finding.get("scan_id", ""))
                if scan_id in findings_by_scan:
                    findings_by_scan[scan_id].append(finding)

        summaries: list[dict[str, Any]] = []
        for row in scans:
            scan_id = str(UUID(str(row["id"])))
            status = row.get("status")
            severity_counts = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "informational": 0,
            }
            actionable_findings = 0
            if status == "completed":
                for finding in findings_by_scan[scan_id]:
                    if finding.get("status") not in {"fail", "warn", "error"}:
                        continue
                    severity = finding.get("severity")
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                        actionable_findings += 1
            summaries.append(
                {
                    "id": scan_id,
                    "target_url": safe_url(row.get("target_url")),
                    "normalized_url": safe_url(row.get("normalized_url")),
                    "status": status,
                    "score": row.get("score"),
                    "score_available": bool(row.get("score_available", False)),
                    "confidence": row.get("score_confidence"),
                    "created_at": row.get("created_at"),
                    "completed_at": row.get("completed_at"),
                    "duration_ms": row.get("duration_ms"),
                    "finding_count": actionable_findings if status == "completed" else None,
                    "severity_counts": severity_counts if status == "completed" else None,
                }
            )
        return {"items": summaries, "total": response.count or 0}


async def _execute_children(client: Any, scan_id: str) -> tuple[Any, Any, Any]:
    import asyncio

    return tuple(
        await asyncio.gather(
            client.table("findings").select("*").eq("scan_id", scan_id).order("created_at").execute(),
            client.table("technologies").select("*").eq("scan_id", scan_id).order("created_at").execute(),
            client.table("scan_check_results").select("*").eq("scan_id", scan_id).order("created_at").execute(),
        )
    )
