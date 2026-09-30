"""Owner-filtered persistence and cache for generated AI guidance."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID

from app.persistence.scans import PersistenceUnavailable


class AiRepository(Protocol):
    async def get_owned_scan_context(self, scan_id: str, user_id: str) -> Mapping[str, Any] | None: ...

    async def get_cached_summary(self, scan_id: str) -> Mapping[str, Any] | None: ...

    async def get_cached_explanation(
        self, scan_id: str, finding_id: str
    ) -> Mapping[str, Any] | None: ...

    async def get_cached_bundle(self, scan_id: str, user_id: str) -> Mapping[str, Any] | None: ...

    async def save_summary(
        self, *, scan_id: str, evidence_hash: str, prompt_version: str,
        content: Mapping[str, Any], provider: str, model: str,
    ) -> Mapping[str, Any]: ...

    async def save_explanation(
        self, *, scan_id: str, finding_id: str, evidence_hash: str,
        prompt_version: str, content: Mapping[str, Any], provider: str, model: str,
    ) -> Mapping[str, Any]: ...


class SupabaseAiRepository:
    """Use the backend-only Supabase client and explicit scan/finding filters."""

    def __init__(self, supabase_client: object | None) -> None:
        self._client = supabase_client

    def _require_client(self) -> Any:
        if self._client is None:
            raise PersistenceUnavailable()
        return self._client

    async def get_owned_scan_context(self, scan_id: str, user_id: str) -> Mapping[str, Any] | None:
        client = self._require_client()
        canonical_scan_id = str(UUID(scan_id))
        canonical_user_id = str(UUID(user_id))
        scan_response = await (
            client.table("scans")
            .select("id,status")
            .eq("id", canonical_scan_id)
            .eq("user_id", canonical_user_id)
            .limit(1)
            .execute()
        )
        scan_rows = scan_response.data or []
        if not scan_rows:
            return None
        scan = scan_rows[0]
        if scan.get("status") != "completed":
            return {"scan": scan, "findings": [], "check_results": []}

        findings_response, check_response = await asyncio.gather(
            client.table("findings")
            .select(
                "id,scan_id,check_id,title,severity,status,description,why_it_matters,"
                "evidence,recommendation"
            )
            .eq("scan_id", canonical_scan_id)
            .order("check_id")
            .limit(51)
            .execute(),
            client.table("scan_check_results")
            .select("check_id,score_explanation")
            .eq("scan_id", canonical_scan_id)
            .execute(),
        )
        return {
            "scan": scan,
            "findings": findings_response.data or [],
            "check_results": check_response.data or [],
        }

    async def get_cached_summary(self, scan_id: str) -> Mapping[str, Any] | None:
        client = self._require_client()
        response = await (
            client.table("scan_ai_summaries")
            .select("scan_id,summary,evidence_hash,generated_at,provider,model,prompt_version")
            .eq("scan_id", str(UUID(scan_id)))
            .limit(1)
            .execute()
        )
        rows = response.data or []
        return rows[0] if rows else None

    async def get_cached_explanation(
        self, scan_id: str, finding_id: str
    ) -> Mapping[str, Any] | None:
        client = self._require_client()
        response = await (
            client.table("finding_ai_explanations")
            .select("scan_id,finding_id,explanation,evidence_hash,generated_at,provider,model,prompt_version")
            .eq("scan_id", str(UUID(scan_id)))
            .eq("finding_id", str(UUID(finding_id)))
            .limit(1)
            .execute()
        )
        rows = response.data or []
        return rows[0] if rows else None

    async def get_cached_bundle(self, scan_id: str, user_id: str) -> Mapping[str, Any] | None:
        """Read cache rows only after independently rechecking scan ownership."""
        client = self._require_client()
        canonical_scan_id = str(UUID(scan_id))
        owner_response = await (
            client.table("scans")
            .select("id")
            .eq("id", canonical_scan_id)
            .eq("user_id", str(UUID(user_id)))
            .limit(1)
            .execute()
        )
        if not owner_response.data:
            return None
        summary_response, explanation_response = await asyncio.gather(
            client.table("scan_ai_summaries")
            .select("scan_id,summary,generated_at,provider,model,prompt_version")
            .eq("scan_id", canonical_scan_id)
            .limit(1)
            .execute(),
            client.table("finding_ai_explanations")
            .select("scan_id,finding_id,explanation,generated_at,provider,model,prompt_version")
            .eq("scan_id", canonical_scan_id)
            .execute(),
        )
        summary_rows = summary_response.data or []
        return {
            "summary": summary_rows[0] if summary_rows else None,
            "explanations": explanation_response.data or [],
        }

    async def save_summary(
        self, *, scan_id: str, evidence_hash: str, prompt_version: str,
        content: Mapping[str, Any], provider: str, model: str,
    ) -> Mapping[str, Any]:
        client = self._require_client()
        row = {
            "scan_id": str(UUID(scan_id)),
            "summary": dict(content),
            "evidence_hash": evidence_hash,
            "generated_at": datetime.now(UTC).isoformat(),
            "provider": provider,
            "model": model,
            "prompt_version": prompt_version,
        }
        response = await (
            client.table("scan_ai_summaries")
            .upsert(row, on_conflict="scan_id")
            .select("scan_id,summary,generated_at,provider,model,prompt_version")
            .single()
            .execute()
        )
        if not isinstance(response.data, Mapping):
            raise RuntimeError("AI summary persistence returned no row.")
        return response.data

    async def save_explanation(
        self, *, scan_id: str, finding_id: str, evidence_hash: str,
        prompt_version: str, content: Mapping[str, Any], provider: str, model: str,
    ) -> Mapping[str, Any]:
        client = self._require_client()
        row = {
            "scan_id": str(UUID(scan_id)),
            "finding_id": str(UUID(finding_id)),
            "explanation": dict(content),
            "evidence_hash": evidence_hash,
            "generated_at": datetime.now(UTC).isoformat(),
            "provider": provider,
            "model": model,
            "prompt_version": prompt_version,
        }
        response = await (
            client.table("finding_ai_explanations")
            .upsert(row, on_conflict="finding_id")
            .select("scan_id,finding_id,explanation,generated_at,provider,model,prompt_version")
            .single()
            .execute()
        )
        if not isinstance(response.data, Mapping):
            raise RuntimeError("AI explanation persistence returned no row.")
        return response.data
