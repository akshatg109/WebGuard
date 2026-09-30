from __future__ import annotations

import unittest
from types import SimpleNamespace
from uuid import uuid4

from app.persistence.scans import SupabaseScanRepository
from app.scanner.checks.registry import run_security_checks
from app.scanner.models import ScanContext, ScanStatus
from app.scanner.scoring import score_findings

USER_ID = "11111111-1111-4111-8111-111111111111"


def completed_context() -> ScanContext:
    url = "https://fixture.example.com/path?token=DO_NOT_PERSIST"
    context = ScanContext(requested_url=url)
    context.normalized_url = url
    context.current_url = url
    context.http_status = 200
    context.response_headers = (
        ("content-type", "text/html"),
        ("strict-transport-security", "max-age=31536000"),
        ("content-security-policy", "default-src 'self'; object-src 'none'; frame-ancestors 'none'"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "strict-origin-when-cross-origin"),
        ("permissions-policy", "camera=(), microphone=()"),
        ("x-frame-options", "DENY"),
        ("x-powered-by", "PHP/8.2"),
    )
    context.response_body = b"<html></html>"
    context.response_body_complete = True
    context.status = ScanStatus.COMPLETED
    return context


class RpcQuery:
    def __init__(self, client: "RpcClient", name: str, params: dict[str, object]) -> None:
        self.client = client
        self.name = name
        self.params = params

    async def execute(self):
        self.client.calls.append((self.name, self.params))
        return SimpleNamespace(data=None)


class RpcClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def rpc(self, name: str, params: dict[str, object]) -> RpcQuery:
        return RpcQuery(self, name, params)


class SupabaseScanPersistenceTests(unittest.IsolatedAsyncioTestCase):
    async def test_completed_result_uses_one_atomic_rpc_with_all_canonical_records(self) -> None:
        context = completed_context()
        findings = run_security_checks(context)
        score = score_findings(findings)
        client = RpcClient()
        repository = SupabaseScanRepository(client)
        scan_id = str(uuid4())

        await repository.persist_completed(
            scan_id=scan_id,
            user_id=USER_ID,
            normalized_url=context.normalized_url,
            duration_ms=23,
            findings=findings,
            score=score,
        )

        self.assertEqual(len(client.calls), 1)
        function_name, params = client.calls[0]
        self.assertEqual(function_name, "persist_completed_scan")
        self.assertEqual(params["p_scan_id"], scan_id)
        self.assertEqual(params["p_user_id"], USER_ID)
        self.assertEqual(params["p_scoring_version"], "1.0")
        self.assertEqual(params["p_score_available"], score.available)
        self.assertEqual(len(params["p_findings"]), 13)
        self.assertEqual(len(params["p_check_results"]), 13)
        self.assertNotIn("checks", params["p_score_details"])
        self.assertIn("categories", params["p_score_details"])
        self.assertEqual(
            {item["check_id"] for item in params["p_findings"]},
            {finding.check_id for finding in findings},
        )
        self.assertNotIn("DO_NOT_PERSIST", str(params))
        self.assertEqual(params["p_normalized_url"], "https://fixture.example.com/path")

    async def test_owned_read_filters_by_both_scan_and_verified_user_before_children(self) -> None:
        scan_id = str(uuid4())

        class Query:
            def __init__(self, client: "ReadClient", table: str) -> None:
                self.client = client
                self.table = table
                self.filters: list[tuple[str, object]] = []

            def select(self, _columns: str):
                return self

            def eq(self, field: str, value: object):
                self.filters.append((field, value))
                return self

            def limit(self, _amount: int):
                return self

            def order(self, _field: str):
                return self

            async def execute(self):
                self.client.queries.append((self.table, tuple(self.filters)))
                data = self.client.rows.get(self.table, [])
                return SimpleNamespace(data=data)

        class ReadClient:
            def __init__(self) -> None:
                self.rows = {"scans": []}
                self.queries: list[tuple[str, tuple[tuple[str, object], ...]]] = []

            def table(self, name: str):
                return Query(self, name)

        client = ReadClient()
        repository = SupabaseScanRepository(client)
        result = await repository.get_owned_bundle(scan_id, USER_ID)

        self.assertIsNone(result)
        self.assertEqual(len(client.queries), 1)
        self.assertEqual(client.queries[0][0], "scans")
        self.assertIn(("id", scan_id), client.queries[0][1])
        self.assertIn(("user_id", USER_ID), client.queries[0][1])

    async def test_owned_scan_history_filters_user_before_reading_findings(self) -> None:
        scan_id = str(uuid4())

        class Query:
            def __init__(self, client: "ListClient", table: str) -> None:
                self.client = client
                self.table = table
                self.filters: list[tuple[str, object]] = []
                self.selected = ""

            def select(self, columns: str, **_kwargs: object):
                self.selected = columns
                return self

            def eq(self, field: str, value: object):
                self.filters.append((field, value))
                return self

            def order(self, _field: str, **_kwargs: object):
                return self

            def range(self, _start: int, _end: int):
                return self

            def in_(self, field: str, values: list[str]):
                self.filters.append((field, values))
                return self

            async def execute(self):
                self.client.queries.append((self.table, self.selected, tuple(self.filters)))
                if self.table == "scans":
                    return SimpleNamespace(
                        data=[
                            {
                                "id": scan_id,
                                "target_url": "https://owned.example.com/?token=PRIVATE",
                                "normalized_url": "https://owned.example.com/",
                                "status": "completed",
                                "score": 90,
                                "score_available": True,
                                "score_confidence": "complete",
                                "created_at": "2026-09-28T10:00:00+00:00",
                                "completed_at": "2026-09-28T10:00:01+00:00",
                                "duration_ms": 1000,
                            }
                        ],
                        count=1,
                    )
                return SimpleNamespace(
                    data=[{"scan_id": scan_id, "severity": "high", "status": "fail"}]
                )

        class ListClient:
            def __init__(self) -> None:
                self.queries: list[tuple[str, str, tuple[tuple[str, object], ...]]] = []

            def table(self, name: str):
                return Query(self, name)

        client = ListClient()
        repository = SupabaseScanRepository(client)
        result = await repository.list_owned_summaries(USER_ID, limit=20, offset=0)

        self.assertEqual(result["total"], 1)
        summary = result["items"][0]
        self.assertEqual(summary["target_url"], "https://owned.example.com/")
        self.assertEqual(summary["finding_count"], 1)
        self.assertEqual(summary["severity_counts"]["high"], 1)
        self.assertEqual(len(client.queries), 2)
        self.assertEqual(client.queries[0][0], "scans")
        self.assertIn(("user_id", USER_ID), client.queries[0][2])
        self.assertEqual(client.queries[1][0], "findings")
        self.assertIn(("scan_id", [scan_id]), client.queries[1][2])
        self.assertNotIn("PRIVATE", str(result))


if __name__ == "__main__":
    unittest.main()
