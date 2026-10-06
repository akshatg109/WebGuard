from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from fastapi.testclient import TestClient
from postgrest.exceptions import APIError as PostgrestAPIError

from app.api.auth import AuthenticatedUser, SupabaseTokenVerifier
from app.api.errors import ApiError
from app.api.rate_limit import InMemoryScanRateLimiter
from app.api.serialization import (
    check_result_persistence_rows,
    finding_persistence_row,
    score_persistence_fields,
    technology_persistence_rows,
)
from app.config import ScanRateLimitSettings
from app.main import create_app
from app.scanner.config import ScannerSettings
from app.scanner.errors import (
    BlockedDestinationError,
    ConnectionFailedError,
    ScannerFailureError,
    ScannerTimeoutError,
)
from app.scanner.findings import Finding
from app.scanner.models import ObservedCookie, ScanContext, ScanStatus
from app.scanner.scoring import ScoreResult

OWNER_ID = "11111111-1111-4111-8111-111111111111"
OTHER_ID = "22222222-2222-4222-8222-222222222222"
VALID_URL = "https://fixture.example.com/page?token=URL_SECRET"
TEST_SCANNER_API_TOKEN = "t" * 40


def fixture_context(url: str = VALID_URL) -> ScanContext:
    context = ScanContext(requested_url=url)
    context.normalized_url = url
    context.current_url = url
    context.hostname = "fixture.example.com"
    context.scheme = "https"
    context.port = 443
    context.http_status = 200
    context.response_headers = (
        ("content-type", "text/html; charset=utf-8"),
        ("strict-transport-security", "max-age=31536000; includeSubDomains"),
        ("content-security-policy", "default-src 'self'; object-src 'none'; frame-ancestors 'none'"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "strict-origin-when-cross-origin"),
        ("permissions-policy", "camera=(), microphone=()"),
        ("x-frame-options", "DENY"),
        ("server", "nginx/1.25"),
        ("x-powered-by", "PHP/8.2"),
    )
    context.response_cookies = (
        ObservedCookie(
            name="session",
            secure=True,
            http_only=True,
            same_site="lax",
            domain_scope="host_only",
            path_scope="root",
            max_age_present=False,
            max_age_valid=False,
            max_age_nonpositive=False,
            expires_present=False,
            expires_valid=False,
            prefix_kind=None,
            prefix_requirements_satisfied=None,
        ),
    )
    context.set_cookie_header_count = 1
    context.response_body = b"<html><img src='http://127.0.0.1/internal'><p>BODY_SECRET</p></html>"
    context.response_body_bytes = len(context.response_body)
    context.response_body_complete = True
    context.status = ScanStatus.COMPLETED
    return context


class FakeScanner:
    def __init__(
        self,
        *,
        failure: Exception | None = None,
        raise_failure: bool = False,
    ) -> None:
        self.settings = ScannerSettings()
        self.failure = failure
        self.raise_failure = raise_failure
        self.calls: list[str] = []

    async def fetch(self, url: str, *, method: str = "GET") -> ScanContext:
        self.calls.append(url)
        if self.failure is None:
            return fixture_context(url)
        if self.raise_failure:
            raise self.failure
        context = ScanContext(requested_url=url)
        context.error = self.failure  # type: ignore[assignment]
        context.status = ScanStatus.FAILED
        return context


class FakeTokenVerifier:
    async def verify(self, token: str) -> AuthenticatedUser | None:
        if token == "valid-token":
            return AuthenticatedUser(OWNER_ID)
        if token == "other-user-token":
            return AuthenticatedUser(OTHER_ID)
        return None


class FakeRepository:
    def __init__(self, *, fail_persist: bool = False) -> None:
        self.scans: dict[str, dict[str, object]] = {}
        self.children: dict[str, dict[str, list[dict[str, object]]]] = {}
        self.events: list[str] = []
        self.fail_persist = fail_persist

    async def create_pending(self, user_id: str, target_url: str):
        scan_id = str(uuid4())
        self.scans[scan_id] = {
            "id": scan_id,
            "user_id": user_id,
            "target_url": target_url,
            "status": "pending",
            "score": None,
            "score_available": False,
            "score_confidence": None,
            "scoring_version": None,
            "score_details": {},
            "error_code": None,
            "error_message": None,
            "created_at": "2026-09-28T10:00:00+00:00",
        }
        self.children[scan_id] = {"findings": [], "technologies": [], "check_results": []}
        self.events.append("pending")
        return {
            "id": scan_id,
            "user_id": user_id,
            "target_url": target_url,
            "status": "pending",
            "created_at": self.scans[scan_id]["created_at"],
        }

    async def mark_running(self, scan_id: str, user_id: str, normalized_url: str) -> None:
        self.scans[scan_id]["status"] = "running"
        self.scans[scan_id]["normalized_url"] = normalized_url.split("?", 1)[0]
        self.events.append("running")

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
        if self.fail_persist:
            raise RuntimeError("DB_PASSWORD=PRIVATE; stack/path details")
        values = score_persistence_fields(score)
        scan = self.scans[scan_id]
        scan.update(
            {
                "status": "completed",
                "normalized_url": normalized_url.split("?", 1)[0],
                **values,
                "duration_ms": duration_ms,
                "completed_at": "2026-09-28T10:00:01+00:00",
            }
        )
        self.children[scan_id] = {
            "findings": [
                {
                    "scan_id": scan_id,
                    "check_id": row["check_id"],
                    "title": row["title"],
                    "severity": row["severity"],
                    "status": row["status"],
                    "description": row["summary"],
                    "why_it_matters": row["why_it_matters"],
                    "evidence": row["evidence"],
                    "recommendation": row["remediation"],
                    "affected_url": row["affected_url"],
                    "metadata": row["metadata"],
                }
                for row in (finding_persistence_row(finding) for finding in findings)
            ],
            "technologies": [
                {"scan_id": scan_id, **row}
                for row in technology_persistence_rows(findings)
            ],
            "check_results": [
                {"scan_id": scan_id, **row}
                for row in check_result_persistence_rows(findings, score)
            ],
        }
        self.events.append("completed")

    async def mark_failed(
        self,
        scan_id: str,
        user_id: str,
        *,
        error_code: str,
        error_message: str,
        duration_ms: int,
    ) -> None:
        self.scans[scan_id].update(
            {
                "status": "failed",
                "error_code": error_code,
                "error_message": error_message,
                "score": None,
                "score_available": False,
                "score_confidence": None,
                "scoring_version": None,
                "score_details": {},
                "duration_ms": duration_ms,
            }
        )
        self.events.append("failed")

    async def get_owned_bundle(self, scan_id: str, user_id: str):
        scan = self.scans.get(scan_id)
        if scan is None or scan["user_id"] != user_id:
            return None
        return {"scan": dict(scan), **self.children[scan_id]}

    async def list_owned_summaries(self, user_id: str, *, limit: int, offset: int):
        owned = [scan for scan in self.scans.values() if scan["user_id"] == user_id]
        owned.sort(key=lambda scan: str(scan.get("created_at", "")), reverse=True)
        page = owned[offset : offset + limit]
        items = []
        for scan in page:
            scan_id = str(scan["id"])
            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
            actionable_count = 0
            if scan["status"] == "completed":
                for finding in self.children[scan_id]["findings"]:
                    if finding["status"] not in {"fail", "warn", "error"}:
                        continue
                    severity = finding["severity"]
                    if severity in counts:
                        counts[severity] += 1
                        actionable_count += 1
            items.append(
                {
                    "id": scan_id,
                    "target_url": scan["target_url"],
                    "normalized_url": scan.get("normalized_url"),
                    "status": scan["status"],
                    "score": scan.get("score"),
                    "score_available": scan.get("score_available", False),
                    "confidence": scan.get("score_confidence"),
                    "created_at": scan.get("created_at"),
                    "completed_at": scan.get("completed_at"),
                    "duration_ms": scan.get("duration_ms"),
                    "finding_count": actionable_count if scan["status"] == "completed" else None,
                    "severity_counts": counts if scan["status"] == "completed" else None,
                }
            )
        return {"items": items, "total": len(owned)}


def build_client(
    *,
    scanner: FakeScanner | None = None,
    repository: FakeRepository | None = None,
    verifier: FakeTokenVerifier | None = None,
    limiter: InMemoryScanRateLimiter | None = None,
    origins: tuple[str, ...] = ("https://frontend.example",),
) -> TestClient:
    app = create_app(
        scanner_service=scanner or FakeScanner(),
        scan_repository=repository or FakeRepository(),
        token_verifier=verifier or FakeTokenVerifier(),
        scan_rate_limiter=limiter,
        scanner_api_token=TEST_SCANNER_API_TOKEN,
        allowed_origins=origins,
    )
    return TestClient(app, headers={"X-WebGuard-Scanner-Token": TEST_SCANNER_API_TOKEN})


class ScanApiTests(unittest.TestCase):
    def test_scan_history_is_authenticated_owner_filtered_and_bounded(self) -> None:
        repository = FakeRepository()
        owned_id = str(uuid4())
        other_id = str(uuid4())
        repository.scans[owned_id] = {
            "id": owned_id,
            "user_id": OWNER_ID,
            "target_url": "https://owned.example.com/",
            "normalized_url": "https://owned.example.com/",
            "status": "completed",
            "score": 91,
            "score_available": True,
            "score_confidence": "complete",
            "created_at": "2026-09-28T10:00:00+00:00",
            "completed_at": "2026-09-28T10:00:01+00:00",
            "duration_ms": 900,
        }
        repository.children[owned_id] = {
            "findings": [
                {"status": "fail", "severity": "high"},
                {"status": "pass", "severity": "critical"},
            ],
            "technologies": [],
            "check_results": [],
        }
        repository.scans[other_id] = {
            **repository.scans[owned_id],
            "id": other_id,
            "user_id": OTHER_ID,
            "target_url": "https://other.example.com/",
        }
        repository.children[other_id] = {"findings": [], "technologies": [], "check_results": []}

        with build_client(repository=repository) as client:
            unauthorized = client.get("/api/scans")
            response = client.get(
                "/api/scans?limit=1&offset=0",
                headers={"Authorization": "Bearer valid-token"},
            )

        self.assertEqual(unauthorized.status_code, 401)
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["total"], 1)
        self.assertEqual(len(result["items"]), 1)
        self.assertEqual(result["items"][0]["id"], owned_id)
        self.assertEqual(result["items"][0]["finding_count"], 1)
        self.assertEqual(result["items"][0]["severity_counts"]["high"], 1)
        self.assertNotIn("other.example.com", response.text)

    def test_scan_history_logs_safe_postgrest_failure_diagnostics(self) -> None:
        class BrokenRepository(FakeRepository):
            async def list_owned_summaries(self, user_id: str, *, limit: int, offset: int):
                raise PostgrestAPIError(
                    {
                        "code": "42703",
                        "message": (
                            "column public.scans.score_confidence does not exist; "
                            "Bearer local-diagnostic-token; "
                            "sb_secret_abcdefghijklmnop; "
                            "Cookie=local-cookie-value; "
                            "Authorization=local-authorization-value"
                        ),
                        "details": "private diagnostic detail must not be logged",
                    }
                )

        with build_client(repository=BrokenRepository()) as client:
            with self.assertLogs("app.api.scans", level="ERROR") as diagnostics:
                response = client.get(
                    "/api/scans",
                    headers={"Authorization": "Bearer valid-token"},
                )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["error"]["code"], "persistence_failure")
        log_output = "\n".join(diagnostics.output)
        self.assertIn("exception_type=APIError", log_output)
        self.assertIn("42703", log_output)
        self.assertIn("column public.scans.score_confidence does not exist", log_output)
        self.assertIn("Bearer [redacted]", log_output)
        self.assertNotIn("local-diagnostic-token", log_output)
        self.assertNotIn("sb_secret_abcdefghijklmnop", log_output)
        self.assertNotIn("local-cookie-value", log_output)
        self.assertNotIn("local-authorization-value", log_output)
        self.assertNotIn("private diagnostic detail", log_output)
        self.assertNotIn("score_confidence", response.text)

    def test_scan_routes_require_the_server_only_service_credential(self) -> None:
        with build_client() as client:
            missing = client.post(
                "/api/scans",
                headers={
                    "X-WebGuard-Scanner-Token": "",
                    "Authorization": "Bearer valid-token",
                },
                json={"url": "https://fixture.example.com/"},
            )
            response = client.post(
                "/api/scans",
                headers={
                    "X-WebGuard-Scanner-Token": "incorrect-service-token",
                    "Authorization": "Bearer valid-token",
                },
                json={"url": "https://fixture.example.com/"},
            )
        self.assertEqual(missing.status_code, 401)
        self.assertEqual(missing.json()["error"]["code"], "unauthorized")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.json(),
            {
                "error": {
                    "code": "unauthorized",
                    "message": "A valid scanner service credential is required.",
                }
            },
        )

    def test_missing_server_token_configuration_fails_closed(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            app = create_app(
                scanner_service=FakeScanner(),
                scan_repository=FakeRepository(),
                token_verifier=FakeTokenVerifier(),
                allowed_origins=("https://frontend.example",),
            )
            with TestClient(app) as client:
                response = client.get("/api/scans")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["error"]["code"], "scanner_unavailable")

    def test_unexpected_exceptions_return_no_traceback_or_exception_text(self) -> None:
        app = create_app(
            scanner_service=FakeScanner(),
            scan_repository=FakeRepository(),
            token_verifier=FakeTokenVerifier(),
            scanner_api_token=TEST_SCANNER_API_TOKEN,
            allowed_origins=("https://frontend.example",),
        )

        def raise_unexpected_error() -> None:
            raise RuntimeError("internal-detail=do-not-return; /internal/stack")

        app.add_api_route("/test-unexpected-error", raise_unexpected_error)
        with TestClient(app, raise_server_exceptions=False) as client:
            response = client.get("/test-unexpected-error")

        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json(),
            {"error": {"code": "internal_error", "message": "The request could not be completed."}},
        )
        self.assertNotIn("internal-detail", response.text)
        self.assertNotIn("/internal/stack", response.text)

    def test_missing_malformed_invalid_and_expired_tokens_are_rejected(self) -> None:
        with build_client() as client:
            missing = client.post("/api/scans", json={"url": VALID_URL})
            malformed = client.post("/api/scans", headers={"Authorization": "Bearer"}, json={"url": VALID_URL})
            wrong_scheme = client.post("/api/scans", headers={"Authorization": "Basic abc"}, json={"url": VALID_URL})
            invalid = client.post("/api/scans", headers={"Authorization": "Bearer invalid-token"}, json={"url": VALID_URL})
            expired = client.post("/api/scans", headers={"Authorization": "Bearer expired-token"}, json={"url": VALID_URL})

        for response in (missing, malformed, wrong_scheme, invalid, expired):
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.json()["error"]["code"], "unauthorized")

    def test_valid_token_runs_pipeline_and_persists_every_result(self) -> None:
        scanner = FakeScanner()
        repository = FakeRepository()
        with build_client(scanner=scanner, repository=repository) as client:
            response = client.post(
                "/api/scans",
                headers={"Authorization": "Bearer valid-token"},
                json={"url": VALID_URL},
            )

        self.assertEqual(response.status_code, 201)
        result = response.json()
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["scoring_version"], "1.0")
        self.assertTrue(result["score_available"])
        self.assertEqual(result["score"], 95)
        self.assertEqual(result["normalized_url"], "https://fixture.example.com/page")
        self.assertIsNotNone(result["created_at"])
        self.assertIsNotNone(result["completed_at"])
        self.assertGreaterEqual(result["duration_ms"], 0)
        self.assertEqual(len(result["findings"]), 13)
        self.assertEqual(len(result["check_results"]), 13)
        self.assertEqual(len(result["technologies"]), 2)
        self.assertIn("PHP", {technology["name"] for technology in result["technologies"]})
        self.assertEqual(scanner.calls, [VALID_URL])
        self.assertEqual(repository.events, ["pending", "running", "completed"])
        stored = repository.scans[result["id"]]
        self.assertEqual(stored["user_id"], OWNER_ID)
        self.assertEqual(stored["status"], "completed")
        self.assertEqual(len(repository.children[result["id"]]["findings"]), 13)
        self.assertEqual(len(repository.children[result["id"]]["technologies"]), 2)
        self.assertEqual(len(repository.children[result["id"]]["check_results"]), 13)
        self.assertEqual(result["target_url"], "https://fixture.example.com/page")

    def test_owned_scan_can_be_read_but_another_user_gets_not_found(self) -> None:
        repository = FakeRepository()
        limiter = InMemoryScanRateLimiter(
            ScanRateLimitSettings(max_requests=20, window_seconds=60)
        )
        with build_client(repository=repository, limiter=limiter) as client:
            created = client.post(
                "/api/scans",
                headers={"Authorization": "Bearer valid-token"},
                json={"url": "https://fixture.example.com/"},
            ).json()
            own = client.get(
                f"/api/scans/{created['id']}",
                headers={"Authorization": "Bearer valid-token"},
            )
            other = client.get(
                f"/api/scans/{created['id']}",
                headers={"Authorization": "Bearer other-user-token"},
            )

        self.assertEqual(own.status_code, 200)
        self.assertEqual(own.json()["id"], created["id"])
        self.assertEqual(other.status_code, 404)
        self.assertEqual(other.json()["error"]["code"], "scan_not_found")

    def test_invalid_targets_are_rejected_before_scan_creation(self) -> None:
        repository = FakeRepository()
        invalid_targets = (
            ("ftp://fixture.example.com", "invalid_target"),
            ("http://127.0.0.1/", "blocked_target"),
            ("https://localhost/", "blocked_target"),
            ("file:///etc/passwd", "invalid_target"),
            ("https://user:secret@fixture.example.com/", "invalid_target"),
            ("https://fixture.example.com:25/", "invalid_target"),
        )
        limiter = InMemoryScanRateLimiter(
            ScanRateLimitSettings(max_requests=20, window_seconds=60)
        )
        with build_client(repository=repository, limiter=limiter) as client:
            results = [
                client.post(
                    "/api/scans",
                    headers={"Authorization": "Bearer valid-token"},
                    json={"url": url},
                )
                for url, _ in invalid_targets
            ]
        for response, (_, code) in zip(results, invalid_targets, strict=True):
            self.assertEqual(response.status_code, 422)
            self.assertEqual(response.json()["error"]["code"], code)
            self.assertNotIn("secret", response.text)
        self.assertEqual(repository.scans, {})

    def test_extra_request_fields_are_rejected_without_echoing_secrets(self) -> None:
        with build_client() as client:
            response = client.post(
                "/api/scans",
                headers={"Authorization": "Bearer valid-token"},
                json={"url": VALID_URL, "headers": {"Authorization": "HEADER_SECRET"}},
            )
        self.assertEqual(response.status_code, 422)
        self.assertNotIn("HEADER_SECRET", response.text)
        self.assertNotIn("URL_SECRET", response.text)

        with build_client() as client:
            owner_override = client.post(
                "/api/scans",
                headers={"Authorization": "Bearer valid-token"},
                json={"url": VALID_URL, "user_id": OTHER_ID},
            )
        self.assertEqual(owner_override.status_code, 422)
        self.assertNotIn(OTHER_ID, owner_override.text)

    def test_oversized_request_body_is_rejected_before_auth_or_scan_creation(self) -> None:
        scanner = FakeScanner()
        repository = FakeRepository()
        with build_client(scanner=scanner, repository=repository) as client:
            response = client.post(
                "/api/scans",
                content=(b'{"url":"https://fixture.example.com/","unused":"' + b"x" * (32 * 1024) + b'"}'),
                headers={"content-type": "application/json"},
            )
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json()["error"]["code"], "request_too_large")
        self.assertEqual(scanner.calls, [])
        self.assertEqual(repository.scans, {})

    def test_response_and_database_payload_omit_secrets_cookie_values_and_internal_ips(self) -> None:
        scanner = FakeScanner()
        repository = FakeRepository()
        with build_client(scanner=scanner, repository=repository) as client:
            response = client.post(
                "/api/scans",
                headers={"Authorization": "Bearer valid-token"},
                json={"url": VALID_URL},
            )
        serialized = response.text + str(repository.scans) + str(repository.children)
        for secret in ("URL_SECRET", "BODY_SECRET", "COOKIE_SECRET", "127.0.0.1", "DB_PASSWORD", "private; stack/path"):
            self.assertNotIn(secret, serialized)
        self.assertIn("cookie_values_stored", response.text)
        self.assertIn("PHP", response.text)

    def test_rate_limit_allows_under_limit_and_rejects_over_limit(self) -> None:
        now = [0.0]
        limiter = InMemoryScanRateLimiter(
            ScanRateLimitSettings(max_requests=1, window_seconds=60),
            clock=lambda: now[0],
        )
        with build_client(limiter=limiter) as client:
            headers = {"Authorization": "Bearer valid-token"}
            first = client.post("/api/scans", headers=headers, json={"url": "https://fixture.example.com/"})
            second = client.post("/api/scans", headers=headers, json={"url": "https://fixture.example.com/"})
            now[0] = 61
            after_window = client.post("/api/scans", headers=headers, json={"url": "https://fixture.example.com/"})
        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.status_code, 429)
        self.assertGreaterEqual(int(second.headers["retry-after"]), 1)
        self.assertEqual(
            second.json(),
            {
                "error": {
                    "code": "rate_limit_exceeded",
                    "message": "The scan creation limit has been reached. Try again later.",
                }
            },
        )
        self.assertEqual(after_window.status_code, 201)

    def test_scanner_blocked_and_timeout_failures_are_safe_and_persisted(self) -> None:
        for failure, expected_status, expected_code in (
            (BlockedDestinationError(), 422, "blocked_target"),
            (ConnectionFailedError(), 502, "network_failure"),
            (ScannerTimeoutError(), 504, "timeout"),
            (ScannerFailureError(), 500, "scanner_error"),
        ):
            repository = FakeRepository()
            with build_client(scanner=FakeScanner(failure=failure), repository=repository) as client:
                response = client.post(
                    "/api/scans",
                    headers={"Authorization": "Bearer valid-token"},
                    json={"url": "https://fixture.example.com/"},
                )
            self.assertEqual(response.status_code, expected_status)
            body = response.json()
            self.assertEqual(body["status"], "failed")
            self.assertEqual(body["error"]["code"], expected_code)
            self.assertEqual(repository.scans[body["id"]]["status"], "failed")
            self.assertEqual(repository.scans[body["id"]]["error_code"], expected_code)

    def test_scanner_exceptions_map_to_controlled_network_failures(self) -> None:
        repository = FakeRepository()
        with build_client(
            scanner=FakeScanner(failure=ConnectionFailedError(), raise_failure=True),
            repository=repository,
        ) as client:
            response = client.post(
                "/api/scans",
                headers={"Authorization": "Bearer valid-token"},
                json={"url": "https://fixture.example.com/"},
            )
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json()["error"]["code"], "network_failure")

    def test_persistence_failure_does_not_claim_completion_or_leak_details(self) -> None:
        repository = FakeRepository(fail_persist=True)
        with build_client(repository=repository) as client:
            response = client.post(
                "/api/scans",
                headers={"Authorization": "Bearer valid-token"},
                json={"url": "https://fixture.example.com/"},
            )
        body = response.json()
        self.assertEqual(response.status_code, 500)
        self.assertEqual(body["status"], "failed")
        self.assertEqual(body["error"]["code"], "persistence_failure")
        self.assertEqual(repository.scans[body["id"]]["status"], "failed")
        self.assertEqual(repository.children[body["id"]], {"findings": [], "technologies": [], "check_results": []})
        self.assertNotIn("PRIVATE", response.text)
        self.assertNotIn("stack/path", response.text)

    def test_only_configured_cors_origin_is_reflected(self) -> None:
        with build_client(origins=("https://frontend.example",)) as client:
            allowed = client.options(
                "/api/scans",
                headers={
                    "Origin": "https://frontend.example",
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "authorization,content-type",
                },
            )
            rejected = client.options(
                "/api/scans",
                headers={
                    "Origin": "https://attacker.example",
                    "Access-Control-Request-Method": "POST",
                },
            )
            browser_service_token = client.options(
                "/api/scans",
                headers={
                    "Origin": "https://frontend.example",
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "authorization,content-type,x-webguard-scanner-token",
                },
            )
        self.assertEqual(allowed.headers.get("access-control-allow-origin"), "https://frontend.example")
        self.assertIsNone(rejected.headers.get("access-control-allow-origin"))
        self.assertEqual(browser_service_token.status_code, 400)
        self.assertNotIn(
            "x-webguard-scanner-token",
            browser_service_token.headers.get("access-control-allow-headers", ""),
        )

    def test_health_and_openapi_show_authenticated_scan_routes(self) -> None:
        with build_client() as client:
            self.assertEqual(client.get("/health").json(), {"status": "ok"})
            openapi = client.get("/openapi.json").json()
        self.assertIn("post", openapi["paths"]["/api/scans"])
        self.assertIn("get", openapi["paths"]["/api/scans"])
        self.assertIn("get", openapi["paths"]["/api/scans/{scan_id}"])
        self.assertIn("SupabaseAccessToken", openapi["components"]["securitySchemes"])
        self.assertIn("ScannerServiceToken", openapi["components"]["securitySchemes"])
        self.assertEqual(
            openapi["paths"]["/api/scans"]["post"]["security"],
            [{"ScannerServiceToken": [], "SupabaseAccessToken": []}],
        )


class SupabaseAuthVerifierTests(unittest.IsolatedAsyncioTestCase):
    async def test_supabase_auth_user_lookup_returns_verified_user_id(self) -> None:
        class Auth:
            async def get_user(self, token: str):
                self.token = token
                return SimpleNamespace(user=SimpleNamespace(id=OWNER_ID))

        auth = Auth()
        user = await SupabaseTokenVerifier(SimpleNamespace(auth=auth)).verify("server-verified-token")
        self.assertEqual(user, AuthenticatedUser(OWNER_ID))
        self.assertEqual(auth.token, "server-verified-token")

    async def test_invalid_and_expired_auth_tokens_are_rejected(self) -> None:
        class Rejected(Exception):
            status = 401

        class Auth:
            async def get_user(self, _token: str):
                raise Rejected("do not return this error")

        verifier = SupabaseTokenVerifier(SimpleNamespace(auth=Auth()))
        self.assertIsNone(await verifier.verify("invalid-or-expired-token"))

    async def test_auth_service_outage_is_not_misreported_as_invalid_token(self) -> None:
        class Auth:
            async def get_user(self, _token: str):
                raise OSError("internal networking details")

        with self.assertRaises(ApiError) as caught:
            await SupabaseTokenVerifier(SimpleNamespace(auth=Auth())).verify("token")
        self.assertEqual(caught.exception.status_code, 503)
        self.assertNotIn("internal networking", caught.exception.message)


class ScanRateLimiterTests(unittest.IsolatedAsyncioTestCase):
    async def test_rate_limiter_is_user_scoped(self) -> None:
        limiter = InMemoryScanRateLimiter(ScanRateLimitSettings(max_requests=1, window_seconds=30))
        self.assertIsNone(await limiter.consume(OWNER_ID))
        self.assertGreaterEqual(await limiter.consume(OWNER_ID), 1)
        self.assertIsNone(await limiter.consume(OTHER_ID))


if __name__ == "__main__":
    unittest.main()
