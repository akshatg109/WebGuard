from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, patch
from uuid import uuid4

from postgrest._async.request_builder import AsyncQueryRequestBuilder
from postgrest.base_request_builder import APIResponse
from postgrest.exceptions import APIError
from supabase import AsyncClient

from app.persistence.retry import execute_with_clock_skew_retry
from app.persistence.scans import SupabaseScanRepository


class PendingInsertQuery:
    def __init__(self, *, failures: int = 1) -> None:
        self.failures = failures
        self.calls = 0
        self.row_id = str(uuid4())

    def insert(self, _data: dict[str, object]) -> "PendingInsertQuery":
        return self

    def select(self, _columns: str) -> "PendingInsertQuery":
        return self

    async def execute(self):
        self.calls += 1
        if self.calls <= self.failures:
            raise APIError({"code": "PGRST303", "message": "JWT issued at future"})
        return APIResponse(data=[{"id": self.row_id}])


class PendingInsertClient:
    def __init__(self, query: PendingInsertQuery) -> None:
        self.query = query

    def table(self, _name: str) -> PendingInsertQuery:
        return self.query


class PostgrestRetryTests(unittest.IsolatedAsyncioTestCase):
    async def test_pending_insert_retries_only_future_issued_jwt_rejection(self) -> None:
        query = PendingInsertQuery()
        repository = SupabaseScanRepository(PendingInsertClient(query))

        with patch("app.persistence.retry.asyncio.sleep", new_callable=AsyncMock) as sleep:
            row = await repository.create_pending(
                "11111111-1111-4111-8111-111111111111",
                "https://owned.example.com/",
            )

        self.assertEqual(row["id"], query.row_id)
        self.assertEqual(query.calls, 2)
        sleep.assert_awaited_once_with(0.3)

    async def test_create_pending_matches_installed_supabase_builder_and_response_shape(self) -> None:
        client = AsyncClient("https://project.example", "test-server-key")
        row = {
            "id": str(uuid4()),
            "user_id": "11111111-1111-4111-8111-111111111111",
            "target_url": "https://owned.example.com/",
            "status": "pending",
            "created_at": "2026-10-06T00:00:00+00:00",
        }
        try:
            builder = (
                client.table("scans")
                .insert({"user_id": row["user_id"]})
                .select("id,user_id,target_url,status,created_at")
            )
            self.assertIsInstance(builder, AsyncQueryRequestBuilder)
            with self.assertRaises(AttributeError):
                builder.single()

            repository = SupabaseScanRepository(client)
            response = APIResponse(data=[row])
            with patch.object(
                AsyncQueryRequestBuilder,
                "execute",
                new=AsyncMock(return_value=response),
            ) as execute:
                created = await repository.create_pending(
                    row["user_id"], row["target_url"]
                )

            self.assertEqual(created, row)
            execute.assert_awaited_once()
        finally:
            await client.auth.close()
            await client.postgrest.aclose()

    async def test_future_issued_jwt_retry_is_bounded(self) -> None:
        query = PendingInsertQuery(failures=3)

        with patch("app.persistence.retry.asyncio.sleep", new_callable=AsyncMock) as sleep:
            with self.assertRaises(APIError):
                await execute_with_clock_skew_retry(query.execute)

        self.assertEqual(query.calls, 3)
        self.assertEqual(
            [call.args[0] for call in sleep.await_args_list],
            [0.3, 0.9],
        )

    async def test_other_postgrest_auth_errors_are_not_retried(self) -> None:
        execute = AsyncMock(
            side_effect=APIError({"code": "PGRST303", "message": "JWT has invalid audience"})
        )

        with patch("app.persistence.retry.asyncio.sleep", new_callable=AsyncMock) as sleep:
            with self.assertRaises(APIError):
                await execute_with_clock_skew_retry(execute)

        execute.assert_awaited_once()
        sleep.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
