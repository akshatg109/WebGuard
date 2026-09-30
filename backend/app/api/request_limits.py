"""Bound scan API request-body buffering before JSON parsing."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

MAX_SCAN_REQUEST_BYTES = 32 * 1024


class ScanRequestSizeLimitMiddleware:
    """Cap POST /api/scans bodies, including chunked requests without a length."""

    def __init__(self, app: Callable[..., Awaitable[None]], *, max_bytes: int = MAX_SCAN_REQUEST_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: dict[str, Any], receive: Callable[..., Awaitable[dict[str, Any]]], send: Callable[..., Awaitable[None]]) -> None:
        if (
            scope.get("type") != "http"
            or scope.get("method") != "POST"
            or scope.get("path") != "/api/scans"
        ):
            await self.app(scope, receive, send)
            return

        headers = {name.lower(): value for name, value in scope.get("headers", [])}
        declared_length = headers.get(b"content-length")
        if declared_length is not None:
            try:
                if int(declared_length) > self.max_bytes:
                    await _send_too_large(send)
                    return
            except ValueError:
                # Leave malformed framing to the ASGI server/request parser.
                pass

        buffered: list[dict[str, Any]] = []
        total_bytes = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                buffered.append(message)
                continue
            total_bytes += len(message.get("body", b""))
            if total_bytes > self.max_bytes:
                await _send_too_large(send)
                return
            buffered.append(message)
            if not message.get("more_body", False):
                break

        async def replay_receive() -> dict[str, Any]:
            if buffered:
                return buffered.pop(0)
            return await receive()

        await self.app(scope, replay_receive, send)


async def _send_too_large(send: Callable[..., Awaitable[None]]) -> None:
    body = json.dumps(
        {
            "error": {
                "code": "request_too_large",
                "message": "The scan request body exceeds the 32 KiB limit.",
            }
        },
        separators=(",", ":"),
    ).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
