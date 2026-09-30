"""Server-to-server credential for the private scanner API boundary."""

from __future__ import annotations

import hmac

from fastapi import Depends, Request
from fastapi.security import APIKeyHeader

from app.api.errors import ApiError

_SCANNER_SERVICE_TOKEN = APIKeyHeader(
    name="X-WebGuard-Scanner-Token",
    scheme_name="ScannerServiceToken",
    auto_error=False,
)


async def require_scanner_service_token(
    request: Request,
    token: str | None = Depends(_SCANNER_SERVICE_TOKEN),
) -> None:
    """Reject direct callers unless they possess the BFF-only service secret."""
    expected = request.app.state.scanner_api_token
    if expected is None:
        raise ApiError(
            503,
            "scanner_unavailable",
            "The scanner is not available right now.",
        )
    if token is None or not hmac.compare_digest(token.encode(), expected.encode()):
        raise ApiError(
            401,
            "unauthorized",
            "A valid scanner service credential is required.",
        )
