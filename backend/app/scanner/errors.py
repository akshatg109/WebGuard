"""Stable scanner errors with deliberately safe public representations."""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from app.scanner.models import ResponseHead


class ScannerErrorCode(StrEnum):
    INVALID_URL = "INVALID_URL"
    UNSUPPORTED_SCHEME = "UNSUPPORTED_SCHEME"
    UNSUPPORTED_PORT = "UNSUPPORTED_PORT"
    UNSUPPORTED_METHOD = "UNSUPPORTED_METHOD"
    BLOCKED_DESTINATION = "BLOCKED_DESTINATION"
    DNS_RESOLUTION_FAILED = "DNS_RESOLUTION_FAILED"
    CONNECTION_FAILED = "CONNECTION_FAILED"
    TIMEOUT = "TIMEOUT"
    REDIRECT_LIMIT_EXCEEDED = "REDIRECT_LIMIT_EXCEEDED"
    REDIRECT_LOOP = "REDIRECT_LOOP"
    UNSAFE_REDIRECT = "UNSAFE_REDIRECT"
    RESPONSE_TOO_LARGE = "RESPONSE_TOO_LARGE"
    UNSUPPORTED_RESPONSE = "UNSUPPORTED_RESPONSE"
    SCANNER_FAILURE = "SCANNER_FAILURE"


_SAFE_MESSAGES: dict[ScannerErrorCode, str] = {
    ScannerErrorCode.INVALID_URL: "The target URL is invalid.",
    ScannerErrorCode.UNSUPPORTED_SCHEME: "Only HTTP and HTTPS targets are allowed.",
    ScannerErrorCode.UNSUPPORTED_PORT: "The target port is not allowed by scanner policy.",
    ScannerErrorCode.UNSUPPORTED_METHOD: "Only GET and HEAD requests are supported.",
    ScannerErrorCode.BLOCKED_DESTINATION: "The target is not on the public internet.",
    ScannerErrorCode.DNS_RESOLUTION_FAILED: "The target hostname could not be safely resolved.",
    ScannerErrorCode.CONNECTION_FAILED: "The target could not be reached safely.",
    ScannerErrorCode.TIMEOUT: "The target request exceeded a configured time limit.",
    ScannerErrorCode.REDIRECT_LIMIT_EXCEEDED: "The target exceeded the allowed redirect limit.",
    ScannerErrorCode.REDIRECT_LOOP: "The target returned a redirect loop.",
    ScannerErrorCode.UNSAFE_REDIRECT: "A redirect destination is not allowed by scanner policy.",
    ScannerErrorCode.RESPONSE_TOO_LARGE: "The target response exceeded the configured size limit.",
    ScannerErrorCode.UNSUPPORTED_RESPONSE: "The target response could not be processed safely.",
    ScannerErrorCode.SCANNER_FAILURE: "The scanner could not complete this request safely.",
}


class ScannerError(Exception):
    """Base error; never includes URLs, addresses, headers, or exception text in serialization."""

    def __init__(
        self,
        code: ScannerErrorCode,
        *,
        retryable: bool = False,
        status_code: int = 502,
        response_head: ResponseHead | None = None,
        bytes_read: int = 0,
    ) -> None:
        self.code = code
        self.safe_message = _SAFE_MESSAGES[code]
        self.retryable = retryable
        self.status_code = status_code
        # Internal-only partial response metadata; intentionally omitted by to_dict().
        self.response_head = response_head
        self.bytes_read = bytes_read
        super().__init__(self.safe_message)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code.value,
            "message": self.safe_message,
            "retryable": self.retryable,
        }


class InvalidTargetError(ScannerError):
    def __init__(self) -> None:
        super().__init__(ScannerErrorCode.INVALID_URL, status_code=400)


class UnsupportedSchemeError(ScannerError):
    def __init__(self) -> None:
        super().__init__(ScannerErrorCode.UNSUPPORTED_SCHEME, status_code=400)


class UnsupportedPortError(ScannerError):
    def __init__(self) -> None:
        super().__init__(ScannerErrorCode.UNSUPPORTED_PORT, status_code=400)


class UnsupportedMethodError(ScannerError):
    def __init__(self) -> None:
        super().__init__(ScannerErrorCode.UNSUPPORTED_METHOD, status_code=400)


class BlockedDestinationError(ScannerError):
    def __init__(self) -> None:
        super().__init__(ScannerErrorCode.BLOCKED_DESTINATION, status_code=400)


class DnsResolutionError(ScannerError):
    def __init__(self) -> None:
        super().__init__(ScannerErrorCode.DNS_RESOLUTION_FAILED, retryable=True)


class ConnectionFailedError(ScannerError):
    def __init__(self) -> None:
        super().__init__(ScannerErrorCode.CONNECTION_FAILED, retryable=True)


class ScannerTimeoutError(ScannerError):
    def __init__(self) -> None:
        super().__init__(ScannerErrorCode.TIMEOUT, retryable=True, status_code=504)


class RedirectLimitExceededError(ScannerError):
    def __init__(self, response_head: ResponseHead | None = None) -> None:
        super().__init__(
            ScannerErrorCode.REDIRECT_LIMIT_EXCEEDED,
            status_code=502,
            response_head=response_head,
        )


class RedirectLoopError(ScannerError):
    def __init__(self, response_head: ResponseHead | None = None) -> None:
        super().__init__(ScannerErrorCode.REDIRECT_LOOP, status_code=502, response_head=response_head)


class UnsafeRedirectError(ScannerError):
    def __init__(self, response_head: ResponseHead | None = None) -> None:
        super().__init__(ScannerErrorCode.UNSAFE_REDIRECT, status_code=502, response_head=response_head)


class ResponseTooLargeError(ScannerError):
    def __init__(
        self,
        *,
        response_head: ResponseHead,
        bytes_read: int,
    ) -> None:
        super().__init__(
            ScannerErrorCode.RESPONSE_TOO_LARGE,
            status_code=502,
            response_head=response_head,
            bytes_read=bytes_read,
        )


class UnsupportedResponseError(ScannerError):
    def __init__(self, response_head: ResponseHead | None = None) -> None:
        super().__init__(
            ScannerErrorCode.UNSUPPORTED_RESPONSE,
            status_code=502,
            response_head=response_head,
        )


class ScannerFailureError(ScannerError):
    def __init__(self) -> None:
        super().__init__(ScannerErrorCode.SCANNER_FAILURE, status_code=500)
