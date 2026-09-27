"""Internal scanner models; deliberately independent of Supabase persistence."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from uuid import uuid4

from app.scanner.errors import ScannerError

IPAddress = IPv4Address | IPv6Address
HeaderPairs = tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class ObservedCookie:
    """Normalized Set-Cookie attributes; intentionally contains no cookie value."""

    name: str
    secure: bool
    http_only: bool
    same_site: str | None
    domain_scope: str
    path_scope: str
    max_age_present: bool
    max_age_valid: bool
    max_age_nonpositive: bool
    expires_present: bool
    expires_valid: bool
    prefix_kind: str | None
    prefix_requirements_satisfied: bool | None


class ScanStatus(StrEnum):
    VALIDATING = "validating"
    RESOLVING = "resolving"
    REQUESTING = "requesting"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ValidatedTarget:
    requested_url: str
    normalized_url: str
    scheme: str
    hostname: str
    port: int
    request_target: str
    is_ip_literal: bool


@dataclass(frozen=True, slots=True)
class ResolvedAddress:
    address: IPAddress
    family: int

    @property
    def compressed(self) -> str:
        return self.address.compressed


@dataclass(frozen=True, slots=True)
class RedirectHop:
    source_url: str
    status_code: int
    location: str
    destination_url: str


@dataclass(frozen=True, slots=True)
class ResponseHead:
    url: str
    status_code: int
    headers: HeaderPairs
    content_length: int | None
    content_type: str | None
    content_encoding: str | None
    cookies: tuple[ObservedCookie, ...] = ()
    malformed_cookie_header_count: int = 0
    set_cookie_header_count: int = 0

    def get_header(self, name: str) -> str | None:
        wanted = name.lower()
        for header_name, value in self.headers:
            if header_name.lower() == wanted:
                return value
        return None


@dataclass(frozen=True, slots=True)
class NetworkResponse:
    head: ResponseHead
    body: bytes
    bytes_read: int
    body_complete: bool
    elapsed_ms: int


@dataclass(slots=True)
class ScanContext:
    """Mutable in-memory context for one request sequence; contains no auth secrets."""

    requested_url: str
    scan_id: str = field(default_factory=lambda: str(uuid4()))
    status: ScanStatus = ScanStatus.VALIDATING
    normalized_url: str | None = None
    current_url: str | None = None
    hostname: str | None = None
    scheme: str | None = None
    port: int | None = None
    resolved_addresses: tuple[str, ...] = ()
    redirect_chain: list[RedirectHop] = field(default_factory=list)
    http_status: int | None = None
    response_headers: HeaderPairs = ()
    response_cookies: tuple[ObservedCookie, ...] = ()
    malformed_cookie_header_count: int = 0
    set_cookie_header_count: int = 0
    response_body: bytes | None = None
    response_body_bytes: int = 0
    response_body_complete: bool = False
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    duration_ms: int | None = None
    error: ScannerError | None = None

    def mark_completed(self) -> None:
        self.status = ScanStatus.COMPLETED
        self.finish_timing()

    def mark_failed(self, error: ScannerError) -> None:
        self.status = ScanStatus.FAILED
        self.error = error
        self.finish_timing()

    def finish_timing(self) -> None:
        self.completed_at = datetime.now(UTC)
        self.duration_ms = max(
            0,
            int((self.completed_at - self.started_at).total_seconds() * 1_000),
        )
