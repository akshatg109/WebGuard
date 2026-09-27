"""Environment-backed resource limits and allowlists for scanner requests."""

from __future__ import annotations

from dataclasses import dataclass
from os import environ
from typing import Mapping

_MAX_PORT = 65_535


@dataclass(frozen=True, slots=True)
class ScannerSettings:
    allowed_schemes: frozenset[str] = frozenset({"http", "https"})
    allowed_ports: frozenset[int] = frozenset({80, 443, 8080, 8443})
    max_url_length: int = 2_048
    max_redirects: int = 5
    max_response_bytes: int = 1_000_000
    max_connections: int = 10
    max_response_headers: int = 128
    max_header_line_bytes: int = 8_190
    max_header_field_bytes: int = 8_190
    dns_timeout_seconds: float = 3.0
    connect_timeout_seconds: float = 3.0
    write_timeout_seconds: float = 3.0
    read_timeout_seconds: float = 8.0
    overall_timeout_seconds: float = 30.0
    read_chunk_bytes: int = 16_384
    user_agent: str = "WebGuard-Security-Scanner/0.1"

    def __post_init__(self) -> None:
        if not self.allowed_schemes or not self.allowed_schemes <= {"http", "https"}:
            raise ValueError("SCANNER_ALLOWED_SCHEMES may contain only http and https.")
        if not self.allowed_ports or any(port < 1 or port > _MAX_PORT for port in self.allowed_ports):
            raise ValueError("SCANNER_ALLOWED_PORTS must contain valid TCP ports.")
        _bounded_int(self.max_url_length, "SCANNER_MAX_URL_LENGTH", 64, 8_192)
        _bounded_int(self.max_redirects, "SCANNER_MAX_REDIRECTS", 0, 10)
        _bounded_int(self.max_response_bytes, "SCANNER_MAX_RESPONSE_BYTES", 1, 50_000_000)
        _bounded_int(self.max_connections, "SCANNER_MAX_CONNECTIONS", 1, 100)
        _bounded_int(self.max_response_headers, "SCANNER_MAX_RESPONSE_HEADERS", 1, 512)
        _bounded_int(self.max_header_line_bytes, "SCANNER_MAX_HEADER_LINE_BYTES", 256, 16_384)
        _bounded_int(self.max_header_field_bytes, "SCANNER_MAX_HEADER_FIELD_BYTES", 256, 16_384)
        _bounded_int(self.read_chunk_bytes, "SCANNER_READ_CHUNK_BYTES", 1, 65_536)
        _bounded_timeout(self.dns_timeout_seconds, "SCANNER_DNS_TIMEOUT_SECONDS", 10)
        _bounded_timeout(self.connect_timeout_seconds, "SCANNER_CONNECT_TIMEOUT_SECONDS", 10)
        _bounded_timeout(self.write_timeout_seconds, "SCANNER_WRITE_TIMEOUT_SECONDS", 10)
        _bounded_timeout(self.read_timeout_seconds, "SCANNER_READ_TIMEOUT_SECONDS", 30)
        _bounded_timeout(self.overall_timeout_seconds, "SCANNER_OVERALL_TIMEOUT_SECONDS", 120)
        if self.overall_timeout_seconds < max(
            self.dns_timeout_seconds,
            self.connect_timeout_seconds,
            self.write_timeout_seconds,
            self.read_timeout_seconds,
        ):
            raise ValueError("SCANNER_OVERALL_TIMEOUT_SECONDS must cover each per-operation timeout.")

    @property
    def request_timeout_seconds(self) -> float:
        """Bound connect, fixed-header write, and individual response-read phases."""
        return min(
            self.overall_timeout_seconds,
            self.connect_timeout_seconds + self.write_timeout_seconds + self.read_timeout_seconds,
        )

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> "ScannerSettings":
        env = environment if environment is not None else environ
        defaults = cls()
        return cls(
            allowed_schemes=_csv_lower(env.get("SCANNER_ALLOWED_SCHEMES", "http,https")),
            allowed_ports=_csv_int(env.get("SCANNER_ALLOWED_PORTS", "80,443,8080,8443"), "SCANNER_ALLOWED_PORTS"),
            max_url_length=_env_int(env, "SCANNER_MAX_URL_LENGTH", defaults.max_url_length),
            max_redirects=_env_int(env, "SCANNER_MAX_REDIRECTS", defaults.max_redirects),
            max_response_bytes=_env_int(env, "SCANNER_MAX_RESPONSE_BYTES", defaults.max_response_bytes),
            max_connections=_env_int(env, "SCANNER_MAX_CONNECTIONS", defaults.max_connections),
            max_response_headers=_env_int(env, "SCANNER_MAX_RESPONSE_HEADERS", defaults.max_response_headers),
            max_header_line_bytes=_env_int(env, "SCANNER_MAX_HEADER_LINE_BYTES", defaults.max_header_line_bytes),
            max_header_field_bytes=_env_int(env, "SCANNER_MAX_HEADER_FIELD_BYTES", defaults.max_header_field_bytes),
            dns_timeout_seconds=_env_float(env, "SCANNER_DNS_TIMEOUT_SECONDS", defaults.dns_timeout_seconds),
            connect_timeout_seconds=_env_float(env, "SCANNER_CONNECT_TIMEOUT_SECONDS", defaults.connect_timeout_seconds),
            write_timeout_seconds=_env_float(env, "SCANNER_WRITE_TIMEOUT_SECONDS", defaults.write_timeout_seconds),
            read_timeout_seconds=_env_float(env, "SCANNER_READ_TIMEOUT_SECONDS", defaults.read_timeout_seconds),
            overall_timeout_seconds=_env_float(env, "SCANNER_OVERALL_TIMEOUT_SECONDS", defaults.overall_timeout_seconds),
            read_chunk_bytes=_env_int(env, "SCANNER_READ_CHUNK_BYTES", defaults.read_chunk_bytes),
        )


def _bounded_int(value: int, name: str, minimum: int, maximum: int) -> None:
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}.")


def _bounded_timeout(value: float, name: str, maximum: float) -> None:
    if not 0 < value <= maximum:
        raise ValueError(f"{name} must be greater than 0 and no more than {maximum} seconds.")


def _csv_lower(value: str) -> frozenset[str]:
    return frozenset(part.strip().lower() for part in value.split(",") if part.strip())


def _csv_int(value: str, name: str) -> frozenset[int]:
    try:
        return frozenset(int(part.strip(), 10) for part in value.split(",") if part.strip())
    except ValueError as exc:
        raise ValueError(f"{name} must be a comma-separated list of ports.") from exc


def _env_int(env: Mapping[str, str], name: str, default: int) -> int:
    try:
        return int(env.get(name, str(default)), 10)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer.") from exc


def _env_float(env: Mapping[str, str], name: str, default: float) -> float:
    try:
        return float(env.get(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} must be a number of seconds.") from exc
