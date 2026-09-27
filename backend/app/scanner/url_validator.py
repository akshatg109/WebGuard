"""Strict URL parsing and canonicalization at the scanner boundary."""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlsplit, urlunsplit

import idna

from app.scanner.config import ScannerSettings
from app.scanner.errors import (
    BlockedDestinationError,
    InvalidTargetError,
    UnsupportedPortError,
    UnsupportedSchemeError,
)
from app.scanner.models import ValidatedTarget
from app.scanner.network import is_public_address

_INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9a-fA-F]{2})")
_NUMERIC_HOST = re.compile(r"^[0-9.]+$")
_BLOCKED_HOSTS = frozenset(
    {
        "localhost",
        "metadata",
        "metadata.goog",
        "metadata.google.internal",
        "instance-data.ec2.internal",
        "home.arpa",
    }
)
_BLOCKED_SUFFIXES = (
    ".localhost",
    ".local",
    ".localdomain",
    ".internal",
    ".home.arpa",
    ".test",
    ".example",
    ".invalid",
)


def validate_target_url(
    url: str,
    settings: ScannerSettings | None = None,
) -> ValidatedTarget:
    """Parse a target without performing DNS or any network I/O.

    Fragments are removed because they are not sent in HTTP requests. Unsafe or
    ambiguous host spellings are rejected instead of rewritten to another host.
    """
    policy = settings or ScannerSettings()
    if not isinstance(url, str) or not url or len(url) > policy.max_url_length:
        raise InvalidTargetError()
    if url != url.strip() or any(
        char.isspace() or ord(char) < 0x20 or ord(char) == 0x7F for char in url
    ):
        raise InvalidTargetError()
    if "\\" in url:
        raise InvalidTargetError()
    if _INVALID_PERCENT_ESCAPE.search(url):
        raise InvalidTargetError()

    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        if not scheme:
            raise InvalidTargetError()
        if scheme not in policy.allowed_schemes:
            raise UnsupportedSchemeError()
        if not parts.netloc or parts.hostname is None:
            raise InvalidTargetError()
        if parts.username is not None or parts.password is not None or "@" in parts.netloc:
            raise InvalidTargetError()
        if parts.netloc.endswith(":"):
            raise InvalidTargetError()
        raw_host = parts.hostname
        port = parts.port
    except (ValueError, UnicodeError):
        raise InvalidTargetError() from None

    if not raw_host or "%" in raw_host:
        # Reject escaped host labels and IPv6 zone identifiers; neither is needed
        # for a public website and both can produce parser/resolver differences.
        raise InvalidTargetError()

    host, ip_literal = _canonical_host(raw_host)
    if _is_blocked_local_name(host):
        raise BlockedDestinationError()

    effective_port = port if port is not None else (443 if scheme == "https" else 80)
    if effective_port not in policy.allowed_ports:
        raise UnsupportedPortError()

    if ip_literal is not None and not is_public_address(ip_literal):
        raise BlockedDestinationError()

    path = parts.path or "/"
    request_target = path + (f"?{parts.query}" if parts.query else "")
    authority_host = f"[{host}]" if ip_literal and ip_literal.version == 6 else host
    default_port = 443 if scheme == "https" else 80
    authority = authority_host if effective_port == default_port else f"{authority_host}:{effective_port}"
    normalized = urlunsplit((scheme, authority, path, parts.query, ""))

    return ValidatedTarget(
        requested_url=url,
        normalized_url=normalized,
        scheme=scheme,
        hostname=host,
        port=effective_port,
        request_target=request_target,
        is_ip_literal=ip_literal is not None,
    )


def _canonical_host(host: str) -> tuple[str, ipaddress.IPv4Address | ipaddress.IPv6Address | None]:
    if host.endswith(".."):
        raise InvalidTargetError()
    host_without_root_dot = host[:-1] if host.endswith(".") else host
    if not host_without_root_dot:
        raise InvalidTargetError()

    try:
        address = ipaddress.ip_address(host_without_root_dot)
    except ValueError:
        address = None

    if address is not None:
        return address.compressed.lower(), address

    # Numeric hosts which are not canonical IP literals may be interpreted as
    # octal, integer, or shortened IPv4 forms by some resolvers and libraries.
    if _NUMERIC_HOST.fullmatch(host_without_root_dot):
        raise InvalidTargetError()
    try:
        # inet_aton recognizes legacy integer/octal/hex and shortened IPv4 forms
        # on common platforms. If it parses a non-canonical host, reject rather
        # than letting a downstream resolver reinterpret it as a numeric address.
        socket.inet_aton(host_without_root_dot)
    except OSError:
        pass
    else:
        raise InvalidTargetError()

    try:
        ascii_host = idna.encode(host_without_root_dot, uts46=True, std3_rules=True).decode("ascii").lower()
    except (idna.IDNAError, UnicodeError):
        raise InvalidTargetError() from None
    if len(ascii_host) > 253 or any(not label for label in ascii_host.split(".")):
        raise InvalidTargetError()
    if "." not in ascii_host and ascii_host not in _BLOCKED_HOSTS:
        raise InvalidTargetError()
    return ascii_host, None


def _is_blocked_local_name(host: str) -> bool:
    return host in _BLOCKED_HOSTS or any(host.endswith(suffix) for suffix in _BLOCKED_SUFFIXES)
