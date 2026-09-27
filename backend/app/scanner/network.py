"""Public-address validation, DNS pinning, and bounded async HTTP transport."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from collections.abc import Awaitable, Callable, Sequence
from typing import Protocol

import aiohttp
from aiohttp.abc import AbstractResolver, ResolveResult

from app.scanner.cookie_metadata import parse_set_cookie_headers
from app.scanner.config import ScannerSettings
from app.scanner.errors import (
    BlockedDestinationError,
    ConnectionFailedError,
    DnsResolutionError,
    ResponseTooLargeError,
    ScannerTimeoutError,
    UnsupportedMethodError,
    UnsupportedResponseError,
)
from app.scanner.models import NetworkResponse, ResolvedAddress, ResponseHead, ValidatedTarget

_UNSAFE_V4 = tuple(
    ipaddress.ip_network(value)
    for value in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",  # carrier-grade NAT
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",  # IETF protocol assignments (conservative)
        "192.0.2.0/24",
        "192.88.99.0/24",  # deprecated 6to4 relay anycast
        "192.168.0.0/16",
        "198.18.0.0/15",  # benchmarking
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved / limited broadcast
        "168.63.129.16/32",  # Azure platform virtual IP
    )
)
_UNSAFE_V6 = tuple(
    ipaddress.ip_network(value)
    for value in (
        "::/128",  # unspecified
        "::1/128",  # loopback
        "64:ff9b::/96",  # well-known NAT64 embeds IPv4 destinations
        "64:ff9b:1::/48",  # local-use NAT64
        "100::/64",  # discard-only
        "2001::/23",  # IETF protocol assignments, including Teredo
        "2001:db8::/32",  # documentation
        "2002::/16",  # 6to4 embeds IPv4 destinations
        "fc00::/7",  # unique-local
        "fe80::/10",  # link-local
        "fec0::/10",  # deprecated site-local
        "ff00::/8",  # multicast
    )
)


def is_public_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return true only for globally routable unicast addresses we permit."""
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None or address.sixtofour is not None or address.teredo is not None:
            return False
        if any(address in network for network in _UNSAFE_V6):
            return False
    else:
        if any(address in network for network in _UNSAFE_V4):
            return False
    return address.is_global and not address.is_multicast and not address.is_unspecified


class AddressResolver(Protocol):
    async def resolve(
        self, target: ValidatedTarget, settings: ScannerSettings
    ) -> tuple[ResolvedAddress, ...]: ...


GetAddrInfo = Callable[..., Awaitable[list[tuple[int, int, int, str, tuple]]]]


class SystemAddressResolver:
    """Resolve once, validate every answer, then return addresses to pin."""

    def __init__(self, getaddrinfo: GetAddrInfo | None = None) -> None:
        self._getaddrinfo = getaddrinfo

    async def resolve(self, target: ValidatedTarget, settings: ScannerSettings) -> tuple[ResolvedAddress, ...]:
        if target.is_ip_literal:
            try:
                address = ipaddress.ip_address(target.hostname)
            except ValueError:
                raise BlockedDestinationError() from None
            if not is_public_address(address):
                raise BlockedDestinationError()
            return (ResolvedAddress(address, socket.AF_INET6 if address.version == 6 else socket.AF_INET),)

        loop = asyncio.get_running_loop()
        getaddrinfo = self._getaddrinfo or loop.getaddrinfo
        try:
            results = await asyncio.wait_for(
                getaddrinfo(
                    target.hostname,
                    target.port,
                    family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM,
                    proto=socket.IPPROTO_TCP,
                ),
                timeout=settings.dns_timeout_seconds,
            )
        except TimeoutError:
            raise ScannerTimeoutError() from None
        except (OSError, socket.gaierror):
            raise DnsResolutionError() from None

        addresses: dict[str, ResolvedAddress] = {}
        for family, _socktype, _proto, _canonname, sockaddr in results:
            try:
                raw_address = sockaddr[0]
                # Scoped IPv6 answers are local-interface-specific, not public targets.
                if "%" in raw_address:
                    raise ValueError("scoped IPv6")
                address = ipaddress.ip_address(raw_address)
            except (IndexError, ValueError):
                raise BlockedDestinationError() from None
            if not is_public_address(address):
                # Reject mixed answer sets too; the connector must not choose a
                # public answer while another answer points into a protected range.
                raise BlockedDestinationError()
            addresses[address.compressed] = ResolvedAddress(address, family)

        if not addresses:
            raise DnsResolutionError()
        return tuple(addresses.values())


class PinnedResolver(AbstractResolver):
    """aiohttp resolver that returns only addresses already checked by policy.

    It never performs a second DNS lookup. A fresh connector is used for every
    request/redirect hop, with DNS caching and keep-alive disabled.
    """

    def __init__(self, hostname: str, addresses: Sequence[ResolvedAddress]) -> None:
        if not addresses or any(not is_public_address(item.address) for item in addresses):
            raise BlockedDestinationError()
        self._hostname = hostname.lower().rstrip(".")
        self._addresses = tuple(addresses)

    async def resolve(
        self,
        host: str,
        port: int = 0,
        family: socket.AddressFamily = socket.AF_INET,
    ) -> list[ResolveResult]:
        if host.lower().rstrip(".") != self._hostname:
            raise OSError("Unpinned scanner hostname")
        results: list[ResolveResult] = []
        for resolved in self._addresses:
            if family not in (socket.AF_UNSPEC, resolved.family):
                continue
            results.append(
                {
                    "hostname": self._hostname,
                    "host": resolved.compressed,
                    "port": port,
                    "family": resolved.family,
                    "proto": socket.IPPROTO_TCP,
                    "flags": socket.AI_NUMERICHOST,
                }
            )
        if not results:
            raise OSError("No pinned address for scanner hostname")
        return results

    async def close(self) -> None:
        return None


class HttpTransport(Protocol):
    async def request(
        self,
        target: ValidatedTarget,
        addresses: Sequence[ResolvedAddress],
        method: str,
    ) -> NetworkResponse: ...


class AiohttpTransport:
    """Small-header GET/HEAD transport pinned to previously checked addresses."""

    _REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

    def __init__(self, settings: ScannerSettings) -> None:
        self._settings = settings

    async def request(
        self,
        target: ValidatedTarget,
        addresses: Sequence[ResolvedAddress],
        method: str,
    ) -> NetworkResponse:
        method = method.upper()
        if method not in {"GET", "HEAD"}:
            raise UnsupportedMethodError()
        if not addresses or any(not is_public_address(item.address) for item in addresses):
            raise BlockedDestinationError()
        started = time.perf_counter()
        resolver = PinnedResolver(target.hostname, addresses)
        connector = aiohttp.TCPConnector(
            resolver=resolver,
            use_dns_cache=False,
            force_close=True,
            limit=self._settings.max_connections,
            limit_per_host=self._settings.max_connections,
            family=socket.AF_UNSPEC,
        )
        timeout = aiohttp.ClientTimeout(
            total=self._settings.request_timeout_seconds,
            connect=self._settings.connect_timeout_seconds,
            sock_connect=self._settings.connect_timeout_seconds,
            sock_read=self._settings.read_timeout_seconds,
        )
        headers = {
            "User-Agent": self._settings.user_agent,
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
            "Accept-Encoding": "identity",
        }

        try:
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                trust_env=False,
                auto_decompress=False,
                cookie_jar=aiohttp.DummyCookieJar(),
                raise_for_status=False,
                max_headers=self._settings.max_response_headers,
                max_line_size=self._settings.max_header_line_bytes,
                max_field_size=self._settings.max_header_field_bytes,
                read_bufsize=self._settings.read_chunk_bytes,
            ) as session:
                async with session.request(
                    method,
                    target.normalized_url,
                    headers=headers,
                    allow_redirects=False,
                    skip_auto_headers={"Accept", "Accept-Encoding", "User-Agent"},
                ) as response:
                    head = _response_head(response, target.normalized_url)
                    location = head.get_header("location")
                    if response.status in self._REDIRECT_STATUSES and location is not None:
                        return NetworkResponse(head, b"", 0, False, _elapsed_ms(started))
                    if method == "HEAD" or response.status in {204, 304}:
                        return NetworkResponse(head, b"", 0, True, _elapsed_ms(started))
                    if head.content_length is not None and head.content_length > self._settings.max_response_bytes:
                        raise ResponseTooLargeError(response_head=head, bytes_read=0)

                    body = bytearray()
                    bytes_read = 0
                    while True:
                        # Read at most one byte beyond the cap to detect overflow.
                        remaining = self._settings.max_response_bytes - len(body)
                        chunk = await response.content.read(
                            min(self._settings.read_chunk_bytes, remaining + 1)
                        )
                        if not chunk:
                            break
                        bytes_read += len(chunk)
                        if len(body) + len(chunk) > self._settings.max_response_bytes:
                            raise ResponseTooLargeError(response_head=head, bytes_read=bytes_read)
                        body.extend(chunk)
                    return NetworkResponse(head, bytes(body), bytes_read, True, _elapsed_ms(started))
        except ResponseTooLargeError:
            raise
        except (asyncio.TimeoutError, TimeoutError, aiohttp.ServerTimeoutError):
            raise ScannerTimeoutError() from None
        except aiohttp.ClientConnectorDNSError:
            # The HTTP connector should only see numeric addresses from PinnedResolver.
            raise DnsResolutionError() from None
        except aiohttp.ClientResponseError:
            raise UnsupportedResponseError() from None
        except (aiohttp.ClientError, OSError, ValueError):
            raise ConnectionFailedError() from None
        except Exception:
            # Do not carry aiohttp exception text, request URLs, or local details
            # into future API responses.
            raise UnsupportedResponseError() from None


def _response_head(response: aiohttp.ClientResponse, url: str) -> ResponseHead:
    try:
        header_pairs: list[tuple[str, str]] = []
        set_cookie_values: list[str] = []
        for raw_name, raw_value in response.raw_headers:
            name = raw_name.decode("latin-1").lower()
            value = raw_value.decode("latin-1")
            if name == "set-cookie":
                set_cookie_values.append(value)
            else:
                header_pairs.append((name, value))
    except (AttributeError, UnicodeError):
        raise UnsupportedResponseError() from None
    cookies, malformed_cookie_count = parse_set_cookie_headers(set_cookie_values, target_url=url)
    return ResponseHead(
        url=url,
        status_code=response.status,
        headers=tuple(header_pairs),
        content_length=response.content_length,
        content_type=response.headers.get("Content-Type"),
        content_encoding=response.headers.get("Content-Encoding"),
        cookies=cookies,
        malformed_cookie_header_count=malformed_cookie_count,
        set_cookie_header_count=len(set_cookie_values),
    )


def _elapsed_ms(started: float) -> int:
    return max(0, int((time.perf_counter() - started) * 1_000))
