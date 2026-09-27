"""Orchestrate one bounded HTTP fetch without executing security checks."""

from __future__ import annotations

import asyncio
from urllib.parse import urljoin

import aiohttp

from app.scanner.config import ScannerSettings
from app.scanner.errors import (
    ConnectionFailedError,
    RedirectLimitExceededError,
    RedirectLoopError,
    ScannerError,
    ScannerFailureError,
    ScannerTimeoutError,
    UnsafeRedirectError,
    UnsupportedMethodError,
)
from app.scanner.models import (
    NetworkResponse,
    RedirectHop,
    ResolvedAddress,
    ScanContext,
    ScanStatus,
    ValidatedTarget,
)
from app.scanner.network import AiohttpTransport, AddressResolver, HttpTransport, SystemAddressResolver
from app.scanner.url_validator import validate_target_url

_SAFE_METHODS = frozenset({"GET", "HEAD"})
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class ScannerService:
    """Safe HTTP collection primitive; no checks, persistence, or public route.

    This internal service does not authenticate callers. Any future route must
    verify the user's session, enforce authorization/rate limits, and only then
    call this service. Keep an app-scoped instance so its concurrency semaphore
    is shared across requests. Phase 4A intentionally mounts no such route.
    """

    def __init__(
        self,
        settings: ScannerSettings | None = None,
        *,
        resolver: AddressResolver | None = None,
        transport: HttpTransport | None = None,
    ) -> None:
        self.settings = settings or ScannerSettings.from_environment()
        self._resolver = resolver or SystemAddressResolver()
        self._transport = transport or AiohttpTransport(self.settings)
        # Bound simultaneous scan contexts per service instance, not just each
        # per-hop aiohttp connector.
        self._slots = asyncio.Semaphore(self.settings.max_connections)

    async def fetch(self, url: str, *, method: str = "GET") -> ScanContext:
        """Validate a URL and capture one final HTTP response plus redirect history.

        Only GET and HEAD are accepted. Every redirect is canonicalized, resolved,
        and checked before the transport can connect to its pinned addresses.
        Errors are returned on the internal ScanContext as stable ScannerError
        objects; their public serialization contains no URL or network detail.
        """
        context = ScanContext(requested_url=url if isinstance(url, str) else "")
        normalized_method = method.upper() if isinstance(method, str) else ""

        try:
            if normalized_method not in _SAFE_METHODS:
                raise UnsupportedMethodError()
            await asyncio.wait_for(
                self._fetch_into_context(context, url, normalized_method),
                timeout=self.settings.overall_timeout_seconds,
            )
            context.mark_completed()
        except ScannerError as exc:
            self._capture_partial_response(context, exc)
            context.mark_failed(exc)
        except (asyncio.TimeoutError, TimeoutError):
            error = ScannerTimeoutError()
            context.mark_failed(error)
        except (aiohttp.ClientError, OSError, ConnectionError):
            context.mark_failed(ConnectionFailedError())
        except Exception:
            # Do not include exception strings or local details in scan state.
            context.mark_failed(ScannerFailureError())
        return context

    async def _fetch_into_context(
        self,
        context: ScanContext,
        url: str,
        method: str,
    ) -> None:
        async with self._slots:
            target = validate_target_url(url, self.settings)
            context.normalized_url = target.normalized_url
            pinned_addresses: tuple[ResolvedAddress, ...] | None = None
            visited: set[str] = set()

            while True:
                if target.normalized_url in visited:
                    raise RedirectLoopError()
                visited.add(target.normalized_url)
                context.status = ScanStatus.RESOLVING
                context.current_url = target.normalized_url
                context.hostname = target.hostname
                context.scheme = target.scheme
                context.port = target.port

                addresses = pinned_addresses
                if addresses is None:
                    addresses = await self._resolver.resolve(target, self.settings)
                context.resolved_addresses = tuple(address.compressed for address in addresses)

                context.status = ScanStatus.REQUESTING
                response = await self._transport.request(target, addresses, method)
                self._capture_response(context, response)

                location = response.head.get_header("location")
                if response.head.status_code not in _REDIRECT_STATUSES or location is None:
                    return
                if len(context.redirect_chain) >= self.settings.max_redirects:
                    raise RedirectLimitExceededError(response.head)

                destination_text = urljoin(target.normalized_url, location)
                try:
                    destination = validate_target_url(destination_text, self.settings)
                    # Resolve now, before the next connection; no later unpinned
                    # DNS lookup can replace this answer set.
                    destination_addresses = await self._resolver.resolve(destination, self.settings)
                except ScannerError:
                    raise UnsafeRedirectError(response.head) from None

                context.redirect_chain.append(
                    RedirectHop(
                        source_url=target.normalized_url,
                        status_code=response.head.status_code,
                        location=location,
                        destination_url=destination.normalized_url,
                    )
                )
                target = destination
                pinned_addresses = destination_addresses

    @staticmethod
    def _capture_response(context: ScanContext, response: NetworkResponse) -> None:
        context.current_url = response.head.url
        context.http_status = response.head.status_code
        context.response_headers = response.head.headers
        context.response_cookies = response.head.cookies
        context.malformed_cookie_header_count = response.head.malformed_cookie_header_count
        context.set_cookie_header_count = response.head.set_cookie_header_count
        context.response_body = response.body
        context.response_body_bytes = response.bytes_read
        context.response_body_complete = response.body_complete

    @staticmethod
    def _capture_partial_response(context: ScanContext, error: ScannerError) -> None:
        head = error.response_head
        if head is None:
            return
        context.current_url = head.url
        context.http_status = head.status_code
        context.response_headers = head.headers
        context.response_cookies = head.cookies
        context.malformed_cookie_header_count = head.malformed_cookie_header_count
        context.set_cookie_header_count = head.set_cookie_header_count
        context.response_body = None
        context.response_body_bytes = error.bytes_read
        context.response_body_complete = False
