import asyncio
import ipaddress
import socket
import unittest

import aiohttp

from app.scanner.config import ScannerSettings
from app.scanner.errors import (
    BlockedDestinationError,
    ConnectionFailedError,
    DnsResolutionError,
    RedirectLimitExceededError,
    ResponseTooLargeError,
    ScannerErrorCode,
    ScannerTimeoutError,
    UnsafeRedirectError,
)
from app.scanner.models import NetworkResponse, ObservedCookie, ResolvedAddress, ResponseHead, ScanStatus, ValidatedTarget
from app.scanner.service import ScannerService


def public_address(value: str = "93.184.216.34") -> ResolvedAddress:
    return ResolvedAddress(ipaddress.ip_address(value), socket.AF_INET)


def response(
    url: str,
    status: int = 200,
    headers: tuple[tuple[str, str], ...] = (),
    body: bytes = b"",
    *,
    complete: bool = True,
) -> NetworkResponse:
    head = ResponseHead(
        url=url,
        status_code=status,
        headers=headers,
        content_length=len(body),
        content_type="text/html",
        content_encoding=None,
    )
    return NetworkResponse(head, body, len(body), complete, 2)


class FakeResolver:
    def __init__(self, records: dict[str, tuple[ResolvedAddress, ...] | Exception]) -> None:
        self.records = records
        self.calls: list[str] = []

    async def resolve(self, target: ValidatedTarget, _settings: ScannerSettings) -> tuple[ResolvedAddress, ...]:
        self.calls.append(target.hostname)
        value = self.records.get(target.hostname)
        if isinstance(value, Exception):
            raise value
        if value is None:
            raise DnsResolutionError()
        return value


class FakeTransport:
    def __init__(self, responses: list[NetworkResponse | Exception]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, tuple[str, ...], str]] = []

    async def request(
        self,
        target: ValidatedTarget,
        addresses: tuple[ResolvedAddress, ...] | list[ResolvedAddress],
        method: str,
    ) -> NetworkResponse:
        self.calls.append((target.normalized_url, tuple(address.compressed for address in addresses), method))
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class ScannerServiceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.settings = ScannerSettings()
        self.public = (public_address(),)

    async def test_successful_fetch_builds_context_without_checks(self) -> None:
        target = "https://public-fixture.example.com/"
        resolver = FakeResolver({"public-fixture.example.com": self.public})
        transport = FakeTransport([response(target, headers=(("server", "example"),), body=b"ok")])

        context = await ScannerService(self.settings, resolver=resolver, transport=transport).fetch(target)

        self.assertEqual(context.status, ScanStatus.COMPLETED)
        self.assertEqual(context.normalized_url, target)
        self.assertEqual(context.current_url, target)
        self.assertEqual(context.resolved_addresses, ("93.184.216.34",))
        self.assertEqual(context.http_status, 200)
        self.assertEqual(context.response_body, b"ok")
        self.assertEqual(context.response_headers, (("server", "example"),))
        self.assertEqual(context.redirect_chain, [])
        self.assertIsNone(context.error)

    async def test_http_server_error_is_captured_not_treated_as_transport_failure(self) -> None:
        url = "https://public-fixture.example.com/"
        resolver = FakeResolver({"public-fixture.example.com": self.public})
        transport = FakeTransport([response(url, 503, body=b"unavailable")])

        context = await ScannerService(self.settings, resolver=resolver, transport=transport).fetch(url)

        self.assertEqual(context.status, ScanStatus.COMPLETED)
        self.assertEqual(context.http_status, 503)
        self.assertEqual(context.response_body, b"unavailable")
        self.assertIsNone(context.error)

    async def test_normal_redirect_is_recorded_and_resolved_before_request(self) -> None:
        start = "http://start-fixture.example.com/"
        intermediate = "https://middle-fixture.example.com/step"
        destination = "https://next-fixture.example.com/report"
        resolver = FakeResolver({
            "start-fixture.example.com": self.public,
            "middle-fixture.example.com": (public_address("8.8.8.8"),),
            "next-fixture.example.com": (public_address("2606:4700:4700::1111"),),
        })
        transport = FakeTransport([
            response(start, 302, (("location", intermediate),), complete=False),
            response(intermediate, 307, (("location", "https://next-fixture.example.com/report"),), complete=False),
            response(destination, 200, body=b"ok"),
        ])

        context = await ScannerService(self.settings, resolver=resolver, transport=transport).fetch(start)

        self.assertEqual(context.status, ScanStatus.COMPLETED)
        self.assertEqual(context.current_url, destination)
        self.assertEqual([hop.status_code for hop in context.redirect_chain], [302, 307])
        self.assertEqual(context.redirect_chain[-1].destination_url, destination)
        self.assertEqual([call[2] for call in transport.calls], ["GET", "GET", "GET"])
        self.assertEqual(resolver.calls, ["start-fixture.example.com", "middle-fixture.example.com", "next-fixture.example.com"])
        self.assertEqual(transport.calls[2][1], ("2606:4700:4700::1111",))

    async def test_redirect_to_private_destination_is_rejected_before_request(self) -> None:
        start = "https://start-fixture.example.com/"
        resolver = FakeResolver({
            "start-fixture.example.com": self.public,
            "private-fixture.example.com": BlockedDestinationError(),
        })
        transport = FakeTransport([
            response(start, 302, (("location", "http://private-fixture.example.com/"),), complete=False),
        ])

        context = await ScannerService(self.settings, resolver=resolver, transport=transport).fetch(start)

        self.assertEqual(context.error.code, ScannerErrorCode.UNSAFE_REDIRECT)
        self.assertEqual(len(transport.calls), 1)

    async def test_redirect_to_literal_loopback_is_rejected(self) -> None:
        start = "https://start-fixture.example.com/"
        resolver = FakeResolver({"start-fixture.example.com": self.public})
        transport = FakeTransport([
            response(start, 302, (("location", "http://127.0.0.1/admin"),), complete=False),
        ])

        context = await ScannerService(self.settings, resolver=resolver, transport=transport).fetch(start)

        self.assertEqual(context.error.code, ScannerErrorCode.UNSAFE_REDIRECT)
        self.assertEqual(len(transport.calls), 1)

    async def test_redirect_to_unsupported_scheme_is_rejected(self) -> None:
        start = "https://start-fixture.example.com/"
        resolver = FakeResolver({"start-fixture.example.com": self.public})
        transport = FakeTransport([
            response(start, 302, (("location", "file:///etc/passwd"),), complete=False),
        ])

        context = await ScannerService(self.settings, resolver=resolver, transport=transport).fetch(start)

        self.assertEqual(context.error.code, ScannerErrorCode.UNSAFE_REDIRECT)
        self.assertEqual(len(transport.calls), 1)

    async def test_redirect_limit_is_enforced(self) -> None:
        settings = ScannerSettings(max_redirects=1)
        start = "https://start-fixture.example.com/"
        resolver = FakeResolver({"start-fixture.example.com": self.public})
        transport = FakeTransport([
            response(start, 302, (("location", "/one"),), complete=False),
            response("https://start-fixture.example.com/one", 302, (("location", "/two"),), complete=False),
        ])

        context = await ScannerService(settings, resolver=resolver, transport=transport).fetch(start)

        self.assertEqual(context.error.code, ScannerErrorCode.REDIRECT_LIMIT_EXCEEDED)
        self.assertEqual(len(transport.calls), 2)
        self.assertIsInstance(context.error, RedirectLimitExceededError)

    async def test_redirect_loop_is_detected(self) -> None:
        start = "https://start-fixture.example.com/"
        resolver = FakeResolver({"start-fixture.example.com": self.public})
        transport = FakeTransport([
            response(start, 301, (("location", "/"),), complete=False),
        ])

        context = await ScannerService(self.settings, resolver=resolver, transport=transport).fetch(start)

        self.assertEqual(context.error.code, ScannerErrorCode.REDIRECT_LOOP)
        self.assertEqual(len(transport.calls), 1)

    async def test_dns_failure_is_a_structured_failure(self) -> None:
        resolver = FakeResolver({"missing-fixture.example.com": DnsResolutionError()})
        transport = FakeTransport([])

        context = await ScannerService(self.settings, resolver=resolver, transport=transport).fetch(
            "https://missing-fixture.example.com/"
        )

        self.assertEqual(context.status, ScanStatus.FAILED)
        self.assertEqual(context.error.code, ScannerErrorCode.DNS_RESOLUTION_FAILED)
        self.assertEqual(transport.calls, [])

    async def test_only_get_and_head_are_supported(self) -> None:
        resolver = FakeResolver({})
        transport = FakeTransport([])
        context = await ScannerService(self.settings, resolver=resolver, transport=transport).fetch(
            "https://public-fixture.example.com/", method="POST"
        )
        self.assertEqual(context.error.code, ScannerErrorCode.UNSUPPORTED_METHOD)
        self.assertEqual(resolver.calls, [])
        self.assertEqual(transport.calls, [])

    async def test_head_is_supported_without_a_response_body(self) -> None:
        url = "https://public-fixture.example.com/"
        resolver = FakeResolver({"public-fixture.example.com": self.public})
        transport = FakeTransport([response(url, 200, body=b"")])
        context = await ScannerService(self.settings, resolver=resolver, transport=transport).fetch(
            url, method="HEAD"
        )
        self.assertEqual(context.status, ScanStatus.COMPLETED)
        self.assertEqual(transport.calls[0][2], "HEAD")

    async def test_connection_errors_are_sanitized(self) -> None:
        url = "https://public-fixture.example.com/"
        resolver = FakeResolver({"public-fixture.example.com": self.public})
        transport = FakeTransport([aiohttp.ClientConnectionError("private host and socket details")])

        context = await ScannerService(self.settings, resolver=resolver, transport=transport).fetch(url)

        self.assertEqual(context.error.code, ScannerErrorCode.CONNECTION_FAILED)
        self.assertNotIn("private host", str(context.error))
        self.assertNotIn("private host", str(context.error.to_dict()))

    async def test_scan_deadline_is_enforced(self) -> None:
        settings = ScannerSettings(
            dns_timeout_seconds=0.02,
            connect_timeout_seconds=0.02,
            write_timeout_seconds=0.02,
            read_timeout_seconds=0.02,
            overall_timeout_seconds=0.05,
        )

        class SlowTransport:
            async def request(self, *_args: object) -> NetworkResponse:
                await asyncio.sleep(0.2)
                raise AssertionError("deadline should interrupt before this line")

        resolver = FakeResolver({"public-fixture.example.com": self.public})
        context = await ScannerService(settings, resolver=resolver, transport=SlowTransport()).fetch(
            "https://public-fixture.example.com/"
        )
        self.assertEqual(context.error.code, ScannerErrorCode.TIMEOUT)
        self.assertIsInstance(context.error, ScannerTimeoutError)

    async def test_oversize_error_preserves_internal_headers_but_not_in_serialization(self) -> None:
        url = "https://public-fixture.example.com/?auth=secret"
        head = ResponseHead(
            url=url,
            status_code=200,
            headers=(),
            content_length=100,
            content_type="text/html",
            content_encoding=None,
            cookies=(
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
            ),
            set_cookie_header_count=1,
        )
        resolver = FakeResolver({"public-fixture.example.com": self.public})
        transport = FakeTransport([ResponseTooLargeError(response_head=head, bytes_read=9)])

        context = await ScannerService(self.settings, resolver=resolver, transport=transport).fetch(url)

        self.assertEqual(context.http_status, 200)
        self.assertEqual(context.response_cookies[0].name, "session")
        self.assertIsNone(context.response_body)
        self.assertEqual(context.response_body_bytes, 9)
        self.assertNotIn("secret", str(context.error.to_dict()))
        self.assertNotIn("do-not-expose", str(context.error.to_dict()))


if __name__ == "__main__":
    unittest.main()
