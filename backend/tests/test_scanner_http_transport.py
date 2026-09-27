import asyncio
import ipaddress
import socket
import unittest
from unittest.mock import patch

from app.scanner.config import ScannerSettings
from app.scanner.errors import (
    BlockedDestinationError,
    ConnectionFailedError,
    ResponseTooLargeError,
    ScannerTimeoutError,
    UnsupportedMethodError,
)
from app.scanner.models import ResolvedAddress, ValidatedTarget
from app.scanner.network import AiohttpTransport


class AiohttpTransportTests(unittest.IsolatedAsyncioTestCase):
    async def _start_server(self, response_bytes: bytes, *, delay: float = 0.0):
        requests: list[bytes] = []

        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                request_head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=1)
                requests.append(request_head)
                if delay:
                    await asyncio.sleep(delay)
                writer.write(response_bytes)
                await writer.drain()
            except (asyncio.IncompleteReadError, ConnectionError, asyncio.TimeoutError):
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except ConnectionError:
                    pass

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        self.addAsyncCleanup(self._close_server, server)
        return server, port, requests

    @staticmethod
    async def _close_server(server: asyncio.AbstractServer) -> None:
        server.close()
        await server.wait_closed()

    def _target(self, port: int, *, path: str = "/") -> ValidatedTarget:
        url = f"http://scanner-test.invalid:{port}{path}"
        return ValidatedTarget(
            requested_url=url,
            normalized_url=url,
            scheme="http",
            hostname="scanner-test.invalid",
            port=port,
            request_target=path,
            is_ip_literal=False,
        )

    @staticmethod
    def _loopback_pin() -> tuple[ResolvedAddress, ...]:
        return (ResolvedAddress(ipaddress.ip_address("127.0.0.1"), socket.AF_INET),)

    async def test_get_captures_response_and_sends_only_scanner_headers(self) -> None:
        _server, port, requests = await self._start_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok"
        )
        transport = AiohttpTransport(ScannerSettings())

        # The fixture binds loopback. This unit test isolates HTTP formatting and
        # streaming; production service paths enforce the real public-IP policy.
        with patch("app.scanner.network.is_public_address", return_value=True):
            result = await transport.request(self._target(port), self._loopback_pin(), "GET")

        self.assertEqual(result.head.status_code, 200)
        self.assertEqual(result.body, b"ok")
        self.assertTrue(result.body_complete)
        request = requests[0].lower()
        self.assertIn(b"get / http/1.1", request)
        self.assertIn(b"user-agent: webguard-security-scanner/0.1", request)
        self.assertIn(b"accept-encoding: identity", request)
        self.assertNotIn(b"cookie:", request)
        self.assertNotIn(b"authorization:", request)

    async def test_server_error_status_is_returned_as_response_metadata(self) -> None:
        _server, port, _requests = await self._start_server(
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\n\r\ndown"
        )
        transport = AiohttpTransport(ScannerSettings())
        with patch("app.scanner.network.is_public_address", return_value=True):
            result = await transport.request(self._target(port), self._loopback_pin(), "GET")
        self.assertEqual(result.head.status_code, 503)
        self.assertEqual(result.body, b"down")

    async def test_set_cookie_values_are_normalized_out_of_response_metadata(self) -> None:
        _server, port, _requests = await self._start_server(
            b"HTTP/1.1 200 OK\r\nSet-Cookie: sessionid=super-secret; Secure; HttpOnly; SameSite=Lax\r\nContent-Length: 0\r\n\r\n"
        )
        transport = AiohttpTransport(ScannerSettings())
        with patch("app.scanner.network.is_public_address", return_value=True):
            result = await transport.request(self._target(port), self._loopback_pin(), "GET")
        self.assertEqual(result.head.cookies[0].name, "sessionid")
        self.assertTrue(result.head.cookies[0].secure)
        self.assertTrue(result.head.cookies[0].http_only)
        self.assertEqual(result.head.cookies[0].same_site, "lax")
        self.assertEqual(result.head.set_cookie_header_count, 1)
        self.assertNotIn("set-cookie", str(result.head.headers).casefold())
        self.assertNotIn("super-secret", repr(result))

    async def test_redirect_response_is_not_followed_by_aiohttp(self) -> None:
        _server, port, requests = await self._start_server(
            b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/blocked\r\nContent-Length: 5\r\n\r\nhello"
        )
        transport = AiohttpTransport(ScannerSettings())
        with patch("app.scanner.network.is_public_address", return_value=True):
            result = await transport.request(self._target(port), self._loopback_pin(), "GET")
        self.assertEqual(result.head.status_code, 302)
        self.assertFalse(result.body_complete)
        self.assertEqual(len(requests), 1)

    async def test_declared_oversize_response_fails_before_body_read(self) -> None:
        _server, port, _requests = await self._start_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"
        )
        settings = ScannerSettings(max_response_bytes=8, read_chunk_bytes=4)
        transport = AiohttpTransport(settings)
        with patch("app.scanner.network.is_public_address", return_value=True):
            with self.assertRaises(ResponseTooLargeError) as raised:
                await transport.request(self._target(port), self._loopback_pin(), "GET")
        self.assertEqual(raised.exception.bytes_read, 0)
        self.assertEqual(raised.exception.response_head.status_code, 200)

    async def test_streamed_oversize_response_stops_at_limit_plus_one_byte(self) -> None:
        chunked = (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"4\r\nabcd\r\n4\r\nefgh\r\n0\r\n\r\n"
        )
        _server, port, _requests = await self._start_server(chunked)
        settings = ScannerSettings(max_response_bytes=5, read_chunk_bytes=2)
        transport = AiohttpTransport(settings)
        with patch("app.scanner.network.is_public_address", return_value=True):
            with self.assertRaises(ResponseTooLargeError) as raised:
                await transport.request(self._target(port), self._loopback_pin(), "GET")
        self.assertEqual(raised.exception.bytes_read, 6)

    async def test_read_timeout_is_structured(self) -> None:
        _server, port, _requests = await self._start_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", delay=0.1
        )
        settings = ScannerSettings(
            dns_timeout_seconds=0.03,
            connect_timeout_seconds=0.03,
            write_timeout_seconds=0.03,
            read_timeout_seconds=0.02,
            overall_timeout_seconds=0.2,
        )
        transport = AiohttpTransport(settings)
        with patch("app.scanner.network.is_public_address", return_value=True):
            with self.assertRaises(ScannerTimeoutError):
                await transport.request(self._target(port), self._loopback_pin(), "GET")

    async def test_connect_timeout_is_structured(self) -> None:
        settings = ScannerSettings(
            dns_timeout_seconds=0.02,
            connect_timeout_seconds=0.01,
            write_timeout_seconds=0.03,
            read_timeout_seconds=0.03,
            overall_timeout_seconds=0.2,
        )
        target = ValidatedTarget(
            requested_url="http://public-fixture.example.com/",
            normalized_url="http://public-fixture.example.com/",
            scheme="http",
            hostname="public-fixture.example.com",
            port=80,
            request_target="/",
            is_ip_literal=False,
        )

        async def stall_connect(**_kwargs: object) -> None:
            await asyncio.sleep(0.1)

        transport = AiohttpTransport(settings)
        with patch("aiohttp.connector.aiohappyeyeballs.start_connection", side_effect=stall_connect):
            with self.assertRaises(ScannerTimeoutError):
                await transport.request(
                    target,
                    (ResolvedAddress(ipaddress.ip_address("93.184.216.34"), socket.AF_INET),),
                    "GET",
                )

    async def test_connection_failure_is_sanitized(self) -> None:
        server, port, _requests = await self._start_server(b"HTTP/1.1 204 No Content\r\n\r\n")
        await self._close_server(server)
        transport = AiohttpTransport(ScannerSettings())
        with patch("app.scanner.network.is_public_address", return_value=True):
            with self.assertRaises(ConnectionFailedError) as raised:
                await transport.request(self._target(port), self._loopback_pin(), "GET")
        self.assertNotIn("scanner-test.invalid", str(raised.exception))

    async def test_non_public_pins_are_rejected_before_connect(self) -> None:
        transport = AiohttpTransport(ScannerSettings())
        with self.assertRaises(BlockedDestinationError) as raised:
            await transport.request(
                self._target(80),
                (ResolvedAddress(ipaddress.ip_address("127.0.0.1"), socket.AF_INET),),
                "GET",
            )
        self.assertEqual(raised.exception.code.value, "BLOCKED_DESTINATION")

    async def test_transport_refuses_state_changing_methods(self) -> None:
        transport = AiohttpTransport(ScannerSettings())
        with self.assertRaises(UnsupportedMethodError) as raised:
            await transport.request(self._target(80), self._loopback_pin(), "POST")
        self.assertEqual(raised.exception.code.value, "UNSUPPORTED_METHOD")


if __name__ == "__main__":
    unittest.main()
