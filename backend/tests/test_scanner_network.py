import asyncio
import ipaddress
import socket
import unittest

from app.scanner.config import ScannerSettings
from app.scanner.errors import BlockedDestinationError, DnsResolutionError, ScannerTimeoutError
from app.scanner.models import ResolvedAddress
from app.scanner.network import PinnedResolver, SystemAddressResolver, is_public_address
from app.scanner.url_validator import validate_target_url


class PublicAddressPolicyTests(unittest.TestCase):
    def test_public_unicast_addresses_are_allowed(self) -> None:
        self.assertTrue(is_public_address(ipaddress.ip_address("93.184.216.34")))
        self.assertTrue(is_public_address(ipaddress.ip_address("2606:4700:4700::1111")))

    def test_non_public_address_classes_are_denied(self) -> None:
        for value in (
            "0.0.0.0",
            "10.0.0.1",
            "100.64.1.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.20.1.2",
            "192.168.0.1",
            "198.18.0.1",
            "192.0.2.1",
            "224.0.0.1",
            "240.0.0.1",
            "::",
            "::1",
            "::ffff:8.8.8.8",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "2002:0808:0808::1",
            "64:ff9b::808:808",
        ):
            with self.subTest(value=value):
                self.assertFalse(is_public_address(ipaddress.ip_address(value)))


class SystemResolverTests(unittest.IsolatedAsyncioTestCase):
    def settings(self, **overrides: object) -> ScannerSettings:
        values: dict[str, object] = {
            "dns_timeout_seconds": 0.05,
            "connect_timeout_seconds": 0.1,
            "write_timeout_seconds": 0.1,
            "read_timeout_seconds": 0.1,
            "overall_timeout_seconds": 0.5,
        }
        values.update(overrides)
        return ScannerSettings(**values)  # type: ignore[arg-type]

    async def test_public_hostname_result_is_returned_as_pinned_address(self) -> None:
        async def lookup(*_args: object, **_kwargs: object) -> list[tuple[int, int, int, str, tuple]]:
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 80))]

        target = validate_target_url("http://public-fixture.example.com/")
        addresses = await SystemAddressResolver(lookup).resolve(target, self.settings())
        self.assertEqual([address.compressed for address in addresses], ["93.184.216.34"])

    async def test_private_resolution_is_blocked(self) -> None:
        async def lookup(*_args: object, **_kwargs: object) -> list[tuple[int, int, int, str, tuple]]:
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.0.0.2", 80))]

        target = validate_target_url("http://private-fixture.example.com/")
        with self.assertRaises(BlockedDestinationError):
            await SystemAddressResolver(lookup).resolve(target, self.settings())

    async def test_loopback_resolution_is_blocked(self) -> None:
        async def lookup(*_args: object, **_kwargs: object) -> list[tuple[int, int, int, str, tuple]]:
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 80))]

        target = validate_target_url("http://loopback-fixture.example.com/")
        with self.assertRaises(BlockedDestinationError):
            await SystemAddressResolver(lookup).resolve(target, self.settings())

    async def test_mixed_public_and_private_answers_are_all_rejected(self) -> None:
        async def lookup(*_args: object, **_kwargs: object) -> list[tuple[int, int, int, str, tuple]]:
            return [
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 80)),
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.168.1.2", 80)),
            ]

        target = validate_target_url("http://mixed-fixture.example.com/")
        with self.assertRaises(BlockedDestinationError):
            await SystemAddressResolver(lookup).resolve(target, self.settings())

    async def test_dns_failure_maps_to_safe_dns_error(self) -> None:
        async def lookup(*_args: object, **_kwargs: object) -> list[tuple[int, int, int, str, tuple]]:
            raise socket.gaierror("internal resolver details")

        target = validate_target_url("http://missing-fixture.example.com/")
        with self.assertRaises(DnsResolutionError) as raised:
            await SystemAddressResolver(lookup).resolve(target, self.settings())
        self.assertNotIn("internal resolver details", str(raised.exception))

    async def test_dns_timeout_is_bounded_and_structured(self) -> None:
        async def lookup(*_args: object, **_kwargs: object) -> list[tuple[int, int, int, str, tuple]]:
            await asyncio.sleep(0.05)
            return []

        target = validate_target_url("http://slow-fixture.example.com/")
        with self.assertRaises(ScannerTimeoutError):
            await SystemAddressResolver(lookup).resolve(target, self.settings(dns_timeout_seconds=0.005))


class PinnedResolverTests(unittest.IsolatedAsyncioTestCase):
    async def test_resolver_returns_only_the_prevalidated_addresses(self) -> None:
        pinned = PinnedResolver(
            "public-fixture.example.com",
            (ResolvedAddress(ipaddress.ip_address("93.184.216.34"), socket.AF_INET),),
        )
        records = await pinned.resolve("public-fixture.example.com", 8080, socket.AF_UNSPEC)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["host"], "93.184.216.34")
        self.assertEqual(records[0]["port"], 8080)

    async def test_resolver_refuses_to_perform_a_second_dns_lookup(self) -> None:
        pinned = PinnedResolver(
            "public-fixture.example.com",
            (ResolvedAddress(ipaddress.ip_address("93.184.216.34"), socket.AF_INET),),
        )
        with self.assertRaises(OSError):
            await pinned.resolve("different-fixture.example.com", 80, socket.AF_UNSPEC)


if __name__ == "__main__":
    unittest.main()
