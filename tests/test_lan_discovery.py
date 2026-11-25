import queue
import threading
import unittest
from ipaddress import IPv4Address, IPv4Network
from unittest.mock import patch

from scapy.all import ARP

from core.lan_discovery import AdapterSubnet, scan_subnet


class LanDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.adapter = AdapterSubnet(
            "Test adapter", "test0", IPv4Address("192.168.10.1"),
            IPv4Network("192.168.10.0/29"), "02:00:00:00:00:01", object(),
        )
        self.events = queue.Queue()
        self.cancelled = threading.Event()

    def test_probes_only_other_usable_addresses_on_selected_adapter(self):
        with patch("core.lan_discovery.srp") as exchange:
            def reply(requests, **kwargs):
                self.assertIs(kwargs["iface"], self.adapter.interface)
                self.assertEqual([request.pdst for request in requests],
                                 [f"192.168.10.{i}" for i in range(2, 7)])
                self.assertTrue(all(request.psrc == "192.168.10.1" for request in requests))
                return [
                    (requests[0], ARP(op=2, psrc="192.168.10.2", hwsrc="02:00:00:00:00:02")),
                    (requests[1], ARP(op=2, psrc="192.168.11.3", hwsrc="02:00:00:00:00:03")),
                ], []

            exchange.side_effect = reply
            scan_subnet(self.adapter, self.cancelled, self.events)

        self.assertEqual(self.events.get_nowait(), ("devices", [("192.168.10.1", self.adapter.mac)], 0))
        self.assertEqual(self.events.get_nowait(), ("devices", [("192.168.10.2", "02:00:00:00:00:02")], 5))
        self.assertEqual(self.events.get_nowait(), ("done", False, 5))

    def test_cancelled_scan_sends_no_packets(self):
        self.cancelled.set()
        with patch("core.lan_discovery.srp") as exchange:
            scan_subnet(self.adapter, self.cancelled, self.events)
            exchange.assert_not_called()
        self.assertEqual(self.events.get_nowait(), ("done", True, 0))

    def test_permission_error_is_reported(self):
        with patch("core.lan_discovery.srp", side_effect=PermissionError("Raw socket denied")):
            scan_subnet(self.adapter, self.cancelled, self.events)
        self.events.get_nowait()
        self.assertEqual(self.events.get_nowait(), ("error", "Raw socket denied", 0))
        self.assertEqual(self.events.get_nowait(), ("done", False, 0))
