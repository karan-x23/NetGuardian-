"""Discover ARP responders on a directly connected private IPv4 subnet."""

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from itertools import islice

from scapy.all import ARP, Ether, conf, srp


PRIVATE_NETWORKS = tuple(IPv4Network(cidr) for cidr in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
))


@dataclass(frozen=True)
class AdapterSubnet:
    name: str
    interface_id: str
    address: IPv4Address
    network: IPv4Network
    mac: str
    interface: object = field(compare=False, repr=False)

    @property
    def label(self):
        return f"{self.name} · {self.address} · {self.network}"


def adapter_subnets():
    conf.ifaces.reload()
    conf.route.resync()
    subnets = {}
    for destination, mask, gateway, identifier, source, _ in conf.route.routes:
        if gateway != "0.0.0.0" or not mask:
            continue
        network = IPv4Network((destination, mask.bit_count()), strict=False)
        address = IPv4Address(source)
        if mask != int(network.netmask) or address not in network or network.prefixlen == 32:
            continue
        if not any(network.subnet_of(private) for private in PRIVATE_NETWORKS):
            continue
        try:
            interface = conf.ifaces.dev_from_networkname(identifier)
        except ValueError:
            continue
        mac = interface.mac
        if not mac or mac == "00:00:00:00:00:00":
            continue
        flags = set(str(getattr(interface, "flags", "") or "").split("+")) - {""}
        if flags & {"NOARP", "POINTOPOINT", "LOOPBACK"} or (flags and "UP" not in flags):
            continue
        subnet = AdapterSubnet(interface.name, identifier, address, network, mac, interface)
        subnets[subnet.label] = subnet
    return subnets


def scan_subnet(adapter, cancelled, events):
    """Report progress through a queue. Tk widgets stay on the main thread."""
    scanned = 0
    try:
        if cancelled.is_set():
            return
        events.put(("devices", [(str(adapter.address), adapter.mac)], scanned))
        targets = (str(host) for host in adapter.network.hosts() if host != adapter.address)
        while batch := tuple(islice(targets, 64)):
            if cancelled.is_set():
                break
            requests = [
                Ether(src=adapter.mac, dst="ff:ff:ff:ff:ff:ff") /
                ARP(op=1, hwsrc=adapter.mac, psrc=str(adapter.address), pdst=target)
                for target in batch
            ]
            answers, _ = srp(requests, iface=adapter.interface, timeout=1, inter=0.025, verbose=False)
            devices = [
                (reply.psrc, reply.hwsrc) for request, reply in answers
                if reply.haslayer(ARP) and reply[ARP].op == 2 and reply.psrc == request.pdst
            ]
            scanned += len(batch)
            events.put(("devices", devices, scanned))
    except Exception as exc:
        events.put(("error", str(exc), scanned))
    finally:
        events.put(("done", cancelled.is_set(), scanned))
