"""Extract concise protocol fields for the packet inspector."""

import re
from ipaddress import IPv6Address

from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, Ether, IPv6


HEADER_FIELDS = (
    (Ether, ("src", "dst", "type")),
    (ARP, ("op", "hwsrc", "psrc", "hwdst", "pdst")),
    (IP, ("src", "dst", "ttl", "proto", "id", "flags", "frag", "len")),
    (IPv6, ("src", "dst", "hlim", "nh", "tc", "fl", "plen")),
    (TCP, ("sport", "dport", "seq", "ack", "flags", "window")),
    (UDP, ("sport", "dport", "len")),
    (ICMP, ("type", "code")),
    (DNS, ("id", "qr", "opcode", "rcode", "qdcount", "ancount")),
)


def packet_headers(packet):
    headers = {}
    for protocol, fields in HEADER_FIELDS:
        layer = packet.getlayer(protocol)
        if layer is not None:
            headers[protocol.__name__] = {field: layer.getfieldval(field) for field in fields}
    return headers


def packet_ports(headers):
    for layer in ("TCP", "UDP"):
        if layer in headers:
            return headers[layer]["sport"], headers[layer]["dport"]
    return ()


def packet_conversation(row, headers):
    """Group both directions by transport and endpoint pairs."""
    ports = packet_ports(headers)
    protocol = ("TCP" if "TCP" in headers else "UDP") if ports else row[4]
    source, destination = row[2:4]
    sport, dport = ports or (None, None)
    endpoints = sorted(((source, sport), (destination, dport)))
    return protocol, *endpoints


def display_filter(text, header_lookup, protocols):
    text = text.lower()
    addresses = set(re.findall(r"\d+\.\d+\.\d+\.\d+", text))
    for token in re.split(r"[\s,;()\[\]]+", text):
        if ":" not in token:
            continue
        try:
            addresses.add(str(IPv6Address(token)))
        except ValueError:
            continue
    names = {name.lower() for name in protocols if re.search(rf"\b{re.escape(name.lower())}\b", text)}
    ports = {int(port) for port in re.findall(r"\bport\s*:\s*([0-9]{1,5})\b", text)}

    def matches(row):
        if addresses and addresses.isdisjoint(row[2:4]):
            return False
        headers = header_lookup(row[0]) if ports or names else {}
        if names and row[4].lower() not in names and not any(layer.lower() in names for layer in headers):
            return False
        return not ports or not ports.isdisjoint(packet_ports(headers))

    return matches
