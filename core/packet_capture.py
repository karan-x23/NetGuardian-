from scapy.all import sniff, IP, TCP, UDP
from collections import Counter


total_packets = 0
tcp_packets = 0
udp_packets = 0
other_packets = 0

source_ips = Counter()


def process_packet(packet):
    global total_packets, tcp_packets, udp_packets, other_packets

    if IP in packet:
        total_packets += 1

        source = packet[IP].src
        source_ips[source] += 1

        destination = packet[IP].dst

        if TCP in packet:
            protocol_name = "TCP"
            tcp_packets += 1

        elif UDP in packet:
            protocol_name = "UDP"
            udp_packets += 1

        else:
            protocol_name = "OTHER"
            other_packets += 1

        print(
            f"[PACKET] {source} -> {destination} | "
            f"Protocol: {protocol_name}"
        )


def start_capture():
    print("[+] Network monitor started")
    print("[+] Capturing 20 packets...\n")

    sniff(
        prn=process_packet,
        count=20
    )

    print("\n[+] Capture completed")

    print("\n===== PACKET STATISTICS =====")
    print(f"Total Packets : {total_packets}")
    print(f"TCP Packets   : {tcp_packets}")
    print(f"UDP Packets   : {udp_packets}")
    print(f"Other Packets : {other_packets}")

    print("\n===== TOP ACTIVE IPs =====")

    for ip, count in source_ips.most_common(5):
        print(f"{ip} : {count} packets")