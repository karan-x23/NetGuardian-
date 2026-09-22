from scapy.all import sniff, IP, TCP, UDP
from collections import Counter


port_counts = Counter()


def analyze_packet(packet):
    if IP not in packet:
        return

    source = packet[IP].src
    destination = packet[IP].dst

    if TCP in packet:
        port = packet[TCP].dport
        protocol = "TCP"

    elif UDP in packet:
        port = packet[UDP].dport
        protocol = "UDP"

    else:
        return

    port_counts[(protocol, port)] += 1

    print(
        f"[PORT] {source} -> {destination} | "
        f"{protocol} Port: {port}"
    )


def start_port_monitor():
    print("=" * 45)
    print("       NETGUARDIAN PORT MONITOR")
    print("=" * 45)

    print("[+] Monitoring 20 packets...\n")

    sniff(
        prn=analyze_packet,
        count=20
    )

    print("\n[+] Port monitoring completed")

    print("\n===== TOP DESTINATION PORTS =====")

    for (protocol, port), count in port_counts.most_common(10):
        print(
            f"{protocol} Port {port} : "
            f"{count} packets"
        )


if __name__ == "__main__":
    start_port_monitor()