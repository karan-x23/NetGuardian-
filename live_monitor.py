try:
    from scapy.all import sniff, IP, TCP, UDP
except ModuleNotFoundError:
    print("[-] Missing dependency: scapy")
    print("[-] Activate the project virtual environment or install it with:")
    print("     .\\venv\\Scripts\\activate")
    print("     python -m pip install scapy")
    raise SystemExit(1)

from datetime import datetime
total_packets = 0
tcp_packets =0
udp_packets =0
other_packets =0


def process_live_packet(packet):
    global total_packets, tcp_packets, udp_packets, other_packets 
    if IP in packet:
        total_packets += 1
        source = packet[IP].src
        destination = packet[IP].dst
        timestamp = datetime.now().strftime("%H:%M:%S")

        if TCP in packet:
            protocol = "TCP"
            tcp_packets += 1
        elif UDP in packet:
            protocol = "UDP"
            udp_packets += 1
        else:
            protocol = "OTHER"
            other_packets += 1

        print(
            f"[{timestamp}] {source} -> {destination} | "
            f"Protocol: {protocol}"
        )
        print(
            f"total:{total_packets} | TCP:{tcp_packets} | UDP:{udp_packets} | OTHER:{other_packets}"

        )



def start_live_monitor():
    print("=" * 55)
    print("          SECUREOPS REAL-TIME MONITOR")
    print("=" * 55)
    print("[+] Live monitoring started")
    print("[+] Press CTRL+C to stop")
    print()

    try:
        sniff(
            prn=process_live_packet,
            store=False
        )
    except KeyboardInterrupt:
        print("\n[+] Live monitoring stopped")
    except PermissionError:
        print("\n[-] Permission denied. Run this script as Administrator or allow packet capture access.")
    except OSError as exc:
        print(f"\n[-] Network interface error: {exc}")


if __name__ == "__main__":
    start_live_monitor()