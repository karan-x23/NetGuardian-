from scapy.all import sniff, IP, TCP, UDP
import csv
from datetime import datetime


LOG_FILE = "traffic_log.csv"


def log_packet(packet):
    if IP not in packet:
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    source = packet[IP].src
    destination = packet[IP].dst

    if TCP in packet:
        protocol = "TCP"
        port = packet[TCP].dport

    elif UDP in packet:
        protocol = "UDP"
        port = packet[UDP].dport

    else:
        protocol = "OTHER"
        port = ""

    with open(LOG_FILE, "a", newline="") as file:
        writer = csv.writer(file)

        writer.writerow([
            timestamp,
            source,
            destination,
            protocol,
            port
        ])

    print(
        f"[LOGGED] {timestamp} | "
        f"{source} -> {destination} | "
        f"{protocol} | Port: {port}"
    )


def start_traffic_logger():

    print("=" * 50)
    print("          NETGUARDIAN TRAFFIC LOGGER")
    print("=" * 50)

    print("[+] Logging network traffic...")
    print("[+] Press CTRL+C to stop\n")

    try:
        with open(LOG_FILE, "a", newline="") as file:
            writer = csv.writer(file)

            if file.tell() == 0:
                writer.writerow([
                    "Timestamp",
                    "Source IP",
                    "Destination IP",
                    "Protocol",
                    "Destination Port"
                ])

        sniff(
            prn=log_packet,
            store=False
        )

    except KeyboardInterrupt:
        print("\n[+] Traffic logging stopped.")


if __name__ == "__main__":
    start_traffic_logger()