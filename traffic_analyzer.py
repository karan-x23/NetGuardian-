import csv
from collections import Counter


LOG_FILE = "traffic_log.csv"


def analyze_traffic():

    total_packets = 0
    protocol_counts = Counter()
    port_counts = Counter()
    source_ips = Counter()
    destination_ips = Counter()

    try:
        with open(LOG_FILE, "r", newline="") as file:
            reader = csv.DictReader(file)

            for row in reader:
                total_packets += 1

                protocol = row["Protocol"]
                port = row["Destination Port"]
                source = row["Source IP"]
                destination = row["Destination IP"]

                protocol_counts[protocol] += 1
                source_ips[source] += 1
                destination_ips[destination] += 1

                if port:
                    port_counts[port] += 1

    except FileNotFoundError:
        print("[-] traffic_log.csv not found.")
        print("[+] Run the traffic logger first.")
        return

    print("=" * 55)
    print("          NETGUARDIAN TRAFFIC ANALYZER")
    print("=" * 55)

    print(f"\nTotal Packets : {total_packets}")

    print("\n===== PROTOCOL STATISTICS =====")
    for protocol, count in protocol_counts.most_common():
        print(f"{protocol} : {count}")

    print("\n===== TOP DESTINATION PORTS =====")
    for port, count in port_counts.most_common(10):
        print(f"Port {port} : {count} packets")

    print("\n===== TOP SOURCE IPs =====")
    for ip, count in source_ips.most_common(10):
        print(f"{ip} : {count} packets")

    print("\n===== TOP DESTINATION IPs =====")
    for ip, count in destination_ips.most_common(10):
        print(f"{ip} : {count} packets")


if __name__ == "__main__":
    analyze_traffic()