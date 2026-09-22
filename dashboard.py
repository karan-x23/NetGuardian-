import csv
from collections import Counter


LOG_FILE = "traffic_log.csv"
PORT_THRESHOLD = 50


def load_data():

    protocol_counts = Counter()
    port_counts = Counter()
    source_ips = Counter()
    destination_ips = Counter()

    total_packets = 0

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
        return None

    return (
        total_packets,
        protocol_counts,
        port_counts,
        source_ips,
        destination_ips
    )


def show_dashboard():

    data = load_data()

    if data is None:
        return

    (
        total_packets,
        protocol_counts,
        port_counts,
        source_ips,
        destination_ips
    ) = data

    print("\n")
    print("=" * 65)
    print("                 NETGUARDIAN")
    print("              NETWORK DASHBOARD")
    print("=" * 65)

    print("\n===== OVERVIEW =====")
    print(f"Total Packets : {total_packets}")
    print(f"TCP Packets   : {protocol_counts.get('TCP', 0)}")
    print(f"UDP Packets   : {protocol_counts.get('UDP', 0)}")
    print(f"Other         : {protocol_counts.get('OTHER', 0)}")

    print("\n===== TOP DESTINATION PORTS =====")

    for port, count in port_counts.most_common(5):
        print(f"Port {port:<6} : {count} packets")

    print("\n===== TOP SOURCE IPs =====")

    for ip, count in source_ips.most_common(5):
        print(f"{ip:<16} : {count} packets")

    print("\n===== TOP DESTINATION IPs =====")

    for ip, count in destination_ips.most_common(5):
        print(f"{ip:<16} : {count} packets")

    print("\n===== SECURITY ALERTS =====")

    alerts = 0

    for port, count in port_counts.items():

        if count >= PORT_THRESHOLD:
            print(
                f"[ALERT] Port {port} "
                f"has {count} packets"
            )
            alerts += 1

    if alerts == 0:
        print("[OK] No threshold alerts detected.")

    print("\n" + "=" * 65)
    print("              DASHBOARD COMPLETE")
    print("=" * 65)


if __name__ == "__main__":
    show_dashboard()