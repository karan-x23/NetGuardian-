import csv
from collections import Counter
from datetime import datetime


LOG_FILE = "traffic_log.csv"


def generate_report(filename=None):

    protocol_counts = Counter()
    port_counts = Counter()
    source_ips = Counter()

    total_packets = 0

    try:
        with open(LOG_FILE, "r", newline="") as file:
            reader = csv.DictReader(file)

            for row in reader:
                total_packets += 1

                protocol_counts[row["Protocol"]] += 1
                source_ips[row["Source IP"]] += 1

                port = row["Destination Port"]

                if port:
                    port_counts[port] += 1

    except FileNotFoundError:
        print("[-] traffic_log.csv not found.")
        print("[+] Run the traffic logger first.")
        return

    if filename is None:
        filename = (
            "NetGuardian_Report_"
            + datetime.now().strftime("%Y%m%d_%H%M%S")
            + ".txt"
        )
    elif not filename.lower().endswith(".txt"):
        filename += ".txt"

    with open(filename, "w") as report:

        report.write("=" * 60 + "\n")
        report.write("             NETGUARDIAN TRAFFIC REPORT\n")
        report.write("=" * 60 + "\n\n")

        report.write(
            "Generated: "
            + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            + "\n\n"
        )

        report.write("===== OVERVIEW =====\n")
        report.write(f"Total Packets : {total_packets}\n")
        report.write(
            f"TCP Packets   : {protocol_counts.get('TCP', 0)}\n"
        )
        report.write(
            f"UDP Packets   : {protocol_counts.get('UDP', 0)}\n"
        )
        report.write(
            f"Other Packets : {protocol_counts.get('OTHER', 0)}\n"
        )

        report.write("\n===== TOP DESTINATION PORTS =====\n")

        for port, count in port_counts.most_common(10):
            report.write(
                f"Port {port} : {count} packets\n"
            )

        report.write("\n===== TOP SOURCE IPs =====\n")

        for ip, count in source_ips.most_common(10):
            report.write(
                f"{ip} : {count} packets\n"
            )

        report.write("\n===== SECURITY ALERTS =====\n")

        alerts = 0

        for port, count in port_counts.items():

            if count >= 50:
                report.write(
                    f"[ALERT] Port {port} has {count} packets\n"
                )
                alerts += 1

        if alerts == 0:
            report.write("[OK] No threshold alerts detected.\n")

        report.write("\n" + "=" * 60 + "\n")
        report.write("             END OF REPORT\n")
        report.write("=" * 60 + "\n")

    print("\n[+] Report generated successfully.")
    print(f"[+] File: {filename}")
    return filename


if __name__ == "__main__":
    generate_report() 