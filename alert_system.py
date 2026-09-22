import csv
from collections import Counter


LOG_FILE = "traffic_log.csv"

# Alert threshold
PORT_THRESHOLD = 50


def check_alerts():

    port_counts = Counter()

    try:
        with open(LOG_FILE, "r", newline="") as file:
            reader = csv.DictReader(file)

            for row in reader:
                port = row["Destination Port"]

                if port:
                    port_counts[port] += 1

    except FileNotFoundError:
        print("[-] traffic_log.csv not found.")
        print("[+] Run the traffic logger first.")
        return

    print("=" * 55)
    print("          NETGUARDIAN ALERT SYSTEM")
    print("=" * 55)

    print(f"\n[+] Alert threshold: {PORT_THRESHOLD} packets")

    alerts_found = False

    for port, count in port_counts.items():

        if count >= PORT_THRESHOLD:
            alerts_found = True

            print(
                f"[ALERT] Port {port} has "
                f"{count} packets!"
            )

    if not alerts_found:
        print("\n[OK] No traffic threshold alerts detected.")


if __name__ == "__main__":
    check_alerts()