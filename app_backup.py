from core.packet_capture import start_capture
from core.analysis.port_monitor import start_port_monitor


def main():
    print("=" * 45)
    print("          NETGUARDIAN")
    print("       Network Monitor")
    print("=" * 45)

    print("\nSelect an option:")
    print("1. Packet Capture & Statistics")
    print("2. Port Monitoring")
    print("3. Exit")

    choice = input("\nEnter your choice: ")

    if choice == "1":
        start_capture()

    elif choice == "2":
        start_port_monitor()

    elif choice == "3":
        print("[+] NetGuardian closed.")

    else:
        print("[-] Invalid choice.")


if __name__ == "__main__":
    main()