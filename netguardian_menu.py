from core.packet_capture import start_capture
from core.analysis.port_monitor import start_port_monitor
from traffic_logger import start_traffic_logger
from traffic_analyzer import analyze_traffic
from alert_system import check_alerts
from dashboard import show_dashboard
from report_generator import generate_report


def show_menu():

    while True:

        print("\n" + "=" * 55)
        print("              NETGUARDIAN")
        print("           SECURITY MONITOR")
        print("=" * 55)

        print("\n1. Packet Capture")
        print("2. Port Monitoring")
        print("3. Traffic Logger")
        print("4. Traffic Analyzer")
        print("5. Alert System")
        print("6. Dashboard")
        print("7. Report Generator")
        print("8. Exit")

        choice = input("\nEnter your choice: ")

        if choice == "1":
            start_capture()

        elif choice == "2":
            start_port_monitor()

        elif choice == "3":
            start_traffic_logger()

        elif choice == "4":
            analyze_traffic()

        elif choice == "5":
            check_alerts()

        elif choice == "6":
            show_dashboard()

        elif choice == "7":
            generate_report()

        elif choice == "8":
            print("\n[+] NetGuardian closed.")
            break

        else:
            print("\n[-] Invalid choice.")

        input("\nPress Enter to return to menu...")


if __name__ == "__main__":
    show_menu()