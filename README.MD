# NetGuardian

A Python-based network monitoring and traffic analysis dashboard for local network visibility, packet capture, protocol breakdown, port monitoring, and alerting.

## Overview

NetGuardian is designed to monitor live network traffic from the local machine and display important information such as:

- packet activity
- protocol distribution
- top source and destination IPs
- connected devices
- port-level alerting
- live traffic trends

This project is intended for educational and defensive network monitoring use on networks where you have explicit permission to inspect traffic.

## Features

- Real-time packet capture using Scapy
- Protocol analysis for TCP, UDP, ICMP, DNS, and ARP
- Traffic rate and byte monitoring
- Top IP address analysis
- Device visibility based on local network traffic
- Port traffic threshold alerts
- Desktop dashboard built with Tkinter
- CSV log export and report generation

## Project Structure

- `app.py` - application entry point
- `gui_dashboard.py` - desktop monitoring dashboard
- `traffic_logger.py` - packet logging helper
- `traffic_analyzer.py` - traffic analysis logic
- `alert_system.py` - alert processing
- `report_generator.py` - report generation
- `core/` - packet capture and analysis modules
- `tests/` - automated tests
- `requirements.txt` - project dependencies

## Requirements

- Python 3.10+
- Windows admin privileges may be required for packet capture
- Npcap on Windows
- Scapy

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/your-username/NetGuardian.git
   cd NetGuardian
   ```

2. Create and activate a virtual environment:

   ```bash
   python -m venv .venv
   .venv\Scripts\activate
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## Run the app

```bash
python gui_dashboard.py
```

If packet capture fails, make sure you are running with administrator privileges and that Npcap is installed on Windows.

## Usage Notes

- Run only on trusted local networks.
- Do not use on networks where you do not have permission to monitor traffic.
- Alert thresholds can be adjusted in the Settings panel inside the dashboard.

## Testing

```bash
python -m pytest -q
```

## Security Notice

This project is intended for defensive, authorized network monitoring only. It should never be used for unauthorized surveillance or privacy invasion.

## Roadmap

Planned future improvements include:

- improved interface selection
- cleaner alert configuration
- persistent log storage and review
- better device identification
- stronger error handling and recovery
- more advanced anomaly detection

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Project Status

This is a working prototype for a network monitoring dashboard and analysis tool. It is suitable for learning, experimentation, and defensive monitoring in authorized environments.

## Limitations

- Packet capture depends on local system permissions and network adapter access.
- Monitoring behavior can vary by OS, hardware, and interface availability.
- This is not a full enterprise intrusion detection platform.

4. Traffic Analyzer
5. Alert System
6. Dashboard
7. Exit

---

## 11. Testing Status

All major modules have been tested successfully in the local development environment.

| Module | Status |
|---|---|
| Packet Capture | Tested |
| Port Monitoring | Tested |
| Live Monitoring | Tested |
| Traffic Logger | Tested |
| Traffic Analyzer | Tested |
| Alert System | Tested |
| Dashboard | Tested |
| Main Menu | Tested |

---

## 12. Current Project Status

NetGuardian has reached a functional prototype stage. The core network monitoring, traffic logging, analysis, alerting and dashboard components are implemented and have been tested.

The project can be further improved with features such as graphical visualization, advanced anomaly detection, configurable alert thresholds, report generation and improved user interface.

---

## 13. Conclusion

NetGuardian is a defensive network monitoring project designed to provide visibility into network traffic through packet capture, protocol analysis, port monitoring, traffic logging and security alerts.

The project demonstrates practical use of Python, Scapy, network monitoring concepts, CSV-based logging and modular software development.