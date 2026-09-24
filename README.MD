# NetGuardian

NetGuardian is a Python-based network monitoring dashboard designed for local traffic visibility, packet analysis, port activity monitoring, and alert generation. It provides a desktop interface for observing network behavior in real time and reviewing captured packet data from the local machine.

This project is intended for authorized, defensive network monitoring use on networks where you have explicit permission to inspect traffic.

## Features

- Real-time packet capture using Scapy
- Traffic monitoring for TCP, UDP, ICMP, DNS, and ARP
- Protocol distribution analysis
- Top IP and traffic usage insights
- Connected device visibility
- Port-based threshold alerting
- Live usage charts and dashboard panels
- CSV log generation and report export
- Desktop UI built with Tkinter

## Project structure

- `app.py` – main app entry point
- `gui_dashboard.py` – Tkinter dashboard and monitoring interface
- `traffic_logger.py` – packet logging utilities
- `traffic_analyzer.py` – traffic analysis and summaries
- `alert_system.py` – alert handling logic
- `report_generator.py` – report generation
- `core/` – packet capture and analysis modules
- `tests/` – automated validation tests
- `requirements.txt` – Python dependencies
- `LICENSE` – project license

## Requirements

- Python 3.10+
- Windows: run with Administrator privileges if packet capture is required
- Windows: Npcap installation recommended
- Scapy

## Installation

1. Clone the repository

   ```bash
   git clone https://github.com/your-username/NetGuardian.git
   cd NetGuardian
   ```

2. Create a virtual environment

   ```bash
   python -m venv .venv
   .venv\Scripts\activate
   ```

3. Install dependencies

   ```bash
   pip install -r requirements.txt
   ```

## Running the project

Start the dashboard:

```bash
python gui_dashboard.py
```

If packet capture does not work, check the following:

- you are running the app with administrator privileges
- Npcap is installed on Windows
- your network adapter supports traffic capture in your environment

## Usage notes

- Use only on trusted or authorized local networks
- Do not deploy in environments where monitoring permission is not explicit
- Threshold values and monitoring settings can be adjusted from the dashboard

## Testing

Run the project tests:

```bash
python -m pytest -q
```

The repository also includes a focused unittest suite for threshold behavior and dashboard logic.

## Security and legal notice

NetGuardian is intended for defensive, authorized traffic monitoring. It should not be used for unauthorized surveillance, privacy invasion, or any activity that violates laws or network policies.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Status

NetGuardian is currently a working prototype focused on live monitoring, packet inspection, port alerting, and local network visibility. It is suitable for learning, experimentation, and defensive monitoring in approved environments.

## Limitations

- Packet capture depends on OS permissions and adapter support
- Behavior can vary by system, OS, and network conditions
- This is not a full enterprise-grade IDS/IPS platform
