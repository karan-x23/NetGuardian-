"""NetGuardian - Network Monitor & Analyzer  (SecureOps UI + real scapy backend)

Run (needs admin / root for packet capture; on Windows also install Npcap):
    pip install scapy
    python netguardian_secureops.py

Layout / look  : taken from gui_tkinter.py (SecureOps)
Real data      : taken from gui_dashboard.py (NetGuardian) - AsyncSniffer, CSV log,
                 port-threshold alerts, text report.

The code is split in two parts:
    TrafficMonitor  -> no tkinter at all: sniffing, counters, alerts, CSV log
    App             -> tkinter UI, only reads from TrafficMonitor
"""
import csv
import ipaddress
import math
import os
import re
import socket
import threading
import time
import tkinter as tk
from collections import Counter, deque
from datetime import datetime
from functools import lru_cache
from tkinter import filedialog, messagebox, ttk

from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, AsyncSniffer, Ether, conf

# ============================================================
# SETTINGS
# ============================================================
APP_NAME = "NetGuardian"   # <- change to "SecureOps" if you prefer that name
VERSION = "v1.0"
LOG_FILE = "traffic_log.csv"
ALERT_THRESHOLD = 50       # packets on one port before an alert is raised
HIST = 60                  # seconds of history in the usage chart
ONLINE_WINDOW = 60         # device counts as "Online" if seen in the last N seconds
MAX_ROWS = 5000            # packets kept in memory for Export

# ---------- reference-inspired dark cyber dashboard ----------
BG = "#061a2d"
SIDE = "#0b1d2f"
PANEL = "#0d233b"
PANEL_ALT = "#0f2b43"
BORDER = "#1d5689"
TEXT = "#edf7ff"
MUTED = "#8fb0d1"
BLUE = "#2aa8ff"
GREEN = "#3ed7a3"
RED = "#ff5e7d"
YELLOW = "#f5d76d"
PURPLE = "#a66af5"
GRAY = "#7e9bb3"
BTN = "#123d69"
FONT = "Segoe UI"

NAV = [("🏠", "Dashboard"), ("📈", "Live Monitor"), ("🖥", "Devices"), ("📦", "Packet Capture"),
       ("🔍", "Protocol Analysis"), ("⚠", "Alerts"), ("📄", "Logs"), ("📊", "Reports"), ("⚙", "Settings")]
PROTOCOLS = [("TCP", BLUE), ("UDP", GREEN), ("ICMP", YELLOW), ("ARP", RED), ("DNS", PURPLE), ("Others", GRAY)]
PKT_COLS = [("No.", 55), ("Time", 100), ("Source", 130), ("Destination", 130),
            ("Protocol", 70), ("Length", 60), ("Info", 300)]
NO_CAPTURE_HINT = ("Packet capture needs administrator / root rights.\n"
                   "Windows: run the terminal as Administrator and install Npcap.\n"
                   "Linux / macOS: run with sudo.")

FLAG_NAMES = {"F": "FIN", "S": "SYN", "R": "RST", "P": "PSH", "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR"}
ICMP_TYPES = {0: "Echo reply", 3: "Destination unreachable", 8: "Echo request", 11: "Time exceeded"}


# ============================================================
# SMALL HELPERS
# ============================================================
def fmt_bytes(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.2f} TB"


def fmt_rate(bps, compact=False):
    """bits/second -> '12.3 Mbps'. compact=True gives '50 Mbps' for chart axis labels."""
    for unit, div in (("Gbps", 1e9), ("Mbps", 1e6), ("Kbps", 1e3)):
        if bps >= div:
            v = bps / div
            return f"{v:g} {unit}" if compact else f"{v:.1f} {unit}"
    return f"{bps:.0f} bps"


def nice_max(bits):
    """Pick a round top value (1/2/5 x 10^n bps) for the chart's y axis."""
    steps = [m * 10 ** e for e in range(3, 11) for m in (1, 2, 5)]
    need = max(bits * 1.15, 10_000)
    return next((s for s in steps if s >= need), steps[-1])


def pie_layout(canvas_w, canvas_h):
    """Return centered, canvas-fit geometry for the protocol donut chart."""
    pad = 18
    cx = canvas_w / 2
    cy = canvas_h / 2
    radius = max(38, min(canvas_w, canvas_h) * 0.38)
    r = min(radius, (min(canvas_w, canvas_h) - pad * 2) / 2)
    return {"cx": cx, "cy": cy, "r": r, "inner_r": r * 0.54, "text_y": cy - 10, "sub_y": cy + 20}


def map_layout(canvas_w, canvas_h, node_count):
    """Return a compact network layout: router in the center, devices around it."""
    node_count = max(1, node_count)
    cx = canvas_w / 2
    cy = canvas_h / 2 + 10
    ring_radius = min(canvas_w, canvas_h) * 0.24
    x_positions, y_positions = [], []
    for i in range(node_count):
        angle = (2 * math.pi * i / node_count) - (math.pi / 2)
        x = cx + math.cos(angle) * ring_radius
        y = cy + math.sin(angle) * ring_radius
        x_positions.append(min(max(x, 42), canvas_w - 42))
        y_positions.append(min(max(y, 52), canvas_h - 48))
    return {"cx": cx, "cy": cy, "router_y": cy, "device_y": cy + 56,
            "x_positions": x_positions, "y_positions": y_positions}


def local_ip():
    """IP of this PC on the default route (a UDP 'connect' sends no packet)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "0.0.0.0"


def gateway_ip():
    try:
        gw = conf.route.route("0.0.0.0")[2]
        return "" if gw in ("0.0.0.0", None) else gw
    except Exception:
        return ""


def iface_name():
    try:
        i = conf.iface
        return getattr(i, "name", None) or str(i)
    except Exception:
        return "unknown"


@lru_cache(maxsize=4096)
def is_local(ip):
    """True for LAN-side addresses (192.168.x.x, 10.x.x.x ...) - these are the 'devices'."""
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private and not a.is_unspecified and not a.is_loopback
    except ValueError:
        return False


def service_name(port):
    try:
        name = socket.getservbyport(int(port))
        return {"domain": "dns", "https": "https"}.get(name, name)
    except (OSError, ValueError, OverflowError):
        return ""


def read_log_tail(n=300):
    """Last n rows of the CSV log (reads only the end of the file, so it stays fast when it is huge)."""
    if not os.path.exists(LOG_FILE):
        return []
    try:
        with open(LOG_FILE, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 65536))
            lines = f.read().decode("utf-8", errors="replace").splitlines()
        if size > 65536:
            lines = lines[1:]  # first line is probably cut in half
        rows = [r + [""] * (5 - len(r)) for r in csv.reader(lines) if r and r[0] != "Timestamp"]
        return rows[-n:]
    except OSError:
        return []


def parse_packet(pkt):
    """scapy packet -> dict for the UI, or None if it is not IP / ARP."""
    if ARP in pkt:
        a = pkt[ARP]
        info = f"Who has {a.pdst}? Tell {a.psrc}" if a.op == 1 else f"{a.psrc} is at {a.hwsrc}"
        return dict(src=a.psrc, dst=a.pdst, protocol="ARP", port="", info=info,
                    mac=a.hwsrc, length=len(pkt))
    if IP not in pkt:
        return None

    ip = pkt[IP]
    proto, port, info = "Others", "", f"IP protocol {ip.proto}"
    if TCP in pkt:
        t = pkt[TCP]
        flags = ", ".join(FLAG_NAMES.get(c, c) for c in str(t.flags))
        proto, port = "TCP", t.dport
        info = f"{t.sport} → {t.dport} [{flags}] Len={len(t.payload)}"
    elif UDP in pkt:
        u = pkt[UDP]
        proto, port = "UDP", u.dport
        info = f"{u.sport} → {u.dport} Len={len(u.payload)}"
    elif ICMP in pkt:
        proto = "ICMP"
        info = ICMP_TYPES.get(pkt[ICMP].type, f"Type {pkt[ICMP].type}")

    if DNS in pkt:
        proto = "DNS"
        name = ""
        if DNSQR in pkt:
            q = pkt[DNSQR].qname
            name = (q.decode(errors="replace") if isinstance(q, bytes) else str(q)).rstrip(".")
        info = ("Standard query " if pkt[DNS].qr == 0 else "Standard query response ") + name

    mac = pkt[Ether].src if Ether in pkt else ""
    return dict(src=ip.src, dst=ip.dst, protocol=proto, port=port, info=info,
                mac=mac, length=len(pkt))


# ============================================================
# BACKEND  (no tkinter here)
# ============================================================
class TrafficMonitor:
    """Sniffs packets on a background thread and keeps all statistics.
    The UI thread only calls sample() / snapshot() / start() / stop()."""

    def __init__(self, threshold=ALERT_THRESHOLD):
        self.lock = threading.Lock()
        self.threshold = threshold
        self.sniffer = None
        self.running = False

        self.local_ip = local_ip()
        self.gateway = gateway_ip()
        self.iface = iface_name()

        self.total_packets = 0
        self.total_bytes = 0
        self.total_rx = 0          # bytes received by this PC
        self.total_tx = 0          # bytes sent by this PC
        self.protocol_counts = Counter()
        self.port_counts = Counter()
        self.ip_bytes = Counter()
        self.devices = {}          # ip -> {packets, bytes, mac, last_seen}
        self.alerts = []           # newest first, max 100
        self.alert_total = 0

        self.queue = deque(maxlen=5000)   # packets waiting for the UI
        self.down = deque([0.0] * HIST, maxlen=HIST)   # bits per second
        self.up = deque([0.0] * HIST, maxlen=HIST)
        self.pps = deque([0.0] * HIST, maxlen=HIST)
        self._acc_pkts = self._acc_rx = self._acc_tx = 0
        self._last_sample = time.time()

        self._log_fh = None
        self._log_writer = None
        self._log_retry_at = 0

    # ---------- control ----------
    def start(self):
        if self.running:
            return
        self.sniffer = AsyncSniffer(prn=self.capture, store=False)
        self.sniffer.start()
        self.running = True

    def stop(self):
        if self.sniffer is not None:
            try:
                self.sniffer.stop()
            except Exception:
                pass  # was not running (e.g. failed to start)
        self.running = False
        self.flush_log()

    def error(self):
        """Exception raised inside the sniffer thread (e.g. no permission), else None."""
        return getattr(self.sniffer, "exception", None) if self.sniffer else None

    # ---------- runs on the sniffer thread ----------
    def capture(self, pkt):
        try:
            info = parse_packet(pkt)
            if info is None:
                return
            now = datetime.now()
            src, dst, proto, port, length = info["src"], info["dst"], info["protocol"], info["port"], info["length"]

            with self.lock:
                self.total_packets += 1
                self.total_bytes += length
                self._acc_pkts += 1
                if dst == self.local_ip:
                    self.total_rx += length
                    self._acc_rx += length
                elif src == self.local_ip:
                    self.total_tx += length
                    self._acc_tx += length

                self.protocol_counts[proto] += 1
                self.ip_bytes[src] += length
                self.ip_bytes[dst] += length

                if is_local(src):
                    d = self.devices.setdefault(src, dict(packets=0, bytes=0, mac="", last_seen=0))
                    d["packets"] += 1
                    d["bytes"] += length
                    d["last_seen"] = time.time()
                    if info["mac"] and (proto == "ARP" or not d["mac"]):
                        d["mac"] = info["mac"]

                self.queue.append((self.total_packets, now.strftime("%H:%M:%S.%f")[:-3],
                                   src, dst, proto, length, info["info"]))
                self._write_log(now, src, dst, proto, port)
                self._check_alert(now, port)
        except Exception:
            pass  # never let one odd packet kill the sniffer thread

    def _check_alert(self, now, port):
        if port == "":
            return
        key = str(port)
        self.port_counts[key] += 1
        count = self.port_counts[key]
        # same rule as before: first alert at the threshold, then every 25 packets
        if count >= self.threshold and (count == self.threshold or count % 25 == 0):
            self.alerts.insert(0, dict(time=now.strftime("%H:%M:%S"), port=key, packets=count,
                                       message=f"Port {key} reached {count} packets"))
            del self.alerts[100:]
            self.alert_total += 1

    def _write_log(self, now, src, dst, proto, port):
        if self._log_writer is None:
            if time.time() < self._log_retry_at:
                return
            try:
                new = not os.path.exists(LOG_FILE) or os.path.getsize(LOG_FILE) == 0
                self._log_fh = open(LOG_FILE, "a", newline="", encoding="utf-8")
                self._log_writer = csv.writer(self._log_fh)
                if new:
                    self._log_writer.writerow(["Timestamp", "Source IP", "Destination IP",
                                               "Protocol", "Destination Port"])
            except OSError:
                self._log_retry_at = time.time() + 10  # e.g. file open in Excel; try again later
                return
        try:
            self._log_writer.writerow([now.strftime("%Y-%m-%d %H:%M:%S"), src, dst, proto, port])
        except OSError:
            self._log_writer = None

    # ---------- called from the UI thread ----------
    def sample(self):
        """Turn the per-second accumulators into speeds. Call once per second."""
        with self.lock:
            now = time.time()
            dt = max(now - self._last_sample, 0.001)
            self.pps.append(self._acc_pkts / dt)
            self.down.append(self._acc_rx * 8 / dt)
            self.up.append(self._acc_tx * 8 / dt)
            self._acc_pkts = self._acc_rx = self._acc_tx = 0
            self._last_sample = now
            if self._log_fh:
                try:
                    self._log_fh.flush()
                except OSError:
                    pass

    def snapshot(self):
        with self.lock:
            return dict(packets=self.total_packets, bytes=self.total_bytes,
                        rx=self.total_rx, tx=self.total_tx,
                        protocols=Counter(self.protocol_counts), ports=Counter(self.port_counts),
                        ip_bytes=Counter(self.ip_bytes),
                        devices={ip: dict(d) for ip, d in self.devices.items()},
                        alerts=list(self.alerts), alert_total=self.alert_total)

    def drain(self, limit=300):
        out = []
        while len(out) < limit:
            try:
                out.append(self.queue.popleft())
            except IndexError:
                break
        return out

    def flush_log(self):
        with self.lock:
            if self._log_fh:
                try:
                    self._log_fh.flush()
                except OSError:
                    pass

    def close(self):
        self.stop()
        with self.lock:
            if self._log_fh:
                try:
                    self._log_fh.close()
                except OSError:
                    pass
                self._log_fh = self._log_writer = None


# ============================================================
# UI HELPERS
# ============================================================
def card(parent):
    frame = tk.Frame(parent, bg=PANEL, highlightbackground=BORDER, highlightthickness=1, bd=0)
    frame.configure(padx=0, pady=0)
    return frame


def heading(parent, text, color=TEXT):
    return tk.Label(parent, text=text, bg=PANEL, fg=color, font=(FONT, 12, "bold"), padx=0, pady=0)


def table(parent, cols, height=3):
    tv = ttk.Treeview(parent, columns=[str(i) for i in range(len(cols))], show="headings",
                      height=height, style="Dark.Treeview", selectmode="browse")
    for i, (name, width) in enumerate(cols):
        tv.heading(str(i), text=name, anchor="w")
        tv.column(str(i), width=width, minwidth=30, anchor="w")
    return tv


def fill(tree, rows, tags=None):
    """Replace every row of a table (small tables only)."""
    tree.delete(*tree.get_children())
    for i, r in enumerate(rows):
        tree.insert("", "end", values=r, tags=(tags[i],) if tags and tags[i] else ())


def flat_button(parent, text, command, bg=BTN, **kw):
    opts = dict(padx=14, pady=4)
    opts.update(kw)
    btn = tk.Button(parent, text=text, command=command, bg=bg, fg=TEXT, relief="solid", bd=1,
                    highlightbackground="#2a6ea8", highlightthickness=1, highlightcolor="#7bd5ff",
                    activebackground="#1f5f97", activeforeground=TEXT, font=(FONT, 9, "bold"),
                    cursor="hand2", **opts)
    btn.bind("<Enter>", lambda e: btn.config(bg="#1a5a8e", highlightbackground="#7bd5ff"))
    btn.bind("<Leave>", lambda e: btn.config(bg=bg, highlightbackground="#2a6ea8"))
    return btn


# ============================================================
# UI
# ============================================================
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} {VERSION} - Network Monitor & Analyzer")
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{min(1440, sw - 80)}x{min(900, sh - 100)}+30+20")
        self.minsize(1200, 760)
        self.configure(bg=BG)

        self.mon = TrafficMonitor()
        self.snap = self.mon.snapshot()
        self.t0 = time.time()
        self.rows = deque(maxlen=MAX_ROWS)      # captured packets, for Export / re-filtering
        self.pkt_trees, self.usage_canvases, self.cap_buttons = [], [], []
        self.filter_var = tk.StringVar()
        self.pages, self.current = {}, "Dashboard"
        self.err_shown = False

        self.setup_style()
        self.build_header()
        self.build_statusbar()
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True)
        self.build_sidebar(body)
        self.content = tk.Frame(body, bg=BG)
        self.content.pack(side="left", fill="both", expand=True, padx=(6, 8), pady=(0, 2))

        builders = {"Dashboard": self.page_dashboard, "Live Monitor": self.page_live,
                    "Devices": self.page_devices, "Packet Capture": self.page_capture,
                    "Protocol Analysis": self.page_protocols, "Alerts": self.page_alerts,
                    "Logs": self.page_logs, "Reports": self.page_reports, "Settings": self.page_settings}
        for name, build in builders.items():
            self.pages[name] = tk.Frame(self.content, bg=BG)
            build(self.pages[name])

        self.select("Dashboard")
        self.refresh_capture_ui()
        self.protocol("WM_DELETE_WINDOW", self.close)
        # Do not start packet capture automatically when the tool opens.
        # The user must press Start to begin monitoring.
        self.after(250, self.drain_packets)
        self.after(1000, self.tick)

    # ---------- styling ----------
    def setup_style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.layout("Dark.Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        s.configure("Dark.Treeview", background=PANEL, fieldbackground=PANEL, foreground=TEXT,
                    rowheight=23, borderwidth=0, font=(FONT, 9))
        s.configure("Dark.Treeview.Heading", background="#102b4f", foreground=TEXT, relief="flat",
                    borderwidth=0, font=(FONT, 9))
        s.map("Dark.Treeview", background=[("selected", "#153d6e")], foreground=[("selected", TEXT)])
        s.map("Dark.Treeview.Heading", background=[("active", "#102b4f")])

    # ---------- header / status bar / sidebar ----------
    def build_header(self):
        hdr = tk.Frame(self, bg="#0a2137", highlightbackground=BORDER, highlightthickness=1)
        hdr.pack(fill="x", padx=12, pady=(10, 8))

        brand = tk.Frame(hdr, bg="#0a2137")
        brand.pack(side="left", padx=(4, 8))
        logo = tk.Canvas(brand, width=34, height=34, bg=BG, highlightthickness=0)
        logo.pack(side="left")
        logo.create_oval(4, 4, 30, 30, fill="#0d2647", outline="#2aa8ff", width=2)
        logo.create_polygon(15, 9, 21, 15, 21, 22, 15, 28, 9, 22, 9, 15, fill="#2aa8ff", outline="#2aa8ff")
        logo.create_polygon(12, 16, 15, 13, 18, 16, 15, 19, fill="#dfeeff", outline="#dfeeff")
        t = tk.Frame(brand, bg=BG)
        t.pack(side="left", padx=(6, 0))
        tk.Label(t, text=APP_NAME, fg=TEXT, bg=BG, font=(FONT, 18, "bold")).pack(anchor="w")
        tk.Label(t, text="Network Monitor & Security Analyzer", fg="#a8c7eb", bg=BG,
                 font=(FONT, 9)).pack(anchor="w")

        search = tk.Frame(hdr, bg="#081d31", highlightbackground="#1d4f7b", highlightthickness=1)
        search.pack(side="left", expand=True, fill="x", padx=(10, 12), pady=4)
        tk.Label(search, text="🔍", bg="#081d31", fg="#8bc2ff", font=(FONT, 10)).pack(side="left", padx=(10, 6))
        e = tk.Entry(search, bg="#081d31", fg=TEXT, relief="flat", insertbackground=TEXT,
                     highlightthickness=0, width=36, font=(FONT, 10), justify="left")
        e.insert(0, "Search devices, IPs, domains, ports...")
        e.pack(side="left", fill="x", expand=True, padx=(0, 10), pady=7)

        r = tk.Frame(hdr, bg="#0a2137")
        r.pack(side="right", padx=(0, 10), pady=8)
        live = tk.Frame(r, bg="#0d2541", highlightbackground="#1d4f7b", highlightthickness=1,
                        cursor="hand2")
        live.pack(anchor="e", pady=3, padx=(0, 8))
        self.live_status = live
        self.live_dot = tk.Label(live, text="●", fg=GREEN, bg="#0d2541", font=(FONT, 11, "bold"))
        self.live_dot.pack(side="left", padx=(10, 4), pady=4)
        self.v_live = tk.StringVar(value=" Monitoring Active")
        self.live_label = tk.Label(live, textvariable=self.v_live, fg="#dff9ff", bg="#0d2541",
                                   font=(FONT, 9, "bold"), cursor="hand2")
        self.live_label.pack(side="left", padx=(0, 10), pady=4)
        live.bind("<Button-1>", lambda e: self.toggle_monitoring())
        self.live_label.bind("<Button-1>", lambda e: self.toggle_monitoring())

        info = tk.Frame(r, bg="#0a2137")
        info.pack(anchor="e", pady=2)
        tk.Label(info, text=f"{datetime.now().strftime('%a, %d %b %Y')}  {time.strftime('%H:%M:%S')}",
                 fg="#9ecbff", bg="#0a2137", font=(FONT, 9)).pack(side="right", padx=(6, 0))
        bell = tk.Label(info, text="🔔", fg="#dfeeff", bg="#0a2137", font=(FONT, 9), padx=8)
        bell.pack(side="right")

    def build_statusbar(self):
        bar = tk.Frame(self, bg=SIDE, highlightbackground=BORDER, highlightthickness=1)
        bar.pack(side="bottom", fill="x")
        self.status_msg = tk.StringVar(value="Ready")
        self.v_status_pk, self.v_uptime = tk.StringVar(), tk.StringVar()
        kw = dict(bg=SIDE, fg=MUTED, font=(FONT, 9))
        tk.Label(bar, textvariable=self.status_msg, **kw).pack(side="left", padx=(14, 8), pady=5)
        tk.Label(bar, textvariable=self.v_uptime, **kw).pack(side="right", padx=14)
        tk.Label(bar, textvariable=self.v_status_pk, **kw).pack(side="right", padx=10)
        tk.Label(bar, text=f"IP: {self.mon.local_ip}", **kw).pack(side="right", padx=10)
        tk.Label(bar, text=f"Interface: {self.mon.iface}", **kw).pack(side="right", padx=10)

        status_tag = tk.Label(bar, text="●", bg=SIDE, fg=GREEN, font=(FONT, 8, "bold"))
        status_tag.pack(side="right", padx=(10, 2), pady=4)

    def build_sidebar(self, parent):
        side = tk.Frame(parent, bg=SIDE, width=175, highlightbackground=BORDER, highlightthickness=1)
        side.pack(side="left", fill="y", padx=(6, 0), pady=(0, 8))
        side.pack_propagate(False)
        self.nav = {}
        for icon, name in NAV:
            row = tk.Frame(side, bg=SIDE, cursor="hand2", highlightbackground="#2d4b6d",
                           highlightthickness=0)
            row.pack(fill="x", padx=8, pady=2)
            lbl = tk.Label(row, text=f"{icon}   {name}", bg=SIDE, fg=TEXT, font=(FONT, 10),
                           anchor="w", padx=10, pady=8)
            lbl.pack(side="left", fill="x", expand=True)
            if name == "Alerts":
                self.badge = tk.Label(row, text="0", bg=RED, fg="white",
                                      font=(FONT, 8, "bold"), width=4, padx=2, pady=1)
                self.badge.pack(side="right", padx=(0, 12))
            for w in (row, lbl):
                w.bind("<Button-1>", lambda e, n=name: self.select(n))
                w.bind("<Enter>", lambda e, n=name: self.hover_nav(n, True))
                w.bind("<Leave>", lambda e, n=name: self.hover_nav(n, False))
            self.nav[name] = (row, lbl)
        footer = tk.Frame(side, bg=SIDE)
        footer.pack(side="bottom", fill="x", padx=10, pady=(10, 12))
        shield = tk.Canvas(footer, width=42, height=42, bg=SIDE, highlightthickness=0)
        shield.pack(side="left")
        shield.create_oval(6, 6, 36, 36, fill="#0f2d45", outline="#2aa8ff", width=2)
        shield.create_polygon(21, 12, 30, 17, 30, 26, 21, 31, 12, 26, 12, 17, fill="#2aa8ff", outline="#2aa8ff")
        tk.Label(footer, text=f"{APP_NAME}\n{VERSION}", bg=SIDE, fg=TEXT,
                 font=(FONT, 10, "bold"), justify="left").pack(side="left", padx=(6, 0))

    def hover_nav(self, name, active):
        if name == self.current:
            return
        row, lbl = self.nav[name]
        if active:
            row.config(bg="#123449", highlightthickness=1, highlightbackground="#3aa8ff")
            lbl.config(bg="#123449", fg="#ebfff4")
        else:
            row.config(bg=SIDE, highlightthickness=0, highlightbackground="#2d4b4d")
            lbl.config(bg=SIDE, fg=TEXT)

    def select(self, name):
        for n, (row, lbl) in self.nav.items():
            selected = n == name
            bg = "#123449" if selected else SIDE
            row.config(bg=bg, highlightthickness=1 if selected else 0)
            row.config(highlightbackground="#35a5ff" if selected else "#2d4b4d")
            lbl.config(bg=bg)
            if selected:
                lbl.config(fg="#e9fff5")
            else:
                lbl.config(fg=TEXT)
        for f in self.pages.values():
            f.pack_forget()
        self.pages[name].pack(fill="both", expand=True)
        self.current = name
        if name == "Logs":
            self.refresh_logs()
        self.update_idletasks()
        self.refresh_views()

    # ---------- reusable panels ----------
    def cap_buttons_in(self, parent):
        """Start / Stop buttons; every pair is kept in sync by refresh_capture_ui()."""
        bk = dict(relief="solid", bd=1, font=(FONT, 9), padx=14, pady=4, cursor="hand2", fg="white",
                  disabledforeground=MUTED, highlightthickness=1, highlightbackground="#2d4b4d")
        start = tk.Button(parent, text="▶ Start", command=lambda: self.set_capture(True), **bk)
        stop = tk.Button(parent, text="⏹ Stop", command=lambda: self.set_capture(False), **bk)
        start.pack(side="left")
        stop.pack(side="left", padx=6)
        self.cap_buttons.append((start, stop))

    def filter_entry(self, parent):
        tk.Label(parent, text="Filter (IP / tcp / udp ...):", bg=PANEL, fg=TEXT,
                 font=(FONT, 9)).pack(side="left", padx=(14, 4))
        e = tk.Entry(parent, textvariable=self.filter_var, width=20, bg="#0d1517", fg="#bfead4", relief="flat",
                     insertbackground=TEXT, highlightbackground=BORDER, highlightthickness=1, font=(FONT, 9))
        e.pack(side="left", ipady=3)
        e.bind("<Return>", lambda ev: self.refilter())   # Enter = apply to rows already shown

    def packet_panel(self, parent, title, controls=True, clear=True):
        p = card(parent)
        top = tk.Frame(p, bg=PANEL)
        top.pack(fill="x", padx=12, pady=(8, 4))
        heading(top, title).pack(side="left")
        if controls:
            ctl = tk.Frame(p, bg=PANEL)
            ctl.pack(fill="x", padx=12, pady=(0, 6))
            self.cap_buttons_in(ctl)
            flat_button(ctl, "Export", self.export).pack(side="right")
            if clear:
                flat_button(ctl, "Clear", self.clear_packets).pack(side="right", padx=6)
            tk.Label(ctl, textvariable=self.v_cap, bg=PANEL, fg=BLUE, font=(FONT, 9)).pack(side="right", padx=14)
            tk.Label(ctl, text="Captured:", bg=PANEL, fg=TEXT, font=(FONT, 9)).pack(side="right")
            self.filter_entry(ctl)
        tree = table(p, PKT_COLS)
        tree.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.pkt_trees.append(tree)
        return p

    def usage_panel(self, parent, height=150):
        p = card(parent)
        top = tk.Frame(p, bg=PANEL)
        top.pack(fill="x", padx=12, pady=(8, 0))
        for txt, clr in (("Upload", PURPLE), ("Download", BLUE)):
            tk.Label(top, text=f"■ {txt}", bg=PANEL, fg=clr, font=(FONT, 9)).pack(side="right", padx=6)
        heading(top, "🌐 Network Usage (Live)").pack(side="left")
        c = tk.Canvas(p, bg=PANEL, height=height, highlightthickness=0)
        c.pack(fill="both", expand=True, padx=8, pady=(4, 8))
        c.bind("<Configure>", lambda e, c=c: self.draw_usage(c))
        self.usage_canvases.append(c)
        return p

    def stat_card(self, parent, col, icon, color, label, sub_colors):
        c = card(parent)
        c.grid(row=0, column=col, sticky="nsew", padx=5, pady=0)
        c.grid_propagate(False)
        icon_box = tk.Frame(c, bg="#102d48", highlightbackground="#23598d", highlightthickness=1)
        icon_box.pack(side="left", padx=(10, 8), pady=10)
        icon_box.pack_propagate(False)
        tk.Label(icon_box, text=icon, bg="#102d48", fg=color, font=(FONT, 20)).pack(padx=12, pady=10)
        box = tk.Frame(c, bg=PANEL)
        box.pack(side="left", fill="both", expand=True, pady=13)
        tk.Label(box, text=label, bg=PANEL, fg=TEXT, font=(FONT, 10)).pack(anchor="w")
        var = tk.StringVar(value="0")
        tk.Label(box, textvariable=var, bg=PANEL, fg=TEXT, font=(FONT, 17, "bold")).pack(anchor="w")
        sub = tk.Frame(box, bg=PANEL)
        sub.pack(anchor="w")
        subs = []
        for clr in sub_colors:
            v = tk.StringVar()
            tk.Label(sub, textvariable=v, bg=PANEL, fg=clr, font=(FONT, 8)).pack(side="left", padx=(0, 6))
            subs.append(v)
        return var, subs

    # ============================================================
    # PAGES
    # ============================================================
    def page_dashboard(self, main):
        main.columnconfigure(0, weight=1)
        main.rowconfigure(0, weight=0)
        for r in (1, 2, 3):
            main.rowconfigure(r, weight=1)
        self.v_cap = tk.StringVar(value="0 packets")

        def row(i, weights):
            f = tk.Frame(main, bg=BG)
            f.grid(row=i, column=0, sticky="nsew", padx=0, pady=(0, 8))
            f.rowconfigure(0, weight=1)
            for c, w in enumerate(weights):
                f.columnconfigure(c, weight=w, uniform=f"r{i}")
            return f

        # row 0: stat cards
        stats = row(0, [1] * 5)
        stats.rowconfigure(0, weight=0)
        self.v_dev, (self.v_on, self.v_off) = self.stat_card(stats, 0, "🖥", BLUE, "Total Devices", [GREEN, RED])
        self.v_pps, (self.v_pps_sub,) = self.stat_card(stats, 1, "📈", BLUE, "Packets / Second", [GREEN])
        self.v_down, _ = self.stat_card(stats, 2, "⬇", BLUE, "Download Speed", [])
        self.v_up, _ = self.stat_card(stats, 3, "⬆", PURPLE, "Upload Speed", [])
        self.v_total, (self.v_tdown, self.v_tup) = self.stat_card(stats, 4, "🗄", BLUE, "Total Data (Session)",
                                                                  [BLUE, PURPLE])

        # row 1: usage chart, protocol donut, top IPs
        r1 = row(1, [5, 4, 4])
        self.usage_panel(r1).grid(row=0, column=0, sticky="nsew", padx=5)

        p = card(r1)
        p.grid(row=0, column=1, sticky="nsew", padx=5)
        heading(p, "Protocol Distribution").pack(anchor="w", padx=12, pady=(10, 0))
        inner = tk.Frame(p, bg=PANEL)
        inner.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        inner.columnconfigure(0, weight=1)
        inner.columnconfigure(1, weight=0)
        self.pie = tk.Canvas(inner, bg=PANEL, width=170, height=170, highlightthickness=0)
        self.pie.grid(row=0, column=0, sticky="nsew")
        self.pie_txt = self.pie.create_text(86, 78, text="0", fill=TEXT, font=(FONT, 18, "bold"))
        self.pie.create_text(86, 100, text="pkts/s", fill=MUTED, font=(FONT, 9))
        legend = tk.Frame(inner, bg=PANEL)
        legend.grid(row=0, column=1, sticky="n", padx=(8, 0), pady=(12, 0))
        self.pie_vars = {}
        for i, (name, clr) in enumerate(PROTOCOLS):
            self.pie_vars[name] = tk.StringVar(value="0%")
            tk.Label(legend, text="■", bg=PANEL, fg=clr).grid(row=i, column=0, pady=2)
            tk.Label(legend, text=name, bg=PANEL, fg=TEXT, font=(FONT, 9)).grid(row=i, column=1, sticky="w", padx=6)
            tk.Label(legend, textvariable=self.pie_vars[name], bg=PANEL, fg=TEXT,
                     font=(FONT, 9)).grid(row=i, column=2, padx=(14, 0))

        p = card(r1)
        p.grid(row=0, column=2, sticky="nsew", padx=5)
        heading(p, "Top IP Addresses (By Traffic)").pack(anchor="w", padx=12, pady=(10, 4))
        self.tree_top = table(p, [("#", 30), ("IP Address", 140), ("Data Usage", 90)])
        self.tree_top.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        # row 2: devices + live alerts
        r2 = row(2, [1, 1])
        p = card(r2)
        p.grid(row=0, column=0, sticky="nsew", padx=5)
        heading(p, "Connected Devices").pack(anchor="w", padx=12, pady=(10, 4))
        self.tree_dev = table(p, [("IP Address", 110), ("MAC Address", 140), ("Device Name", 100),
                                  ("Status", 80), ("Data", 90)])
        self.tree_dev.tag_configure("off", foreground="#f87171")
        self.tree_dev.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        p = card(r2)
        p.grid(row=0, column=1, sticky="nsew", padx=5)
        top = tk.Frame(p, bg=PANEL)
        top.pack(fill="x", padx=12, pady=(10, 4))
        heading(top, "Live Security Alerts").pack(side="left")
        va = tk.Label(top, text="View All", bg=PANEL, fg=BLUE, font=(FONT, 9), cursor="hand2")
        va.pack(side="right")
        va.bind("<Button-1>", lambda e: self.select("Alerts"))
        self.tree_alert = table(p, [("Time", 70), ("Alert", 160), ("Details", 300)])
        self.tree_alert.tag_configure("alert", foreground="#ff8a8a")
        self.tree_alert.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        # row 3: packet capture + network map
        r3 = row(3, [2, 1])
        self.packet_panel(r3, "📄 Packet Capture (Live)", clear=False).grid(row=0, column=0, sticky="nsew", padx=5)

        p = card(r3)
        p.grid(row=0, column=1, sticky="nsew", padx=5)
        top = tk.Frame(p, bg=PANEL)
        top.pack(fill="x", padx=12, pady=(10, 0))
        heading(top, "Network Map").pack(side="left")
        flat_button(top, "Refresh", self.draw_map, padx=10, pady=2).pack(side="right")
        self.map = tk.Canvas(p, bg=PANEL, height=150, highlightthickness=0)
        self.map.pack(fill="both", expand=True, padx=8, pady=8)
        self.map.bind("<Configure>", lambda e: self.draw_map())

    def page_live(self, f):
        f.columnconfigure(0, weight=1)
        f.rowconfigure(1, weight=2)
        f.rowconfigure(2, weight=3)
        bar = card(f)
        bar.grid(row=0, column=0, sticky="ew", padx=5, pady=4)
        heading(bar, "📈 Live Monitor").pack(side="left", padx=12, pady=8)
        inner = tk.Frame(bar, bg=PANEL)
        inner.pack(side="right", padx=12)
        self.cap_buttons_in(inner)
        self.usage_panel(f, height=200).grid(row=1, column=0, sticky="nsew", padx=5, pady=4)
        self.packet_panel(f, "📄 Live Packets", controls=False).grid(row=2, column=0, sticky="nsew", padx=5, pady=4)

    def page_devices(self, f):
        f.columnconfigure(0, weight=1)
        f.rowconfigure(0, weight=1)
        p = card(f)
        p.grid(row=0, column=0, sticky="nsew", padx=5, pady=4)
        heading(p, "🖥 Devices on your network").pack(anchor="w", padx=12, pady=(8, 0))
        tk.Label(p, text="Devices are found from the traffic your PC can see (private IP addresses only).",
                 bg=PANEL, fg=MUTED, font=(FONT, 9)).pack(anchor="w", padx=12, pady=(0, 6))
        self.tree_dev_page = table(p, [("IP Address", 130), ("MAC Address", 160), ("Device Name", 130),
                                       ("Packets", 90), ("Data", 100), ("Status", 100), ("Last Seen", 100)])
        self.tree_dev_page.tag_configure("off", foreground="#f87171")
        self.tree_dev_page.pack(fill="both", expand=True, padx=8, pady=(0, 8))

    def page_capture(self, f):
        f.columnconfigure(0, weight=1)
        f.rowconfigure(0, weight=1)
        self.packet_panel(f, "📦 Packet Capture").grid(row=0, column=0, sticky="nsew", padx=5, pady=4)

    def page_protocols(self, f):
        f.columnconfigure((0, 1), weight=1, uniform="pr")
        f.rowconfigure(1, weight=1)
        bar = card(f)
        bar.grid(row=0, column=0, columnspan=2, sticky="ew", padx=5, pady=4)
        heading(bar, "🔍 Protocol Analysis").pack(side="left", padx=12, pady=8)
        self.v_proto_sum = tk.StringVar()
        tk.Label(bar, textvariable=self.v_proto_sum, bg=PANEL, fg=BLUE, font=(FONT, 10)).pack(side="right", padx=14)

        p = card(f)
        p.grid(row=1, column=0, sticky="nsew", padx=5, pady=4)
        heading(p, "Protocols").pack(anchor="w", padx=12, pady=(8, 4))
        self.tree_proto = table(p, [("Protocol", 120), ("Packets", 100), ("Share", 80)])
        self.tree_proto.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        p = card(f)
        p.grid(row=1, column=1, sticky="nsew", padx=5, pady=4)
        heading(p, "Destination Ports").pack(anchor="w", padx=12, pady=(8, 4))
        self.tree_port = table(p, [("Port", 80), ("Service", 120), ("Packets", 100)])
        self.tree_port.pack(fill="both", expand=True, padx=8, pady=(0, 8))

    def page_alerts(self, f):
        f.columnconfigure(0, weight=1)
        f.rowconfigure(0, weight=1)
        p = card(f)
        p.grid(row=0, column=0, sticky="nsew", padx=5, pady=4)
        heading(p, "⚠ Security Alerts").pack(anchor="w", padx=12, pady=(8, 0))
        self.v_alert_note = tk.StringVar()
        tk.Label(p, textvariable=self.v_alert_note, bg=PANEL, fg=MUTED, font=(FONT, 9)).pack(anchor="w", padx=12,
                                                                                            pady=(0, 6))
        self.tree_alerts_page = table(p, [("Time", 90), ("Alert", 170), ("Port", 70), ("Packets", 80),
                                          ("Details", 380)])
        self.tree_alerts_page.tag_configure("alert", foreground="#ff8a8a")
        self.tree_alerts_page.pack(fill="both", expand=True, padx=8, pady=(0, 8))

    def page_logs(self, f):
        f.columnconfigure(0, weight=1)
        f.rowconfigure(0, weight=1)
        p = card(f)
        p.grid(row=0, column=0, sticky="nsew", padx=5, pady=4)
        top = tk.Frame(p, bg=PANEL)
        top.pack(fill="x", padx=12, pady=(8, 4))
        heading(top, "📄 Traffic Log").pack(side="left")
        flat_button(top, "Refresh Logs", self.refresh_logs).pack(side="right")
        tk.Label(top, text=f"{os.path.abspath(LOG_FILE)}  (last 300 rows)", bg=PANEL, fg=MUTED,
                 font=(FONT, 8)).pack(side="right", padx=12)
        self.tree_logs = table(p, [("Timestamp", 160), ("Source IP", 150), ("Destination IP", 150),
                                   ("Protocol", 90), ("Destination Port", 120)])
        self.tree_logs.pack(fill="both", expand=True, padx=8, pady=(0, 8))

    def page_reports(self, f):
        p = card(f)
        p.pack(fill="x", padx=5, pady=4)
        heading(p, "📊 Reports").pack(anchor="w", padx=12, pady=(10, 2))
        tk.Label(p, text="Saves a text report (packets, protocols, ports, top IPs, alerts) in the current folder.",
                 bg=PANEL, fg=MUTED, font=(FONT, 9)).pack(anchor="w", padx=12, pady=(0, 10))
        tk.Button(p, text="Generate Report", command=self.generate_report, bg="#2a4a45", fg="white",
                  relief="solid", bd=1, highlightbackground="#7ae1a6", highlightthickness=1,
                  font=(FONT, 10, "bold"), padx=18, pady=6, cursor="hand2").pack(anchor="w", padx=12)
        self.v_report = tk.StringVar()
        tk.Label(p, textvariable=self.v_report, bg=PANEL, fg=GREEN, font=(FONT, 9)).pack(anchor="w", padx=12,
                                                                                        pady=10)

    def page_settings(self, f):
        p = card(f)
        p.pack(fill="x", padx=5, pady=4)
        heading(p, "⚙ Settings").pack(anchor="w", padx=12, pady=(10, 8))
        r = tk.Frame(p, bg=PANEL)
        r.pack(anchor="w", padx=12, pady=4)
        tk.Label(r, text="Alert threshold (packets per port):", bg=PANEL, fg=TEXT, font=(FONT, 10)).pack(side="left")
        self.threshold_entry = tk.Entry(r, width=8, bg="#0d1517", fg=TEXT, relief="flat", insertbackground=TEXT,
                                        highlightbackground=BORDER, highlightthickness=1, font=(FONT, 10))
        self.threshold_entry.insert(0, str(self.mon.threshold))
        self.threshold_entry.pack(side="left", padx=10, ipady=3)
        tk.Button(r, text="Save", command=self.save_settings, bg="#2a4a45", fg="white", relief="solid",
                  bd=1, highlightbackground="#7ae1a6", highlightthickness=1,
                  font=(FONT, 9, "bold"), padx=16, pady=3, cursor="hand2").pack(side="left")
        for label, value in (("Interface", self.mon.iface), ("Local IP", self.mon.local_ip),
                             ("Gateway", self.mon.gateway or "unknown"), ("Log file", os.path.abspath(LOG_FILE))):
            tk.Label(p, text=f"{label}:  {value}", bg=PANEL, fg=MUTED, font=(FONT, 9)).pack(anchor="w", padx=12, pady=2)
        tk.Frame(p, bg=PANEL, height=10).pack()

    # ============================================================
    # DRAWING
    # ============================================================
    def draw_usage(self, c):
        c.delete("all")
        w, h = c.winfo_width(), c.winfo_height()
        if w < 80 or h < 60:
            return

        pad_left, pad_right, pad_top, pad_bottom = 64, 12, 10, 26
        chart_w = w - pad_left - pad_right
        chart_h = h - pad_top - pad_bottom

        if chart_w <= 0 or chart_h <= 0:
            return

        max_value = max(10_000, max(max(self.mon.down), max(self.mon.up)))
        y_top = nice_max(max_value)

        for frac in (0, 0.25, 0.5, 0.75, 1):
            y = pad_top + chart_h - int(chart_h * frac)
            c.create_line(pad_left, y, w - pad_right, y, fill="#1d3a59", width=1)
            c.create_text(pad_left - 6, y, text=fmt_rate(y_top * frac, compact=True), anchor="e",
                          fill=MUTED, font=(FONT, 8))

        for series, line_color, glow_color, fill_color in (
            (self.mon.down, "#3fa9ff", "#8fd1ff", "#163d68"),
            (self.mon.up, "#a88dff", "#d8caff", "#2e245a")
        ):
            if not series:
                continue

            pts = []
            for i, v in enumerate(series):
                x = pad_left + int(round(chart_w * i / max(len(series) - 1, 1)))
                y = pad_top + chart_h - int(round(chart_h * min(v, y_top) / y_top))
                pts.extend([x, y])

            if len(pts) >= 4:
                fill_pts = pts + [w - pad_right, h - pad_bottom, pad_left, h - pad_bottom]
                c.create_polygon(fill_pts, fill=fill_color, outline="", smooth=False)
                c.create_line(pts, fill=glow_color, width=7, smooth=False)
                c.create_line(pts, fill=line_color, width=3, smooth=False, splines=False)

        now = time.time()
        for k in range(0, HIST, 12):
            x = pad_left + int(round(chart_w * k / (HIST - 1)))
            label = time.strftime("%H:%M:%S", time.localtime(now - (HIST - 1 - k)))
            c.create_text(x, h - 8, text=label, fill=MUTED, font=(FONT, 8))

    def draw_pie(self):
        c = self.pie
        c.delete("all")
        counts = self.snap["protocols"]
        total = sum(counts.values())
        w, h = c.winfo_width(), c.winfo_height()
        layout = pie_layout(w, h)
        cx, cy, r = layout["cx"], layout["cy"], layout["r"]

        c.create_oval(cx - r, cy - r, cx + r, cy + r, fill="#0b2038", outline="#214d77", width=2)
        if total == 0:
            c.create_arc(cx - r + 8, cy - r + 8, cx + r - 8, cy + r - 8, start=90, extent=-359.9,
                         style="arc", outline=BORDER, width=18, tags="arc")
        else:
            start = 90
            for name, clr in PROTOCOLS:
                extent = -360 * counts.get(name, 0) / total
                if extent > -0.5:
                    continue
                c.create_arc(cx - r + 8, cy - r + 8, cx + r - 8, cy + r - 8, start=start,
                             extent=max(extent, -359.9), style="arc", outline=clr, width=18, tags="arc")
                start += extent
        inner_r = layout["inner_r"]
        c.create_oval(cx - inner_r, cy - inner_r, cx + inner_r, cy + inner_r, fill="#0f2339", outline="")
        for name, _ in PROTOCOLS:
            share = counts.get(name, 0) * 100 / total if total else 0
            self.pie_vars[name].set(f"{share:.0f}%")
        c.itemconfig(self.pie_txt, text=f"{self.mon.pps[-1]:.0f}")
        c.coords(self.pie_txt, cx, layout["text_y"])

    def draw_map(self):
        c = self.map
        c.delete("all")
        w, h = c.winfo_width(), c.winfo_height()
        if w < 80 or h < 60:
            return
        now = time.time()
        gw = self.mon.gateway
        nodes = [(ip, d) for ip, d in sorted(self.snap["devices"].items(),
                                             key=lambda kv: kv[1]["last_seen"], reverse=True) if ip != gw][:5]
        layout = map_layout(w, h, len(nodes) or 1)
        cx = layout["cx"]
        cy = layout["cy"]

        c.create_line(cx, 12, cx, 46, fill=BLUE, width=2)
        c.create_oval(cx - 18, 2, cx + 18, 34, outline=BLUE, width=2, fill="")
        c.create_text(cx, 18, text="Internet", fill=TEXT, font=(FONT, 8))

        router_r = min(w, h) * 0.12
        c.create_oval(cx - router_r, cy - router_r, cx + router_r, cy + router_r,
                      fill="#0b2238", outline=BLUE, width=2)
        c.create_text(cx, cy, text="Router", fill=TEXT, font=(FONT, 8, "bold"))
        c.create_text(cx, cy + 16, text=gw or 'unknown', fill=MUTED, font=(FONT, 7))

        if not nodes:
            c.create_text(cx, h - 24, text="No devices seen yet", fill=MUTED, font=(FONT, 9))
            return

        for i, (ip, d) in enumerate(nodes):
            x = layout["x_positions"][i]
            y = layout["y_positions"][i]
            up = now - d["last_seen"] <= ONLINE_WINDOW
            c.create_line(cx, cy, x, y, fill=GREEN if up else RED, width=2)
            node_r = 15
            c.create_oval(x - node_r, y - node_r, x + node_r, y + node_r,
                          fill="#0b2238", outline=BLUE if up else RED, width=2)
            c.create_text(x, y - 2, text="PC", fill=TEXT, font=(FONT, 7, "bold"))
            c.create_text(x, y + 16, text=self.device_name(ip), fill=TEXT, font=(FONT, 7), justify="center")
            c.create_text(x, y + 28, text=ip, fill=MUTED, font=(FONT, 6), justify="center")

    def device_name(self, ip):
        if ip == self.mon.local_ip:
            return "This PC"
        return "Router" if ip == self.mon.gateway else "Device"

    # ============================================================
    # PACKETS
    # ============================================================
    def filter_rule(self):
        text = self.filter_var.get().lower()
        ips = re.findall(r"\d+\.\d+\.\d+\.\d+", text)
        protos = {n.lower() for n, _ in PROTOCOLS if re.search(rf"\b{n.lower()}\b", text)}
        return lambda row: (not ips or any(ip in (row[2], row[3]) for ip in ips)) and \
                           (not protos or row[4].lower() in protos)

    def insert_rows(self, tree, rows):
        at_bottom = tree.yview()[1] >= 0.999          # only auto-scroll if the user is at the bottom
        for r in rows:
            tree.insert("", "end", values=r)
        kids = tree.get_children()
        if len(kids) > 200:
            tree.delete(*kids[:len(kids) - 200])
            kids = tree.get_children()
        if kids and at_bottom:
            tree.see(kids[-1])

    def drain_packets(self):
        try:
            batch = self.mon.drain()
            if batch:
                self.rows.extend(batch)
                rule = self.filter_rule()
                show = [r for r in batch if rule(r)][-40:]
                if show:
                    for tree in self.pkt_trees:
                        self.insert_rows(tree, show)
        finally:
            self.after(250, self.drain_packets)

    def refilter(self):
        rule = self.filter_rule()
        rows = [r for r in self.rows if rule(r)][-200:]
        for tree in self.pkt_trees:
            tree.delete(*tree.get_children())
            self.insert_rows(tree, rows)

    def clear_packets(self):
        self.rows.clear()
        for tree in self.pkt_trees:
            tree.delete(*tree.get_children())

    def export(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV file", "*.csv")])
        if path:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["No", "Time", "Source", "Destination", "Protocol", "Length", "Info"])
                w.writerows(self.rows)
            self.status_msg.set(f"Exported {len(self.rows)} packets to {path}")

    # ============================================================
    # CAPTURE CONTROL
    # ============================================================
    def toggle_monitoring(self):
        self.set_capture(not self.mon.running)

    def set_capture(self, on):
        if on:
            self.err_shown = False
            try:
                self.mon.start()
            except Exception as e:
                messagebox.showerror("Capture Error", f"Could not start packet capture.\n\n{e}\n\n{NO_CAPTURE_HINT}")
        else:
            self.mon.stop()
        self.refresh_capture_ui()

    def refresh_capture_ui(self):
        on = self.mon.running
        if "cap_buttons" in self.__dict__:
            for start, stop in self.cap_buttons:
                start.config(state="disabled" if on else "normal", bg="#2a4a45" if on else GREEN,
                            highlightbackground="#9ae6b4" if on else "#2d4b4d")
                stop.config(state="normal" if on else "disabled", bg=RED if on else "#2a4a45",
                            highlightbackground="#ffb1a8" if on else "#2d4b4d")
        if "live_dot" in self.__dict__:
            self.live_dot.config(fg=GREEN if on else RED)
        if "live_status" in self.__dict__:
            self.live_status.config(bg="#0d2541", highlightbackground="#2aa8ff" if on else "#1d4f7b")
        if "live_label" in self.__dict__:
            self.live_label.config(fg="#dff9ff" if on else "#f4d7d7")
        if "v_live" in self.__dict__:
            self.v_live.set(" Monitoring Active" if on else " Monitoring Stopped")
        if "status_msg" in self.__dict__:
            self.status_msg.set("Capturing packets..." if on else "Stopped")

    def check_sniffer(self):
        """The sniffer runs in its own thread, so a permission error only shows up here."""
        err = self.mon.error()
        if err and self.mon.running and not self.err_shown:
            self.err_shown = True
            self.mon.running = False
            self.refresh_capture_ui()
            messagebox.showerror("Capture Error", f"Packet capture stopped.\n\n{err}\n\n{NO_CAPTURE_HINT}")

    # ============================================================
    # REFRESH LOOP
    # ============================================================
    def tick(self):
        try:
            self.check_sniffer()
            self.mon.sample()
            self.snap = self.mon.snapshot()
            self.refresh_views()
        finally:
            self.after(1000, self.tick)

    def refresh_views(self):
        s, mon, now = self.snap, self.mon, time.time()
        devs = s["devices"]
        online = sum(now - d["last_seen"] <= ONLINE_WINDOW for d in devs.values())
        pps, down, up = mon.pps[-1], mon.down[-1], mon.up[-1]
        prev = list(mon.pps)[-11:-1]
        avg = sum(prev) / len(prev) if prev else 0
        pct = (pps - avg) / avg * 100 if avg > 0 else 0

        self.v_dev.set(str(len(devs)))
        self.v_on.set(f"{online} Online")
        self.v_off.set(f"{len(devs) - online} Offline")
        self.v_pps.set(f"{pps:.0f}")
        self.v_pps_sub.set(f"{'↑' if pct >= 0 else '↓'} {abs(pct):.0f}%")
        self.v_down.set(fmt_rate(down))
        self.v_up.set(fmt_rate(up))
        self.v_total.set(fmt_bytes(s["bytes"]))
        self.v_tdown.set(f"↓ {fmt_bytes(s['rx'])}")
        self.v_tup.set(f"↑ {fmt_bytes(s['tx'])}")
        self.v_cap.set(f"{s['packets']:,} packets")
        self.v_status_pk.set(f"Packets: {s['packets']:,}")
        secs = int(now - self.t0)
        self.v_uptime.set(f"Uptime: {secs // 3600:02d}:{secs % 3600 // 60:02d}:{secs % 60:02d}")
        n = s["alert_total"]
        self.badge.config(text="99+" if n > 99 else str(n), bg=RED if n else "#2a4a45")

        for c in self.usage_canvases:
            if c.winfo_ismapped():
                self.draw_usage(c)

        dev_rows, dev_tags = [], []
        for ip, d in sorted(devs.items(), key=lambda kv: kv[1]["last_seen"], reverse=True):
            up_now = now - d["last_seen"] <= ONLINE_WINDOW
            dev_rows.append((ip, d["mac"] or "—", self.device_name(ip), "● Online" if up_now else "● Offline",
                             fmt_bytes(d["bytes"]), d["packets"], time.strftime("%H:%M:%S", time.localtime(d["last_seen"]))))
            dev_tags.append(None if up_now else "off")
        alert_rows = [(a["time"], "⚠ High Port Traffic", a["port"], a["packets"], a["message"]) for a in s["alerts"]]

        if self.current == "Dashboard":
            self.draw_pie()
            self.draw_map()
            fill(self.tree_top, [(i, ip, fmt_bytes(b)) for i, (ip, b) in enumerate(s["ip_bytes"].most_common(5), 1)])
            fill(self.tree_dev, [(r[0], r[1], r[2], r[3], r[4]) for r in dev_rows[:8]], dev_tags[:8])
            fill(self.tree_alert, [(r[0], r[1], r[4]) for r in alert_rows[:8]], ["alert"] * len(alert_rows[:8]))
        elif self.current == "Devices":
            fill(self.tree_dev_page, [(r[0], r[1], r[2], r[5], r[4], r[3], r[6]) for r in dev_rows], dev_tags)
        elif self.current == "Protocol Analysis":
            p, total = s["protocols"], sum(s["protocols"].values())
            self.v_proto_sum.set("     ".join(f"{n}: {p.get(n, 0)}" for n, _ in PROTOCOLS))
            fill(self.tree_proto, [(k, v, f"{v * 100 / total:.1f}%") for k, v in p.most_common()])
            fill(self.tree_port, [(k, service_name(k), v) for k, v in s["ports"].most_common(20)])
        elif self.current == "Alerts":
            self.v_alert_note.set(f"Alert when one port receives {mon.threshold}+ packets   |   "
                                  f"{s['alert_total']} alert(s) this session (showing latest 100)")
            fill(self.tree_alerts_page, alert_rows, ["alert"] * len(alert_rows))

    def refresh_logs(self):
        fill(self.tree_logs, reversed(read_log_tail()))

    # ============================================================
    # SETTINGS / REPORT / CLOSE
    # ============================================================
    def save_settings(self):
        try:
            value = int(self.threshold_entry.get())
            if value < 1:
                raise ValueError
        except ValueError:
            messagebox.showerror("Settings", "Please enter a valid number (1 or more).")
            return
        self.mon.threshold = value
        messagebox.showinfo("Settings", f"Alert threshold set to {value} packets.")

    def generate_report(self):
        s = self.mon.snapshot()
        name = f"{APP_NAME}_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(name, "w", encoding="utf-8") as f:
                w = f.write
                w("====================================\n")
                w(f"        {APP_NAME.upper()} REPORT\n")
                w("====================================\n\n")
                w(f"Generated: {datetime.now()}\n")
                w(f"Interface: {self.mon.iface}   IP: {self.mon.local_ip}\n\n")
                w(f"Total Packets: {s['packets']}\n")
                w(f"Total Data: {s['bytes'] / 1024 / 1024:.2f} MB\n\n")
                w("PROTOCOL STATISTICS\n-------------------\n")
                for k, v in s["protocols"].most_common():
                    w(f"{k}: {v}\n")
                w("\nTOP DESTINATION PORTS\n----------------------\n")
                for k, v in s["ports"].most_common(20):
                    w(f"Port {k}: {v}\n")
                w("\nTOP IP ADDRESSES\n-----------------\n")
                for k, v in s["ip_bytes"].most_common(20):
                    w(f"{k}: {v / 1024:.2f} KB\n")
                w("\nSECURITY ALERTS\n----------------\n")
                for a in s["alerts"]:
                    w(f"{a['time']} | Port {a['port']} | {a['packets']} packets | {a['message']}\n")
            self.v_report.set(f"Report saved: {os.path.abspath(name)}")
            messagebox.showinfo("Report", "Report generated successfully.")
        except OSError as e:
            messagebox.showerror("Report Error", str(e))

    def close(self):
        self.mon.close()
        self.destroy()


if __name__ == "__main__":
    App().mainloop()