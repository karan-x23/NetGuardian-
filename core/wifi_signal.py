"""Read the current Windows Wi-Fi link quality without scanning networks."""

import os
import re
import subprocess


def parse_signal(output, adapter_mac):
    """Match the selected interface by MAC and read its reported percentage."""
    mac_pattern = r"(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}"
    adapter_mac = adapter_mac.lower().replace("-", ":")
    for block in re.split(r"\r?\n\s*\r?\n", output):
        # The first MAC is the interface address; later entries may be the AP's BSSID.
        mac = re.search(rf"^\s*[^:\r\n]+:\s*({mac_pattern})\s*$", block, re.I | re.M)
        if not mac or mac.group(1).lower().replace("-", ":") != adapter_mac:
            continue
        values = re.findall(r"^\s*[^:\r\n]+:\s*(\d{1,3})\s*%\s*$", block, re.M)
        if len(values) == 1 and int(values[0]) <= 100:
            return int(values[0])
    return None


def wifi_signal(adapter_mac):
    if os.name != "nt":
        return None
    result = subprocess.run(
        ["netsh", "wlan", "show", "interfaces"],
        capture_output=True, text=True, errors="replace", timeout=3,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if result.returncode != 0:
        return None
    return parse_signal(result.stdout, adapter_mac)
