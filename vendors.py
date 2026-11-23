"""Manufacturer lookup from the first three bytes of a MAC address (the OUI).

The built-in table is short and covers common home and office brands. For the
full list, download the IEEE OUI file (oui.txt) and point "oui_file" in
config.json at it; NetWatch reads lines like "B8-27-EB   (hex)   Raspberry Pi".
"""
import json
import os

BASE = os.path.dirname(os.path.abspath(__file__))

BUILTIN = {
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "00:0C:29": "VMware",
    "00:50:56": "VMware",
    "24:0A:C4": "Espressif (IoT)",
    "30:AE:A4": "Espressif (IoT)",
    "18:E8:29": "Ubiquiti",
    "FC:EC:DA": "Ubiquiti",
    "00:1B:63": "Apple",
    "3C:22:FB": "Apple",
    "00:50:F2": "Microsoft",
    "00:15:5D": "Microsoft (Hyper-V)",
    "00:1A:11": "Google",
    "00:0C:43": "Ralink (Wi-Fi chip)",
}

_cache = {}


def _load_file(path):
    table = {}
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if "(hex)" in line:
                    prefix, _, name = line.partition("(hex)")
                    key = prefix.strip().replace("-", ":").upper()
                    if len(key) == 8:
                        table[key] = name.strip()
    except OSError:
        pass
    return table


def configure(oui_file=None):
    """Load the optional full OUI file, if configured and present."""
    _cache.clear()
    if oui_file:
        path = oui_file if os.path.isabs(oui_file) else os.path.join(BASE, oui_file)
        _cache.update(_load_file(path))


def vendor_for(mac):
    if not mac or len(mac) < 8:
        return None
    key = mac.upper()[:8]
    return _cache.get(key) or BUILTIN.get(key)
