# NetWatch

A local web dashboard that watches your home or office network:

- **Devices**: finds every device on your LAN (nmap ping sweep), shows IP, MAC and hostname, and lets you mark devices as trusted.
- **New device alerts**: a pop-up when an unknown device joins the network.
- **Traffic**: per-IP bytes and packets, plus a drill-down that shows the recent packets for any IP you click.
- **Attack alerts**: pop-ups for possible port scans, SYN floods, ARP spoofing (someone pretending to be your router) and unusual traffic spikes.
- **Vulnerabilities**: service and version scan of a device you choose, with each finding's severity, a description and how to fix it.

## Setup (Kali Linux)

```bash
cd netwatch
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
sudo apt install -y nmap
```

Edit `config.json`:
- `interface`: your network interface, e.g. `eth0` or `wlan0` (run `ip -br addr`).
- `discovery_subnet`: your LAN, e.g. `192.168.1.0/24`, or leave `auto`.
- `allowed_networks`: the only ranges the scanner will accept. Keep these to networks you own.

## Run

```bash
sudo .venv/bin/python app.py
```

Then open http://127.0.0.1:5000 in your browser.

Packet capture needs root. Without it, the dashboard still works, and the Traffic tab shows that capture is off.

## How it works

| Part | File | What it does |
|---|---|---|
| Discovery and capture | `monitor.py` | nmap ping sweep every `discovery_interval_seconds`; Scapy sniffs packets on the interface |
| Attack detection | `monitor.py` | port scan, SYN flood, ARP spoof, traffic spike; thresholds in `config.json` |
| Vulnerability scan | `scanner.py` | nmap `-sV` on the target, then matches `vulns.json` rules |
| API and pages | `app.py`, `templates/index.html` | Flask JSON API and single-page dashboard |
| Storage | `db.py` | SQLite file `netwatch.db` |

Alerts are stored in the database, and the dashboard polls for new ones every 4 seconds and shows a pop-up for each.

## Limits and responsible use

- The vulnerability scanner checks open ports and software versions against `vulns.json`. It does not run exploits, brute-force passwords or attack services. Findings are matches against known issues, so confirm them before acting, and treat the list as a starting point rather than a full audit.
- Scans are refused for any address outside `allowed_networks`. Only scan devices you own or have written permission to test.
- Attack alerts are heuristics. A busy device or a legitimate backup job can trigger a traffic spike, so check the traffic view before assuming an attack.
- The dashboard has no login. It listens on 127.0.0.1 by default. Do not change `bind_host` to a network address unless you add authentication first.
- Capturing packets shows traffic metadata (addresses, ports, sizes). It does not store payload contents.

## Adding rules

Add an entry to `vulns.json` with a `match` (`port`, `ports`, `service`, or `product` plus `version_lt`), a `severity` (`low`, `medium`, `high`, `critical`), a `title`, a `description` and a `fix`. Restart the app to load it.
