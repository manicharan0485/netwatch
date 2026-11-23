# NetWatch

A network monitor for home and office networks. Run it on a computer that is connected to the network. It finds every device, checks them for known problems, and tells people what to do in plain language.

## What people see

- **Home screen:** one status light (green, yellow or red) with a short explanation, and five big buttons:
  - **Scan my network:** finds all devices now.
  - **My devices:** who is connected, with Approve and Block buttons. Blocking gives step-by-step router instructions.
  - **Alerts:** what has happened.
  - **Fix problems:** each problem with a checklist of steps, and a Check again button.
  - **Send report:** emails a summary.
- **Technician view** (`/advanced`): the detailed dashboard, with traffic per IP and packet drill-down.
- **Accounts:** admins can do everything. Viewers can only look.

## Automatic network scan

When it starts, NetWatch finds the network it is connected to and scans every device on it:

- **Device count:** known devices and how many are online right now.
- **OS and version guess:** from nmap OS detection (needs root).
- **Open ports and vulnerabilities:** each device is checked against `vulns.json`, with steps from `fixes.json`.
- **Public location:** the network's internet address, geolocated (city, region, ISP). Devices on the LAN have private addresses and cannot be geolocated.

Devices are scanned one at a time and rescanned every `auto_scan_hours` (24 by default).

## Setup on Linux with Python

```bash
cd netwatch
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
sudo apt install -y nmap
```

Edit `config.json`:

- `interface`: the network interface, e.g. `eth0` or `wlan0` (run `ip -br addr`).
- `discovery_subnet`: your network, or `auto`.
- `allowed_networks`: the only ranges the scanner will accept. Keep these to networks you own.
- `router_admin_url`: the address of your router's settings page, used in block instructions.
- `help_contact`: who people should call when they need help.
- `email`: see Email below.

Run it:

```bash
sudo .venv/bin/python app.py
```

Open http://127.0.0.1:5000. The first time, create the admin account. Packet capture and OS detection need `sudo`. Without it, the dashboard still works.

## Setup with Docker (Linux)

```bash
docker compose up -d --build
```

The container uses the host network so it can see the LAN. Your data is kept in `./data`. Open `http://<this-machine>:5000`. To reach it from other computers, set `bind_host` to `0.0.0.0` in `config.json`, and only do this on a trusted network, or behind HTTPS (see Limits).

## Email

Serious alerts (critical or high) are emailed when `email.enabled` is `true`. The weekly summary is sent on `weekly_day` (0 = Monday) at `weekly_hour`. Set the SMTP password in the environment, not in the file:

```bash
export NETWATCH_SMTP_PASSWORD='your-password'
```

## Logins and roles

- The first account is an admin, created on first visit.
- Admins can scan, approve or block devices, mark alerts as read, send reports and add accounts.
- Viewers can see everything but change nothing.
- Five wrong passwords lock an account for five minutes.
- Every action is recorded in the audit log (`/api/audit`).

## How it works

| Part | File | What it does |
|---|---|---|
| Discovery and capture | `monitor.py` | nmap ping sweep every `discovery_interval_seconds`; Scapy sniffs packets on the interface |
| Attack detection | `monitor.py` | port scan, SYN flood, ARP spoof, traffic spike; thresholds in `config.json` |
| Vulnerability scan | `scanner.py` | nmap `-sV` and `-O` on each device, then matches `vulns.json` |
| Status light | `health.py` | turns alerts and findings into green, yellow or red |
| Email | `notify.py` | serious alerts and the weekly summary |
| Pages and API | `app.py`, `templates/` | login, home screen, technician view, JSON API |
| Storage | `db.py` | SQLite file `netwatch.db` in the data folder |

## Limits and responsible use

- **Vulnerability checks are not a full audit.** They match open ports and software versions against a short list of known issues. An all-clear does not mean a device is secure.
- **Traffic from other devices is only visible with a mirror port or monitor-mode adapter.** On Wi-Fi or most switches, a computer only receives its own traffic.
- **Blocking a device happens in the router.** NetWatch records the decision and shows the steps; it does not change the router.
- **Scans are refused for any address outside `allowed_networks`.** Only scan networks you own or have written permission to test.
- **Attack alerts are heuristics.** A busy device or a backup job can trigger a traffic spike.
- **Plain HTTP.** The app does not use HTTPS itself. If you open it to other computers, put it behind an HTTPS reverse proxy first (for example Caddy or nginx), or use a VPN.
- **Monitoring people.** Monitoring staff traffic may need a written policy and, in many countries, consent from the works council or a data protection review.

## Adding rules and fixes

- `vulns.json`: a rule with a `match` (`port`, `ports`, `service`, or `product` plus `version_lt`), a `severity` (`low`, `medium`, `high`, `critical`), a `title`, a `description` and a `fix`.
- `fixes.json`: the step-by-step checklist for a finding. The key must match the rule's `title` exactly.
