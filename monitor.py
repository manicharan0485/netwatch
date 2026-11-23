"""Device discovery, packet capture and intrusion detection.

Discovery uses nmap's ping scan. Packet capture uses Scapy and needs root.
Everything here is passive or host-discovery only; nothing attacks anything.
"""
import ipaddress
import json
import logging
import socket
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict, deque

import db

log = logging.getLogger("netwatch.monitor")


def detect_subnet(configured):
    """Return the LAN subnet to scan. 'auto' uses the /24 of the default-route address."""
    if configured and configured != "auto":
        return str(ipaddress.ip_network(configured, strict=False))
    try:
        # Connecting a UDP socket sends no packets; it just picks the outgoing address.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
    except OSError:
        ip = "192.168.1.1"
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


class Monitor:
    def __init__(self, cfg):
        self.cfg = cfg
        self.thresholds = cfg["thresholds"]
        self.subnet = detect_subnet(cfg.get("discovery_subnet"))
        self.lock = threading.Lock()
        self.ip_mac = {}                       # ip -> mac, from ARP observations
        self.stats = defaultdict(lambda: {
            "bytes_in": 0, "bytes_out": 0, "packets": 0,
            "first": None, "last": None,
            "ports": Counter(), "protocols": Counter(),
        })
        self.recent = deque(maxlen=3000)       # recent packet summaries
        self.syn_times = defaultdict(deque)    # src -> timestamps of SYNs
        self.port_hits = defaultdict(dict)     # src -> {dport: timestamp}
        self.bytes_window = defaultdict(deque) # src -> (ts, bytes) for spike check
        self.first_discovery_done = False
        self.sniffing = False
        self.sniff_error = None

    # ------------------------------------------------------------ discovery

    def discover(self):
        """Ping-sweep the subnet with nmap and update the device table."""
        try:
            out = subprocess.run(
                ["nmap", "-sn", "-oX", "-", self.subnet],
                capture_output=True, text=True, timeout=600, check=False,
            ).stdout
            root = ET.fromstring(out)
        except (subprocess.SubprocessError, ET.ParseError, OSError) as exc:
            log.warning("discovery failed: %s", exc)
            return 0

        now = time.time()
        seen = 0
        for host in root.findall("host"):
            if host.find("status") is None or host.find("status").get("state") != "up":
                continue
            ip = mac = hostname = None
            for addr in host.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    ip = addr.get("addr")
                elif addr.get("addrtype") == "mac":
                    mac = addr.get("addr").upper()
            hn = host.find("hostnames/hostname")
            hostname = hn.get("name") if hn is not None else None
            if not ip:
                continue
            if not mac:
                mac = self._mac_from_arp(ip)
            if not mac:
                continue
            seen += 1
            self._upsert_device(ip, mac, hostname, now)
        self.first_discovery_done = True
        log.info("discovery of %s found %d hosts", self.subnet, seen)
        return seen

    def _mac_from_arp(self, ip):
        try:
            with open("/proc/net/arp") as fh:
                next(fh, None)
                for line in fh:
                    f = line.split()
                    if len(f) >= 4 and f[0] == ip and f[3] != "00:00:00:00:00:00":
                        return f[3].upper()
        except OSError:
            pass
        return None

    def _upsert_device(self, ip, mac, hostname, now):
        existing = db.one("SELECT * FROM devices WHERE mac=?", (mac,))
        if existing is None:
            # On the very first discovery, treat what is already there as trusted
            # if configured, so you only get alerted about later arrivals.
            trusted = 1 if (self.cfg.get("learn_on_first_scan") and
                            not self.first_discovery_done) else 0
            db.write(
                "INSERT INTO devices (mac, ip, hostname, first_seen, last_seen, trusted)"
                " VALUES (?,?,?,?,?,?)",
                (mac, ip, hostname, now, now, trusted),
            )
            if not trusted:
                db.add_alert(
                    "medium", "new_device", "New device joined the network",
                    f"IP {ip}, MAC {mac}, hostname {hostname or 'unknown'}. "
                    "Open the device list to trust it or investigate.",
                    ip=ip, dedupe_key=f"new_device:{mac}", window_seconds=86400,
                )
        else:
            if existing["ip"] != ip:
                db.write("UPDATE devices SET ip=?, last_seen=? WHERE mac=?", (ip, now, mac))
            else:
                db.write("UPDATE devices SET last_seen=? WHERE mac=?", (now, mac))

    def discovery_loop(self):
        while True:
            try:
                self.discover()
            except Exception:  # keep the loop alive no matter what
                log.exception("discovery loop error")
            time.sleep(self.cfg.get("discovery_interval_seconds", 120))

    # ------------------------------------------------------------ capture

    def start(self):
        threading.Thread(target=self.discovery_loop, daemon=True).start()
        threading.Thread(target=self.sniff_loop, daemon=True).start()

    def sniff_loop(self):
        try:
            from scapy.all import sniff
        except ImportError as exc:
            self.sniff_error = f"scapy not installed: {exc}"
            log.error(self.sniff_error)
            return
        self.sniffing = True
        try:
            sniff(iface=self.cfg.get("interface"), prn=self.on_packet, store=False)
        except PermissionError:
            self.sniff_error = "packet capture needs root (run with sudo)"
        except Exception as exc:  # interface missing, etc.
            self.sniff_error = str(exc)
        finally:
            self.sniffing = False
            log.error("capture stopped: %s", self.sniff_error)

    def on_packet(self, pkt):
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.l2 import ARP

        now = time.time()
        if ARP in pkt:
            self._check_arp(pkt[ARP], now)
            return
        if IP not in pkt:
            return

        ip = pkt[IP]
        src, dst, length = ip.src, ip.dst, len(pkt)
        proto, sport, dport, flags = "OTHER", None, None, ""
        if TCP in pkt:
            proto, sport, dport = "TCP", pkt[TCP].sport, pkt[TCP].dport
            flags = str(pkt[TCP].flags)
        elif UDP in pkt:
            proto, sport, dport = "UDP", pkt[UDP].sport, pkt[UDP].dport
        elif ICMP in pkt:
            proto = "ICMP"

        with self.lock:
            s_src = self.stats[src]
            s_src["bytes_out"] += length
            s_src["packets"] += 1
            s_src["first"] = s_src["first"] or now
            s_src["last"] = now
            s_src["protocols"][proto] += 1
            s_dst = self.stats[dst]
            s_dst["bytes_in"] += length
            s_dst["packets"] += 1
            s_dst["first"] = s_dst["first"] or now
            s_dst["last"] = now
            s_dst["protocols"][proto] += 1
            if dport is not None:
                s_dst["ports"][dport] += 1
            self.recent.append({
                "ts": now, "src": src, "dst": dst, "proto": proto,
                "sport": sport, "dport": dport, "length": length, "flags": flags,
            })
            self._detect(src, dport, flags, length, now)

    # ------------------------------------------------------------ detection

    def _detect(self, src, dport, flags, length, now):
        """Called with self.lock held."""
        th = self.thresholds

        # Port scan: one source touching many distinct destination ports quickly.
        if dport is not None:
            hits = self.port_hits[src]
            hits[dport] = now
            for p in [p for p, t in hits.items() if now - t > 10]:
                del hits[p]
            if len(hits) >= th["port_scan_distinct_ports_10s"]:
                db.add_alert(
                    "high", "port_scan", "Possible port scan detected",
                    f"{src} touched {len(hits)} different ports in the last 10 seconds.",
                    ip=src, dedupe_key=f"port_scan:{src}", window_seconds=300,
                )
                hits.clear()

        # SYN flood: a large number of SYN packets from one source.
        if flags == "S":
            q = self.syn_times[src]
            q.append(now)
            while q and now - q[0] > 5:
                q.popleft()
            if len(q) >= th["syn_per_5s"]:
                db.add_alert(
                    "critical", "syn_flood", "Possible SYN flood",
                    f"{src} sent {len(q)} SYN packets in 5 seconds.",
                    ip=src, dedupe_key=f"syn_flood:{src}", window_seconds=300,
                )
                q.clear()

        # Traffic spike: bytes sent by one source within 10 seconds.
        w = self.bytes_window[src]
        w.append((now, length))
        while w and now - w[0][0] > 10:
            w.popleft()
        total = sum(b for _, b in w)
        if total >= th["traffic_bytes_per_10s"]:
            db.add_alert(
                "high", "traffic_spike", "Unusually high traffic from one host",
                f"{src} sent about {total / 1_000_000:.1f} MB in the last 10 seconds.",
                ip=src, dedupe_key=f"traffic_spike:{src}", window_seconds=300,
            )
            w.clear()

    def _check_arp(self, arp, now):
        """Detect ARP spoofing: one IP suddenly claiming a different MAC."""
        if arp.op != 2:  # only replies can poison a cache
            return
        ip, mac = arp.psrc, arp.hwsrc.upper()
        with self.lock:
            previous = self.ip_mac.get(ip)
            self.ip_mac[ip] = mac
        if previous and previous != mac:
            db.add_alert(
                "critical", "arp_spoof", "Possible ARP spoofing",
                f"IP {ip} changed from MAC {previous} to {mac}. "
                "Someone may be intercepting traffic on your network.",
                ip=ip, dedupe_key=f"arp_spoof:{ip}:{mac}", window_seconds=3600,
            )

    # ------------------------------------------------------------ queries

    def traffic_summary(self):
        with self.lock:
            rows = []
            for ip, s in self.stats.items():
                rows.append({
                    "ip": ip,
                    "bytes_in": s["bytes_in"],
                    "bytes_out": s["bytes_out"],
                    "packets": s["packets"],
                    "last": s["last"],
                    "top_protocols": dict(s["protocols"].most_common(3)),
                })
        rows.sort(key=lambda r: r["bytes_in"] + r["bytes_out"], reverse=True)
        return rows[:200]

    def ip_detail(self, ip, limit=200):
        with self.lock:
            s = self.stats.get(ip)
            stats = None
            if s is not None:
                stats = {
                    "bytes_in": s["bytes_in"], "bytes_out": s["bytes_out"],
                    "packets": s["packets"], "first": s["first"], "last": s["last"],
                    "protocols": dict(s["protocols"]),
                    "top_ports": dict(s["ports"].most_common(10)),
                }
            packets = [p for p in self.recent if p["src"] == ip or p["dst"] == ip]
        return {"ip": ip, "stats": stats, "packets": packets[-limit:][::-1]}

    def status(self):
        return {
            "subnet": self.subnet,
            "sniffing": self.sniffing,
            "sniff_error": self.sniff_error,
            "interface": self.cfg.get("interface"),
            "tracked_hosts": len(self.stats),
        }
