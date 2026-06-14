
import random, time, socket, json, threading
from typing import Optional
from .utils import now_ts

try:
    from scapy.all import sniff, rdpcap
except Exception:
    sniff = None
    rdpcap = None

class CaptureSource:
    """Provides packets/flow-like events to the bus. Modes:
    - simulate: generates synthetic 'net_event' dicts
    - live: uses scapy to sniff (root required)
    - pcap: replays packets from a pcap file
    - netflow: listens for simple JSON-over-UDP 'flow' records and maps them to events
    """
    def __init__(self, mode: str = "simulate", iface: str = "eth0", bus=None, pcap_file: str = "", netflow_port: int = 2055):
        self.mode = mode
        self.iface = iface
        self.pcap_file = pcap_file
        self.netflow_port = netflow_port
        self.bus = bus
        self._stop = False

    def start(self, duration: Optional[int] = None):
        if self.mode == "simulate":
            self._simulate(duration or 10)
        elif self.mode == "live":
            self._live()
        elif self.mode == "pcap":
            self._pcap_replay()
        elif self.mode == "netflow":
            self._netflow_udp_listener()
        else:
            self._simulate(duration or 10)

    def stop(self):
        self._stop = True

    def _simulate(self, duration: int):
        t_start = time.time()
        end = t_start + duration

        # Phase boundary fractions of total duration
        p1 = t_start + duration * 0.30   # normal baseline ends
        p2 = t_start + duration * 0.50   # DDoS flood ends
        p3 = t_start + duration * 0.65   # malware phase ends
        p4 = t_start + duration * 0.80   # insider threat ends
        # remainder → IoT violations

        # ── Phase 1: normal background traffic (builds EWMA baseline) ─────
        print("[SIM] Phase 1: normal background traffic")
        while time.time() < p1 and not self._stop:
            event = {
                "ts": now_ts(),
                "src_ip": f"10.0.{random.randint(0,3)}.{random.randint(1,254)}",
                "dst_ip": f"10.1.{random.randint(0,3)}.{random.randint(1,254)}",
                "dst_port": random.choice([80, 443, 22, 554, 5683, 8883, 53]),
                "proto": random.choice(["tcp", "udp"]),
                "bytes": random.randint(60, 1500),
                "user": random.choice(["alice", "bob", "carol"]),
                "device_id": random.choice(["camera-01", "sensor-05", "laptop-22", "edge-gw01"]),
                "proc": random.choice(["chrome.exe", "ssh", "python"]),
                "dns_qname_len": 0,
            }
            self.bus and self.bus.publish("net_event", event)
            time.sleep(0.01)

        # ── Phase 2: DDoS flood — burst across multiple targets ───────────
        print("[SIM] Phase 2: DDoS flood")
        # 15 unique dst targets → 15 independent throttle keys → 15+ alerts
        ddos_targets = [f"10.1.{i // 8}.{i % 8 + 1}" for i in range(15)]
        for i in range(3000):
            if self._stop:
                break
            event = {
                "ts": now_ts(),
                "src_ip": f"203.0.113.{random.randint(1, 254)}",
                "dst_ip": ddos_targets[i % len(ddos_targets)],
                "dst_port": 443,
                "proto": "tcp",
                "bytes": random.randint(60, 120),
                "user": "unknown",
                "device_id": "edge-gw01",
                "proc": "unknown",
                "dns_qname_len": 0,
            }
            self.bus and self.bus.publish("net_event", event)

        # ── Phase 3: malware — suspicious processes + DNS tunneling ───────
        print("[SIM] Phase 3: malware — suspicious procs & DNS tunneling")
        _mal_hosts = ["laptop-22", "edge-gw01", "workstation-03"]
        _mal_procs = ["mimikatz.exe", "nc.exe", "powershell.exe"]
        while time.time() < p3 and not self._stop:
            # 50 unique src IPs → 50 independent DNS-tunnel throttle keys
            src = f"10.0.1.{random.randint(1, 50)}"
            event = {
                "ts": now_ts(),
                "src_ip": src,
                "dst_ip": f"185.220.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "dst_port": random.choice([4444, 1337, 8443]),
                "proto": "tcp",
                "bytes": random.randint(200, 8000),
                "user": random.choice(["alice", "bob", "carol"]),
                "device_id": random.choice(_mal_hosts),
                "proc": random.choice(_mal_procs),
                "dns_qname_len": random.randint(50, 120),
            }
            self.bus and self.bus.publish("net_event", event)
            time.sleep(0.01)

        # ── Phase 4: insider threat — data exfil + many hosts + off-hours ─
        print("[SIM] Phase 4: insider threat — exfiltration & off-hours")
        # 4 users × 3 alert types = 12 independent throttle keys
        _ins_users = ["eve", "mallory", "oscar", "victor"]
        today_utc_midnight = int(time.time() / 86400) * 86400
        off_hours_ts = today_utc_midnight + 2 * 3600
        elapsed = 0.0
        _ins_idx = 0
        while time.time() < p4 and not self._stop:
            user = _ins_users[_ins_idx % len(_ins_users)]
            event = {
                "ts": off_hours_ts + elapsed,
                "src_ip": f"10.0.{random.randint(2,4)}.{random.randint(1,50)}",
                "dst_ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                "dst_port": 443,
                "proto": "tcp",
                "bytes": random.randint(10_000_000, 20_000_000),
                "user": user,
                "device_id": random.choice(["laptop-22", "workstation-03", "desktop-07"]),
                "proc": "python",
                "dns_qname_len": 0,
            }
            self.bus and self.bus.publish("net_event", event)
            elapsed += 0.01
            _ins_idx += 1
            time.sleep(0.01)

        # ── Phase 5: IoT policy violations ────────────────────────────────
        print("[SIM] Phase 5: IoT policy violations")
        # Cycle through device × port combos so each pair gets its own throttle key
        _iot_devices = ["camera-01", "camera-02", "camera-03", "sensor-05", "sensor-07"]
        _iot_ports = [23, 21, 8080, 1883, 6667]
        _iot_idx = 0
        while time.time() < end and not self._stop:
            dev = _iot_devices[_iot_idx % len(_iot_devices)]
            port = _iot_ports[(_iot_idx // len(_iot_devices)) % len(_iot_ports)]
            event = {
                "ts": now_ts(),
                "src_ip": f"192.168.10.{random.randint(1, 30)}",
                "dst_ip": f"10.1.0.{random.randint(1, 10)}",
                "dst_port": port,
                "proto": "tcp",
                "bytes": random.randint(60, 500),
                "user": "unknown",
                "device_id": dev,
                "proc": "unknown",
                "dns_qname_len": 0,
            }
            self.bus and self.bus.publish("net_event", event)
            _iot_idx += 1
            time.sleep(0.01)

    def _live(self):
        if sniff is None:
            raise RuntimeError("scapy not available. Install and run with privileges.")
        def handle(pkt):
            try:
                src = pkt[0][1].src
                dst = pkt[0][1].dst
                proto = pkt.lastlayer().name.lower()
                size = len(pkt)
                dport = getattr(getattr(pkt, 'dport', None), 'value', 0) or getattr(pkt, 'dport', 0) or 0
            except Exception:
                return
            event = {
                "ts": now_ts(),
                "src_ip": src,
                "dst_ip": dst,
                "dst_port": dport,
                "proto": proto,
                "bytes": size,
                "user": "unknown",
                "device_id": "unknown",
                "proc": "unknown",
                "dns_qname_len": 0,
            }
            self.bus and self.bus.publish("net_event", event)
        sniff(iface=self.iface, prn=handle, store=False)

    def _pcap_replay(self):
        if rdpcap is None:
            raise RuntimeError("scapy not available to parse pcap.")
        pkts = rdpcap(self.pcap_file)
        for pkt in pkts:
            if self._stop: break
            try:
                src = pkt[0][1].src
                dst = pkt[0][1].dst
                size = len(pkt)
                proto = pkt.lastlayer().name.lower()
                dport = getattr(getattr(pkt, 'dport', None), 'value', 0) or getattr(pkt, 'dport', 0) or 0
            except Exception:
                continue
            event = {
                "ts": now_ts(),
                "src_ip": src,
                "dst_ip": dst,
                "dst_port": dport,
                "proto": proto,
                "bytes": size,
                "user": "unknown",
                "device_id": "unknown",
                "proc": "unknown",
                "dns_qname_len": 0,
            }
            self.bus and self.bus.publish("net_event", event)

    def _netflow_udp_listener(self):
        """A minimal JSON-over-UDP 'flow' listener. Send records like:
        {"src_ip":"1.2.3.4","dst_ip":"10.0.0.5","dst_port":443,"proto":"tcp","bytes":1200}
        to UDP port configured in 'netflow_udp_port'. This is NOT real NetFlow/IPFIX parsing,
        but a lightweight shim to integrate flow exporters or simulators that can emit JSON.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('', self.netflow_port))
        sock.settimeout(1.0)
        try:
            while not self._stop:
                try:
                    data, addr = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                try:
                    record = json.loads(data.decode('utf-8', errors='ignore'))
                    event = {
                        "ts": now_ts(),
                        "src_ip": record.get("src_ip",""),
                        "dst_ip": record.get("dst_ip",""),
                        "dst_port": int(record.get("dst_port", 0)),
                        "proto": record.get("proto","tcp").lower(),
                        "bytes": int(record.get("bytes", 0)),
                        "user": record.get("user","unknown"),
                        "device_id": record.get("device_id","unknown"),
                        "proc": record.get("proc","unknown"),
                        "dns_qname_len": int(record.get("dns_qname_len", 0)),
                    }
                    self.bus and self.bus.publish("net_event", event)
                except Exception:
                    continue
        finally:
            sock.close()
