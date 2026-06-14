import warnings
warnings.filterwarnings("ignore", message=".*LibreSSL.*", category=Warning)
warnings.filterwarnings("ignore", message=".*NotOpenSSL.*", category=Warning)

import argparse, os, signal, yaml
from .core.bus import EventBus
from .core.store import AlertStore
from .core.capture import CaptureSource
from .core.forwarder import AlertForwarder
from .core import siem as _siem_mod
from .detectors.ddos import DDoSDetector
from .detectors.malware import MalwareDetector
from .detectors.insider import InsiderDetector
from .detectors.iot import IoTDetector

def main():
    ap = argparse.ArgumentParser(description="Tactical Security Starter Agent")
    ap.add_argument("--config", default="configs/config.yaml")
    ap.add_argument("--mode", choices=["simulate","live","pcap","netflow"], default=None)
    ap.add_argument("--iface", default=None)
    ap.add_argument("--pcap", default=None)
    ap.add_argument("--duration", type=int, default=10)
    args = ap.parse_args()

    with open(args.config, "r") as f:
        cfg = yaml.safe_load(f)

    if args.mode: cfg["capture"]["mode"] = args.mode
    if args.iface: cfg["capture"]["iface"] = args.iface
    if args.pcap: cfg["capture"]["pcap_file"] = args.pcap

    # Build forwarder if forwarding is enabled.
    forwarder = None
    if cfg.get("agent", {}).get("forward_alerts", False):
        srv = cfg.get("server", {})
        if srv.get("ingest_url"):
            client_cert = None
            if srv.get("client_cert") and srv.get("client_key"):
                client_cert = (srv["client_cert"], srv["client_key"])

            # Persistent queue: use queue_db if configured, else in-memory.
            queue_db = cfg.get("agent", {}).get("queue_db") or None

            forwarder = AlertForwarder(
                ingest_url=srv["ingest_url"],
                timeout=float(srv.get("timeout_seconds", 2.0)),
                api_key=srv.get("api_key"),
                ca_cert=srv.get("ca_cert"),
                client_cert=client_cert,
                queue_db=queue_db,
            )

    # Build SIEM forwarder from config.
    siem = _siem_mod.from_cfg(cfg)

    def _shutdown(signum, frame):
        if forwarder is not None:
            forwarder.stop(flush_timeout=5.0)
        siem.stop(timeout=3.0)
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    bus = EventBus()
    store = AlertStore(cfg["store"]["path"])

    if cfg["ddos"]["enable"]:    DDoSDetector(bus, cfg, store, forwarder, siem=siem)
    if cfg["malware"]["enable"]: MalwareDetector(bus, cfg, store, forwarder, siem=siem)
    if cfg["insider"]["enable"]: InsiderDetector(bus, cfg, store, forwarder, siem=siem)
    if cfg["iot"]["enable"]:     IoTDetector(bus, cfg, store, forwarder, siem=siem)

    src = CaptureSource(
        mode=cfg["capture"]["mode"],
        iface=cfg["capture"]["iface"],
        bus=bus,
        pcap_file=cfg["capture"]["pcap_file"],
        netflow_port=cfg["capture"]["netflow_udp_port"],
    )
    src.start(duration=args.duration)

    if forwarder is not None:
        forwarder.stop(flush_timeout=5.0)
    siem.stop(timeout=3.0)

if __name__ == "__main__":
    main()
