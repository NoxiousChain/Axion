
from ..responders.actions import Alert

def matches_pattern(name: str, pattern: str) -> bool:
    if pattern.endswith("*"):
        return name.startswith(pattern[:-1])
    return name == pattern

class IoTDetector:
    def __init__(self, bus, cfg, store, forwarder=None, siem=None):
        self.bus = bus
        self.cfg = cfg
        self.store = store
        self.alerter = Alert(store, cfg, forwarder=forwarder, siem=siem)
        bus.subscribe("net_event", self.on_event)

    def on_event(self, e):
        dev = e.get("device_id") or ""
        svc = f"{e.get('proto','tcp')}/{e.get('dst_port',0)}"
        for pattern, allowed in (self.cfg["iot"]["allowed_services"] or {}).items():
            if matches_pattern(dev, pattern):
                if svc not in allowed:
                    self.alerter.emit("IoTDetector", "medium", "Policy violation by IoT device",
                                      {"device_id": dev, "service": svc, "allowed": allowed},
                                      key=(dev, svc))
                break

        # Weak credential check (AC-2, IA-5): flag auth events using known-weak usernames.
        username = e.get("username") or e.get("user") or ""
        weak_creds = self.cfg["iot"].get("weak_creds_usernames") or []
        if username and username in weak_creds:
            self.alerter.emit(
                "IoTDetector", "high", "Weak credential detected on IoT device",
                {"device_id": dev, "username": username},
                key=(dev, username),
            )
