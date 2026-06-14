# Axion — Tactical Network Security Platform

A modular, agent-based threat detection and incident management platform for **tactical networks**. Edge agents run detectors locally and forward alerts to a central server; the server correlates them into incidents and exposes a live dashboard.

> **Prototype-grade** — intended for lab and simulation use. Harden, audit, and test before any production or field deployment.

---

## Features

### Detection (edge agent)
| Detector | What it catches |
|---|---|
| **DDoS** | Packet-rate threshold + per-destination EWMA anomaly (catches slow-burn floods below static ceilings) |
| **Malware** | Suspicious process names, DNS tunnelling (long query names) |
| **Insider / UEBA** | Off-hours activity, excessive data volume, broad host scanning, per-user EWMA anomaly |
| **IoT Policy** | Wildcard device profiles against allowed TCP/UDP services |

All detectors share an **EWMA anomaly tracker** — each entity (IP, user, device) builds its own learned baseline; deviations beyond a configurable z-score threshold fire an anomaly alert alongside any static rule.

### Correlation (central server)
Alerts that share an entity (`src_ip`, `dst_ip`, `user`, `device_id`, `host`) within a 5-minute sliding window are automatically grouped into **incidents**. Each incident:
- Tracks severity (escalates to the maximum of its constituent alerts, never downgrades)
- Records which detectors contributed
- Updates its title as new alerts arrive (`4-alert incident on 10.0.0.5 [DDoSDetector, MalwareDetector]`)
- Can be acknowledged in one action, cascading to all constituent alerts

### Dashboard
A single-page dark-theme UI served by the central server:
- **Stat cards** — alerts (60 min), high severity count, open incidents, top detector, active nodes
- **Charts** — alerts-per-minute timeline, severity doughnut
- **Incidents panel** — expandable rows showing entity tags, all constituent alerts with details
- **Alerts table** — filterable by severity, detector, node, free-text search; `INC-N` badge jumps to the incident
- Live updates via WebSocket; polling fallback

---

## Architecture

```
Edge node                          Central server
─────────────────────────────      ────────────────────────────────
CaptureSource  ──►  EventBus       POST /api/alerts
                        │               │
              ┌─────────┼──────┐        ▼
              │         │      │   IncidentCorrelator
          DDoS  Malware Insider IoT      │
              │                  │       ▼
              └──► AlertStore ◄──┘   SQLite (incidents + alerts)
                       │                  │
               AlertForwarder ────────────►  WebSocket broadcast
                                              ▼
                                          Dashboard (index.html)
```

**Agent side** — `EventBus` is synchronous; detector handlers run inline with `publish()`. `AlertForwarder` posts to the server on a background thread with a bounded queue so capture is never blocked.

**Server side** — FastAPI + SQLite. `IncidentCorrelator` runs synchronously in the ingest path so every stored alert is tagged with an `incident_id` before the response returns.

---

## Quickstart

```bash
# 1. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the central server (in one terminal)
python -m tacnet_sec.server.api --port 8000

# 4. Run the edge agent in simulation mode (in another terminal)
python -m tacnet_sec.cli --mode simulate --duration 30

# 5. Open the dashboard
open http://localhost:8000
```

Alerts appear in the dashboard in real time. Simulated traffic generates DDoS, malware, insider, and IoT alerts that the correlator groups into incidents.

### Live capture (optional)

Requires `scapy` and elevated privileges:

```bash
sudo python -m tacnet_sec.cli --mode live --iface eth0
```

> IP blocking via iptables is stubbed behind `dry_run_block: true` in the config. Wire it to your policy engine or SDN for real enforcement.

---

## Configuration

All tuning knobs live in `configs/config.yaml`:

```yaml
agent:
  node_id: "node-001"
  forward_alerts: true         # POST alerts to the central server

anomaly:
  enable: true
  alpha: 0.1                   # EWMA smoothing (0.1 ≈ 10-sample memory)
  z_threshold: 3.0             # sigmas before anomaly fires
  cold_start_samples: 20       # observations before scoring begins

ddos:
  pkt_rate_threshold: 120      # static packets/sec ceiling
  window_seconds: 8

insider:
  baseline_hours: [6, 20]      # off-hours window
  max_data_mb_per_hour: 120

iot:
  allowed_services:
    "camera-*": ["tcp/554", "tcp/443"]
    "sensor-*": ["udp/5683"]
```

---

## Project Layout

```
tacnet_sec/
  core/
    anomaly.py       # EWMATracker — per-entity z-score baseline learning
    bus.py           # EventBus — sync pub/sub
    capture.py       # CaptureSource — simulate / live / pcap / netflow modes
    store.py         # AlertStore — SQLite wrapper (edge)
    throttle.py      # AlertThrottler — per-key cooldown / dedupe
    forwarder.py     # AlertForwarder — background HTTP poster
  detectors/
    ddos.py          # DDoS / flood detector
    malware.py       # Process name + DNS tunnel heuristics
    insider.py       # UEBA-lite + EWMA anomaly
    iot.py           # Device policy enforcement
  responders/
    actions.py       # Alert.emit() + block_ip() stub
  server/
    api.py           # FastAPI server — REST + WebSocket
    correlator.py    # Incident correlator — grouping + severity escalation
    static/
      index.html     # Single-page dashboard
  tests/
    test_detectors.py   # Detector + anomaly tracker tests (29 tests)
    test_correlator.py  # Correlator + API endpoint tests (39 tests)
  cli.py             # Edge agent entrypoint
configs/
  config.yaml        # All tuning knobs and policy
```

---

## Running Tests

```bash
pip install httpx pytest     # httpx required for FastAPI TestClient
python -m pytest tacnet_sec/tests -v
```

68 tests covering detectors, anomaly tracking, incident correlation, and all API endpoints.

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Server uptime |
| `POST` | `/api/alerts` | Ingest alert from agent; returns `alert_id` + `incident_id` |
| `GET` | `/api/alerts` | List alerts (filters: `severity`, `detector`, `node_id`, `q`, `incident_id`, `hide_acked`) |
| `POST` | `/api/alerts/{id}/ack` | Acknowledge a single alert |
| `GET` | `/api/incidents` | List incidents (`hide_acked=true` default) |
| `GET` | `/api/incidents/{id}` | Incident detail with constituent alerts |
| `POST` | `/api/incidents/{id}/ack` | Acknowledge incident and cascade to all its alerts |
| `GET` | `/api/stats` | Aggregated counts — severity, detector, node, timeline, open incidents |
| `WS` | `/api/ws` | Live alert broadcast |

---

## Safety & Ethics

- This repo contains **defensive** examples only. No exploit code.
- Always obtain authorization before monitoring or blocking traffic on any network.
- For ITAR/CUI environments, integrate with your compliance and audit stack.

## License

MIT (starter). Replace with your organization's license as needed.
