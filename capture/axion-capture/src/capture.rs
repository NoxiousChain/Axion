use crate::ddos::DdosDetector;
use crate::forwarder::{Alert, Forwarder};
use anyhow::Result;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tracing::{info, warn};

// ─── Live capture (pnet) ─────────────────────────────────────────────────────

pub async fn run_live(iface: &str, fwd: Forwarder, detector: DdosDetector) -> Result<()> {
    use pnet::datalink::{self, Channel::Ethernet};
    use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::tcp::TcpPacket;
    use pnet::packet::udp::UdpPacket;
    use pnet::packet::Packet;

    let iface_name = iface.to_owned();
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|i| i.name == iface_name)
        .ok_or_else(|| anyhow::anyhow!("Interface '{}' not found", iface_name))?;

    let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => anyhow::bail!("Unsupported datalink channel type"),
        Err(e) => anyhow::bail!("Failed to open channel on {}: {}", iface_name, e),
    };

    info!(iface = %iface_name, "Live packet capture started");

    let fwd = Arc::new(Mutex::new(fwd));
    let detector = Arc::new(Mutex::new(detector));

    loop {
        match rx.next() {
            Ok(raw) => {
                let Some(eth) = EthernetPacket::new(raw) else { continue };
                if eth.get_ethertype() != EtherTypes::Ipv4 {
                    continue;
                }
                let Some(ipv4) = Ipv4Packet::new(eth.payload()) else { continue };

                let src = ipv4.get_source().to_string();
                let dst = ipv4.get_destination().to_string();
                let dst_port = match ipv4.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        TcpPacket::new(ipv4.payload()).map(|p| p.get_destination()).unwrap_or(0)
                    }
                    IpNextHeaderProtocols::Udp => {
                        UdpPacket::new(ipv4.payload()).map(|p| p.get_destination()).unwrap_or(0)
                    }
                    _ => 0,
                };

                let alert = {
                    let mut det = detector.lock().await;
                    det.process(&src, &dst)
                };

                if let Some(a) = alert {
                    let fwd = fwd.clone();
                    let ts = now_ts();
                    tokio::spawn(async move {
                        let alert = Alert {
                            detector: "DDoSDetector".into(),
                            title: a.title(),
                            severity: a.severity.to_owned(),
                            ts,
                            node_id: String::new(), // filled by Forwarder::submit
                            details: serde_json::json!({
                                "dst_ip":      a.dst_ip,
                                "dst_port":    dst_port,
                                "pkt_rate":    a.pkt_rate,
                                "src_entropy": a.src_entropy,
                                "type":        a.kind_str(),
                            }),
                        };
                        let mut f = fwd.lock().await;
                        if let Err(e) = f.submit(alert).await {
                            warn!("Alert forward failed: {e}");
                        }
                    });
                }
            }
            Err(e) => {
                warn!("Packet read error: {e}");
            }
        }
    }
}

// ─── Simulate mode ───────────────────────────────────────────────────────────

pub async fn run_simulate(fwd: Forwarder, detector: DdosDetector) -> Result<()> {
    use tokio::time::{sleep, Duration};

    info!("Running in simulate mode");

    let fwd = Arc::new(Mutex::new(fwd));
    let detector = Arc::new(Mutex::new(detector));

    // Phase 1 — baseline traffic (low rate, high entropy)
    info!("Phase 1: baseline traffic");
    for i in 0u32..200 {
        let src = format!("10.0.{}.{}", (i / 254) % 254, i % 254 + 1);
        let _ = detector.lock().await.process(&src, "192.168.1.10");
        sleep(Duration::from_millis(50)).await;
    }

    // Phase 2 — DDoS flood (high rate, concentrated src IPs)
    info!("Phase 2: simulated DDoS flood");
    for i in 0u32..600 {
        let src = format!("10.1.{}.{}", i % 4, i % 8 + 1); // low-entropy src
        if let Some(a) = detector.lock().await.process(&src, "192.168.1.10") {
            let fwd2 = fwd.clone();
            let ts = now_ts();
            tokio::spawn(async move {
                let alert = Alert {
                    detector: "DDoSDetector".into(),
                    title: a.title(),
                    severity: a.severity.to_owned(),
                    ts,
                    node_id: String::new(),
                    details: serde_json::json!({
                        "dst_ip": a.dst_ip, "pkt_rate": a.pkt_rate,
                        "src_entropy": a.src_entropy, "type": a.kind_str(),
                    }),
                };
                let mut f = fwd2.lock().await;
                let _ = f.submit(alert).await;
            });
        }
        sleep(Duration::from_millis(4)).await;
    }

    info!("Simulation complete");
    Ok(())
}

// ─── eBPF / XDP mode ─────────────────────────────────────────────────────────

#[cfg(feature = "ebpf")]
pub async fn run_ebpf(iface: &str, fwd: Forwarder, detector: DdosDetector) -> Result<()> {
    use aya::{include_bytes_aligned, maps::HashMap as BpfMap, programs::Xdp, Bpf};
    use aya_log::BpfLogger;
    use std::convert::TryInto;
    use tokio::signal;
    use tokio::time::{interval, Duration};

    info!(iface, "Loading eBPF XDP DDoS probe");

    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/axion-capture-ebpf"
    ))?;

    BpfLogger::init(&mut bpf)?;

    let program: &mut Xdp = bpf.program_mut("xdp_ddos_probe").unwrap().try_into()?;
    program.load()?;
    program.attach(iface, aya::programs::XdpFlags::default())?;
    info!(iface, "eBPF XDP probe attached");

    let fwd = Arc::new(Mutex::new(fwd));
    let detector = Arc::new(Mutex::new(detector));
    let mut tick = interval(Duration::from_secs(1));

    loop {
        tokio::select! {
            _ = tick.tick() => {
                let pkt_counts: BpfMap<_, [u8; 4], u64> =
                    BpfMap::try_from(bpf.map_mut("PKT_COUNTS")?)?;

                for item in pkt_counts.iter() {
                    if let Ok((dst_bytes, count)) = item {
                        let dst_ip = format!(
                            "{}.{}.{}.{}",
                            dst_bytes[0], dst_bytes[1], dst_bytes[2], dst_bytes[3]
                        );
                        if let Some(a) = detector.lock().await.process("0.0.0.0", &dst_ip) {
                            let fwd2 = fwd.clone();
                            let ts = now_ts();
                            tokio::spawn(async move {
                                let alert = Alert {
                                    detector: "DDoSDetector/eBPF".into(),
                                    title: a.title(),
                                    severity: a.severity.to_owned(),
                                    ts,
                                    node_id: String::new(),
                                    details: serde_json::json!({
                                        "dst_ip":   dst_ip,
                                        "pkt_rate": count,
                                        "source":   "ebpf_xdp",
                                        "type":     a.kind_str(),
                                    }),
                                };
                                let mut f = fwd2.lock().await;
                                let _ = f.submit(alert).await;
                            });
                        }
                    }
                }
            }
            _ = signal::ctrl_c() => {
                info!("Ctrl-C received — detaching eBPF program");
                break;
            }
        }
    }

    Ok(())
}

fn now_ts() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
