mod anomaly;
mod capture;
mod config;
mod ddos;
mod forwarder;
#[cfg(test)]
mod tests;

use anyhow::Result;
use clap::Parser;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "axion-capture", about = "Axion packet capture & DDoS detection agent")]
struct Args {
    /// Network interface to capture on (live/ebpf modes)
    #[arg(short, long, default_value = "eth0")]
    iface: String,

    /// Axion server base URL
    #[arg(short, long, default_value = "http://localhost:8000", env = "AXION_SERVER_URL")]
    server: String,

    /// Capture mode: live | simulate | ebpf
    #[arg(short, long, default_value = "live")]
    mode: String,

    /// API key forwarded to the server with every alert
    #[arg(short, long, env = "AXION_API_KEY")]
    api_key: String,

    /// Logical identifier for this edge node
    #[arg(short, long, default_value = "node-001", env = "AXION_NODE_ID")]
    node_id: String,

    /// Path to SQLite persistent queue (leave empty for in-memory only)
    #[arg(long, env = "AXION_QUEUE_DB")]
    db_path: Option<String>,

    /// DDoS packet-rate threshold (pkts/s) before hard-threshold alert fires
    #[arg(long, default_value_t = 120.0)]
    pkt_rate_threshold: f64,

    /// Minimum source-IP Shannon entropy; below this triggers a flood alert
    #[arg(long, default_value_t = 2.3)]
    entropy_min: f64,

    /// EWMA anomaly z-score threshold
    #[arg(long, default_value_t = 3.0)]
    z_threshold: f64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    info!(
        mode = %args.mode,
        iface = %args.iface,
        server = %args.server,
        "Axion capture agent starting"
    );

    let fwd = forwarder::Forwarder::new(
        args.server.clone(),
        args.api_key.clone(),
        args.node_id.clone(),
        args.db_path.clone(),
    )
    .await?;

    let detector = ddos::DdosDetector::new(args.pkt_rate_threshold, args.entropy_min, args.z_threshold);

    match args.mode.as_str() {
        "simulate" => capture::run_simulate(fwd, detector).await?,
        "ebpf" => {
            #[cfg(feature = "ebpf")]
            capture::run_ebpf(&args.iface, fwd, detector).await?;

            #[cfg(not(feature = "ebpf"))]
            anyhow::bail!(
                "eBPF mode requires recompilation with --features ebpf \
                 and target bpfel-unknown-none"
            );
        }
        _ => capture::run_live(&args.iface, fwd, detector).await?,
    }

    Ok(())
}
