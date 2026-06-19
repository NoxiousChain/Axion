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

    /// Path to CA certificate for server TLS verification (PEM).
    /// If unset, the system CA store is used. Set to verify a self-signed server cert.
    #[arg(long, env = "AXION_CA_CERT")]
    ca_cert: Option<String>,

    /// Path to client certificate for mTLS (PEM). Requires --client-key (L3).
    #[arg(long, env = "AXION_CLIENT_CERT")]
    client_cert: Option<String>,

    /// Path to client private key for mTLS (PEM). Requires --client-cert (L3).
    #[arg(long, env = "AXION_CLIENT_KEY")]
    client_key: Option<String>,

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

    let tls = forwarder::TlsConfig {
        ca_cert_path: args.ca_cert.clone(),
        client_cert_path: args.client_cert.clone(),
        client_key_path: args.client_key.clone(),
    };

    let fwd = forwarder::Forwarder::new(
        args.server.clone(),
        args.api_key.clone(),
        args.node_id.clone(),
        args.db_path.clone(),
        tls,
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
