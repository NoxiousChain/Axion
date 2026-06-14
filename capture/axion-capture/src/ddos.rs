use crate::anomaly::EwmaTracker;
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct DdosDetector {
    pkt_rate_threshold: f64,
    entropy_min: f64,
    anomaly: EwmaTracker,
    windows: HashMap<String, Window>,
    window_duration: Duration,
}

struct Window {
    count: u64,
    src_ips: HashMap<String, u64>,
    start: Instant,
}

#[derive(Debug)]
pub struct DdosAlert {
    pub dst_ip: String,
    pub pkt_rate: f64,
    pub src_entropy: f64,
    pub kind: AlertKind,
    pub severity: &'static str,
}

#[derive(Debug)]
pub enum AlertKind {
    ThresholdFlood,
    LowEntropy,
    Anomaly,
}

impl DdosAlert {
    pub fn kind_str(&self) -> &'static str {
        match self.kind {
            AlertKind::ThresholdFlood => "threshold_flood",
            AlertKind::LowEntropy => "low_entropy_flood",
            AlertKind::Anomaly => "anomaly",
        }
    }

    pub fn title(&self) -> String {
        match self.kind {
            AlertKind::ThresholdFlood => {
                format!("DDoS flood toward {} ({:.0} pkt/s)", self.dst_ip, self.pkt_rate)
            }
            AlertKind::LowEntropy => {
                format!(
                    "Amplification/reflection toward {} (entropy {:.2})",
                    self.dst_ip, self.src_entropy
                )
            }
            AlertKind::Anomaly => {
                format!(
                    "Traffic anomaly toward {} ({:.0} pkt/s, EWMA)",
                    self.dst_ip, self.pkt_rate
                )
            }
        }
    }
}

impl DdosDetector {
    pub fn new(pkt_rate_threshold: f64, entropy_min: f64, z_threshold: f64) -> Self {
        DdosDetector {
            pkt_rate_threshold,
            entropy_min,
            anomaly: EwmaTracker::new(0.1, z_threshold),
            windows: HashMap::new(),
            window_duration: Duration::from_secs(2),
        }
    }

    /// Process one packet (src_ip → dst_ip).
    /// Returns an alert if the current window's statistics cross a threshold.
    pub fn process(&mut self, src_ip: &str, dst_ip: &str) -> Option<DdosAlert> {
        let now = Instant::now();
        let win = self.windows.entry(dst_ip.to_owned()).or_insert_with(|| Window {
            count: 0,
            src_ips: HashMap::new(),
            start: now,
        });

        if now.duration_since(win.start) <= self.window_duration {
            win.count += 1;
            *win.src_ips.entry(src_ip.to_owned()).or_insert(0) += 1;
            return None;
        }

        // Window rolled — evaluate before resetting
        let elapsed = now.duration_since(win.start).as_secs_f64().max(f64::EPSILON);
        let pkt_rate = win.count as f64 / elapsed;
        let entropy = shannon_entropy(&win.src_ips);
        let is_anomaly = self.anomaly.update(&format!("dst:{dst_ip}"), pkt_rate);

        let alert = if pkt_rate > self.pkt_rate_threshold {
            let severity = if pkt_rate > self.pkt_rate_threshold * 2.0 {
                "critical"
            } else {
                "high"
            };
            Some(DdosAlert {
                dst_ip: dst_ip.to_owned(),
                pkt_rate,
                src_entropy: entropy,
                kind: AlertKind::ThresholdFlood,
                severity,
            })
        } else if entropy < self.entropy_min && pkt_rate > self.pkt_rate_threshold * 0.3 {
            Some(DdosAlert {
                dst_ip: dst_ip.to_owned(),
                pkt_rate,
                src_entropy: entropy,
                kind: AlertKind::LowEntropy,
                severity: "high",
            })
        } else if is_anomaly {
            Some(DdosAlert {
                dst_ip: dst_ip.to_owned(),
                pkt_rate,
                src_entropy: entropy,
                kind: AlertKind::Anomaly,
                severity: "medium",
            })
        } else {
            None
        };

        *win = Window {
            count: 1,
            src_ips: HashMap::from([(src_ip.to_owned(), 1)]),
            start: now,
        };
        alert
    }
}

fn shannon_entropy(counts: &HashMap<String, u64>) -> f64 {
    let total: u64 = counts.values().sum();
    if total == 0 {
        return 0.0;
    }
    counts.values().fold(0.0, |acc, &c| {
        let p = c as f64 / total as f64;
        if p == 0.0 { acc } else { acc - p * p.log2() }
    })
}
