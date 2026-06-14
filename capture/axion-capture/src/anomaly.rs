use std::collections::HashMap;

/// Per-key EWMA baseline with variance tracking.
/// Mirrors the Python `EwmaAnomalyTracker` in `tacnet_sec/core/anomaly.py`.
pub struct EwmaTracker {
    alpha: f64,
    z_threshold: f64,
    states: HashMap<String, EwmaState>,
}

struct EwmaState {
    mean: f64,
    variance: f64,
    n: u64,
}

impl EwmaTracker {
    pub fn new(alpha: f64, z_threshold: f64) -> Self {
        EwmaTracker {
            alpha,
            z_threshold,
            states: HashMap::new(),
        }
    }

    /// Feed a new observation for `key`.  Returns `true` if the value is
    /// anomalous (|z-score| > threshold) after the warm-up period (n < 10).
    pub fn update(&mut self, key: &str, value: f64) -> bool {
        let s = self.states.entry(key.to_owned()).or_insert(EwmaState {
            mean: value,
            variance: 0.0,
            n: 0,
        });

        s.n += 1;

        if s.n < 10 {
            // Welford-style online mean during warm-up (no anomaly scoring yet)
            let delta = value - s.mean;
            s.mean += delta / s.n as f64;
            return false;
        }

        let a = self.alpha;
        let prev_mean = s.mean;
        s.mean = a * value + (1.0 - a) * prev_mean;
        let dev = value - prev_mean;
        s.variance = a * dev * dev + (1.0 - a) * s.variance;

        let std_dev = s.variance.sqrt().max(1e-10);
        let z = (value - s.mean).abs() / std_dev;
        z > self.z_threshold
    }
}
