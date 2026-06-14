/// Static default configuration constants.
/// Can be overridden via CLI flags — see `main.rs`.
pub struct Defaults;

impl Defaults {
    pub const PKT_RATE_THRESHOLD: f64 = 120.0;
    pub const ENTROPY_MIN: f64 = 2.3;
    pub const EWMA_ALPHA: f64 = 0.1;
    pub const Z_THRESHOLD: f64 = 3.0;
    pub const WINDOW_SECS: u64 = 2;
}
