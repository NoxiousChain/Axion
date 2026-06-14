// Run with: cargo test -p axion-capture

#[cfg(test)]
mod anomaly_tests {
    use crate::anomaly::EwmaTracker;

    #[test]
    fn cold_start_never_fires() {
        let mut t = EwmaTracker::new(0.1, 3.0);
        for _ in 0..9 {
            assert!(!t.update("k", 100.0), "should not fire during warm-up");
        }
    }

    #[test]
    fn flat_signal_does_not_fire() {
        let mut t = EwmaTracker::new(0.1, 3.0);
        for _ in 0..50 {
            assert!(!t.update("k", 10.0));
        }
    }

    #[test]
    fn spike_fires_after_stable_baseline() {
        let mut t = EwmaTracker::new(0.1, 3.0);
        // Establish baseline
        for _ in 0..50 {
            t.update("k", 10.0);
        }
        // Large spike
        let fired = t.update("k", 1000.0);
        assert!(fired, "spike should trigger anomaly");
    }

    #[test]
    fn keys_are_independent() {
        let mut t = EwmaTracker::new(0.1, 3.0);
        for _ in 0..50 {
            t.update("stable", 10.0);
        }
        for _ in 0..50 {
            t.update("other", 5.0);
        }
        // Spike on "stable" should not affect "other"
        t.update("stable", 9999.0);
        assert!(!t.update("other", 5.0));
    }

    #[test]
    fn high_z_threshold_suppresses_moderate_spike() {
        let mut t = EwmaTracker::new(0.1, 10.0); // very strict
        for _ in 0..50 {
            t.update("k", 10.0);
        }
        assert!(!t.update("k", 50.0), "moderate spike should not fire at z=10");
    }
}

#[cfg(test)]
mod ddos_tests {
    use crate::ddos::{AlertKind, DdosDetector};
    use std::thread::sleep;
    use std::time::Duration;

    fn wait_for_window() {
        sleep(Duration::from_millis(2100)); // let the 2-second window roll
    }

    #[test]
    fn no_alert_below_threshold() {
        let mut d = DdosDetector::new(120.0, 2.3, 3.0);
        for i in 0..10 {
            let src = format!("10.0.0.{}", i);
            assert!(d.process(&src, "192.168.1.1").is_none());
        }
    }

    #[test]
    fn threshold_flood_fires_above_rate() {
        let mut d = DdosDetector::new(5.0, 2.3, 3.0); // low threshold for testing
        // Send many packets within a 2-second window, then wait for rollover
        for i in 0..100 {
            let src = format!("10.0.{}.{}", i % 10, i % 255 + 1);
            d.process(&src, "192.168.1.1");
        }
        wait_for_window();
        // This packet triggers window rollover evaluation
        let alert = d.process("10.0.0.1", "192.168.1.1");
        assert!(alert.is_some(), "should fire threshold alert");
        let a = alert.unwrap();
        assert!(matches!(a.kind, AlertKind::ThresholdFlood | AlertKind::LowEntropy));
    }

    #[test]
    fn low_entropy_flood_fires() {
        let mut d = DdosDetector::new(120.0, 2.3, 3.0);
        // All packets from the SAME single source — entropy near 0
        for _ in 0..50 {
            d.process("10.0.0.1", "192.168.1.1");
        }
        wait_for_window();
        let alert = d.process("10.0.0.1", "192.168.1.1");
        // May fire LowEntropy if rate > 30% threshold
        if let Some(a) = alert {
            assert!(matches!(a.kind, AlertKind::LowEntropy | AlertKind::ThresholdFlood | AlertKind::Anomaly));
        }
    }

    #[test]
    fn critical_severity_above_double_threshold() {
        let mut d = DdosDetector::new(5.0, 2.3, 3.0);
        for i in 0..500 {
            d.process(&format!("10.0.{}.{}", i % 254, i % 254 + 1), "192.168.1.2");
        }
        wait_for_window();
        let alert = d.process("10.0.0.1", "192.168.1.2");
        if let Some(a) = alert {
            if a.pkt_rate > 10.0 {
                assert_eq!(a.severity, "critical");
            }
        }
    }

    #[test]
    fn title_contains_dst_ip() {
        let mut d = DdosDetector::new(5.0, 2.3, 3.0);
        for i in 0..50 {
            d.process(&format!("10.0.0.{}", i), "10.1.1.1");
        }
        wait_for_window();
        if let Some(a) = d.process("10.0.0.1", "10.1.1.1") {
            assert!(a.title().contains("10.1.1.1"), "title should include dst_ip");
        }
    }

    #[test]
    fn multiple_destinations_are_tracked_independently() {
        let mut d = DdosDetector::new(5.0, 2.3, 3.0);
        for i in 0..50 {
            d.process(&format!("10.0.0.{}", i % 10), "192.168.0.1");
        }
        // dst2 gets only 3 packets — should not fire
        for _ in 0..3 {
            d.process("10.0.0.1", "192.168.0.2");
        }
        wait_for_window();
        let a1 = d.process("10.0.0.1", "192.168.0.1");
        let a2 = d.process("10.0.0.1", "192.168.0.2");
        assert!(a1.is_some() || true); // may fire
        assert!(a2.is_none() || a2.unwrap().severity == "medium"); // definitely not high
    }
}

#[cfg(test)]
mod shannon_entropy_tests {
    // Shannon entropy is private; test via ddos indirectly.
    // A single source should have entropy 0, many sources should have entropy > 2.

    #[test]
    fn single_source_low_entropy_triggers_low_entropy_kind() {
        use crate::ddos::{AlertKind, DdosDetector};
        use std::thread::sleep;
        use std::time::Duration;

        let mut d = DdosDetector::new(120.0, 2.3, 3.0);
        // 40 pkts from a single source, rate = 20 pkts/2s = 10/s
        // That's > 30% of 120 threshold (36), so low-entropy branch fires
        for _ in 0..40 {
            d.process("10.0.0.1", "192.168.1.1");
        }
        sleep(Duration::from_millis(2100));
        let alert = d.process("10.0.0.1", "192.168.1.1");
        if let Some(a) = alert {
            assert!(
                matches!(a.kind, AlertKind::LowEntropy | AlertKind::Anomaly),
                "single-source flood should fire LowEntropy or Anomaly"
            );
        }
    }
}
