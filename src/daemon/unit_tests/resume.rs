// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use super::{NipartResumeMonitor, RESUME_THRESHOLD, suspend_duration};

#[test]
fn test_clocks_advancing_together_is_not_a_resume() {
    assert_eq!(
        suspend_duration(Duration::from_secs(5), Duration::from_secs(5)),
        None
    );
}

#[test]
fn test_polling_jitter_is_not_a_resume() {
    assert_eq!(
        suspend_duration(
            Duration::from_millis(5000),
            Duration::from_millis(4999)
        ),
        None
    );
}

#[test]
fn test_suspend_is_detected_from_the_clock_gap() {
    assert_eq!(
        suspend_duration(Duration::from_secs(61), Duration::from_secs(1)),
        Some(Duration::from_secs(60))
    );
}

#[test]
fn test_threshold_gap_is_a_resume() {
    assert_eq!(
        suspend_duration(
            Duration::from_secs(3) + RESUME_THRESHOLD,
            Duration::from_secs(3)
        ),
        Some(RESUME_THRESHOLD)
    );
}

#[test]
fn test_monotonic_jump_forward_is_not_a_resume() {
    assert_eq!(
        suspend_duration(Duration::from_secs(1), Duration::from_secs(30)),
        None
    );
}

/// A monitor without a usable boottime clock must stay pending instead
/// of busy-looping or reporting a bogus resume.
#[tokio::test]
async fn test_disabled_monitor_never_completes() {
    let mut monitor = NipartResumeMonitor {
        last_boottime: None,
        last_monotonic: std::time::Instant::now(),
        next_poll: tokio::time::Instant::now(),
    };
    let result = tokio::time::timeout(
        Duration::from_millis(50),
        monitor.wait_for_resume(),
    )
    .await;
    assert!(result.is_err(), "disabled monitor must never complete");
}
