// SPDX-License-Identifier: Apache-2.0

//! System suspend/resume detection.
//!
//! The daemon has no dependency on logind; instead it watches the
//! divergence between `CLOCK_BOOTTIME` (which keeps counting while the
//! system is suspended) and `CLOCK_MONOTONIC` (which stops).  A gap
//! between the two clocks can only be produced by a suspend/resume
//! cycle, so this also catches suspends that bypass logind (e.g. a VM
//! pause, or a container host suspend).

use std::time::{Duration, Instant};

use nipart::{ErrorKind, NipartError};
use nix::time::{ClockId, clock_gettime};

/// How often the two clocks are sampled.  The detector only has to be
/// fast enough to cancel a plugin's retry backoff shortly after wake.
const RESUME_POLL_INTERVAL: Duration = Duration::from_secs(1);
/// Minimum divergence between the boottime and monotonic clocks that is
/// treated as a suspend.  A smaller drift is polling jitter.
const RESUME_THRESHOLD: Duration = Duration::from_secs(2);

/// Monitors the host for suspend/resume cycles.
#[derive(Debug)]
pub(crate) struct NipartResumeMonitor {
    /// Last sampled `CLOCK_BOOTTIME`, `None` when the clock is not
    /// available and monitoring is disabled.
    last_boottime: Option<Duration>,
    last_monotonic: Instant,
    /// Next clock sample deadline. It survives a cancellation of the
    /// `select!` future so a busy daemon main loop cannot starve resume
    /// detection by restarting the one-second sleep.
    next_poll: tokio::time::Instant,
}

impl NipartResumeMonitor {
    pub(crate) fn new() -> Self {
        let last_boottime = match boottime() {
            Ok(boottime) => Some(boottime),
            Err(e) => {
                // Suspend/resume detection is a best-effort feature: a
                // host without CLOCK_BOOTTIME must still be able to run
                // the daemon.
                log::warn!("{e}; suspend/resume detection is disabled");
                None
            }
        };
        Self {
            last_boottime,
            last_monotonic: Instant::now(),
            next_poll: tokio::time::Instant::now() + RESUME_POLL_INTERVAL,
        }
    }

    /// Wait until the system comes back from suspend and return how long
    /// the suspend lasted.
    ///
    /// A disabled monitor (missing clock) never completes. Clock read
    /// errors disable the monitor instead of making the daemon's main
    /// loop spin.
    pub(crate) async fn wait_for_resume(&mut self) -> Duration {
        if self.last_boottime.is_none() {
            return std::future::pending().await;
        }
        loop {
            tokio::time::sleep_until(self.next_poll).await;
            self.next_poll = tokio::time::Instant::now() + RESUME_POLL_INTERVAL;
            let Some(last_boottime) = self.last_boottime else {
                return std::future::pending().await;
            };
            let boottime = match boottime() {
                Ok(boottime) => boottime,
                Err(e) => {
                    log::warn!("{e}; suspend/resume detection is disabled");
                    self.last_boottime = None;
                    return std::future::pending().await;
                }
            };
            let monotonic = Instant::now();
            let boottime_delta = boottime.saturating_sub(last_boottime);
            let monotonic_delta =
                monotonic.saturating_duration_since(self.last_monotonic);
            self.last_boottime = Some(boottime);
            self.last_monotonic = monotonic;
            if let Some(suspended) =
                suspend_duration(boottime_delta, monotonic_delta)
            {
                return suspended;
            }
        }
    }
}

/// Return how long the system was suspended when `boottime_delta`
/// advanced at least [`RESUME_THRESHOLD`] more than `monotonic_delta`.
///
/// A negative difference (the monotonic clock advanced further than
/// boottime) is a clock anomaly, not a resume.
fn suspend_duration(
    boottime_delta: Duration,
    monotonic_delta: Duration,
) -> Option<Duration> {
    let suspended = boottime_delta.checked_sub(monotonic_delta)?;
    (suspended >= RESUME_THRESHOLD).then_some(suspended)
}

fn boottime() -> Result<Duration, NipartError> {
    let now = clock_gettime(ClockId::CLOCK_BOOTTIME).map_err(|e| {
        NipartError::new(
            ErrorKind::DaemonFailure,
            format!("Failed to read CLOCK_BOOTTIME: {e}"),
        )
    })?;
    // CLOCK_BOOTTIME is non-negative and tv_nsec is always below one
    // second, so both casts are lossless.
    Ok(Duration::new(now.tv_sec() as u64, now.tv_nsec() as u32))
}

#[cfg(test)]
#[path = "unit_tests/resume.rs"]
mod unit_tests;
