// SPDX-License-Identifier: Apache-2.0

use nipart::{
    ErrorKind, NetworkState, NipartError, NipartNoDaemon, NipartQueryOption,
};

use super::{commander::NipartCommander, daemon::DAEMON_IS_ONLINE};

// The wait-online polling backs off after the first 5 seconds, but the
// backoff also delays noticing that the daemon has become online: with a
// max of 8 seconds, `npt wait-online` could linger up to 8 seconds after
// the network was already configured. Cap it at 2 seconds so a wired NIC
// that comes up quickly is reported within ~2 seconds of going online.
const MAX_RETRY_WAIT: u64 = 2;

impl NipartCommander {
    /// Shared daemon online-state update.
    ///
    /// Every daemon path that can change the network online state
    /// (`npt apply`, `npt up/down`, `npt wifi on/off`, ...) or that notices
    /// it (the event worker after an apply, DHCP lease/gateway
    /// notifications, the monitor reconcile pass) must call this.  It is a
    /// one-shot latch: once online, later calls are no-ops.
    pub(crate) async fn update_daemon_online_state(
        &mut self,
    ) -> Result<(), NipartError> {
        if DAEMON_IS_ONLINE.initialized() {
            return Ok(());
        }
        self.try_set_daemon_online(None, None).await
    }

    pub(crate) async fn try_set_daemon_online(
        &mut self,
        saved_state: Option<&NetworkState>,
        cur_state: Option<&NetworkState>,
    ) -> Result<(), NipartError> {
        if DAEMON_IS_ONLINE.initialized() {
            return Ok(());
        }
        let saved_state = if let Some(s) = saved_state {
            s.clone()
        } else {
            self.conf_manager.query_state().await?
        };
        let online_cfg = saved_state.wait_online.unwrap_or_default();
        if online_cfg.conditions.is_empty() {
            // Ignore Err because it only fails when already set which is
            // OK for us to move on.
            DAEMON_IS_ONLINE.set(()).ok();
            return Ok(());
        }

        let cur_state = if let Some(c) = cur_state {
            c.clone()
        } else {
            NipartNoDaemon::query_network_state(NipartQueryOption::running())
                .await?
        };

        if online_cfg
            .conditions
            .into_iter()
            .all(|condition| condition.is_met(&cur_state))
        {
            DAEMON_IS_ONLINE.set(()).ok();
        }

        Ok(())
    }

    pub(crate) async fn wait_online(&mut self) -> Result<(), NipartError> {
        let saved_state = self.conf_manager.query_state().await?;
        let timeout_sec = saved_state
            .wait_online
            .clone()
            .unwrap_or_default()
            .timeout_sec;
        match tokio::time::timeout(
            std::time::Duration::from_secs(timeout_sec.into()),
            self._wait_online(Some(&saved_state), timeout_sec),
        )
        .await
        {
            Err(_) => Err(NipartError::new(
                ErrorKind::Timeout,
                "Timeout on waiting daemon to reach online state".to_string(),
            )),
            Ok(result) => result,
        }
    }

    async fn _wait_online(
        &mut self,
        saved_state: Option<&NetworkState>,
        timeout_sec: u32,
    ) -> Result<(), NipartError> {
        let mut retry_count = 0;
        let started = std::time::Instant::now();
        let budget = std::time::Duration::from_secs(timeout_sec.into());
        // Retry every 1 second for the first 5 seconds for quick boot
        // support, afterwards back off exponentially, but never sleep past
        // the timeout budget: the network may only become online late in
        // the window (e.g. wifi scan + connect + DHCP), so keep polling
        // until the deadline instead of scheduling the next poll beyond it
        // and giving up without ever observing the online state.
        while !DAEMON_IS_ONLINE.initialized() {
            self.try_set_daemon_online(saved_state, None).await?;
            let wait = next_retry_wait(retry_count, budget, started.elapsed());
            tokio::time::sleep(wait).await;
            retry_count += 1;
        }
        Ok(())
    }
}

/// Compute how long to wait before the next online-state poll.
///
/// Polls every 1 second for the first 5 retries, then backs off
/// exponentially up to [MAX_RETRY_WAIT], but never schedules a poll beyond
/// the remaining `budget` so the loop keeps polling until the deadline.
fn next_retry_wait(
    retry_count: u64,
    budget: std::time::Duration,
    elapsed: std::time::Duration,
) -> std::time::Duration {
    let retry_wait = if retry_count > 5 {
        // `ilog2()` bounds the exponent so the shift can never overflow,
        // and anything >= MAX_RETRY_WAIT is clamped anyway.
        let exp = (retry_count - 5).min(MAX_RETRY_WAIT.ilog2() as u64) as u32;
        2u64.pow(exp).clamp(1, MAX_RETRY_WAIT)
    } else {
        1
    };
    let remain = budget.saturating_sub(elapsed);
    std::time::Duration::from_secs(retry_wait).min(remain)
}

#[cfg(test)]
#[path = "unit_tests/wait_online.rs"]
mod tests;
