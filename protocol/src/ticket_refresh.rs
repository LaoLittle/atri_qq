use crate::{Client, login};
use std::{future::pending, sync::Weak, time::Duration};
use tokio::time::{Instant, Interval, MissedTickBehavior};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Schedule {
    pub(crate) generation: u64,
    pub(crate) interval_seconds: Option<i32>,
    pub(crate) selected_time: bool,
}

impl Schedule {
    fn timer(self) -> Option<Interval> {
        let seconds = self.interval_seconds.filter(|seconds| *seconds > 0)?;
        let period = Duration::from_secs(seconds as u64);
        let mut timer = tokio::time::interval_at(Instant::now() + period, period);
        timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
        Some(timer)
    }
}

pub(crate) async fn run(weak: Weak<Client>, generation: u64, cancel: CancellationToken) {
    let mut updates = {
        let Some(client) = weak.upgrade() else { return };
        let Ok(updates) = client.ticket_refresh_schedule(generation) else {
            return;
        };
        updates
    };
    let mut loaded = false;
    loop {
        if cancel.is_cancelled() {
            return;
        }
        let schedule = *updates.borrow_and_update();
        if schedule.generation != generation {
            return;
        }
        if schedule.selected_time && !loaded {
            loaded = true;
            if schedule.interval_seconds.is_none() {
                let Some(client) = weak.upgrade() else { return };
                let result = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return,
                    result = crate::lifecycle::config::load_ticket_refresh_interval(&client, generation) => result,
                };
                let unconfigured = updates.borrow().interval_seconds.is_none();
                match result {
                    Ok(Some(seconds)) if unconfigured => {
                        if client
                            .set_ticket_refresh_interval(generation, seconds)
                            .is_err()
                        {
                            return;
                        }
                    }
                    Ok(_) => {}
                    Err(error) => {
                        tracing::warn!(%error, "NT ticket refresh configuration could not be loaded")
                    }
                }
                drop(client);
                continue;
            }
        }
        let mut timer = schedule.timer();
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return,
                changed = updates.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    let updated = *updates.borrow_and_update();
                    if updated.generation != generation {
                        return;
                    }
                    if updated.interval_seconds != schedule.interval_seconds
                        || schedule.interval_seconds.is_none()
                    {
                        break;
                    }
                    continue;
                }
                _ = async {
                    match &mut timer {
                        Some(timer) => { timer.tick().await; },
                        None => pending::<()>().await,
                    }
                } => {},
            }
            let Some(client) = weak.upgrade() else { return };
            if !client.is_current_online(generation) {
                return;
            }
            let result = tokio::select! {
                biased;
                _ = cancel.cancelled() => return,
                result = login::refresh_tickets_for_generation(&client, generation) => result,
            };
            if !client.is_current_online(generation) {
                return;
            }
            if let Err(error) = result {
                tracing::warn!(%error, "NT ticket refresh check failed");
            }
            drop(client);
            if updates.has_changed().unwrap_or(true) {
                let updated = *updates.borrow_and_update();
                if updated.generation != generation {
                    return;
                }
                if updated.interval_seconds != schedule.interval_seconds {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn missing_zero_and_negative_configuration_never_arm_a_timer() {
        for interval_seconds in [None, Some(0), Some(-1), Some(i32::MIN)] {
            assert!(
                Schedule {
                    interval_seconds,
                    ..Default::default()
                }
                .timer()
                .is_none()
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn first_check_waits_a_full_period_and_missed_checks_are_skipped() {
        let start = Instant::now();
        let mut timer = Schedule {
            interval_seconds: Some(5),
            ..Default::default()
        }
        .timer()
        .unwrap();
        assert_eq!(timer.tick().await, start + Duration::from_secs(5));
        tokio::time::advance(Duration::from_secs(21)).await;
        assert_eq!(timer.tick().await, start + Duration::from_secs(10));
        assert_eq!(timer.tick().await, start + Duration::from_secs(30));
    }

    #[tokio::test(start_paused = true)]
    async fn changed_configuration_restarts_from_a_full_new_period() {
        let mut schedule = Schedule {
            interval_seconds: Some(5),
            ..Default::default()
        };
        let mut previous = schedule.timer().unwrap();
        previous.tick().await;
        schedule.interval_seconds = Some(9);
        let start = Instant::now();
        assert_eq!(
            schedule.timer().unwrap().tick().await,
            start + Duration::from_secs(9)
        );
        schedule.interval_seconds = Some(0);
        assert!(schedule.timer().is_none());
    }
}
