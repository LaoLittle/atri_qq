use super::*;
use crate::ios_device::network::wall_millis;

pub(super) struct RequestTiming {
    pub created: i64,
    pub sent: Option<i64>,
    pub eligible_for_timeout_at_submit: bool,
}

impl RequestTiming {
    pub(super) fn new(inner: &Inner) -> Result<Option<Self>> {
        if inner.ios_network.is_none() {
            return Ok(None);
        }
        Ok(Some(Self {
            created: wall_millis()?,
            sent: None,
            eligible_for_timeout_at_submit: inner.connection.is_some(),
        }))
    }
}

impl Client {
    pub(crate) fn ios_background_since(&self) -> Option<u64> {
        self.inner.lock().unwrap().signer.ios_background_since()
    }

    pub(super) fn prepare_ios_connection(&self, inner: &mut Inner) -> Result<()> {
        if inner.ios_network.is_none() {
            return Ok(());
        }
        let now = wall_millis()?;
        let adjusted = inner.clock.unix_seconds()?;
        let virtual_state = inner
            .state
            .keystore
            .ios_virtual_state
            .as_mut()
            .ok_or_else(|| {
                wire::malformed("Virtual iOS transport lost its persistent device state")
            })?;
        inner.ios_network.as_mut().unwrap().prepare(
            &mut virtual_state.connection_sequence,
            (now / 1000) as u32,
            adjusted,
            now,
        );
        self.emit(LoginEvent::KeystoreChanged(inner.state.keystore.clone()));
        Ok(())
    }

    pub(super) fn start_ios_network_work(&self, generation: u64) {
        let cancel = {
            let inner = self.inner.lock().unwrap();
            if inner.generation != generation || inner.ios_network.is_none() {
                return;
            }
            inner.cancel.clone()
        };
        let weak = self.weak.clone();
        let task = tokio::spawn(async move {
            let period = Duration::from_secs(1);
            let mut ticks = tokio::time::interval_at(Instant::now() + period, period);
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return,
                    _ = ticks.tick() => {},
                }
                let Some(client) = weak.upgrade() else { return };
                let now = match wall_millis() {
                    Ok(now) => now,
                    Err(error) => {
                        client.terminate_generation(
                            generation,
                            format!("iOS network clock failed: {error}"),
                        );
                        return;
                    }
                };
                let mut inner = client.inner.lock().unwrap();
                if inner.generation != generation || inner.connection.is_none() {
                    return;
                }
                if let Some(network) = &mut inner.ios_network {
                    network.tick(now);
                }
            }
        });
        self.tasks.lock().unwrap().push(task);
    }

    pub(super) fn mark_ios_send_started(&self, generation: u64, sequence: i32) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.generation == generation {
            if let Some(timing) = inner
                .pending
                .get_mut(&sequence)
                .and_then(|request| request.ios.as_mut())
            {
                timing.sent = Some(wall_millis()?);
            }
        }
        Ok(())
    }

    pub(super) fn note_ios_timeout(&self, sequence: i32, id: u64) {
        let mut inner = self.inner.lock().unwrap();
        let Inner {
            pending,
            ios_network,
            ..
        } = &mut *inner;
        if let Some(network) = ios_network {
            if let Some(request) = pending.get(&sequence).filter(|request| request.id == id) {
                network.timeout(
                    &request.command,
                    request
                        .ios
                        .as_ref()
                        .map(|timing| i32::from(timing.eligible_for_timeout_at_submit)),
                );
            }
        }
    }
}
