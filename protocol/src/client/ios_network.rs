use super::*;
use crate::ios_device::network::wall_millis;

#[derive(Default)]
pub(super) struct BlockCheck {
    pub running: bool,
    pub timed_out: bool,
}

pub(super) struct RequestTiming {
    pub created: i64,
    pub sent: Option<i64>,
    pub eligible_for_timeout_at_submit: bool,
}

impl RequestTiming {
    pub(super) fn new(inner: &Inner) -> Result<Option<Self>> {
        if inner.ios().and_then(|ios| ios.network.as_ref()).is_none() {
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
    pub(crate) fn ios_registration_context(
        &self,
    ) -> Result<crate::ios_device::registration::Context> {
        self.inner.lock().unwrap().ios_registration_context()
    }

    pub(super) fn prepare_ios_connection(&self, inner: &mut Inner) -> Result<()> {
        if inner.ios().and_then(|ios| ios.network.as_ref()).is_none() {
            return Ok(());
        }
        let now = wall_millis()?;
        let adjusted = inner.clock.unix_seconds()?;
        let Inner {
            state, platform, ..
        } = inner;
        let PlatformRuntime::Ios(ios) = platform else {
            return Ok(());
        };
        let virtual_state = state.keystore.ios_virtual_state.as_mut().ok_or_else(|| {
            wire::malformed("Virtual iOS transport lost its persistent device state")
        })?;
        ios.network.as_mut().unwrap().prepare(
            &mut virtual_state.connection_sequence,
            (now / 1000) as u32,
            adjusted,
            now,
        );
        self.emit(LoginEvent::KeystoreChanged(state.keystore.clone()));
        Ok(())
    }

    pub(super) fn start_ios_network_work(&self, generation: u64) {
        let cancel = {
            let inner = self.inner.lock().unwrap();
            if inner.generation != generation
                || inner.ios().and_then(|ios| ios.network.as_ref()).is_none()
            {
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
                if let Some(network) = inner.ios_mut().and_then(|ios| ios.network.as_mut()) {
                    network.tick(now);
                }
            }
        });
        self.tasks.lock().unwrap().push(task);
    }

    pub(super) fn mark_ios_send_started(
        &self,
        generation: u64,
        sequence: i32,
        attempt: u64,
        source: &CancellationToken,
    ) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.generation == generation && !source.is_cancelled() {
            if let Some(request) = inner.pending.get_mut(&sequence).filter(|request| {
                request
                    .replay
                    .as_ref()
                    .is_none_or(|replay| replay.attempt == attempt)
            }) {
                if let Some(replay) = &mut request.replay {
                    replay.phase = ios_header::Phase::Writing(Instant::now());
                }
                if let Some(timing) = &mut request.ios {
                    timing.sent = Some(wall_millis()?);
                }
            }
        }
        Ok(())
    }

    pub(super) fn note_ios_timeout(&self, sequence: i32, id: u64) {
        let mut inner = self.inner.lock().unwrap();
        let actual_timeout = inner
            .pending
            .get(&sequence)
            .filter(|request| request.id == id && request.command != "Heartbeat.Alive")
            .and_then(|request| request.replay.as_ref())
            .is_some_and(|replay| replay.phase.sent().is_some());
        if actual_timeout {
            if let Some(ios) = inner.ios_mut() {
                ios.block_check.timed_out = true;
                self.arm_ios_block_checks(&mut inner);
            }
        }
        let Inner {
            pending, platform, ..
        } = &mut *inner;
        if let PlatformRuntime::Ios(IosRuntime {
            network: Some(network),
            ..
        }) = platform
        {
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

    pub(super) fn arm_ios_block_checks(&self, inner: &mut Inner) {
        let Some(ios) = inner.ios() else { return };
        if ios.block_check.running
            || inner.connection.is_none()
            || inner.cancel.is_cancelled()
            || inner.transport_cancel.is_cancelled()
            || (inner.pending.is_empty() && !ios.block_check.timed_out)
        {
            return;
        }
        inner.ios_mut().unwrap().block_check.running = true;
        inner.alive_cancel = inner.transport_cancel.child_token();
        let cancel = inner.alive_cancel.clone();
        let generation = inner.generation;
        let weak = self.weak.clone();
        let task = tokio::spawn(async move {
            let mut previous = Instant::now();
            let mut ticks =
                tokio::time::interval_at(previous + Duration::from_secs(1), Duration::from_secs(1));
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return,
                    _ = ticks.tick() => {}
                }
                let Some(client) = weak.upgrade() else { return };
                let now = Instant::now();
                let delta = now.duration_since(previous).as_secs().max(1);
                previous = now;
                let probe = {
                    let mut inner = client.inner.lock().unwrap();
                    if inner.generation != generation
                        || inner.connection.is_none()
                        || inner.cancel.is_cancelled()
                        || cancel.is_cancelled()
                    {
                        return;
                    }
                    let probe = Self::ios_block_check_due(&mut inner, now, delta);
                    if inner.pending.is_empty() && !probe {
                        inner.ios_mut().unwrap().block_check.running = false;
                        return;
                    }
                    probe
                };
                if probe {
                    client.send_ios_block_probe(generation, cancel.clone());
                }
            }
        });
        let mut tasks = self.tasks.lock().unwrap();
        tasks.retain(|task| !task.is_finished());
        tasks.push(task);
    }

    pub(super) fn ios_block_check_due(inner: &mut Inner, now: Instant, delta: u64) -> bool {
        let Some(ios) = inner.ios_mut() else {
            return false;
        };
        let mut timed_out = std::mem::take(&mut ios.block_check.timed_out);
        let mut alive_in_flight = false;
        let mut commands = [""; 6];
        let mut command_count = 0;
        for pending in inner.pending.values_mut() {
            if pending.cancel.is_cancelled() {
                continue;
            }
            let Some(replay) = &mut pending.replay else {
                continue;
            };
            let sent = replay.phase.sent().is_some();
            if sent && replay.internal_control && pending.command == "Heartbeat.Alive" {
                alive_in_flight = true;
            }
            if sent && replay.deadline <= now {
                timed_out = true;
            }
            if matches!(replay.phase, ios_header::Phase::Awaiting(_)) {
                let elapsed = now.duration_since(replay.created).as_secs();
                replay.accumulated_wait =
                    replay.accumulated_wait.saturating_add(delta.min(elapsed));
                let command = pending.command.as_str();
                if replay.accumulated_wait >= 6
                    && command_count < commands.len()
                    && !commands[..command_count].contains(&command)
                {
                    commands[command_count] = command;
                    command_count += 1;
                }
            }
        }
        !alive_in_flight && (timed_out || command_count == commands.len())
    }

    fn send_ios_block_probe(&self, generation: u64, cancel: CancellationToken) {
        let weak = self.weak.clone();
        let task = tokio::spawn(async move {
            let Some(client) = weak.upgrade() else { return };
            let result = tokio::select! {
                biased;
                _ = cancel.cancelled() => return,
                result = client.request_inner(
                    "Heartbeat.Alive",
                    Bytes::from_static(&[0, 0, 0, 4]),
                    RequestType::D2,
                    Encryption::None,
                    Duration::from_secs(8),
                    Some(RequestBinding::IosControl { generation, source: &cancel }),
                ) => result,
            };
            if matches!(result, Err(Error::Timeout)) && !cancel.is_cancelled() {
                client.terminate_generation(generation, "ConsecutivePacketTimeout".into());
            }
        });
        let mut tasks = self.tasks.lock().unwrap();
        tasks.retain(|task| !task.is_finished());
        tasks.push(task);
    }

    pub(super) fn accept_ios_block_check(&self, inner: &mut Inner, pending: &Pending) {
        let Some(replay) = &pending.replay else {
            return;
        };
        if !replay.internal_control || pending.command != "Heartbeat.Alive" {
            return;
        }
        let Some(probe_sent) = replay.phase.sent() else {
            return;
        };
        for pending in inner.pending.values_mut() {
            if let Some(replay) = &mut pending.replay {
                if let ios_header::Phase::Awaiting(sent) = replay.phase {
                    if sent < probe_sent {
                        replay.accumulated_wait = 0;
                    }
                }
            }
        }
    }
}

impl Inner {
    pub(super) fn ios_registration_context(
        &self,
    ) -> Result<crate::ios_device::registration::Context> {
        Ok(crate::ios_device::registration::Context {
            now_seconds: if self.ios().is_some() {
                u64::try_from(wall_millis()? / 1000)
                    .map_err(|_| wire::malformed("iOS registration precedes Unix epoch"))?
            } else {
                0
            },
            background_since: self.signer.ios_background_since(),
            first_register: self.ios().is_some_and(|ios| ios.first_register),
        })
    }
}
