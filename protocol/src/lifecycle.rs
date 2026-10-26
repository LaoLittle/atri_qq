//! QQ desktop business polling, separate from transport/account heartbeats.
use crate::Client;
use std::{sync::Weak, time::Duration};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

mod club;
pub(crate) mod config;
pub(crate) mod maintenance;
pub(crate) mod personal_events;
pub(crate) mod status;

const CLUB_DEFAULT_INTERVAL: Duration = Duration::from_secs(300);
const CONFIG_INTERVAL: Duration = Duration::from_secs(3600);

pub(crate) async fn run(weak: Weak<Client>, generation: u64, cancel: CancellationToken) {
    tokio::join!(
        run_club(weak.clone(), generation, cancel.clone()),
        run_config(weak.clone(), generation, cancel.clone()),
        status::run(weak.clone(), generation, cancel.clone()),
        run_network(weak.clone(), generation, cancel.clone()),
        personal_events::run(weak.clone(), generation, cancel.clone()),
        maintenance::run(weak, generation, cancel),
    );
}

async fn run_network(weak: Weak<Client>, generation: u64, cancel: CancellationToken) {
    let Some(client) = weak.upgrade() else { return };
    if !client.is_current_online(generation) {
        return;
    }
    let result = tokio::select! {
        biased;
        _ = cancel.cancelled() => return,
        result = client.refresh_ip_direct_configuration(generation) => result,
    };
    if let Err(error) = result
        && client.is_current_online(generation)
    {
        tracing::warn!(%error, "QQ domain address configuration could not be loaded");
    }
}

async fn run_club(weak: Weak<Client>, generation: u64, cancel: CancellationToken) {
    let mut next = Instant::now();
    let mut initial = true;
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep_until(next) => {},
        }
        let Some(client) = weak.upgrade() else { return };
        if !client.is_current_online(generation) {
            return;
        }
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            result = club::poll(&client, generation, initial) => result,
        };
        if !client.is_current_online(generation) {
            return;
        }
        initial = false;
        next = match result {
            Ok(deadline) => deadline,
            Err(error) => {
                tracing::warn!(%error, "QQClub/RedTouch poll failed; retaining normal business cadence");
                Instant::now() + CLUB_DEFAULT_INTERVAL
            }
        };
        drop(client);
    }
}

async fn run_config(weak: Weak<Client>, generation: u64, cancel: CancellationToken) {
    let mut next = Instant::now();
    let mut state = config::ConfigState::default();
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep_until(next) => {},
        }
        let Some(client) = weak.upgrade() else { return };
        if !client.is_current_online(generation) {
            return;
        }
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            result = config::poll(&client, generation, &mut state) => result,
        };
        if !client.is_current_online(generation) {
            return;
        }
        if let Err(error) = result {
            tracing::warn!(%error, "QQ config poll failed; retaining normal business cadence");
        }
        next = Instant::now() + CONFIG_INTERVAL;
        drop(client);
    }
}
