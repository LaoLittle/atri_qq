use crate::{
    Client, Encryption, Error, Profile, RequestType, Result,
    proto::{decode, lifecycle as pb},
};
use bytes::Bytes;
use prost::Message;
use tokio::time::Instant;

const COMMAND: &str = "trpc.group_pro.configdistribution.ConfigDistributionSvr.SsoGetConfig";

#[derive(Clone, Default, PartialEq, Eq)]
pub(super) struct ConfigState {
    revision: u64,
    incremental_cookie: Option<Bytes>,
    last_round_started: Option<Instant>,
}

pub(super) fn build(
    profile: &Profile,
    state: &ConfigState,
    source: i32,
    elapsed_seconds: u32,
) -> pb::ConfigRequest {
    let cold = state.incremental_cookie.is_none();
    let cookie = state.incremental_cookie.clone().unwrap_or_default();
    pb::ConfigRequest {
        origin: Some(pb::ConfigOrigin {
            scene_id: Some(2),
            model_type: Some(1),
            trigger_type: Some(source),
            trigger_interval: Some(elapsed_seconds),
        }),
        identity: Some(pb::ConfigIdentity {
            brand: Some(String::new()),
            model: Some(String::new()),
            platform: Some(pb::ConfigPlatform {
                kind: Some(5),
                // The session profile is authoritative, not the host's kernel.
                kernel: Some(profile.kernel.clone()),
            }),
        }),
        cache: Some(pb::ConfigCache {
            cookies: Some(Bytes::new()),
            environment: Some(String::new()),
            config_sequence: Some(state.revision),
            no_login_snapshot: Some(String::new()),
            inc_cookies: Some(cookie.clone()),
            inc_nologin_cookies: Some(cookie),
        }),
        targets: ["10006", "10020"]
            .into_iter()
            .map(|id| pb::ConfigTarget {
                id: Some(id.into()),
            })
            .collect(),
        continuation: Some(pb::ConfigContinuation {
            last_index: Some(if cold { -1 } else { 0 }),
        }),
        fetch_type: Some(if cold { 5 } else { 8 }),
        client: Some(pb::ConfigVersion {
            version: Some(profile.version.clone()),
        }),
        config_snapshot: Some(String::new()),
        flags: Some(pb::ConfigFlags {
            group_id: Some(0),
            new_version: Some(0),
        }),
    }
}

pub(super) fn apply(state: &mut ConfigState, body: Bytes) -> Result<()> {
    // ConfigResponse intentionally omits record field 2: no guild consumer uses
    // it here, so prost skips even a full cold-cache response without caching it.
    let response: pb::ConfigResponse = decode(body)?;
    let server = response
        .state
        .ok_or_else(|| Error::Malformed("Configuration response has no server state".into()))?;
    if let Some(revision) = server.config_sequence {
        state.revision = revision;
    }
    if let Some(cookie) = server.inc_cookies.filter(|cookie| !cookie.is_empty()) {
        state.incremental_cookie = Some(cookie);
    }
    Ok(())
}

fn ensure_current(client: &Client, generation: u64) -> Result<()> {
    if client.is_current_online(generation) {
        Ok(())
    } else {
        Err(Error::Disconnected)
    }
}

pub(super) async fn poll(client: &Client, generation: u64, state: &mut ConfigState) -> Result<()> {
    ensure_current(client, generation)?;
    let started = Instant::now();
    let profile = &client.config.profile;
    ensure_current(client, generation)?;
    let source = if state.last_round_started.is_some() {
        3
    } else {
        1
    };
    let elapsed_seconds = state
        .last_round_started
        .map(|previous| started.saturating_duration_since(previous).as_secs() as u32)
        .unwrap_or(0);
    // Later requests consume earlier responses, but a failed/cancelled group
    // must not publish a partially negotiated revision to the next poll.
    let mut working = state.clone();
    for _ in 0..4 {
        let body = Bytes::from(build(profile, &working, source, elapsed_seconds).encode_to_vec());
        ensure_current(client, generation)?;
        let response = client
            .request(
                COMMAND,
                body,
                RequestType::D2,
                Encryption::D2,
                client.config.timeout,
            )
            .await;
        ensure_current(client, generation)?;
        apply(&mut working, response?)?;
    }
    ensure_current(client, generation)?;
    working.last_round_started = Some(started);
    *state = working;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ClientConfig, Keystore};
    use std::time::Duration;

    fn reply(revision: Option<u64>, cookie: Option<Bytes>) -> Bytes {
        pb::ConfigResponse {
            state: Some(pb::ConfigServerState {
                config_sequence: revision,
                inc_cookies: cookie,
                ..Default::default()
            }),
            resource_report_denominator: Some(1000),
            ..Default::default()
        }
        .encode_to_vec()
        .into()
    }

    #[test]
    fn opaque_cookie_controls_delta_state_without_decoding_its_contents() {
        let profile = Profile::default();
        let mut state = ConfigState::default();
        let cold = build(&profile, &state, 1, 0);
        assert_eq!(cold.fetch_type, Some(5));
        assert_eq!(cold.continuation.unwrap().last_index, Some(-1));
        let cookie = Bytes::from_static(b"\xff\x00\x80");
        apply(&mut state, reply(Some(u64::MAX), Some(cookie.clone()))).unwrap();
        let delta = build(&profile, &state, 3, 607);
        assert_eq!(delta.fetch_type, Some(8));
        assert_eq!(delta.continuation.unwrap().last_index, Some(0));
        let cache = delta.cache.unwrap();
        assert_eq!(cache.config_sequence, Some(u64::MAX));
        assert_eq!(cache.inc_cookies, Some(cookie.clone()));
        assert_eq!(cache.inc_nologin_cookies, Some(cookie));
    }

    #[test]
    fn partial_server_state_preserves_unspecified_cache_fields() {
        let profile = Profile::default();
        let mut state = ConfigState::default();
        let first = Bytes::from_static(b"\x08\x1d");
        let second = Bytes::from_static(b"\x00");
        apply(&mut state, reply(Some(17), Some(first.clone()))).unwrap();
        apply(&mut state, reply(Some(88), None)).unwrap();
        let cache = build(&profile, &state, 3, 605).cache.unwrap();
        assert_eq!(cache.config_sequence, Some(88));
        assert_eq!(cache.inc_cookies, Some(first));
        apply(&mut state, reply(None, Some(second.clone()))).unwrap();
        let cache = build(&profile, &state, 3, 605).cache.unwrap();
        assert_eq!(cache.config_sequence, Some(88));
        assert_eq!(cache.inc_cookies, Some(second.clone()));
        apply(&mut state, reply(Some(0), Some(Bytes::new()))).unwrap();
        let before = state.clone();
        apply(&mut state, reply(None, None)).unwrap();
        assert!(state == before);
        let request = build(&profile, &state, 3, 605);
        assert_eq!(request.fetch_type, Some(8));
        let cache = request.cache.unwrap();
        assert_eq!(cache.config_sequence, Some(0));
        assert_eq!(cache.inc_cookies, Some(second));
    }

    #[test]
    fn malformed_reply_preserves_all_negotiated_state() {
        let mut state = ConfigState {
            revision: 17,
            incremental_cookie: Some(Bytes::from_static(b"\x08\x1d")),
            last_round_started: Some(Instant::now()),
        };
        let before = state.clone();
        let invalid = [
            Bytes::from_static(b"\x22\x80"),
            Bytes::from(
                pb::ConfigResponse {
                    resource_report_denominator: Some(1000),
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
        ];
        for body in invalid {
            assert!(apply(&mut state, body).is_err());
            assert!(state == before);
        }
    }

    #[test]
    fn cold_partial_state_does_not_invent_a_cookie() {
        let mut state = ConfigState::default();
        apply(&mut state, reply(Some(88), None)).unwrap();
        let request = build(&Profile::default(), &state, 1, 0);
        assert_eq!(request.continuation.unwrap().last_index, Some(-1));
        assert_eq!(request.fetch_type, Some(5));
        let cache = request.cache.unwrap();
        assert_eq!(cache.config_sequence, Some(88));
        assert_eq!(cache.inc_cookies, Some(Bytes::new()));
        assert_eq!(cache.inc_nologin_cookies, Some(Bytes::new()));
    }

    #[tokio::test(start_paused = true)]
    async fn obsolete_generation_cannot_replace_negotiated_state() {
        let client = Client::new(ClientConfig::default(), Keystore::default()).unwrap();
        let mut state = ConfigState {
            revision: 11,
            incremental_cookie: Some(Bytes::from_static(b"\x08\x1f")),
            last_round_started: Some(Instant::now() - Duration::from_secs(605)),
        };
        let before = state.clone();
        assert!(matches!(
            poll(&client, u64::MAX, &mut state).await,
            Err(Error::Disconnected)
        ));
        assert!(state == before);
    }
}
