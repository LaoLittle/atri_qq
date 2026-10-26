use crate::{
    Client, Error, Profile, Result,
    proto::{decode, lifecycle as pb},
};
use bytes::Bytes;
use prost::Message;
use std::{collections::HashMap, sync::Arc};
use tokio::time::Instant;

const COMMAND: &str = "trpc.group_pro.configdistribution.ConfigDistributionSvr.SsoGetConfig";

const TICKET_REFRESH_GROUP: &str = "107055";
const APPLICATION_UPDATE_GROUP: &str = "100085";

#[derive(Clone, Default, PartialEq)]
pub(crate) struct ConfigState {
    revision: u64,
    incremental_cookie: Option<Bytes>,
    last_round_started: Option<Instant>,
    groups: Arc<HashMap<GroupKey, Arc<CachedGroup>>>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct GroupKey(Bytes, bool);

#[derive(PartialEq)]
struct CachedGroup {
    wire: pb::ConfigGroup,
    content: Bytes,
    refresh_interval: Option<i32>,
}

fn group_key(group: &pb::ConfigGroup) -> Option<GroupKey> {
    let no_login = group.no_login.unwrap_or(false);
    if let Some(name) = group.name.as_ref().filter(|name| !name.is_empty()) {
        Some(GroupKey(Bytes::copy_from_slice(name.as_bytes()), no_login))
    } else {
        group
            .group_id
            .filter(|id| *id != 0)
            .map(|id| GroupKey(id.to_string().into(), no_login))
    }
}

pub(super) fn build(
    profile: &Profile,
    state: &ConfigState,
    source: i32,
    elapsed_seconds: u32,
) -> pb::ConfigRequest {
    let exact = source == 2;
    let cold = state.incremental_cookie.is_none();
    let cookie = if exact {
        Bytes::new()
    } else {
        state.incremental_cookie.clone().unwrap_or_default()
    };
    pb::ConfigRequest {
        origin: Some(pb::ConfigOrigin {
            scene_id: Some(2),
            model_type: Some(if exact { 2 } else { 1 }),
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
            config_sequence: Some(if exact { 0 } else { state.revision }),
            no_login_snapshot: Some(String::new()),
            inc_cookies: Some(cookie.clone()),
            inc_nologin_cookies: Some(cookie),
        }),
        groups: Vec::new(),
        targets: ["10006", "10020"]
            .into_iter()
            .map(|id| pb::ConfigTarget {
                id: Some(id.into()),
            })
            .collect(),
        continuation: Some(pb::ConfigContinuation {
            last_index: Some(if exact || cold { -1 } else { 0 }),
        }),
        fetch_type: Some(if exact { 2 } else if cold { 5 } else { 8 }),
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

fn build_exact(profile: &Profile, state: &ConfigState, name: &'static str) -> pb::ConfigRequest {
    let mut request = build(profile, state, 2, 0);
    let cached = state
        .groups
        .get(&GroupKey(Bytes::from_static(name.as_bytes()), false));
    request.groups.push(pb::ConfigGroupRequest {
        name: Some(name.to_owned()),
        old_version: Some("1".to_owned()),
        group_id: Some(cached.and_then(|group| group.wire.group_id).unwrap_or(0)),
        new_version: Some(cached.and_then(|group| group.wire.new_version).unwrap_or(0)),
    });
    request
}

fn decode_record(record: &pb::ConfigRecord) -> Result<Bytes> {
    let content = record.content.clone().unwrap_or_default();
    if record.compression.unwrap_or(0) != 1 {
        return Ok(content);
    }
    let size = record.uncompressed_size.unwrap_or(0);
    if size == 0 || size > crate::wire::MAX_FRAME_SIZE as u64 {
        return Err(Error::Malformed("Invalid configuration record size".into()));
    }
    let mut output = vec![0; size as usize];
    let written = lz4_flex::block::decompress_into(&content, &mut output)
        .map_err(|_| Error::Malformed("Invalid LZ4 configuration record".into()))?;
    output.truncate(written);
    Ok(output.into())
}

fn ticket_refresh_interval(content: &[u8]) -> Result<Option<i32>> {
    if content.is_empty() {
        return Ok(None);
    }
    let json: serde_json::Value = serde_json::from_slice(content)
        .map_err(|_| Error::Malformed("Invalid ticket refresh configuration JSON".into()))?;
    let Some(value) = json.get("refresh_check_interval") else {
        return Ok(Some(0));
    };
    let seconds = match value {
        serde_json::Value::Number(number) => number
            .as_i64()
            .and_then(|seconds| i32::try_from(seconds).ok())
            .or_else(|| {
                number
                    .as_f64()
                    .filter(|seconds| {
                        seconds.is_finite()
                            && seconds.fract() == 0.0
                            && *seconds >= i32::MIN as f64
                            && *seconds <= i32::MAX as f64
                    })
                    .map(|seconds| seconds as i32)
            }),
        _ => None,
    };
    Ok(Some(seconds.unwrap_or(0)))
}

fn apply_groups(state: &mut ConfigState, groups: Vec<pb::ConfigGroup>) -> Result<Option<i32>> {
    let mut observed = false;
    for group in groups {
        let Some(key) = group_key(&group) else {
            continue;
        };
        let is_refresh = key.0.as_ref() == TICKET_REFRESH_GROUP.as_bytes() && !key.1;
        let version = group.new_version.unwrap_or(0);
        if state
            .groups
            .get(&key)
            .and_then(|cached| cached.wire.new_version)
            .is_some_and(|old| old != 0 && old == version)
        {
            continue;
        }
        if version == 0 {
            observed |= is_refresh;
            Arc::make_mut(&mut state.groups).remove(&key);
            continue;
        }
        let Some(record) = group.records.first() else {
            continue;
        };
        let content = decode_record(record)?;
        let refresh_interval = if is_refresh && !record.is_cdn.unwrap_or(false) {
            ticket_refresh_interval(&content)?
        } else {
            None
        };
        observed |= is_refresh;
        Arc::make_mut(&mut state.groups).insert(
            key,
            Arc::new(CachedGroup {
                wire: group,
                content,
                refresh_interval,
            }),
        );
    }
    Ok(observed
        .then(|| cached_ticket_refresh_interval(state))
        .flatten())
}

fn cached_ticket_refresh_interval(state: &ConfigState) -> Option<i32> {
    state
        .groups
        .get(&GroupKey(
            Bytes::from_static(TICKET_REFRESH_GROUP.as_bytes()),
            false,
        ))
        .and_then(|group| group.refresh_interval)
}

pub(super) fn apply(state: &mut ConfigState, body: Bytes) -> Result<Option<i32>> {
    let response: pb::ConfigResponse = decode(body)?;
    let server = response
        .state
        .ok_or_else(|| Error::Malformed("Configuration response has no server state".into()))?;
    let mut candidate = state.clone();
    let interval = apply_groups(&mut candidate, response.groups)?;
    if let Some(revision) = server.config_sequence {
        candidate.revision = revision;
    }
    if let Some(cookie) = server.inc_cookies.filter(|cookie| !cookie.is_empty()) {
        candidate.incremental_cookie = Some(cookie);
    }
    *state = candidate;
    Ok(interval)
}

fn apply_exact(state: &mut ConfigState, body: Bytes) -> Result<Option<i32>> {
    let response: pb::ConfigResponse = decode(body)?;
    if response.state.is_none() {
        return Err(Error::Malformed("Configuration response has no server state".into()));
    }
    let mut candidate = state.clone();
    let interval = apply_groups(&mut candidate, response.groups)?;
    *state = candidate;
    Ok(interval)
}

pub(crate) async fn load_ticket_refresh_interval(
    client: &Client,
    generation: u64,
) -> Result<Option<i32>> {
    ensure_current(client, generation)?;
    let mut state = ConfigState::default();
    let body = build_exact(&client.config.profile, &state, TICKET_REFRESH_GROUP)
        .encode_to_vec()
        .into();
    let response = client
        .request_online(generation, COMMAND, body, client.config.timeout)
        .await;
    ensure_current(client, generation)?;
    apply_exact(&mut state, response?)
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
    if state.last_round_started.is_none() {
        let body = build(profile, state, 1, 0).encode_to_vec().into();
        let response = client
            .request_online(generation, COMMAND, body, client.config.timeout)
            .await;
        ensure_current(client, generation)?;
        let refresh_interval = apply(state, response?)?;
        if refresh_interval.is_some()
            && let Some(seconds) = cached_ticket_refresh_interval(state)
        {
            client.set_ticket_refresh_interval(generation, seconds)?;
        }
        state.last_round_started = Some(started);
    }
    let body = build_exact(profile, state, APPLICATION_UPDATE_GROUP)
        .encode_to_vec()
        .into();
    let response = client
        .request_online(generation, COMMAND, body, client.config.timeout)
        .await;
    ensure_current(client, generation)?;
    apply_exact(state, response?)?;
    state.last_round_started = Some(started);
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
            ..Default::default()
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
            ..Default::default()
        };
        let before = state.clone();
        assert!(matches!(
            poll(&client, u64::MAX, &mut state).await,
            Err(Error::Disconnected)
        ));
        assert!(state == before);
        assert!(matches!(
            load_ticket_refresh_interval(&client, u64::MAX).await,
            Err(Error::Disconnected)
        ));
    }

    fn group_reply(groups: Vec<pb::ConfigGroup>) -> Bytes {
        pb::ConfigResponse {
            groups,
            state: Some(pb::ConfigServerState {
                config_sequence: Some(90),
                inc_cookies: Some(Bytes::from_static(b"new-cookie")),
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode_to_vec()
        .into()
    }

    fn group(name: &str, version: u32, content: &'static [u8]) -> pb::ConfigGroup {
        pb::ConfigGroup {
            name: Some(name.to_owned()),
            old_version: Some("opaque-version".into()),
            group_id: Some(17),
            new_version: Some(version),
            records: vec![pb::ConfigRecord {
                content: Some(Bytes::from_static(content)),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn exact_group_responses_do_not_replace_global_cookie_or_revision() {
        let mut state = ConfigState::default();
        apply(
            &mut state,
            group_reply(vec![group(APPLICATION_UPDATE_GROUP, 8, b"[]")]),
        )
        .unwrap();
        let revision = state.revision;
        let cookie = state.incremental_cookie.clone();
        let response = pb::ConfigResponse {
            groups: vec![group(APPLICATION_UPDATE_GROUP, 9, b"[{}]")],
            state: Some(pb::ConfigServerState {
                config_sequence: Some(0),
                inc_cookies: Some(Bytes::from_static(b"scoped-cookie")),
                ..Default::default()
            }),
            ..Default::default()
        };
        apply_exact(&mut state, response.encode_to_vec().into()).unwrap();
        assert_eq!(state.revision, revision);
        assert_eq!(state.incremental_cookie, cookie);
        let exact = build_exact(&Profile::default(), &state, APPLICATION_UPDATE_GROUP);
        assert_eq!(exact.groups[0].old_version.as_deref(), Some("1"));
        assert_eq!(exact.groups[0].new_version, Some(9));
        assert_eq!(exact.cache.unwrap().inc_cookies, Some(Bytes::new()));
    }

    #[test]
    fn lz4_record_wrapper_decodes_without_treating_all_content_as_json() {
        let json = br#"{"refresh_check_interval":-9}"#;
        let record = pb::ConfigRecord {
            content: Some(lz4_flex::block::compress(json).into()),
            compression: Some(1),
            uncompressed_size: Some(json.len() as u64),
            switch_on: Some(false),
            is_cdn: Some(false),
            metadata6: Some(u32::MAX),
        };
        assert_eq!(decode_record(&record).unwrap().as_ref(), json);
        let mut configured = group(TICKET_REFRESH_GROUP, 8, b"");
        configured.records = vec![record];
        let mut state = ConfigState::default();
        assert_eq!(
            apply(&mut state, group_reply(vec![configured])).unwrap(),
            Some(-9)
        );
        assert_eq!(
            apply(
                &mut state,
                group_reply(vec![group("other", 1, b"\xff\x00")])
            )
            .unwrap(),
            None
        );
        let raw = pb::ConfigRecord {
            content: Some(Bytes::from_static(b"\xff\x00")),
            compression: Some(2),
            ..Default::default()
        };
        assert_eq!(
            decode_record(&raw).unwrap().as_ptr(),
            raw.content.as_ref().unwrap().as_ptr()
        );
    }

    #[test]
    fn refresh_json_uses_integral_seconds_and_disables_invalid_values() {
        for (json, expected) in [
            (br#"{"refresh_check_interval":0}"#.as_slice(), 0),
            (
                br#"{"refresh_check_interval":-2147483648}"#.as_slice(),
                i32::MIN,
            ),
            (
                br#"{"refresh_check_interval":2147483647}"#.as_slice(),
                i32::MAX,
            ),
            (br#"{"refresh_check_interval":37.0}"#.as_slice(), 37),
            (br#"{"refresh_check_interval":1e1}"#.as_slice(), 10),
        ] {
            assert_eq!(ticket_refresh_interval(json).unwrap(), Some(expected));
        }
        for json in [
            br#"{"refresh_check_interval":2147483648}"#.as_slice(),
            br#"{"refresh_check_interval":-2147483649}"#.as_slice(),
            br#"{"refresh_check_interval":1.5}"#.as_slice(),
            br#"{"refresh_check_interval":"37"}"#.as_slice(),
            br#"{"refresh_check_interval":true}"#.as_slice(),
            br#"{"refresh_check_interval":null}"#.as_slice(),
        ] {
            assert_eq!(ticket_refresh_interval(json).unwrap(), Some(0));
        }
        assert_eq!(ticket_refresh_interval(b"{}").unwrap(), Some(0));
        assert_eq!(ticket_refresh_interval(b"").unwrap(), None);
        assert!(ticket_refresh_interval(b"{").is_err());
    }

    #[test]
    fn merge_preserves_absent_groups_and_ignores_equal_but_not_lower_versions() {
        let mut state = ConfigState::default();
        assert_eq!(
            apply(
                &mut state,
                group_reply(vec![group(
                    TICKET_REFRESH_GROUP,
                    8,
                    br#"{"refresh_check_interval":37}"#
                )])
            )
            .unwrap(),
            Some(37)
        );
        let before = state.groups.values().next().unwrap().clone();
        assert_eq!(apply(&mut state, group_reply(vec![])).unwrap(), None);
        assert!(Arc::ptr_eq(&before, state.groups.values().next().unwrap()));
        assert_eq!(
            apply(
                &mut state,
                group_reply(vec![group(TICKET_REFRESH_GROUP, 8, b"bad-json")])
            )
            .unwrap(),
            None
        );
        assert!(Arc::ptr_eq(&before, state.groups.values().next().unwrap()));
        assert_eq!(
            apply(
                &mut state,
                group_reply(vec![group(
                    TICKET_REFRESH_GROUP,
                    2,
                    br#"{"refresh_check_interval":0}"#
                )])
            )
            .unwrap(),
            Some(0)
        );
        let mut no_records = group(TICKET_REFRESH_GROUP, 3, b"");
        no_records.records.clear();
        assert_eq!(
            apply(&mut state, group_reply(vec![no_records])).unwrap(),
            None
        );
        assert_eq!(cached_ticket_refresh_interval(&state), Some(0));
        assert_eq!(
            apply(
                &mut state,
                group_reply(vec![group(TICKET_REFRESH_GROUP, 0, b"")])
            )
            .unwrap(),
            None
        );
        assert!(state.groups.is_empty());
    }

    #[test]
    fn invalid_groups_preserve_all_negotiated_state_atomically() {
        let mut state = ConfigState::default();
        apply(
            &mut state,
            group_reply(vec![group(
                TICKET_REFRESH_GROUP,
                8,
                br#"{"refresh_check_interval":37}"#,
            )]),
        )
        .unwrap();
        let before = state.clone();
        let mut compressed = group("other", 1, b"not-an-lz4-block");
        compressed.records[0].compression = Some(1);
        compressed.records[0].uncompressed_size = Some(80);
        let mut oversized = compressed.clone();
        oversized.records[0].uncompressed_size = Some(u64::MAX);
        let mut zero = compressed.clone();
        zero.records[0].uncompressed_size = Some(0);
        for invalid in [
            group(TICKET_REFRESH_GROUP, 9, b"{"),
            compressed,
            oversized,
            zero,
        ] {
            assert!(
                apply(
                    &mut state,
                    group_reply(vec![group("earlier", 1, b"valid opaque data"), invalid])
                )
                .is_err()
            );
            assert!(state == before);
        }
    }

    #[test]
    fn a_valid_configuration_without_the_interval_stops_an_active_schedule() {
        let mut state = ConfigState::default();
        assert_eq!(
            apply(
                &mut state,
                group_reply(vec![group(
                    TICKET_REFRESH_GROUP,
                    1,
                    br#"{"refresh_check_interval":37}"#
                ),])
            )
            .unwrap(),
            Some(37)
        );
        assert_eq!(
            apply(
                &mut state,
                group_reply(vec![group(TICKET_REFRESH_GROUP, 2, b"{}"),])
            )
            .unwrap(),
            Some(0)
        );
        assert_eq!(cached_ticket_refresh_interval(&state), Some(0));
    }

    #[test]
    fn only_first_record_is_consumed_and_cdn_or_no_login_never_publish() {
        let mut first = group(TICKET_REFRESH_GROUP, 1, br#"{"refresh_check_interval":11}"#);
        first.records.push(
            group(TICKET_REFRESH_GROUP, 1, br#"{"refresh_check_interval":22}"#)
                .records
                .remove(0),
        );
        let mut state = ConfigState::default();
        assert_eq!(
            apply(&mut state, group_reply(vec![first])).unwrap(),
            Some(11)
        );
        let mut cdn = group(TICKET_REFRESH_GROUP, 2, b"https://localhost.invalid/config");
        cdn.records[0].is_cdn = Some(true);
        assert_eq!(apply(&mut state, group_reply(vec![cdn])).unwrap(), None);
        let mut no_login = group(TICKET_REFRESH_GROUP, 3, br#"{"refresh_check_interval":22}"#);
        no_login.no_login = Some(true);
        assert_eq!(
            apply(&mut state, group_reply(vec![no_login])).unwrap(),
            None
        );
        assert_eq!(cached_ticket_refresh_interval(&state), None);
        assert_eq!(state.groups.len(), 2);
    }

    #[test]
    fn wire_record_metadata_retains_unsigned_widths_and_boolean_presence() {
        let record = pb::ConfigRecord::decode(
            b"\x0a\x02{}\x10\x00\x18\x02\x20\x01\x28\x00\x30\xff\xff\xff\xff\x0f".as_slice(),
        )
        .unwrap();
        assert_eq!(record.content.as_deref(), Some(b"{}".as_slice()));
        assert_eq!(record.compression, Some(0));
        assert_eq!(record.uncompressed_size, Some(2));
        assert_eq!(record.switch_on, Some(true));
        assert_eq!(record.is_cdn, Some(false));
        assert_eq!(record.metadata6, Some(u32::MAX));
    }

    #[test]
    fn numeric_group_fallback_and_duplicate_replacements_use_final_content() {
        let mut first = group(TICKET_REFRESH_GROUP, 1, br#"{"refresh_check_interval":11}"#);
        first.name = None;
        first.group_id = Some(107055);
        let mut state = ConfigState::default();
        assert_eq!(
            apply(&mut state, group_reply(vec![first])).unwrap(),
            Some(11)
        );
        assert_eq!(
            apply(
                &mut state,
                group_reply(vec![
                    group(TICKET_REFRESH_GROUP, 2, br#"{"refresh_check_interval":22}"#),
                    group(TICKET_REFRESH_GROUP, 3, b"{}"),
                ])
            )
            .unwrap(),
            Some(0)
        );
        assert_eq!(cached_ticket_refresh_interval(&state), Some(0));
        assert_eq!(state.groups.len(), 1);
    }
}
