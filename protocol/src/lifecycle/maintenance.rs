use crate::{
    Client, Error, Result,
    media::MediaDownloadKey,
    proto::{maintenance as pb, media as media_pb},
};
use bytes::Bytes;
use prost::Message;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use tokio::{sync::Notify, time::Instant};
use tokio_util::sync::CancellationToken;

const COMMAND: &str = "OidbSvcTrpcTcp.0x9067_202";
const KEY_TYPES: [u32; 4] = [10, 20, 34, 122];

#[derive(Clone)]
pub(crate) struct Binding(Arc<Identity>);
struct Identity {
    generation: u64,
    uin: u64,
    uid: String,
    cancel: CancellationToken,
}
struct CachedKey {
    value: MediaDownloadKey,
    expires: Instant,
}
struct State {
    binding: Binding,
    requested: bool,
    next: Option<Instant>,
    request_id: u64,
    keys: BTreeMap<(u32, u32), CachedKey>,
}
#[derive(Default)]
pub(crate) struct Session {
    state: Mutex<Option<State>>,
    fetch: tokio::sync::Mutex<()>,
    work: Notify,
}
impl Session {
    pub(crate) fn activate(
        &self,
        generation: u64,
        uin: u64,
        uid: &str,
        cancel: &CancellationToken,
    ) {
        let mut slot = self.state.lock().unwrap();
        if slot.as_ref().is_some_and(|state| {
            state.binding.0.generation == generation
                && state.binding.0.uin == uin
                && state.binding.0.uid == uid
                && !state.binding.0.cancel.is_cancelled()
        }) {
            return;
        }
        if let Some(old) = slot.take() {
            old.binding.0.cancel.cancel();
        }
        *slot = Some(State {
            binding: Binding(Arc::new(Identity {
                generation,
                uin,
                uid: uid.to_owned(),
                cancel: cancel.child_token(),
            })),
            requested: false,
            next: None,
            request_id: 0,
            keys: BTreeMap::new(),
        });
        self.work.notify_one();
    }
    pub(crate) fn close(&self, generation: u64) {
        let mut state = self.state.lock().unwrap();
        if state
            .as_ref()
            .is_some_and(|state| state.binding.0.generation == generation)
        {
            if let Some(old) = state.take() {
                old.binding.0.cancel.cancel();
            }
            self.work.notify_one();
        }
    }
    pub(crate) fn binding(&self, generation: u64, uin: u64, uid: &str) -> Result<Binding> {
        let state = self.state.lock().unwrap();
        let state = state.as_ref().ok_or(Error::Disconnected)?;
        let identity = &state.binding.0;
        if identity.generation != generation
            || identity.uin != uin
            || identity.uid != uid
            || identity.cancel.is_cancelled()
        {
            return Err(Error::Disconnected);
        }
        Ok(state.binding.clone())
    }
    fn with_state<T>(
        &self,
        binding: &Binding,
        f: impl FnOnce(&mut State) -> Result<T>,
    ) -> Result<T> {
        let mut state = self.state.lock().unwrap();
        let state = state.as_mut().ok_or(Error::Disconnected)?;
        if !Arc::ptr_eq(&state.binding.0, &binding.0) || binding.0.cancel.is_cancelled() {
            return Err(Error::Disconnected);
        }
        f(state)
    }
    fn key(
        &self,
        binding: &Binding,
        business_type: u32,
        store_id: u32,
        now: Instant,
    ) -> Result<Option<MediaDownloadKey>> {
        self.with_state(binding, |state| {
            Ok(state
                .keys
                .get(&(business_type, store_id))
                .filter(|key| key.expires > now)
                .map(|key| key.value.clone()))
        })
    }
    fn demand(&self, binding: &Binding) -> Result<()> {
        self.with_state(binding, |state| {
            state.requested = true;
            Ok(())
        })?;
        self.work.notify_one();
        Ok(())
    }
    fn schedule(&self, binding: &Binding) -> Result<Option<Instant>> {
        self.with_state(binding, |state| {
            Ok(state.requested.then_some(state.next).flatten())
        })
    }
    fn suspend(&self, binding: &Binding) {
        let _ = self.with_state(binding, |state| {
            state.requested = false;
            state.next = None;
            Ok(())
        });
    }
    fn request(
        &self,
        binding: &Binding,
        now: Instant,
        needed: Option<(u32, u32)>,
    ) -> Result<Option<Bytes>> {
        self.with_state(binding, |state| {
            if !state.requested {
                return Ok(None);
            }
            if let Some((business_type, store_id)) = needed {
                if state
                    .keys
                    .get(&(business_type, store_id))
                    .is_some_and(|key| key.expires > now)
                {
                    return Ok(None);
                }
            } else if state.next.is_some_and(|next| next > now) {
                return Ok(None);
            }
            state.request_id = state.request_id.wrapping_add(1).max(1);
            let body = pb::DownloadKeyRequest {
                head: Some(media_pb::MediaRequestHead {
                    common: Some(media_pb::MediaCommonRequestHead {
                        request_id: Some(state.request_id),
                        command: Some(202),
                    }),
                    scene: Some(media_pb::MediaSceneInfo {
                        request_type: Some(2),
                        business_type: Some(1),
                        reserved_103: Some(0),
                        scene_type: Some(0),
                        ..Default::default()
                    }),
                    client: Some(media_pb::MediaClientMeta {
                        agent_type: Some(2),
                    }),
                }),
                download: Some(pb::DownloadKeyTypes {
                    types: KEY_TYPES.to_vec(),
                    trigger: Some(if state.keys.is_empty() { 2 } else { 0 }),
                }),
            };
            Ok(Some(
                media_pb::MediaOidbEnvelope {
                    command: Some(0x9067),
                    service: Some(202),
                    body: Some(body.encode_to_vec().into()),
                    reserved: Some(1),
                    ..Default::default()
                }
                .encode_to_vec()
                .into(),
            ))
        })
    }
    fn apply(
        &self,
        binding: &Binding,
        keys: Vec<MediaDownloadKey>,
        server_now: u64,
        now: Instant,
    ) -> Result<()> {
        let mut incoming = BTreeMap::new();
        for value in keys {
            let expiration = value
                .expires_unix_seconds()
                .ok_or_else(|| Error::Malformed("Media key expiry overflow".into()))?;
            if value.parameter.is_empty() || value.ttl_seconds == 0 || expiration <= server_now {
                return Err(Error::Malformed("Media key is empty or expired".into()));
            }
            let expires = now
                .checked_add(Duration::from_secs(expiration - server_now))
                .ok_or_else(|| Error::Malformed("Media key deadline overflow".into()))?;
            let index = (value.business_type, value.store_id);
            if incoming
                .insert(index, CachedKey { value, expires })
                .is_some()
            {
                return Err(Error::Malformed(
                    "Duplicate media key type and store".into(),
                ));
            }
        }
        if incoming.is_empty() {
            return Err(Error::Malformed("Media key response omitted keys".into()));
        }
        self.with_state(binding, |state| {
            state.keys.retain(|_, key| key.expires > now);
            for (index, key) in incoming {
                if state.keys.get(&index).is_some_and(|old| {
                    old.value.expires_unix_seconds() > key.value.expires_unix_seconds()
                }) {
                    continue;
                }
                state.keys.insert(index, key);
            }
            state.next = state.keys.values().map(|key| key.expires).min();
            Ok(())
        })?;
        self.work.notify_one();
        Ok(())
    }
}

fn decode_response(response: Bytes) -> Result<Vec<MediaDownloadKey>> {
    let envelope: media_pb::MediaOidbEnvelope = crate::proto::decode(response)?;
    if envelope.command != Some(0x9067) || envelope.service != Some(202) {
        return Err(Error::Malformed(
            "Mismatched media key response command".into(),
        ));
    }
    let code = envelope.result.unwrap_or_default() as i32;
    if code != 0 {
        return Err(Error::Server {
            code,
            message: "Media download key request failed".into(),
        });
    }
    let response: pb::DownloadKeyResponse = crate::proto::decode(
        envelope
            .body
            .ok_or_else(|| Error::Malformed("Media key response omitted body".into()))?,
    )?;
    let code = response
        .head
        .ok_or_else(|| Error::Malformed("Media key response omitted head".into()))?
        .code
        .unwrap_or_default() as i32;
    if code != 0 {
        return Err(Error::Server {
            code,
            message: "Media download key response failed".into(),
        });
    }
    response
        .download
        .ok_or_else(|| Error::Malformed("Media key response omitted download result".into()))?
        .keys
        .into_iter()
        .map(|key| {
            Ok(MediaDownloadKey {
                business_type: key
                    .business_type
                    .ok_or_else(|| Error::Malformed("Media key omitted business type".into()))?,
                store_id: key
                    .store_id
                    .ok_or_else(|| Error::Malformed("Media key omitted store ID".into()))?,
                parameter: key
                    .parameter
                    .ok_or_else(|| Error::Malformed("Media key omitted parameter".into()))?,
                created_at: key
                    .created_at
                    .ok_or_else(|| Error::Malformed("Media key omitted creation time".into()))?,
                ttl_seconds: key
                    .ttl_seconds
                    .ok_or_else(|| Error::Malformed("Media key omitted TTL".into()))?,
            })
        })
        .collect()
}

async fn refresh(client: &Client, binding: &Binding, needed: Option<(u32, u32)>) -> Result<()> {
    let _fetch = tokio::select! {
        biased;
        _ = binding.0.cancel.cancelled() => return Err(Error::Disconnected),
        fetch = client.media_keys.fetch.lock() => fetch,
    };
    let current = client.media_download_key_binding()?;
    if !Arc::ptr_eq(&current.0, &binding.0) {
        return Err(Error::Disconnected);
    }
    let Some(body) = client.media_keys.request(binding, Instant::now(), needed)? else {
        return Ok(());
    };
    let result = async {
        let response = tokio::select! {
            biased;
            _ = binding.0.cancel.cancelled() => return Err(Error::Disconnected),
            response = client.request_online(binding.0.generation, COMMAND, body, client.config.timeout) => response?,
        };
        let keys = decode_response(response)?;
        let current = client.media_download_key_binding()?;
        if !Arc::ptr_eq(&current.0, &binding.0) {
            return Err(Error::Disconnected);
        }
        client.media_keys.apply(binding, keys, u64::from(client.server_time_seconds()?), Instant::now())
    }.await;
    if result.is_err() {
        client.media_keys.suspend(binding);
    }
    result
}

impl Client {
    pub async fn media_download_key(
        &self,
        business_type: u32,
        store_id: u32,
    ) -> Result<MediaDownloadKey> {
        if !KEY_TYPES.contains(&business_type) || store_id != 1 {
            return Err(Error::Unsupported(
                "Unsupported media key type or store".into(),
            ));
        }
        let binding = self.media_download_key_binding()?;
        self.media_keys.demand(&binding)?;
        if let Some(key) = self
            .media_keys
            .key(&binding, business_type, store_id, Instant::now())?
        {
            return Ok(key);
        }
        refresh(self, &binding, Some((business_type, store_id))).await?;
        self.media_keys
            .key(&binding, business_type, store_id, Instant::now())?
            .ok_or_else(|| {
                Error::Malformed("Media key response omitted requested type and store".into())
            })
    }
}

pub(super) async fn run(weak: Weak<Client>, generation: u64, cancel: CancellationToken) {
    let Some(client) = weak.upgrade() else { return };
    let session = client.media_keys.clone();
    drop(client);
    loop {
        let Some(client) = weak.upgrade() else { return };
        if !client.is_current_online(generation) {
            return;
        }
        let Ok(binding) = client.media_download_key_binding() else {
            return;
        };
        if binding.0.generation != generation {
            return;
        }
        drop(client);
        let Ok(next) = session.schedule(&binding) else {
            continue;
        };
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            _ = binding.0.cancel.cancelled() => continue,
            _ = session.work.notified() => {},
            _ = async {
                if let Some(next) = next {
                    tokio::time::sleep_until(next).await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {},
        }
        match session.schedule(&binding) {
            Ok(Some(deadline)) if deadline <= Instant::now() => {}
            Ok(_) => continue,
            Err(_) => continue,
        }
        let Some(client) = weak.upgrade() else { return };
        if !client.is_current_online(generation) {
            return;
        }
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            result = refresh(&client, &binding, None) => result,
        };
        if result.is_err() {
            if !client.is_current_online(generation) {
                return;
            }
            if binding.0.cancel.is_cancelled() {
                continue;
            }
            tracing::warn!(
                command = COMMAND,
                "Media key refresh failed; awaiting media demand"
            );
        }
        drop(client);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(generation: u64) -> (Session, Binding) {
        let session = Session::default();
        session.activate(generation, 1, "test-account", &CancellationToken::new());
        let binding = session.binding(generation, 1, "test-account").unwrap();
        (session, binding)
    }
    fn key(
        business_type: u32,
        store_id: u32,
        created_at: u32,
        ttl_seconds: u64,
        parameter: &str,
    ) -> MediaDownloadKey {
        MediaDownloadKey {
            business_type,
            store_id,
            parameter: parameter.into(),
            created_at,
            ttl_seconds,
        }
    }
    fn response(keys: Vec<MediaDownloadKey>) -> Bytes {
        media_pb::MediaOidbEnvelope {
            command: Some(0x9067),
            service: Some(202),
            result: Some(0),
            body: Some(
                pb::DownloadKeyResponse {
                    head: Some(media_pb::MediaRichResponseHead {
                        code: Some(0),
                        message: None,
                    }),
                    download: Some(pb::DownloadKeyResult {
                        keys: keys
                            .into_iter()
                            .map(|key| pb::DownloadKey {
                                parameter: Some(key.parameter),
                                ttl_seconds: Some(key.ttl_seconds),
                                store_id: Some(key.store_id),
                                created_at: Some(key.created_at),
                                business_type: Some(key.business_type),
                            })
                            .collect(),
                    }),
                }
                .encode_to_vec()
                .into(),
            ),
            ..Default::default()
        }
        .encode_to_vec()
        .into()
    }
    #[test]
    fn unused_media_does_not_request_and_demand_builds_typed_request() {
        let (session, binding) = session(1);
        let now = Instant::now();
        assert!(session.request(&binding, now, None).unwrap().is_none());
        session.demand(&binding).unwrap();
        let envelope: media_pb::MediaOidbEnvelope =
            crate::proto::decode(session.request(&binding, now, None).unwrap().unwrap()).unwrap();
        assert_eq!(envelope.command, Some(0x9067));
        assert_eq!(envelope.service, Some(202));
        assert_eq!(envelope.reserved, Some(1));
        let request: pb::DownloadKeyRequest = crate::proto::decode(envelope.body.unwrap()).unwrap();
        assert_eq!(request.head.unwrap().scene.unwrap().scene_type, Some(0));
        let download = request.download.unwrap();
        assert_eq!(download.types, KEY_TYPES);
        assert_eq!(download.trigger, Some(2));
    }
    #[test]
    fn response_consumers_use_type_store_and_server_expiry() {
        let (session, binding) = session(1);
        let now = Instant::now();
        session.demand(&binding).unwrap();
        let keys = decode_response(response(vec![
            key(10, 1, 100, 3420, "&rkey=direct"),
            key(20, 1, 100, 3600, "&rkey=group"),
        ]))
        .unwrap();
        session.apply(&binding, keys, 120, now).unwrap();
        assert_eq!(
            session
                .key(&binding, 10, 1, now)
                .unwrap()
                .unwrap()
                .parameter,
            "&rkey=direct"
        );
        assert!(session.key(&binding, 10, 2, now).unwrap().is_none());
        assert_eq!(
            session.schedule(&binding).unwrap(),
            Some(now + Duration::from_secs(3400))
        );
        assert!(
            session
                .key(&binding, 10, 1, now + Duration::from_secs(3400))
                .unwrap()
                .is_none()
        );
        assert!(
            session
                .key(&binding, 20, 1, now + Duration::from_secs(3400))
                .unwrap()
                .is_some()
        );
        assert!(
            session
                .request(&binding, now + Duration::from_secs(3399), None)
                .unwrap()
                .is_none()
        );
        let request: media_pb::MediaOidbEnvelope = crate::proto::decode(
            session
                .request(&binding, now + Duration::from_secs(3400), None)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let request: pb::DownloadKeyRequest = crate::proto::decode(request.body.unwrap()).unwrap();
        assert_eq!(request.download.unwrap().trigger, Some(0));
    }
    #[test]
    fn malformed_batch_does_not_replace_valid_keys() {
        let (session, binding) = session(1);
        let now = Instant::now();
        session
            .apply(
                &binding,
                vec![key(10, 1, 100, 500, "&rkey=valid")],
                100,
                now,
            )
            .unwrap();
        assert!(
            session
                .apply(
                    &binding,
                    vec![key(10, 1, 100, 1000, "&rkey=new"), key(20, 1, 100, 0, "")],
                    100,
                    now
                )
                .is_err()
        );
        assert_eq!(
            session
                .key(&binding, 10, 1, now)
                .unwrap()
                .unwrap()
                .parameter,
            "&rkey=valid"
        );
        assert_eq!(
            session
                .key(&binding, 10, 1, now)
                .unwrap()
                .unwrap()
                .ttl_seconds,
            500
        );
        assert!(
            session
                .apply(&binding, vec![key(20, 1, 1, 2, "&rkey=expired")], 100, now)
                .is_err()
        );
    }
    #[test]
    fn later_expiring_cached_key_wins_over_older_response() {
        let (session, binding) = session(1);
        let now = Instant::now();
        session
            .apply(
                &binding,
                vec![key(10, 1, 100, 1000, "&rkey=newer")],
                100,
                now,
            )
            .unwrap();
        session
            .apply(
                &binding,
                vec![key(10, 1, 100, 500, "&rkey=older")],
                100,
                now,
            )
            .unwrap();
        assert_eq!(
            session
                .key(&binding, 10, 1, now)
                .unwrap()
                .unwrap()
                .parameter,
            "&rkey=newer"
        );
    }
    #[test]
    fn replacement_account_and_generation_reject_old_replies() {
        let (session, old) = session(1);
        let now = Instant::now();
        session.activate(2, 2, "other-account", &CancellationToken::new());
        assert!(old.0.cancel.is_cancelled());
        assert!(matches!(
            session.apply(&old, vec![key(10, 1, 100, 100, "&rkey=old")], 100, now),
            Err(Error::Disconnected)
        ));
        let current = session.binding(2, 2, "other-account").unwrap();
        session.close(1);
        assert!(!current.0.cancel.is_cancelled());
        assert!(session.key(&current, 10, 1, now).unwrap().is_none());
        session.activate(
            2,
            3,
            "same-generation-new-account",
            &CancellationToken::new(),
        );
        assert!(current.0.cancel.is_cancelled());
        assert!(session.binding(2, 2, "other-account").is_err());
    }
    #[test]
    fn cancelled_session_cannot_consume_or_commit_keys() {
        let (session, binding) = session(1);
        binding.0.cancel.cancel();
        assert!(matches!(session.demand(&binding), Err(Error::Disconnected)));
        assert!(matches!(
            session.key(&binding, 10, 1, Instant::now()),
            Err(Error::Disconnected)
        ));
    }
    #[test]
    fn failed_refresh_waits_for_real_demand_without_retrying() {
        let (session, binding) = session(1);
        session.demand(&binding).unwrap();
        session.suspend(&binding);
        assert!(
            session
                .request(&binding, Instant::now(), None)
                .unwrap()
                .is_none()
        );
        session.demand(&binding).unwrap();
        assert!(
            session
                .request(&binding, Instant::now(), None)
                .unwrap()
                .is_some()
        );
    }
}
