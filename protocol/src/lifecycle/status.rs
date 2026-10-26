use crate::{
    Client, Error, Result,
    contacts::{FriendStatus, FriendStatusSnapshot, check_code, required},
    proto::{contacts::OidbEnvelope, status as pb},
};
use bytes::Bytes;
use prost::Message;
use std::{
    collections::BTreeMap,
    sync::{Arc, Weak},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

pub(crate) const COMMAND: &str = "OidbSvcTrpcTcp.0x116d_1";
const INTERVAL: Duration = Duration::from_secs(1800);

pub(crate) struct Binding {
    pub(crate) generation: u64,
    pub(crate) uin: u64,
    pub(crate) uid: String,
    pub(crate) cancel: CancellationToken,
}

#[derive(Default)]
pub(crate) struct Cache {
    pub(crate) binding: Option<Arc<Binding>>,
    pub(crate) snapshot: Option<Arc<FriendStatusSnapshot>>,
}

impl Cache {
    pub(crate) fn clear(&mut self) {
        if let Some(binding) = self.binding.take() {
            binding.cancel.cancel();
        }
        self.snapshot = None;
    }

    pub(crate) fn is_current(&self, binding: &Arc<Binding>) -> bool {
        !binding.cancel.is_cancelled()
            && self.binding.as_ref().is_some_and(|current| Arc::ptr_eq(current, binding))
    }
}

pub(crate) fn build(uid: &str, start_index: u32, has_local: bool) -> Bytes {
    OidbEnvelope {
        command: Some(0x116d),
        service: Some(1),
        body: Some(pb::FriendStatusRequest {
            self_uid: Some(uid.to_owned()),
            field5: Some(1),
            field7: Some(0),
            field8: Some(1),
            social_style: Some(0),
            social_switch: Some(0),
            has_local: has_local.then_some(1),
            start_index: Some(start_index),
            count: Some(400),
        }.encode_to_vec().into()),
        reserved: Some(0),
        ..Default::default()
    }.encode_to_vec().into()
}

fn decode(bytes: Bytes, uid: &str) -> Result<pb::FriendStatusResponse> {
    let envelope: OidbEnvelope = crate::diagnostics::decode_response(COMMAND, bytes)?;
    check_code(envelope.code, envelope.message)?;
    if envelope.command.is_some_and(|command| command != 0x116d)
        || envelope.service.is_some_and(|service| service != 1)
    {
        return Err(Error::Malformed("Unexpected friend status OIDB envelope".into()));
    }
    let body = required(envelope.body, "friend status response body")?;
    let response: pb::FriendStatusResponse = crate::diagnostics::decode_response(COMMAND, body)?;
    if response.self_uid.as_deref().is_some_and(|value| value != uid) {
        return Err(Error::Authentication("Friend status response belongs to another account".into()));
    }
    Ok(response)
}

fn append(statuses: &mut BTreeMap<String, FriendStatus>, records: Vec<pb::FriendOnlineInfo>) -> Result<()> {
    for record in records {
        let uid = record.uid.filter(|uid| !uid.is_empty())
            .or_else(|| record.fallback_uid.filter(|uid| !uid.is_empty()))
            .ok_or_else(|| Error::Malformed("Friend status record has no UID".into()))?;
        statuses.insert(uid, FriendStatus {
            status: record.status_override.or(record.status),
            reported_status: record.status,
            extended_status: record.extended_status,
            battery_status: record.battery_status,
            terminal_type: record.terminal_type,
            network_type: record.network_type,
        });
    }
    Ok(())
}

fn next_start(response: &pb::FriendStatusResponse, previous: u32) -> Result<Option<u32>> {
    if required(response.over, "friend status completion flag")? != 0 {
        return Ok(None);
    }
    let next = required(response.next_start, "friend status next index")?;
    if next <= previous {
        return Err(Error::Malformed("Friend status pagination did not advance".into()));
    }
    Ok(Some(next))
}

pub(crate) async fn fetch(client: &Client, binding: &Arc<Binding>, has_local: bool) -> Result<Arc<FriendStatusSnapshot>> {
    let mut statuses = BTreeMap::new();
    let mut start = 0;
    let mut interval_minutes = None;
    loop {
        let bytes = tokio::select! {
            biased;
            _ = binding.cancel.cancelled() => return Err(Error::Disconnected),
            response = client.request_friend_status(binding, build(&binding.uid, start, has_local)) => response?,
        };
        let response = decode(bytes, &binding.uid)?;
        let next = next_start(&response, start)?;
        interval_minutes = response.interval_minutes.or(interval_minutes);
        append(&mut statuses, response.online_info)?;
        match next {
            Some(next) => start = next,
            None => break,
        }
    }
    let snapshot = Arc::new(FriendStatusSnapshot {
        statuses,
        interval_minutes,
        received_unix_ms: SystemTime::now().duration_since(UNIX_EPOCH)
            .unwrap_or_default().as_millis().try_into().unwrap_or(u64::MAX),
    });
    client.commit_friend_statuses(binding, snapshot.clone())?;
    Ok(snapshot)
}

pub(crate) async fn run(weak: Weak<Client>, generation: u64, cancel: CancellationToken) {
    let mut next = Instant::now();
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
            result = client.fetch_friend_statuses_generation(generation) => result,
        };
        if !client.is_current_online(generation) {
            return;
        }
        let interval = match result {
            Ok(snapshot) => snapshot.interval_minutes.filter(|minutes| *minutes != 0)
                .map(|minutes| Duration::from_secs(u64::from(minutes) * 60))
                .unwrap_or(INTERVAL),
            Err(error) => {
                tracing::warn!(%error, "QQ friend status poll failed; retaining cached statuses and normal cadence");
                INTERVAL
            }
        };
        next = Instant::now() + interval;
        drop(client);
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn native_mapping_keeps_unknown_and_absent_values() {
        let mut statuses = BTreeMap::new();
        append(&mut statuses, vec![pb::FriendOnlineInfo {
            uid: Some("u_synthetic".into()),
            status: Some(10),
            status_override: Some(11),
            extended_status: Some(876543),
            terminal_type: Some(1),
            network_type: Some(5),
            battery_status: Some(83714),
            ..Default::default()
        }, pb::FriendOnlineInfo {
            fallback_uid: Some("u_fallback".into()),
            ..Default::default()
        }]).unwrap();
        let status = &statuses["u_synthetic"];
        assert_eq!(status.status, Some(11));
        assert_eq!(status.reported_status, Some(10));
        assert_eq!(status.extended_status, Some(876543));
        assert_eq!(status.battery_status, Some(83714));
        assert_eq!(statuses["u_fallback"].status, None);
    }

    #[test]
    fn completion_and_pagination_are_explicit() {
        let mut response = pb::FriendStatusResponse::default();
        assert!(next_start(&response, 0).is_err());
        response.over = Some(0);
        response.next_start = Some(400);
        assert_eq!(next_start(&response, 0).unwrap(), Some(400));
        assert!(next_start(&response, 400).is_err());
        response.over = Some(1);
        assert_eq!(next_start(&response, 400).unwrap(), None);
    }

    #[test]
    fn envelope_errors_and_identity_are_not_success() {
        let error = OidbEnvelope { code: Some(17), ..Default::default() };
        assert!(matches!(decode(error.encode_to_vec().into(), "u_self"), Err(Error::Server { code: 17, .. })));
        let envelope = OidbEnvelope {
            body: Some(pb::FriendStatusResponse { self_uid: Some("u_other".into()), ..Default::default() }.encode_to_vec().into()),
            ..Default::default()
        };
        assert!(matches!(decode(envelope.encode_to_vec().into(), "u_self"), Err(Error::Authentication(_))));
    }
}
