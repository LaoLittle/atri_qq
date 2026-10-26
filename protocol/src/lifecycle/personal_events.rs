use crate::{
    Client, Error, Result,
    contacts::{check_code, required},
    personal_events::{Decoded, GroupEvents, MessageBoxEvent, Source},
    proto::{contacts::OidbEnvelope, personal_events as pb},
};
use bytes::Bytes;
use prost::Message;
use std::sync::{Arc, Weak};
use tokio_util::sync::CancellationToken;

pub(crate) const COMMAND: &str = "OidbSvcTrpcTcp.0x1092_0";
const NO_EVENTS: u64 = 0x61ae4;

pub(crate) fn build(cursor: Option<Bytes>) -> Bytes {
    OidbEnvelope {
        command: Some(0x1092),
        service: Some(0),
        body: Some(
            pb::PersonalEventsRequest {
                cursor: Some(cursor.unwrap_or_default()),
            }
            .encode_to_vec()
            .into(),
        ),
        reserved: Some(0),
        ..Default::default()
    }
    .encode_to_vec()
    .into()
}

pub(crate) fn decode(bytes: Bytes) -> Result<Decoded> {
    let envelope: OidbEnvelope = crate::diagnostics::decode_response(COMMAND, bytes)?;
    check_code(envelope.code, envelope.message)?;
    if envelope.command.is_some_and(|command| command != 0x1092)
        || envelope.service.is_some_and(|service| service != 0)
    {
        return Err(Error::Malformed(
            "Unexpected personal event OIDB envelope".into(),
        ));
    }
    let body = required(envelope.body, "personal event response body")?;
    if body.is_empty() {
        return Err(Error::Malformed(
            "Empty personal event response body".into(),
        ));
    }
    let response: pb::PersonalEventsResponse =
        crate::diagnostics::decode_response(COMMAND, body.clone())?;
    let result = response.result.unwrap_or_default();
    if result != 0 && result != NO_EVENTS {
        return Err(Error::Server {
            code: result as i32,
            message: String::from_utf8_lossy(response.error_message.as_deref().unwrap_or_default())
                .into_owned(),
        });
    }
    let mut groups = Vec::with_capacity(response.groups.len());
    for raw_group in response.groups {
        let group: pb::PersonalEventGroup = crate::proto::decode(raw_group.clone())?;
        let group_uin = required(group.group_uin, "personal event group UIN")?;
        let mut events = Vec::with_capacity(group.events.len());
        for raw in group.events {
            let record: pb::PersonalEventRecord = crate::proto::decode(raw.clone())?;
            events.push(Arc::new(MessageBoxEvent {
                source: Source::FirstViewPersonalEvents,
                event_type: record.event_type,
                message_seq: record.message_seq,
                field_3: record.field_3,
                field_4: record.field_4,
                field_5: record.field_5,
                raw,
            }));
        }
        groups.push(GroupEvents {
            group_uin,
            events,
            raw: raw_group,
        });
    }
    Ok(Decoded {
        cursor: response.cursor,
        groups,
        raw_response: body,
    })
}

pub(crate) async fn run(weak: Weak<Client>, generation: u64, cancel: CancellationToken) {
    let mut changes = {
        let Some(client) = weak.upgrade() else { return };
        client.message_sync_changes()
    };
    loop {
        {
            let Some(client) = weak.upgrade() else { return };
            if cancel.is_cancelled() || !client.is_current_online(generation) {
                return;
            }
            if client.message_sync_snapshot().first_view_complete {
                let result = client
                    .sync_personal_events_generation(generation, &cancel)
                    .await;
                if let Err(error) = result {
                    if !cancel.is_cancelled() && client.is_current_online(generation) {
                        tracing::warn!(%error, "QQ personal event sync failed; retaining message boxes and cursor");
                    }
                }
                return;
            }
        }
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            changed = changes.changed() => if changed.is_err() { return },
        }
    }
}

#[cfg(test)]
mod tests;
