use super::*;
use crate::proto::messages as wire;
use prost::Message as ProstMessage;
use std::collections::BTreeMap;
impl Messaging {
    /// Unknown commands, unknown event subtypes, and malformed payloads remain observable verbatim.
    pub async fn decode_push(&self, packet: IncomingPacket) -> Vec<PushEvent> {
        match self.decode_push_inner(&packet).await {
            Ok(events) => {
                if events.iter().any(|event| {
                    matches!(
                        event,
                        PushEvent::Opaque {
                            message_type: Some(528),
                            sub_type: Some(138 | 139),
                            ..
                        } | PushEvent::Opaque {
                            message_type: Some(732),
                            sub_type: Some(17),
                            ..
                        }
                    )
                }) {
                    tracing::warn!(packet = ?packet, raw_hex = %hex::encode(&packet.body), "unhandled QQ recall push");
                }
                events
            }
            Err(error) => {
                tracing::warn!(?error, packet = ?packet, raw_hex = %hex::encode(&packet.body), "decode QQ push failed");
                vec![opaque(&packet, None, None)]
            }
        }
    }
    async fn decode_push_inner(&self, packet: &IncomingPacket) -> Result<Vec<PushEvent>> {
        if packet.command != "trpc.msg.olpush.OlPushService.MsgPush" {
            return Ok(vec![opaque(packet, None, None)]);
        }
        let push = decode::<wire::MessagePush>(&packet.body)?;
        let common = decode::<wire::CommonMessage>(&push.common_message)?;
        let head = common
            .content_head
            .as_ref()
            .ok_or_else(|| missing("content head"))?;
        let routing = common
            .routing_head
            .as_ref()
            .ok_or_else(|| missing("routing head"))?;
        let kind = head.message_type.unwrap_or_default();
        let sub = head.sub_type.unwrap_or_default();
        let state = self.client.snapshot().await;
        if matches!(kind, 82 | 166 | 141) {
            let message = self.parse_message(&push.common_message, &state)?;
            // Content-free records are transport notifications, not user messages.
            // Unknown or encrypted content remains an element and stays observable.
            if message.elements.is_empty() {
                return Ok(vec![opaque(packet, Some(kind), head.sub_type)]);
            }
            for element in &message.elements {
                if let MessageElement::LightApp(json) = element {
                    if let Ok(root) = serde_json::from_str::<serde_json::Value>(json) {
                        if root.get("app").and_then(|v| v.as_str())
                            == Some("com.tencent.qun.invite")
                            && root.get("bizsrc").and_then(|v| v.as_str()) == Some("qun.invite")
                        {
                            if let Some(url) = root
                                .pointer("/meta/news/jumpUrl")
                                .and_then(|v| v.as_str())
                                .and_then(|v| reqwest::Url::parse(v).ok())
                            {
                                if let Some(group) = url
                                    .query_pairs()
                                    .find(|(key, _)| key == "groupcode")
                                    .and_then(|(_, value)| value.parse::<u64>().ok())
                                {
                                    return Ok(vec![PushEvent::GroupInvitation {
                                        group_uin: group,
                                        target_uid: state.keystore.uid,
                                        inviter_uid: message.sender_uid.clone(),
                                        raw: push.common_message.to_vec(),
                                    }]);
                                }
                            }
                        }
                    }
                }
            }
            return Ok(vec![PushEvent::Message { message }]);
        }
        let body = decode::<wire::MessageBody>(&common.message_body)?;
        let Some(content) = body.content else {
            return Ok(vec![opaque(packet, Some(kind), Some(sub))]);
        };
        match kind {
            33 | 34 => {
                let change = decode::<wire::MembershipPush>(&content)?;
                let change_type = change.change_type;
                let member_uid = change.member_uid;
                let operator_uid = if let Some(operator) = change.operator {
                    if kind == 33 {
                        std::str::from_utf8(&operator).ok().map(str::to_owned)
                    } else if matches!(change_type, 3 | 131) {
                        decode::<wire::MembershipOperator>(&operator)?
                            .identity
                            .and_then(|identity| identity.uid)
                    } else {
                        None
                    }
                } else {
                    None
                };
                return Ok(vec![PushEvent::Membership {
                    group_uin: change.group_uin,
                    is_self: !member_uid.is_empty() && member_uid == state.keystore.uid,
                    member_uid,
                    operator_uid,
                    joined: kind == 33,
                    change_type,
                }]);
            }
            84 => {
                let join = decode::<wire::GroupJoinRequestPush>(&content)?;
                return Ok(vec![PushEvent::GroupJoinRequest {
                    group_uin: join.group_uin,
                    target_uid: join.target_uid,
                    request_type: join.request_type,
                    comment: join.comment,
                    raw: content.to_vec(),
                }]);
            }
            525 => {
                let event = decode::<wire::InvitationPush>(&content)?;
                if event.r#type == 87 {
                    if let Some(info) = event.body.and_then(|body| body.info) {
                        return Ok(vec![PushEvent::GroupInvitation {
                            group_uin: info.group_uin,
                            target_uid: info.target_uid,
                            inviter_uid: info.inviter_uid,
                            raw: content.to_vec(),
                        }]);
                    }
                }
            }
            528 => {
                // Direct gray-tip content is GeneralGrayTipInfo itself, not
                // the prefixed GroupNotificationPush used by group nudges.
                if matches!(sub, 290 | 291) {
                    let gray = decode::<wire::GrayTipPush>(&content)?;
                    let parameters: BTreeMap<_, _> = gray
                        .parameters
                        .into_iter()
                        .filter_map(|param| param.key.map(|key| (key, param.value)))
                        .collect();
                    if let Some(actor_uin) = parameters
                        .get("uin_str1")
                        .and_then(|value| value.parse::<u64>().ok())
                        .filter(|uin| *uin != 0)
                    {
                        return Ok(vec![PushEvent::Poke {
                            group_uin: None,
                            actor_uin: Some(actor_uin),
                            target_uin: parameters
                                .get("uin_str2")
                                .and_then(|value| value.parse().ok())
                                .filter(|uin| *uin != 0),
                            parameters,
                            raw: content.to_vec(),
                        }]);
                    }
                }
                if matches!(sub, 138 | 139) {
                    let recall = decode::<wire::DirectRecallPush>(&content)?;
                    let info = recall.info.ok_or_else(|| missing("direct recall info"))?;
                    let from = info.sender_uid;
                    let to = info.recipient_uid;
                    let peer = if from == state.keystore.uid {
                        to
                    } else {
                        from.clone()
                    };
                    if peer.is_empty() {
                        return Err(Error::Malformed("Direct recall lacks peer UID".into()));
                    }
                    let peer_uin = if peer == routing.sender_uid {
                        routing.sender_uin.unwrap_or_default()
                    } else if peer == routing.recipient_uid {
                        routing.recipient_uin.unwrap_or_default()
                    } else {
                        0
                    };
                    return Ok(vec![PushEvent::Recall {
                        conversation: Conversation::Friend {
                            uin: peer_uin,
                            uid: peer,
                        },
                        sequence: info.sequence,
                        random: info.random.or_else(|| info.message_id.map(|id| id as u32)),
                        time: None,
                        author_uid: from.clone(),
                        operator_uid: Some(from),
                        tip: info.tip.map(|tip| tip.text).unwrap_or_default(),
                    }]);
                }
                if sub == 35 {
                    let request = decode::<wire::FriendRequestPush>(&content)?;
                    if !request.requests.is_empty() {
                        return Ok(request
                            .requests
                            .into_iter()
                            .map(|info| PushEvent::FriendRequest {
                                source_uid: info.source_uid,
                                source_uin: routing.sender_uin.unwrap_or_default(),
                                target_uid: info.target_uid,
                                message: info.message,
                                source: info.source,
                                raw: content.to_vec(),
                            })
                            .collect());
                    }
                }
            }
            732 if matches!(sub, 16 | 17 | 20) => {
                let (notify, prefixed_group, bytes) = group_notification(&content)?;
                let group = notify
                    .group_uin
                    .filter(|group| *group != 0)
                    .unwrap_or(prefixed_group);
                if group == 0 {
                    return Err(Error::Malformed(
                        "Group notification lacks group UIN".into(),
                    ));
                }
                if sub == 17 {
                    if let Some(recall) = notify.recall {
                        if recall.messages.is_empty() {
                            return Err(Error::Malformed(
                                "Group recall has no message identities".into(),
                            ));
                        }
                        let tip = recall.tip.map(|tip| tip.text).unwrap_or_default();
                        return Ok(recall
                            .messages
                            .into_iter()
                            .map(|message| PushEvent::Recall {
                                conversation: Conversation::Group { uin: group },
                                sequence: message.sequence,
                                random: Some(message.random),
                                time: Some(message.time),
                                author_uid: message.author_uid,
                                operator_uid: recall.operator_uid.clone(),
                                tip: tip.clone(),
                            })
                            .collect());
                    }
                }
                if sub == 20 && notify.r#type == 19 {
                    if let Some(gray) = notify.gray_tip.filter(|gray| gray.r#type == 12) {
                        let mut parameters = BTreeMap::new();
                        for param in gray.parameters {
                            if let Some(key) = param.key {
                                parameters.insert(key, param.value);
                            }
                        }
                        return Ok(vec![PushEvent::Poke {
                            group_uin: Some(group),
                            actor_uin: parameters.get("uin_str1").and_then(|v| v.parse().ok()),
                            target_uin: parameters.get("uin_str2").and_then(|v| v.parse().ok()),
                            parameters,
                            raw: bytes.to_vec(),
                        }]);
                    }
                }
                if sub == 16 && notify.r#type == 35 {
                    if let Some(level2) = notify
                        .reaction
                        .and_then(|outer| outer.body)
                        .and_then(|level1| level1.body)
                    {
                        if let (Some(target), Some(reaction)) = (level2.target, level2.reaction) {
                            if matches!(reaction.operation, 1 | 2) {
                                return Ok(vec![PushEvent::Reaction {
                                    group_uin: group,
                                    sequence: target.sequence,
                                    operator_uid: reaction.operator_uid,
                                    added: reaction.operation == 1,
                                    code: reaction.code,
                                    count: reaction.count,
                                }]);
                            }
                        }
                    }
                }
                if let Some(essence) = notify
                    .essence
                    .filter(|essence| matches!(essence.operation, 1 | 2))
                {
                    return Ok(vec![PushEvent::Essence {
                        group_uin: essence.group_uin.unwrap_or(group),
                        sequence: essence.sequence,
                        random: essence.random,
                        enabled: essence.operation == 1,
                        author_uin: essence.author_uin,
                        operator_uin: essence.operator_uin,
                        time: essence.time,
                    }]);
                }
            }
            _ => {}
        }
        Ok(vec![opaque(packet, Some(kind), Some(sub))])
    }
}
fn group_notification(content: &[u8]) -> Result<(wire::GroupNotificationPush, u64, &[u8])> {
    if let Ok(notify) = decode::<wire::GroupNotificationPush>(content)
        && notify.group_uin.is_some()
        && notify.recall.is_some()
    {
        return Ok((notify, 0, content));
    }
    if content.len() >= 7 {
        let group = u32::from_be_bytes(content[..4].try_into().unwrap()) as u64;
        let length = u16::from_be_bytes(content[5..7].try_into().unwrap()) as usize;
        if length > 0
            && let Some(bytes) = content.get(7..7 + length)
        {
            return Ok((decode(bytes)?, group, bytes));
        }
    }
    let notify: wire::GroupNotificationPush = decode(content)?;
    if notify.group_uin.is_none() || notify.recall.is_none() {
        return Err(Error::Malformed(
            "Truncated or unsupported group notification".into(),
        ));
    }
    Ok((notify, 0, content))
}
fn opaque(packet: &IncomingPacket, message_type: Option<u64>, sub_type: Option<u64>) -> PushEvent {
    PushEvent::Opaque {
        command: packet.command.clone(),
        message_type,
        sub_type,
        payload: packet.body.to_vec(),
    }
}

fn decode<M: ProstMessage + Default>(bytes: &[u8]) -> Result<M> {
    M::decode(bytes).map_err(|error| Error::Malformed(error.to_string()))
}

fn missing(field: &str) -> Error {
    Error::Malformed(format!("Push lacks {field}"))
}
