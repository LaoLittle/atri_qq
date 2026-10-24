mod codec;
mod models;
mod push;
#[cfg(test)]
mod tests;
use crate::media::{Media, MediaReference, to_cbor};
use crate::models::{Encryption, IncomingPacket, RequestType, SessionState};
use crate::proto::messages as rpc;
use crate::{Error, Result, ServiceClient};
pub use codec::{decode_elements, encode_elements, is_protocol_metadata, validate_metadata};
pub use models::*;
use prost::Message as ProstMessage;
use serde::{Deserialize, de::DeserializeOwned};
use std::{sync::Arc, time::Duration};

pub const MESSAGE_METHODS: &[&str] = &[
    "send",
    "history_c2c",
    "history_group",
    "roam",
    "recall",
    "set_essence",
    "upload_forward",
    "download_forward",
];
pub struct Messaging {
    client: Arc<dyn ServiceClient>,
    media: Arc<Media>,
}
impl Messaging {
    pub fn new(client: Arc<dyn ServiceClient>, media: Arc<Media>) -> Self {
        Self { client, media }
    }
    async fn request<M: ProstMessage, R: ProstMessage + Default + prost::Name + std::fmt::Debug>(
        &self,
        command: &str,
        body: M,
    ) -> Result<R> {
        let bytes = self
            .client
            .request(
                command,
                body.encode_to_vec().into(),
                RequestType::D2,
                Encryption::D2,
                Duration::from_secs(60),
            )
            .await?;
        crate::diagnostics::decode_response(command, bytes)
    }
    pub async fn send(
        &self,
        conversation: Conversation,
        elements: Vec<MessageElement>,
    ) -> Result<Message> {
        self.send_with_nonce(conversation, elements, rand::random::<u32>() & 0x7fff_ffff)
            .await
    }
    pub async fn send_with_nonce(
        &self,
        conversation: Conversation,
        elements: Vec<MessageElement>,
        random: u32,
    ) -> Result<Message> {
        if elements.is_empty() {
            return Err(Error::Malformed("Cannot send an empty message".into()));
        }
        let media_conversation = conversation.media_conversation()?;
        let (recipient_uin, recipient_uid, route) = match &conversation {
            Conversation::Friend { uin, uid } => {
                if uid.is_empty() {
                    return Err(Error::Malformed("Friend send requires peer UID".into()));
                }
                (
                    *uin,
                    uid.clone(),
                    rpc::SendRoute {
                        friend: Some(rpc::SendPeer {
                            uin: None,
                            uid: uid.clone(),
                        }),
                        group: None,
                    },
                )
            }
            Conversation::Group { uin } => {
                if *uin == 0 {
                    return Err(Error::Malformed("Invalid group UIN".into()));
                }
                (
                    0,
                    String::new(),
                    rpc::SendRoute {
                        friend: None,
                        group: Some(rpc::SendGroup { uin: *uin }),
                    },
                )
            }
            Conversation::Temporary { .. } => unreachable!(),
        };
        for element in &elements {
            match element {
                MessageElement::Image(r)
                | MessageElement::Voice(r)
                | MessageElement::Video(r)
                | MessageElement::File(r) => {
                    if r.conversation != media_conversation {
                        return Err(Error::Malformed(
                            "Media upload belongs to another conversation".into(),
                        ));
                    }
                }
                _ => {}
            }
        }
        let state = self.client.snapshot().await;
        if let [MessageElement::File(reference)] = elements.as_slice() {
            return self
                .send_file_message(reference.clone(), conversation, &state)
                .await;
        }
        let body = encode_elements(&elements, &[])?;
        let client_sequence = 10_000 + rand::random::<u64>() % 89_999;
        let request = rpc::SendMessageRequest {
            route: Some(route),
            head: Some(rpc::SendContentHead {
                package_count: Some(1),
                package_index: Some(0),
                division_sequence: Some(0),
                auto_reply: None,
            }),
            body: body.into(),
            client_sequence,
            random: Some(random as u64),
        };
        let response: rpc::SendMessageResponse =
            self.request("MessageSvc.PbSendMsg", request).await?;
        check_result(response.code, response.error.as_deref())?;
        let sequence = if matches!(conversation, Conversation::Group { .. }) {
            response.sequence.or(response.client_sequence)
        } else {
            response
                .client_sequence
                .filter(|sequence| *sequence != 0)
                .or(response.sequence)
        }
        .unwrap_or_default();
        Ok(Message {
            conversation,
            sender_uin: state.keystore.uin,
            sender_uid: state.keystore.uid,
            recipient_uin,
            recipient_uid,
            sender_name: String::new(),
            sequence,
            client_sequence,
            message_id: (0x10000000u64 << 32) | random as u64,
            random,
            time: response.time.unwrap_or_default() as i64,
            is_self: true,
            is_bot: Some(true),
            elements,
            metadata: vec![],
            raw: vec![],
        })
    }
    async fn send_file_message(
        &self,
        reference: MediaReference,
        conversation: Conversation,
        state: &SessionState,
    ) -> Result<Message> {
        // Subscribe before sending; an echo can arrive while the OIDB acknowledgement is in flight.
        let mut packets = self.client.subscribe();
        let receipt = self.media.send_file(&reference).await?;
        if let Conversation::Friend { uin, uid } = &conversation {
            // This service has no message UID in its acknowledgement. Zero means absent; it is
            // intentionally not fabricated from the random nonce. Recall uses the real ack fields.
            return Ok(Message {
                conversation: conversation.clone(),
                sender_uin: state.keystore.uin,
                sender_uid: state.keystore.uid.clone(),
                recipient_uin: *uin,
                recipient_uid: uid.clone(),
                sender_name: String::new(),
                sequence: receipt.sequence.unwrap_or_default(),
                client_sequence: receipt.client_sequence.unwrap_or_default(),
                message_id: 0,
                random: receipt.random,
                time: receipt.time.unwrap_or_default() as i64,
                is_self: true,
                is_bot: Some(true),
                elements: vec![MessageElement::File(reference)],
                metadata: vec![],
                raw: vec![],
            });
        }
        let result = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let packet = match packets.recv().await {
                    Ok(packet) => packet,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => return Err(Error::Disconnected),
                };
                if packet.command != "trpc.msg.olpush.OlPushService.MsgPush" {
                    continue;
                }
                let push: rpc::MessagePush = decode(&packet.body)?;
                if push.common_message.is_empty() {
                    continue;
                }
                let common: rpc::CommonMessage = decode(&push.common_message)?;
                let Some(head) = common.content_head.as_ref() else {
                    continue;
                };
                if head.message_type.unwrap_or_default() != 82
                    || head.random.unwrap_or_default() as u32 != receipt.random
                {
                    continue;
                }
                let mut message = self.parse_message(&push.common_message, state)?;
                if message.conversation != conversation || !message.is_self {
                    continue;
                }
                let matches = message.elements.iter().any(|element| match element {
                    MessageElement::GroupFile(file) => file.file_id == receipt.file_id,
                    MessageElement::File(file) => file.file_id.as_ref() == Some(&receipt.file_id),
                    _ => false,
                });
                if matches {
                    if head.sequence.is_none() || head.time.is_none() || head.message_id.is_none() {
                        return Err(Error::Malformed("File push lacks message identity".into()));
                    }
                    message.is_bot = Some(true);
                    return Ok(message);
                }
            }
        })
        .await;
        match result {
            Ok(Ok(message)) => Ok(message),
            Ok(Err(error)) => Err(Error::UnconfirmedFileSend {
                file_id: receipt.file_id,
                cause: error.to_string(),
            }),
            Err(_) => Err(Error::UnconfirmedFileSend {
                file_id: receipt.file_id,
                cause: "Timed out waiting for matching file push".into(),
            }),
        }
    }
    pub async fn history_c2c(
        &self,
        peer_uid: &str,
        start_sequence: u64,
        end_sequence: u64,
    ) -> Result<Vec<Message>> {
        if peer_uid.is_empty() || start_sequence > end_sequence {
            return Err(Error::Malformed("Invalid C2C history range or UID".into()));
        }
        let response: rpc::MessageListResponse = self
            .request(
                "trpc.msg.register_proxy.RegisterProxy.SsoGetC2cMsg",
                rpc::C2cHistoryRequest {
                    peer_uid: peer_uid.into(),
                    start_sequence: Some(start_sequence),
                    end_sequence: Some(end_sequence),
                },
            )
            .await?;
        check_result(response.code, response.error.as_deref())?;
        let state = self.client.snapshot().await;
        response
            .messages
            .iter()
            .map(|v| self.parse_message(v, &state))
            .collect()
    }
    /// Fetch an inclusive sequence range from a group.
    ///
    /// An empty list is successful only when both response status codes are zero.
    /// A nonzero body status (including 4) remains `Error::Server`; this query does
    /// not log out the client or retry. The meaning of undocumented codes is not inferred.
    pub async fn history_group(
        &self,
        group_uin: u64,
        start_sequence: u64,
        end_sequence: u64,
    ) -> Result<Vec<Message>> {
        if group_uin == 0 || start_sequence > end_sequence {
            return Err(Error::Malformed("Invalid group history range".into()));
        }
        let response: rpc::GroupHistoryResponse = self
            .request(
                "trpc.msg.register_proxy.RegisterProxy.SsoGetGroupMsg",
                rpc::GroupHistoryRequest {
                    range: Some(rpc::GroupHistoryRange {
                        group_uin,
                        start_sequence: Some(start_sequence),
                        end_sequence: Some(end_sequence),
                    }),
                    flag: 1,
                },
            )
            .await?;
        check_result(response.code, response.error.as_deref())?;
        let body = response.body.ok_or_else(|| missing(3))?;
        check_result(body.code, body.error.as_deref())?;
        let state = self.client.snapshot().await;
        body.messages
            .iter()
            .map(|v| self.parse_message(v, &state))
            .collect()
    }
    pub async fn roam(
        &self,
        peer_uid: &str,
        time: u32,
        random: u32,
        count: u32,
        direction: RoamDirection,
    ) -> Result<RoamPage> {
        if peer_uid.is_empty() || !(1..=30).contains(&count) {
            return Err(Error::Malformed(
                "Roam requires UID and count 1..=30".into(),
            ));
        }
        let rsp: rpc::RoamResponse = self
            .request(
                "trpc.msg.register_proxy.RegisterProxy.SsoGetRoamMsg",
                rpc::RoamRequest {
                    peer_uid: peer_uid.into(),
                    time: Some(time as u64),
                    random: Some(random as u64),
                    count: count as u64,
                    direction: match direction {
                        RoamDirection::Upwards => 1,
                        RoamDirection::Downwards => 2,
                    },
                },
            )
            .await?;
        check_result(rsp.code, rsp.error.as_deref())?;
        let state = self.client.snapshot().await;
        Ok(RoamPage {
            peer_uid: rsp.peer_uid.unwrap_or_else(|| peer_uid.to_owned()),
            is_complete: rsp.complete,
            time: rsp.time as u32,
            random: rsp.random as u32,
            messages: rsp
                .messages
                .iter()
                .map(|v| self.parse_message(v, &state))
                .collect::<Result<_>>()?,
        })
    }
    pub async fn recall(&self, message: &Message) -> Result<()> {
        if message.sequence == 0 {
            return Err(Error::Malformed("Recall requires server sequence".into()));
        }
        let (command, request) = match &message.conversation {
            Conversation::Group { uin } => (
                "trpc.msg.msg_svc.MsgService.SsoGroupRecallMsg",
                rpc::GroupRecallRequest {
                    kind: 1,
                    group_uin: Some(*uin),
                    identity: Some(rpc::GroupRecallIdentity {
                        sequence: Some(message.sequence),
                        random: Some(message.random),
                        flag: Some(0),
                    }),
                    options: Some(rpc::GroupRecallOptions { flag: Some(0) }),
                }
                .encode_to_vec(),
            ),
            Conversation::Friend { uid, .. } => {
                if uid.is_empty() {
                    return Err(Error::Malformed("Recall requires peer UID".into()));
                }
                (
                    "trpc.msg.msg_svc.MsgService.SsoC2CRecallMsg",
                    rpc::C2cRecallRequest {
                        kind: 1,
                        peer_uid: uid.clone(),
                        identity: Some(rpc::C2cRecallIdentity {
                            sequence: Some(message.client_sequence),
                            random: Some(message.random as u64),
                            message_id: (0x01000000u64 << 32) | message.random as u64,
                            time: Some(message.time.clamp(0, u32::MAX as i64) as u64),
                            flag: Some(0),
                            client_sequence: Some(message.sequence),
                        }),
                        options: Some(rpc::C2cRecallOptions {
                            first: Some(0),
                            second: Some(0),
                        }),
                        flag: Some(0),
                    }
                    .encode_to_vec(),
                )
            }
            Conversation::Temporary { .. } => {
                return Err(Error::Unsupported(
                    "Desktop temporary-session recall is unsupported".into(),
                ));
            }
        };
        let mut packets = self.client.subscribe();
        tracing::info!(command, conversation = ?message.conversation, sequence = message.sequence,
            client_sequence = message.client_sequence, random = message.random, request_hex = %hex::encode(&request), "submit QQ recall");
        let response = self
            .client
            .request(
                command,
                request.into(),
                RequestType::D2,
                Encryption::D2,
                Duration::from_secs(60),
            )
            .await?;
        tracing::info!(command, packet = ?response, raw_hex = %hex::encode(&response), "QQ recall response; awaiting confirmation");
        let confirmed = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let packet = match packets.recv().await {
                    Ok(packet) => packet,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                        tracing::warn!(count, "recall confirmation packets lagged");
                        continue;
                    }
                    Err(_) => return false,
                };
                for event in self.decode_push(packet).await {
                    if let PushEvent::Recall {
                        conversation,
                        sequence,
                        ..
                    } = event
                        && same_conversation(&message.conversation, &conversation)
                        && sequence == message.sequence
                    {
                        return true;
                    }
                }
            }
        })
        .await
        .unwrap_or(false);
        if confirmed {
            return Ok(());
        }
        let history = match &message.conversation {
            Conversation::Group { uin } => {
                self.history_group(*uin, message.sequence, message.sequence)
                    .await
            }
            Conversation::Friend { uid, .. } => {
                self.history_c2c(uid, message.sequence, message.sequence)
                    .await
            }
            Conversation::Temporary { .. } => unreachable!(),
        };
        match history {
            Ok(rows)
                if rows
                    .iter()
                    .any(|row| row.sequence == message.sequence && row.is_recalled()) =>
            {
                Ok(())
            }
            result => {
                tracing::error!(command, packet = ?response, raw_hex = %hex::encode(&response), history = ?result,
                    "QQ recall was not confirmed");
                Err(Error::Malformed("QQ 未确认撤回，请查看终端返回包".into()))
            }
        }
    }
    pub async fn set_essence(&self, message: &Message, enabled: bool) -> Result<()> {
        let Conversation::Group { uin } = &message.conversation else {
            return Err(Error::Unsupported(
                "Essence only applies to group messages".into(),
            ));
        };
        let service = if enabled { 1 } else { 2 };
        let response: rpc::EssenceResponse = self
            .request(
                &format!("OidbSvcTrpcTcp.0xeac_{service}"),
                rpc::EssenceRequest {
                    command: 0xeac,
                    service,
                    body: Some(rpc::EssenceIdentity {
                        group_uin: Some(*uin),
                        sequence: Some(message.sequence),
                        random: Some(message.random as u64),
                    }),
                    flag: Some(0),
                },
            )
            .await?;
        check_result(response.code, response.error.as_deref())?;
        if let Some(inner) = response.body {
            check_result(inner.code, inner.error.as_deref())?;
        }
        Ok(())
    }
    pub async fn upload_forward(
        &self,
        conversation: Conversation,
        messages: Vec<Message>,
    ) -> Result<ForwardReference> {
        conversation.media_conversation()?;
        if messages.is_empty() {
            return Err(Error::Malformed("Cannot upload empty forward".into()));
        }
        let buffer = rpc::ForwardMessages {
            messages: messages
                .iter()
                .map(|message| self.common_message(message).map(Into::into))
                .collect::<Result<_>>()?,
        };
        let content = rpc::ForwardTransmit {
            messages: vec![],
            items: vec![rpc::ForwardItem {
                name: "MultiMsg".into(),
                body: Some(buffer),
            }],
        };
        let compressed = codec::compress(&content.encode_to_vec(), true)?;
        let (group, uid, kind) = match conversation {
            Conversation::Group { uin } => (uin, uin.to_string(), 3),
            Conversation::Friend { uid, .. } => {
                if uid.is_empty() {
                    return Err(Error::Malformed("Forward requires peer UID".into()));
                }
                (0, uid, 1)
            }
            Conversation::Temporary { .. } => unreachable!(),
        };
        let send = rpc::LongSend {
            kind,
            peer: Some(rpc::LongPeer { uid }),
            group_uin: Some(group),
            payload: compressed.into(),
        };
        let state = self.client.snapshot().await;
        let rsp: rpc::LongSendResponse = self
            .request(
                "trpc.group.long_msg_interface.MsgService.SsoSendLongMsg",
                rpc::LongSendRequest {
                    send: Some(send),
                    attributes: Some(long_attributes(4, &state)),
                },
            )
            .await?;
        let send = rsp.send.ok_or_else(|| missing(2))?;
        let id = if send.resource_id.is_empty() {
            return Err(Error::Malformed(
                "Long message upload returned no resource ID".into(),
            ));
        } else {
            send.resource_id
        };
        Ok(ForwardReference {
            resource_id: id,
            light_app_json: None,
            count: messages.len(),
            raw_element: None,
        })
    }
    pub async fn download_forward(
        &self,
        resource_id: &str,
        is_group: bool,
    ) -> Result<Vec<Message>> {
        if resource_id.is_empty() {
            return Err(Error::Malformed("Forward resource ID empty".into()));
        }
        let state = self.client.snapshot().await;
        let recv = rpc::LongReceive {
            peer: Some(rpc::LongPeer {
                uid: state.keystore.uid.clone(),
            }),
            resource_id: resource_id.into(),
            kind: if is_group { 1 } else { 3 },
        };
        let rsp: rpc::LongReceiveResponse = self
            .request(
                "trpc.group.long_msg_interface.MsgService.SsoRecvLongMsg",
                rpc::LongReceiveRequest {
                    receive: Some(recv),
                    attributes: Some(long_attributes(2, &state)),
                },
            )
            .await?;
        let recv = rsp.receive.ok_or_else(|| missing(1))?;
        let payload = recv
            .payload
            .ok_or_else(|| Error::Malformed("Long message response lacks payload".into()))?;
        let transmit: rpc::ForwardTransmit = decode(&codec::decompress(&payload, true)?)?;
        let direct = transmit.messages;
        let messages = transmit
            .items
            .into_iter()
            .filter(|item| item.name == "MultiMsg")
            .filter_map(|item| item.body)
            .flat_map(|body| body.messages)
            .collect::<Vec<_>>();
        let messages = if messages.is_empty() {
            direct
        } else {
            messages
        };
        if messages.is_empty() {
            return Err(Error::Malformed(
                "Forward archive contains no messages".into(),
            ));
        }
        messages
            .iter()
            .map(|raw| self.parse_message(raw, &state))
            .collect()
    }
    /// Rebuild known fields from the requested entity, preserving unrelated raw protobuf fields.
    /// A raw reference never overrides the requested author, time, routing, or content.
    fn common_message(&self, message: &Message) -> Result<Vec<u8>> {
        let mut route = rpc::RoutingHead {
            sender_uin: Some(message.sender_uin),
            sender_uid: message.sender_uid.clone(),
            recipient_uin: Some(message.recipient_uin),
            recipient_uid: message.recipient_uid.clone(),
            ..Default::default()
        };
        let kind = match &message.conversation {
            Conversation::Group { uin } => {
                route.group = Some(rpc::CommonGroup {
                    uin: Some(*uin),
                    sender_name: message.sender_name.clone(),
                    card_type: Some(2),
                    ..Default::default()
                });
                82
            }
            Conversation::Friend { .. } => {
                route.c2c = Some(rpc::CommonC2c {
                    source: Some(0),
                    sender_name: message.sender_name.clone(),
                });
                166
            }
            Conversation::Temporary { source, .. } => {
                route.c2c = Some(rpc::CommonC2c {
                    source: Some(*source),
                    sender_name: message.sender_name.clone(),
                });
                141
            }
        };
        codec::preserve_common(
            &message.raw,
            rpc::CommonMessage {
                routing_head: Some(route),
                content_head: Some(rpc::ContentHead {
                    message_type: Some(kind),
                    random: Some(message.random as u64),
                    sequence: Some(
                        if matches!(message.conversation, Conversation::Group { .. }) {
                            message.sequence
                        } else {
                            message.reply_sequence()
                        },
                    ),
                    time: Some(message.time as u64),
                    client_sequence: Some(
                        if matches!(message.conversation, Conversation::Group { .. }) {
                            message.client_sequence
                        } else {
                            message.sequence
                        },
                    ),
                    message_id: Some(message.message_id),
                    ..Default::default()
                }),
                message_body: encode_elements(&message.elements, &message.metadata)?.into(),
            },
        )
    }
    fn parse_message(&self, raw: &[u8], state: &SessionState) -> Result<Message> {
        let message: rpc::CommonMessage = decode(raw)?;
        let routing = message.routing_head.ok_or_else(|| missing(1))?;
        let head = message.content_head.ok_or_else(|| missing(2))?;
        let sender_uin = routing.sender_uin.unwrap_or_default();
        let sender_uid = routing.sender_uid;
        let recipient_uin = routing.recipient_uin.unwrap_or_default();
        let recipient_uid = routing.recipient_uid;
        let is_self = (!sender_uid.is_empty() && sender_uid == state.keystore.uid)
            || (sender_uin != 0 && sender_uin == state.keystore.uin);
        let (conversation, sender_name) = if head.message_type.unwrap_or_default() == 141 {
            let c2c = routing.c2c.unwrap_or_default();
            (
                Conversation::Temporary {
                    uin: recipient_uin,
                    uid: recipient_uid.clone(),
                    source: c2c.source.unwrap_or_default(),
                },
                c2c.sender_name,
            )
        } else if let Some(group) = routing.group {
            (
                Conversation::Group {
                    uin: group.uin.unwrap_or_default(),
                },
                group.sender_name,
            )
        } else {
            (
                Conversation::Friend {
                    uin: if is_self { recipient_uin } else { sender_uin },
                    uid: if is_self {
                        recipient_uid.clone()
                    } else {
                        sender_uid.clone()
                    },
                },
                routing.c2c.map(|v| v.sender_name).unwrap_or_default(),
            )
        };
        let decoded = decode_elements(&message.message_body, &conversation, state.keystore.uin)?;
        let (sequence, client_sequence) = if matches!(conversation, Conversation::Group { .. }) {
            (
                head.sequence.unwrap_or_default(),
                head.client_sequence.unwrap_or_default(),
            )
        } else {
            (
                head.client_sequence
                    .filter(|sequence| *sequence != 0)
                    .or(head.sequence)
                    .unwrap_or_default(),
                head.sequence.unwrap_or_default(),
            )
        };
        Ok(Message {
            conversation,
            sender_uin,
            sender_uid,
            recipient_uin,
            recipient_uid,
            sender_name,
            sequence,
            client_sequence,
            message_id: head.message_id.unwrap_or_default(),
            random: head.random.unwrap_or_default() as u32,
            time: head.time.unwrap_or_default() as i64,
            is_self,
            is_bot: None,
            elements: decoded.elements,
            metadata: decoded.metadata,
            raw: raw.to_vec(),
        })
    }
    pub async fn call(&self, method: &str, args: ciborium::Value) -> Result<ciborium::Value> {
        match method {
            "send" => {
                #[derive(Deserialize)]
                struct A {
                    conversation: Conversation,
                    elements: Vec<MessageElement>,
                }
                let a: A = from_args(args)?;
                to_cbor(self.send(a.conversation, a.elements).await?)
            }
            "history_c2c" => {
                #[derive(Deserialize)]
                struct A {
                    peer_uid: String,
                    start_sequence: u64,
                    end_sequence: u64,
                }
                let a: A = from_args(args)?;
                to_cbor(
                    self.history_c2c(&a.peer_uid, a.start_sequence, a.end_sequence)
                        .await?,
                )
            }
            "history_group" => {
                #[derive(Deserialize)]
                struct A {
                    group_uin: u64,
                    start_sequence: u64,
                    end_sequence: u64,
                }
                let a: A = from_args(args)?;
                to_cbor(
                    self.history_group(a.group_uin, a.start_sequence, a.end_sequence)
                        .await?,
                )
            }
            "roam" => {
                #[derive(Deserialize)]
                struct A {
                    peer_uid: String,
                    time: u32,
                    #[serde(default)]
                    random: u32,
                    #[serde(default = "default_count")]
                    count: u32,
                    #[serde(default)]
                    direction: RoamDirection,
                }
                let a: A = from_args(args)?;
                to_cbor(
                    self.roam(&a.peer_uid, a.time, a.random, a.count, a.direction)
                        .await?,
                )
            }
            "recall" => {
                #[derive(Deserialize)]
                struct A {
                    message: Message,
                }
                let a: A = from_args(args)?;
                self.recall(&a.message).await?;
                to_cbor(())
            }
            "set_essence" => {
                #[derive(Deserialize)]
                struct A {
                    message: Message,
                    #[serde(default = "enabled")]
                    enabled: bool,
                }
                let a: A = from_args(args)?;
                self.set_essence(&a.message, a.enabled).await?;
                to_cbor(())
            }
            "upload_forward" => {
                #[derive(Deserialize)]
                struct A {
                    conversation: Conversation,
                    messages: Vec<Message>,
                }
                let a: A = from_args(args)?;
                to_cbor(self.upload_forward(a.conversation, a.messages).await?)
            }
            "download_forward" => {
                #[derive(Deserialize)]
                struct A {
                    resource_id: String,
                    is_group: bool,
                }
                let a: A = from_args(args)?;
                to_cbor(self.download_forward(&a.resource_id, a.is_group).await?)
            }
            _ => Err(Error::Unsupported(format!(
                "Unknown messaging method {method}"
            ))),
        }
    }
}
fn long_attributes(command: u64, state: &SessionState) -> rpc::LongAttributes {
    rpc::LongAttributes {
        command,
        version: 1,
        platform: match state.profile.os.to_lowercase().as_str() {
            "windows" => 3,
            "linux" => 6,
            _ => 7,
        },
        flag: Some(0),
    }
}
fn same_conversation(left: &Conversation, right: &Conversation) -> bool {
    match (left, right) {
        (Conversation::Group { uin: left }, Conversation::Group { uin: right }) => left == right,
        (Conversation::Friend { uid: left, .. }, Conversation::Friend { uid: right, .. }) => {
            left == right
        }
        _ => left == right,
    }
}
fn decode<T: ProstMessage + Default>(raw: &[u8]) -> Result<T> {
    crate::proto::decode(raw)
}
fn missing(field: u32) -> Error {
    Error::Malformed(format!("Missing protobuf field {field}"))
}
fn check_result(code: i64, message: Option<&str>) -> Result<()> {
    if code as i32 != 0 {
        Err(Error::Server {
            code: code as i32,
            message: message.unwrap_or("QQ request failed").into(),
        })
    } else {
        Ok(())
    }
}
fn default_count() -> u32 {
    30
}
fn enabled() -> bool {
    true
}
fn from_args<T: DeserializeOwned>(args: ciborium::Value) -> Result<T> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&args, &mut bytes).map_err(|e| Error::Malformed(e.to_string()))?;
    ciborium::de::from_reader(bytes.as_slice()).map_err(|e| Error::Malformed(e.to_string()))
}
