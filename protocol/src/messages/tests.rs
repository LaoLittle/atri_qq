use super::*;
use crate::models::{Keystore, Profile};
use bytes::Bytes;
use std::sync::Mutex;
use tokio::sync::broadcast;

type Handler =
    dyn Fn(&str, &[u8], &broadcast::Sender<IncomingPacket>) -> Result<Vec<u8>> + Send + Sync;
struct Mock {
    state: Mutex<SessionState>,
    calls: Mutex<Vec<(String, Vec<u8>)>>,
    packets: broadcast::Sender<IncomingPacket>,
    handler: Box<Handler>,
}
impl Mock {
    fn new(
        handler: impl Fn(&str, &[u8], &broadcast::Sender<IncomingPacket>) -> Result<Vec<u8>>
        + Send
        + Sync
        + 'static,
    ) -> Arc<Self> {
        let (packets, _) = broadcast::channel(32);
        let mut keystore = Keystore::default();
        keystore.uin = 100;
        keystore.uid = "self-uid".into();
        Arc::new(Self {
            state: Mutex::new(SessionState {
                profile: Profile::default(),
                keystore,
                machine_id: String::new(),
                online: true,
            }),
            calls: Mutex::new(vec![]),
            packets,
            handler: Box::new(handler),
        })
    }
}
#[async_trait::async_trait]
impl ServiceClient for Mock {
    async fn request(
        &self,
        command: &str,
        body: Bytes,
        _: RequestType,
        _: Encryption,
        _: Duration,
    ) -> Result<Bytes> {
        self.calls
            .lock()
            .unwrap()
            .push((command.to_owned(), body.to_vec()));
        (self.handler)(command, &body, &self.packets).map(Into::into)
    }
    async fn snapshot(&self) -> SessionState {
        self.state.lock().unwrap().clone()
    }
    async fn replace_state(&self, state: SessionState) {
        *self.state.lock().unwrap() = state;
    }
    fn subscribe(&self) -> broadcast::Receiver<IncomingPacket> {
        self.packets.subscribe()
    }
}
fn service(client: Arc<Mock>) -> Messaging {
    Messaging::new(client.clone(), Arc::new(Media::new(client)))
}
fn packet(common: rpc::CommonMessage) -> IncomingPacket {
    IncomingPacket {
        sequence: 7,
        command: "trpc.msg.olpush.OlPushService.MsgPush".into(),
        body: rpc::MessagePush {
            common_message: common.encode_to_vec().into(),
        }
        .encode_to_vec()
        .into(),
        return_code: 0,
        header: Default::default(),
    }
}
fn message() -> Message {
    Message {
        conversation: Conversation::Group { uin: 42 },
        sender_uin: 777,
        sender_uid: "requested-author".into(),
        recipient_uin: 100,
        recipient_uid: "self-uid".into(),
        sender_name: "Requested author".into(),
        sequence: 333,
        client_sequence: 444,
        message_id: 555,
        random: 666,
        time: 123456,
        is_self: false,
        is_bot: None,
        elements: vec![MessageElement::Text("requested content".into())],
        metadata: vec![],
        raw: vec![],
    }
}

#[tokio::test]
async fn actual_push_and_shared_history_forward_parser_separate_protocol_metadata() {
    let client = Mock::new(|_, _, _| panic!("parsing must not issue protocol requests"));
    let messaging = service(client.clone());
    let ancillary = Bytes::from_static(&[0x10, 123, 0x10, 124, 0xba, 0x3e, 2, 0, 255]);
    let element = rpc::Elem {
        text: vec![
            rpc::Text {
                text: Some("/ping".into()),
                ..Default::default()
            }
            .encode_to_vec()
            .into(),
        ],
        general_flags: vec![ancillary.clone(), ancillary.clone()],
        ..Default::default()
    };
    let rich = rpc::RichText {
        attr: vec![ancillary],
        elems: vec![element.encode_to_vec().into()],
        ..Default::default()
    };
    let common = rpc::CommonMessage {
        routing_head: Some(rpc::RoutingHead {
            sender_uin: Some(200),
            sender_uid: "u_sender".into(),
            recipient_uin: Some(100),
            recipient_uid: "self-uid".into(),
            group: Some(rpc::CommonGroup {
                uin: Some(42),
                sender_name: "Sender".into(),
                card_type: Some(2),
                ..Default::default()
            }),
            ..Default::default()
        }),
        content_head: Some(rpc::ContentHead {
            message_type: Some(82),
            sequence: Some(77),
            time: Some(456),
            ..Default::default()
        }),
        message_body: rpc::MessageBody {
            rich_text: rich.encode_to_vec().into(),
            ..Default::default()
        }
        .encode_to_vec()
        .into(),
    };
    let raw = common.encode_to_vec();
    let state = client.snapshot().await;
    let parsed = messaging.parse_message(&raw, &state).unwrap();
    assert!(matches!(parsed.elements.as_slice(), [MessageElement::Text(text)] if text == "/ping"));
    assert_eq!(parsed.time, 456);
    assert_eq!(parsed.sequence, 77);
    assert_eq!(parsed.sender_uid, "u_sender");
    assert_eq!(parsed.conversation, Conversation::Group { uin: 42 });
    assert_eq!(parsed.metadata.len(), 2);
    let rebuilt = messaging.common_message(&parsed).unwrap();
    let restored = messaging.parse_message(&rebuilt, &state).unwrap();
    for original in &parsed.metadata {
        assert!(
            restored
                .metadata
                .iter()
                .any(|record| record.scope == original.scope
                    && record.field == original.field
                    && record.payload == original.payload)
        );
    }
    let event = messaging.decode_push(packet(common)).await.remove(0);
    let PushEvent::Message { message } = event else {
        panic!("typed message push expected")
    };
    assert!(matches!(message.elements.as_slice(), [MessageElement::Text(text)] if text == "/ping"));
    assert_eq!(message.metadata.len(), 2);
    assert_eq!(message.raw, raw);
    assert!(client.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn temporary_sends_and_recall_are_rejected_before_side_effects() {
    let client = Mock::new(|_, _, _| panic!("unsupported send issued request"));
    let messaging = service(client.clone());
    let conversation = Conversation::Temporary {
        uin: 20,
        uid: "peer".into(),
        source: -19,
    };
    assert!(matches!(
        messaging
            .send(
                conversation.clone(),
                vec![MessageElement::Text("hello".into())]
            )
            .await,
        Err(Error::Unsupported(_))
    ));
    let mut msg = message();
    msg.conversation = conversation;
    assert!(matches!(
        messaging.recall(&msg).await,
        Err(Error::Unsupported(_))
    ));
    assert!(client.calls.lock().unwrap().is_empty());
}
#[tokio::test]
async fn friend_routing_keeps_uid_and_distinct_local_and_server_sequences() {
    let client = Mock::new(|command, body, _| {
        assert_eq!(command, "MessageSvc.PbSendMsg");
        let request: rpc::SendMessageRequest = decode(body)?;
        let route = request.route.unwrap().friend.unwrap();
        assert_eq!(route.uid, "uid-distinct-from-uin");
        Ok(rpc::SendMessageResponse {
            sequence: Some(9001),
            time: Some(1700000000),
            client_sequence: Some(request.client_sequence + 1),
            ..Default::default()
        }
        .encode_to_vec())
    });
    let sent = service(client)
        .send(
            Conversation::Friend {
                uin: 42,
                uid: "uid-distinct-from-uin".into(),
            },
            vec![MessageElement::Text("hi".into())],
        )
        .await
        .unwrap();
    assert_eq!(sent.sequence, sent.client_sequence + 1);
    assert_eq!(sent.time, 1700000000);
}
#[tokio::test]
async fn private_ack_with_unknown_metadata_and_no_group_sequence_is_successful() {
    let messaging = service(Mock::new(|_, _, _| {
        Ok(vec![0x18, 101, 0x50, 0, 0x60, 101, 0x70, 7])
    }));
    let sent = messaging
        .send(
            Conversation::Friend {
                uin: 42,
                uid: "u_peer".into(),
            },
            vec![MessageElement::Text("test".into())],
        )
        .await
        .unwrap();
    assert_eq!(sent.sequence, 7);
    assert_eq!(sent.time, 101);
    assert_eq!(sent.recipient_uin, 42);
}
#[tokio::test]
async fn successful_send_accepts_missing_and_zero_server_identity() {
    for (response, expected_sequence, expected_time) in [
        (rpc::SendMessageResponse::default(), 0, 0),
        (
            rpc::SendMessageResponse {
                sequence: Some(0),
                time: Some(0),
                client_sequence: Some(0),
                ..Default::default()
            },
            0,
            0,
        ),
        (
            rpc::SendMessageResponse {
                sequence: Some(9001),
                client_sequence: Some(0),
                time: Some(1700000000),
                ..Default::default()
            },
            9001,
            1700000000,
        ),
        (
            rpc::SendMessageResponse {
                client_sequence: Some(9002),
                ..Default::default()
            },
            9002,
            0,
        ),
    ] {
        let encoded = response.encode_to_vec();
        let messaging = service(Mock::new(move |_, _, _| Ok(encoded.clone())));
        let sent = messaging
            .send(
                Conversation::Group { uin: 42 },
                vec![MessageElement::Text("hello".into())],
            )
            .await
            .unwrap();
        assert_eq!(sent.sequence, expected_sequence);
        assert_eq!(sent.time, expected_time);
    }
}
#[tokio::test]
async fn failed_send_without_server_identity_preserves_server_error() {
    let messaging = service(Mock::new(|_, _, _| {
        Ok(rpc::SendMessageResponse {
            code: 120,
            error: Some("message rejected".into()),
            ..Default::default()
        }
        .encode_to_vec())
    }));
    assert!(matches!(
        messaging.send(
            Conversation::Group { uin: 42 },
            vec![MessageElement::Text("hello".into())],
        ).await,
        Err(Error::Server { code: 120, message }) if message == "message rejected"
    ));
}
#[tokio::test]
async fn type141_preserves_signed_source_and_recipient_routing() {
    let messaging = service(Mock::new(|_, _, _| panic!()));
    let common = rpc::CommonMessage {
        routing_head: Some(rpc::RoutingHead {
            sender_uin: Some(200),
            sender_uid: "sender".into(),
            recipient_uin: Some(300),
            recipient_uid: "recipient".into(),
            c2c: Some(rpc::CommonC2c {
                source: Some(-123),
                sender_name: "name".into(),
            }),
            ..Default::default()
        }),
        content_head: Some(rpc::ContentHead {
            message_type: Some(141),
            sequence: Some(5),
            time: Some(6),
            ..Default::default()
        }),
        message_body: encode_elements(&[MessageElement::Text("temporary".into())], &[])
            .unwrap()
            .into(),
    };
    let events = messaging.decode_push(packet(common.clone())).await;
    let PushEvent::Message { message } = events.into_iter().next().unwrap() else {
        panic!()
    };
    assert_eq!(
        message.conversation,
        Conversation::Temporary {
            uin: 300,
            uid: "recipient".into(),
            source: -123
        }
    );
    assert_eq!(message.raw, common.encode_to_vec());
    assert_eq!(message.is_bot, None);
}
#[tokio::test]
async fn unknown_and_malformed_pushes_keep_raw_payload() {
    let messaging = service(Mock::new(|_, _, _| panic!()));
    let input = IncomingPacket {
        sequence: 0,
        command: "unknown.service".into(),
        body: Bytes::from_static(&[1, 2, 3]),
        return_code: 0,
        header: Default::default(),
    };
    assert!(
        matches!(&messaging.decode_push(input).await[0], PushEvent::Opaque { payload, .. } if payload == &vec![1, 2, 3])
    );
    let mut malformed = packet(rpc::CommonMessage::default());
    malformed.body = Bytes::from_static(&[0xff]);
    assert!(
        matches!(&messaging.decode_push(malformed).await[0], PushEvent::Opaque { payload, .. } if payload == &vec![0xff])
    );
}
#[tokio::test]
async fn forwarded_raw_reference_cannot_override_requested_entity() {
    let client = Mock::new(|command, request, _| {
        assert_eq!(
            command,
            "trpc.group.long_msg_interface.MsgService.SsoSendLongMsg"
        );
        let request: rpc::LongSendRequest = decode(request)?;
        let content: rpc::ForwardTransmit =
            decode(&codec::decompress(&request.send.unwrap().payload, true)?)?;
        let raw = &content.items[0].body.as_ref().unwrap().messages[0];
        let forwarded: rpc::CommonMessage = decode(raw)?;
        let route = forwarded.routing_head.unwrap();
        let head = forwarded.content_head.unwrap();
        assert_eq!(route.sender_uin, Some(777));
        assert_eq!(route.sender_uid, "requested-author");
        assert_eq!(head.time, Some(123456));
        let elements = decode_elements(
            &forwarded.message_body,
            &Conversation::Group { uin: 42 },
            100,
        )?;
        assert!(
            matches!(&elements.elements[0], MessageElement::Text(text) if text == "requested content")
        );
        let descriptor = crate::proto::descriptor_pool()
            .get_message_by_name("atri.qq.messages.CommonMessage")
            .unwrap();
        let dynamic = prost_reflect::DynamicMessage::decode(descriptor, raw.as_ref()).unwrap();
        assert!(dynamic.unknown_fields().any(|field| field.number() == 999));
        Ok(rpc::LongSendResponse {
            send: Some(rpc::LongSendResult {
                resource_id: "real-resource-id".into(),
            }),
        }
        .encode_to_vec())
    });
    let mut requested = message();
    requested.raw = rpc::CommonMessage {
        routing_head: Some(rpc::RoutingHead {
            sender_uin: Some(1),
            sender_uid: "stale-author".into(),
            ..Default::default()
        }),
        content_head: Some(rpc::ContentHead {
            message_type: Some(82),
            time: Some(1),
            ..Default::default()
        }),
        message_body: encode_elements(&[MessageElement::Text("stale content".into())], &[])
            .unwrap()
            .into(),
    }
    .encode_to_vec();
    requested.raw.extend_from_slice(&[0xb8, 0x3e, 0x58]);
    let result = service(client)
        .upload_forward(Conversation::Group { uin: 42 }, vec![requested])
        .await
        .unwrap();
    assert_eq!(result.resource_id, "real-resource-id");
}
fn group_file_echo(random: u32, complete: bool) -> IncomingPacket {
    let extra = rpc::GroupFileEnvelope {
        body: Some(rpc::GroupFileBody {
            info: Some(rpc::GroupFileInfo {
                business_id: Some(102),
                file_id: "file-id".into(),
                size: Some(4),
                name: "file.bin".into(),
                ..Default::default()
            }),
        }),
    }
    .encode_to_vec();
    let mut framed = vec![0];
    framed.extend_from_slice(&(extra.len() as u16).to_be_bytes());
    framed.extend_from_slice(&extra);
    let elem = rpc::Elem {
        trans: vec![
            rpc::TransElem {
                kind: Some(24),
                data: framed.into(),
            }
            .encode_to_vec()
            .into(),
        ],
        ..Default::default()
    };
    let body = rpc::MessageBody {
        rich_text: rpc::RichText {
            elems: vec![elem.encode_to_vec().into()],
            ..Default::default()
        }
        .encode_to_vec()
        .into(),
        ..Default::default()
    };
    packet(rpc::CommonMessage {
        routing_head: Some(rpc::RoutingHead {
            sender_uin: Some(100),
            sender_uid: "self-uid".into(),
            group: Some(rpc::CommonGroup {
                uin: Some(42),
                ..Default::default()
            }),
            ..Default::default()
        }),
        content_head: Some(rpc::ContentHead {
            message_type: Some(82),
            random: Some(random as u64),
            sequence: Some(1234),
            time: Some(1700000000),
            message_id: complete.then_some(987654321),
            ..Default::default()
        }),
        message_body: body.encode_to_vec().into(),
    })
}
fn file_reference() -> MediaReference {
    let mut reference = MediaReference::new(
        crate::media::MediaKind::File,
        crate::media::MediaConversation::Group { uin: 42 },
    );
    reference.file_id = Some("file-id".into());
    reference.name = "file.bin".into();
    reference.size = 4;
    reference
}
#[tokio::test]
async fn friend_file_send_does_not_treat_missing_ack_identity_as_rejection() {
    use crate::proto::contacts as contact;
    let client = Mock::new(|command, _, _| match command {
        "OidbSvcTrpcTcp.0xfe1_2" => Ok(contact::OidbEnvelope {
            body: Some(
                contact::StrangerResponse {
                    body: Some(contact::StrangerBody {
                        uin: Some(42),
                        properties: Some(contact::Properties {
                            bytes: vec![contact::BytesProperty {
                                key: Some(20002),
                                value: Some(Bytes::from_static(b"peer")),
                            }],
                            ..Default::default()
                        }),
                    }),
                }
                .encode_to_vec()
                .into(),
            ),
            ..Default::default()
        }
        .encode_to_vec()),
        "MessageSvc.PbSendMsg" => Ok(rpc::SendMessageResponse::default().encode_to_vec()),
        _ => panic!("unexpected command {command}"),
    });
    let mut reference = file_reference();
    reference.conversation = crate::media::MediaConversation::Friend { uid: "peer".into() };
    reference.compatibility = Some(vec![]);
    let sent = service(client.clone())
        .send(
            Conversation::Friend {
                uin: 42,
                uid: "peer".into(),
            },
            vec![MessageElement::File(reference)],
        )
        .await
        .unwrap();
    assert_eq!(sent.sequence, 0);
    assert_eq!(sent.time, 0);
    assert_eq!(
        client
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(command, _)| command == "MessageSvc.PbSendMsg")
            .count(),
        1,
        "a successful acknowledgement must not trigger a resend"
    );
}
fn file_ack(
    request: &[u8],
    packets: &broadcast::Sender<IncomingPacket>,
    complete: bool,
) -> Result<Vec<u8>> {
    let request: rpc::GroupFileFeedRequest = decode(request)?;
    let random = request
        .body
        .unwrap()
        .operation
        .unwrap()
        .identity
        .unwrap()
        .random;
    packets
        .send(group_file_echo(random as u32, complete))
        .unwrap();
    Ok(rpc::GroupFileFeedResponse {
        body: Some(rpc::GroupFileFeedResponseBody {
            result: Some(rpc::GroupFileFeedResult {}),
        }),
    }
    .encode_to_vec())
}
#[tokio::test]
async fn group_file_identity_comes_from_push_received_during_ack() {
    let client = Mock::new(|command, request, packets| {
        assert_eq!(command, "OidbSvcTrpcTcp.0x6d9_4");
        file_ack(request, packets, true)
    });
    let sent = service(client.clone())
        .send(
            Conversation::Group { uin: 42 },
            vec![MessageElement::File(file_reference())],
        )
        .await
        .unwrap();
    assert_eq!(sent.sequence, 1234);
    assert_eq!(sent.message_id, 987654321);
    assert_eq!(sent.is_bot, Some(true));
    assert_eq!(client.calls.lock().unwrap().len(), 1);
}
#[tokio::test]
async fn incomplete_file_push_is_unconfirmed_and_never_resent() {
    let client = Mock::new(|_, request, packets| file_ack(request, packets, false));
    assert!(
        matches!(service(client.clone()).send(Conversation::Group { uin: 42 }, vec![MessageElement::File(file_reference())]).await, Err(Error::UnconfirmedFileSend { file_id, .. }) if file_id == "file-id")
    );
    assert_eq!(client.calls.lock().unwrap().len(), 1);
}
#[tokio::test]
async fn cbor_facade_exercises_native_send() {
    let messaging = service(Mock::new(|_, _, _| {
        Ok(rpc::SendMessageResponse {
            sequence: Some(12),
            time: Some(34),
            ..Default::default()
        }
        .encode_to_vec())
    }));
    let args = to_cbor(serde_json::json!({"conversation":{"type":"group","uin":42},"elements":[{"type":"text","data":"facade"}]})).unwrap();
    let sent: Message = from_args(messaging.call("send", args).await.unwrap()).unwrap();
    assert_eq!(sent.sequence, 12);
    assert_eq!(sent.time, 34);
}

#[tokio::test]
async fn selected_nonce_is_preserved_for_optimistic_echo_reconciliation() {
    let messaging = service(Mock::new(|command, body, _| {
        assert_eq!(command, "MessageSvc.PbSendMsg");
        let request: rpc::SendMessageRequest = decode(body)?;
        assert_eq!(request.random, Some(1234));
        Ok(rpc::SendMessageResponse {
            sequence: Some(42),
            time: Some(1700000000),
            ..Default::default()
        }
        .encode_to_vec())
    }));
    let sent = messaging
        .send_with_nonce(
            Conversation::Group { uin: 42 },
            vec![MessageElement::Text("hello".into())],
            1234,
        )
        .await
        .unwrap();
    assert_eq!(sent.random, 1234);
    assert_eq!(sent.message_id as u32, 1234);
}
#[tokio::test]
async fn forward_download_reads_direct_nodes_and_skips_empty_archive_items() {
    for direct in [false, true] {
        let messaging = service(Mock::new(move |command, _, _| {
            assert_eq!(
                command,
                "trpc.group.long_msg_interface.MsgService.SsoRecvLongMsg"
            );
            let common = rpc::CommonMessage {
                routing_head: Some(rpc::RoutingHead {
                    sender_uin: Some(777),
                    sender_uid: "peer".into(),
                    group: Some(rpc::CommonGroup {
                        uin: Some(42),
                        sender_name: "Peer".into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                content_head: Some(rpc::ContentHead {
                    message_type: Some(82),
                    sequence: Some(1),
                    time: Some(1700000000),
                    ..Default::default()
                }),
                message_body: encode_elements(&[MessageElement::Text("forwarded".into())], &[])?
                    .into(),
            }
            .encode_to_vec();
            let transmit = if direct {
                rpc::ForwardTransmit {
                    messages: vec![common.into()],
                    items: vec![],
                }
            } else {
                rpc::ForwardTransmit {
                    messages: vec![],
                    items: vec![
                        rpc::ForwardItem {
                            name: "MultiMsg".into(),
                            body: Some(rpc::ForwardMessages::default()),
                        },
                        rpc::ForwardItem {
                            name: "MultiMsg".into(),
                            body: Some(rpc::ForwardMessages {
                                messages: vec![common.into()],
                            }),
                        },
                    ],
                }
            };
            Ok(rpc::LongReceiveResponse {
                receive: Some(rpc::LongReceiveResult {
                    payload: Some(codec::compress(&transmit.encode_to_vec(), true)?.into()),
                }),
            }
            .encode_to_vec())
        }));
        let messages = messaging.download_forward("resource", true).await.unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].sender_name, "Peer");
        assert!(
            matches!(&messages[0].elements[0], MessageElement::Text(text) if text == "forwarded")
        );
    }
}

#[tokio::test]
async fn server_tombstones_keep_identity_without_treating_unknown_content_as_recalled() {
    let client = Mock::new(|_, _, _| panic!("parsing must not issue requests"));
    let messaging = service(client.clone());
    let state = client.snapshot().await;
    let metadata = rpc::MessageBody {
        rich_text: rpc::RichText {
            attr: vec![Bytes::from_static(&[8, 1])],
            ..Default::default()
        }
        .encode_to_vec()
        .into(),
        ..Default::default()
    }
    .encode_to_vec();
    for kind in [82, 166] {
        for (body, recalled) in [
            (Vec::new(), true),
            (metadata.clone(), true),
            (
                encode_elements(&[MessageElement::Text("".into())], &[]).unwrap(),
                true,
            ),
            (
                encode_elements(&[MessageElement::Text("text".into())], &[]).unwrap(),
                false,
            ),
            // An unknown body field is retained as opaque semantic content.
            (vec![0x22, 2, 8, 1], false),
        ] {
            let raw = rpc::CommonMessage {
                routing_head: Some(rpc::RoutingHead {
                    sender_uin: Some(200),
                    sender_uid: "peer".into(),
                    group: (kind == 82).then_some(rpc::CommonGroup {
                        uin: Some(42),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                content_head: Some(rpc::ContentHead {
                    message_type: Some(kind),
                    sequence: Some(77),
                    time: Some(456),
                    ..Default::default()
                }),
                message_body: body.into(),
            }
            .encode_to_vec();
            let message = messaging.parse_message(&raw, &state).unwrap();
            assert_eq!(message.is_recalled(), recalled, "kind {kind}, body {raw:?}");
            assert_eq!(message.sequence, 77);
            assert_eq!(message.time, 456);
            assert_eq!(message.raw, raw);
        }
    }
    let mut local = message();
    local.elements.clear();
    assert!(!local.is_recalled());
}

fn direct_recall_packet(from: &str, to: &str, sequence: u64, random: u32) -> IncomingPacket {
    let content = rpc::DirectRecallPush {
        info: Some(rpc::DirectRecallInfo {
            sender_uid: from.into(),
            recipient_uid: to.into(),
            sequence,
            client_sequence: Some(444),
            random: Some(random),
            ..Default::default()
        }),
    }
    .encode_to_vec();
    packet(rpc::CommonMessage {
        routing_head: Some(rpc::RoutingHead::default()),
        content_head: Some(rpc::ContentHead {
            message_type: Some(528),
            sub_type: Some(138),
            ..Default::default()
        }),
        message_body: rpc::MessageBody {
            content: Some(content.into()),
            ..Default::default()
        }
        .encode_to_vec()
        .into(),
    })
}
fn group_recall_packet(prefixed: bool, sequence: u64, random: u32) -> IncomingPacket {
    let body = rpc::GroupNotificationPush {
        group_uin: Some(42),
        recall: Some(rpc::GroupRecallPush {
            operator_uid: Some("operator".into()),
            messages: vec![rpc::GroupRecallMessage {
                sequence,
                random,
                time: 123456,
                author_uid: "author".into(),
            }],
            ..Default::default()
        }),
        ..Default::default()
    }
    .encode_to_vec();
    let mut content = Vec::new();
    if prefixed {
        content.extend_from_slice(&42u32.to_be_bytes());
        content.push(0);
        content.extend_from_slice(&(body.len() as u16).to_be_bytes());
    }
    content.extend(body);
    packet(rpc::CommonMessage {
        routing_head: Some(rpc::RoutingHead::default()),
        content_head: Some(rpc::ContentHead {
            message_type: Some(732),
            sub_type: Some(17),
            ..Default::default()
        }),
        message_body: rpc::MessageBody {
            content: Some(content.into()),
            ..Default::default()
        }
        .encode_to_vec()
        .into(),
    })
}
#[tokio::test]
async fn recall_pushes_do_not_depend_on_contact_requests_and_keep_server_identity() {
    let client =
        Mock::new(|_, _, _| panic!("recall push must not resolve contacts over the network"));
    let messaging = service(client.clone());
    for (from, to) in [("peer", "self-uid"), ("self-uid", "peer")] {
        let events = messaging
            .decode_push(direct_recall_packet(from, to, 333, 666))
            .await;
        assert!(
            matches!(events.as_slice(), [PushEvent::Recall { conversation: Conversation::Friend { uid, uin: 0 }, sequence: 333, random: Some(666), .. }] if uid == "peer")
        );
    }
    for prefixed in [true, false] {
        let events = messaging
            .decode_push(group_recall_packet(prefixed, 333, 666))
            .await;
        assert!(
            matches!(events.as_slice(), [PushEvent::Recall { conversation: Conversation::Group { uin: 42 }, sequence: 333, random: Some(666), operator_uid: Some(operator), .. }] if operator == "operator")
        );
    }
    assert!(client.calls.lock().unwrap().is_empty());
}
#[tokio::test]
async fn recall_submits_correct_private_fields_and_waits_for_an_early_server_push() {
    let client = Mock::new(|command, raw, packets| {
        assert_eq!(command, "trpc.msg.msg_svc.MsgService.SsoC2CRecallMsg");
        let request: rpc::C2cRecallRequest = decode(raw)?;
        assert_eq!(request.peer_uid, "peer");
        let identity = request.identity.unwrap();
        // Wire field 1 = original sender's local sequence; field 6 = server sequence.
        assert_eq!(identity.sequence, Some(444));
        assert_eq!(identity.client_sequence, Some(333));
        assert_eq!(identity.random, Some(666));
        packets
            .send(direct_recall_packet("self-uid", "peer", 333, 666))
            .unwrap();
        Ok(Vec::new())
    });
    let messaging = service(client.clone());
    let mut item = message();
    item.conversation = Conversation::Friend {
        uin: 200,
        uid: "peer".into(),
    };
    messaging.recall(&item).await.unwrap();
    assert_eq!(client.calls.lock().unwrap().len(), 1);
}
#[tokio::test]
async fn recall_submits_group_sequence_and_random_and_waits_for_confirmation() {
    let client = Mock::new(|command, raw, packets| {
        assert_eq!(command, "trpc.msg.msg_svc.MsgService.SsoGroupRecallMsg");
        let request: rpc::GroupRecallRequest = decode(raw)?;
        assert_eq!(request.group_uin, Some(42));
        let identity = request.identity.unwrap();
        assert_eq!(identity.sequence, Some(333));
        assert_eq!(identity.random, Some(666));
        packets.send(group_recall_packet(true, 333, 666)).unwrap();
        Ok(Vec::new())
    });
    service(client.clone()).recall(&message()).await.unwrap();
    assert_eq!(client.calls.lock().unwrap().len(), 1);
}
#[tokio::test(start_paused = true)]
async fn a_transport_ack_without_recall_confirmation_is_not_success() {
    let client = Mock::new(|command, _, packets| match command {
        "trpc.msg.msg_svc.MsgService.SsoGroupRecallMsg" => {
            // An unrelated recall cannot confirm this request.
            packets.send(group_recall_packet(true, 999, 666)).unwrap();
            Ok(vec![8, 1])
        }
        "trpc.msg.register_proxy.RegisterProxy.SsoGetGroupMsg" => Ok(rpc::GroupHistoryResponse {
            body: Some(rpc::GroupHistoryBody::default()),
            ..Default::default()
        }
        .encode_to_vec()),
        _ => panic!("unexpected request {command}"),
    });
    assert!(service(client.clone()).recall(&message()).await.is_err());
    assert_eq!(client.calls.lock().unwrap().len(), 2);
}
#[tokio::test(start_paused = true)]
async fn recall_can_be_confirmed_by_history_when_the_push_is_missing() {
    let client = Mock::new(|command, _, _| match command {
        "trpc.msg.msg_svc.MsgService.SsoGroupRecallMsg" => Ok(Vec::new()),
        "trpc.msg.register_proxy.RegisterProxy.SsoGetGroupMsg" => {
            let tombstone = rpc::CommonMessage {
                routing_head: Some(rpc::RoutingHead {
                    group: Some(rpc::CommonGroup {
                        uin: Some(42),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                content_head: Some(rpc::ContentHead {
                    message_type: Some(82),
                    sequence: Some(333),
                    ..Default::default()
                }),
                ..Default::default()
            }
            .encode_to_vec();
            Ok(rpc::GroupHistoryResponse {
                body: Some(rpc::GroupHistoryBody {
                    messages: vec![tombstone.into()],
                    ..Default::default()
                }),
                ..Default::default()
            }
            .encode_to_vec())
        }
        _ => panic!("unexpected request {command}"),
    });
    service(client.clone()).recall(&message()).await.unwrap();
    assert_eq!(client.calls.lock().unwrap().len(), 2);
}
#[tokio::test]
async fn private_wire_sequence_roundtrips_and_reply_uses_sender_client_sequence() {
    let client = Mock::new(|_, _, _| panic!("parsing must not issue requests"));
    let messaging = service(client.clone());
    let state = client.snapshot().await;
    let common = rpc::CommonMessage {
        routing_head: Some(rpc::RoutingHead {
            sender_uid: "peer".into(),
            ..Default::default()
        }),
        content_head: Some(rpc::ContentHead {
            message_type: Some(166),
            sequence: Some(444),
            client_sequence: Some(333),
            ..Default::default()
        }),
        message_body: encode_elements(&[MessageElement::Text("hello".into())], &[])
            .unwrap()
            .into(),
    }
    .encode_to_vec();
    let parsed = messaging.parse_message(&common, &state).unwrap();
    assert_eq!((parsed.sequence, parsed.client_sequence), (333, 444));
    assert_eq!(Reply::from(&parsed).sequences, [444]);
    let rebuilt = messaging.common_message(&parsed).unwrap();
    let roundtrip = messaging.parse_message(&rebuilt, &state).unwrap();
    assert_eq!((roundtrip.sequence, roundtrip.client_sequence), (333, 444));
    let mut legacy = parsed;
    legacy.sequence = 444;
    legacy.client_sequence = 333;
    legacy.normalize_identity();
    assert_eq!((legacy.sequence, legacy.client_sequence), (333, 444));
}

#[test]
fn video_compatibility_matches_identity_instead_of_reverse_element_order() {
    use crate::proto::{media as media_pb, messages as rpc};
    let info = |id: &'static str, byte: u8| {
        let index = media_pb::MediaIndex {
            uuid: Some(Bytes::from_static(id.as_bytes())),
            file: Some(media_pb::MediaFileInfo {
                md5: Some(hex::encode([byte; 16]).into()),
                sha1: Some(hex::encode([byte; 20]).into()),
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode_to_vec();
        media_pb::MediaMessageInfo {
            bodies: vec![
                media_pb::MediaMessageInfoBody {
                    index: Some(index.into()),
                }
                .encode_to_vec()
                .into(),
            ],
        }
        .encode_to_vec()
    };
    let compatibility = |id: &'static str, byte: u8| {
        media_pb::VideoFile {
            uuid: Some(Bytes::from_static(id.as_bytes())),
            md5: Some(Bytes::copy_from_slice(&[byte; 16])),
            ..Default::default()
        }
        .encode_to_vec()
    };
    let element = rpc::Elem {
        common: [("first", 1), ("second", 2)]
            .into_iter()
            .map(|(id, byte)| {
                rpc::CommonElem {
                    service_type: Some(48),
                    business_type: Some(21),
                    payload: info(id, byte).into(),
                }
                .encode_to_vec()
                .into()
            })
            .collect(),
        video: vec![
            compatibility("second", 2).into(),
            compatibility("first", 1).into(),
        ],
        ..Default::default()
    };
    let rich = rpc::RichText {
        elems: vec![element.encode_to_vec().into()],
        ..Default::default()
    };
    let body = rpc::MessageBody {
        rich_text: rich.encode_to_vec().into(),
        ..Default::default()
    };
    let decoded =
        decode_elements(&body.encode_to_vec(), &Conversation::Group { uin: 42 }, 99).unwrap();
    assert_eq!(decoded.elements.len(), 2);
    for (element, expected) in decoded.elements.iter().zip(["first", "second"]) {
        let MessageElement::Video(reference) = element else {
            panic!("expected video");
        };
        assert_eq!(reference.uuid.as_deref(), Some(expected));
        let video =
            media_pb::VideoFile::decode(reference.compatibility.as_deref().unwrap()).unwrap();
        assert_eq!(video.uuid.as_deref(), Some(expected.as_bytes()));
    }
}

#[test]
fn metadata_only_ptt_does_not_hide_a_modern_private_voice() {
    use crate::proto::media as media_pb;
    let index = media_pb::MediaIndex {
        uuid: Some(Bytes::from_static(b"voice-resource")),
        file: Some(media_pb::MediaFileInfo {
            md5: Some(hex::encode([7; 16]).into()),
            duration: Some(2),
            size: Some(3893),
            ..Default::default()
        }),
        ..Default::default()
    };
    let info = media_pb::MediaMessageInfo {
        bodies: vec![
            media_pb::MediaMessageInfoBody {
                index: Some(index.encode_to_vec().into()),
            }
            .encode_to_vec()
            .into(),
        ],
    };
    let common = rpc::CommonElem {
        service_type: Some(48),
        business_type: Some(12),
        payload: info.encode_to_vec().into(),
    };
    let ptt = media_pb::Ptt {
        name: Some(Bytes::from_static(b"metadata-only")),
        ..Default::default()
    }
    .encode_to_vec();
    let rich = rpc::RichText {
        elems: vec![
            rpc::Elem {
                common: vec![common.encode_to_vec().into()],
                ..Default::default()
            }
            .encode_to_vec()
            .into(),
        ],
        voice: vec![ptt.clone().into()],
        ..Default::default()
    };
    let body = rpc::MessageBody {
        rich_text: rich.encode_to_vec().into(),
        ..Default::default()
    };
    let decoded = decode_elements(
        &body.encode_to_vec(),
        &Conversation::Friend {
            uid: "peer".into(),
            uin: 42,
        },
        99,
    )
    .unwrap();
    let [MessageElement::Voice(reference)] = decoded.elements.as_slice() else {
        panic!("expected one modern voice, not a duplicate or a lost message");
    };
    assert_eq!(reference.uuid.as_deref(), Some("voice-resource"));
    assert_eq!((reference.size, reference.duration), (3893, 2));
    assert!(reference.download_url.is_none());
    let sidecar = decoded
        .metadata
        .iter()
        .find(|item| item.scope == OpaqueScope::RichText && item.field == 4)
        .unwrap();
    assert_eq!(
        rpc::RichText::decode(sidecar.payload.as_slice())
            .unwrap()
            .voice[0]
            .as_ref(),
        ptt
    );
    let rebuilt = encode_elements(&decoded.elements, &decoded.metadata).unwrap();
    let roundtrip = decode_elements(
        &rebuilt,
        &Conversation::Friend {
            uid: "peer".into(),
            uin: 42,
        },
        99,
    )
    .unwrap();
    assert!(
        matches!(roundtrip.elements.as_slice(), [MessageElement::Voice(reference)]
        if reference.uuid.as_deref() == Some("voice-resource"))
    );
    let hidden_voice = OpaqueElement {
        scope: OpaqueScope::RichText,
        field: 4,
        payload: rpc::RichText {
            voice: vec![
                media_pb::Ptt {
                    md5: Some(Bytes::from_static(&[7; 16])),
                    ..Default::default()
                }
                .encode_to_vec()
                .into(),
            ],
            ..Default::default()
        }
        .encode_to_vec(),
    };
    assert!(super::codec::validate_metadata(&hidden_voice).is_err());
}

#[tokio::test]
async fn legacy_voice_remains_a_voice_in_private_and_group_history() {
    let client = Mock::new(|_, _, _| panic!("decoding a message must not request the network"));
    let messaging = service(client.clone());
    let state = client.snapshot().await;
    for group in [false, true] {
        let common = rpc::CommonMessage {
            routing_head: Some(rpc::RoutingHead {
                sender_uin: Some(200),
                sender_uid: "peer".into(),
                recipient_uin: Some(100),
                recipient_uid: "self-uid".into(),
                group: group.then_some(rpc::CommonGroup {
                    uin: Some(42),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            content_head: Some(rpc::ContentHead {
                message_type: Some(if group { 82 } else { 166 }),
                sequence: Some(77),
                time: Some(456),
                ..Default::default()
            }),
            message_body: rpc::MessageBody {
                rich_text: rpc::RichText {
                    voice: vec![Bytes::from_static(b"\x72\x0bprivate-key\x98\x01\x03")],
                    ..Default::default()
                }
                .encode_to_vec()
                .into(),
                ..Default::default()
            }
            .encode_to_vec()
            .into(),
        };
        let message = messaging
            .parse_message(&common.encode_to_vec(), &state)
            .unwrap();
        let [MessageElement::Voice(reference)] = message.elements.as_slice() else {
            panic!("voice lost: {:?}", message.elements);
        };
        assert_eq!(reference.duration, 3);
        assert_eq!(reference.conversation.is_group(), group);
        assert!(!message.is_recalled());
    }
}

#[tokio::test]
async fn content_free_pushes_remain_notifications_without_hiding_temporary_content() {
    let messaging = service(Mock::new(|_, _, _| {
        panic!("push decoding must not issue requests")
    }));
    let incoming = |body: Vec<u8>| {
        packet(rpc::CommonMessage {
            routing_head: Some(rpc::RoutingHead {
                sender_uin: Some(20),
                sender_uid: "sender".into(),
                recipient_uin: Some(30),
                recipient_uid: "recipient".into(),
                c2c: Some(rpc::CommonC2c {
                    source: Some(0),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            content_head: Some(rpc::ContentHead {
                message_type: Some(141),
                ..Default::default()
            }),
            message_body: body.into(),
        })
    };
    let metadata_only = rpc::MessageBody {
        rich_text: rpc::RichText {
            attr: vec![Bytes::from_static(b"attributes")],
            ..Default::default()
        }
        .encode_to_vec()
        .into(),
        ..Default::default()
    }
    .encode_to_vec();
    for body in [rpc::MessageBody::default().encode_to_vec(), metadata_only] {
        let input = incoming(body);
        let raw = input.body.to_vec();
        let events = messaging.decode_push(input).await;
        assert!(matches!(events.as_slice(),
            [PushEvent::Opaque { message_type: Some(141), payload, .. }] if payload == &raw
        ));
    }
    let input = incoming(encode_elements(&[MessageElement::Text("hello".into())], &[]).unwrap());
    let events = messaging.decode_push(input).await;
    let [PushEvent::Message { message }] = events.as_slice() else {
        panic!("source zero must not suppress a real temporary message");
    };
    assert!(matches!(
        message.conversation,
        Conversation::Temporary { source: 0, .. }
    ));
    assert!(matches!(message.elements.as_slice(), [MessageElement::Text(text)] if text == "hello"));

    let input = incoming(
        rpc::MessageBody {
            content: Some(Bytes::from_static(b"\xff")),
            ..Default::default()
        }
        .encode_to_vec(),
    );
    let events = messaging.decode_push(input).await;
    assert!(matches!(events.as_slice(),
        [PushEvent::Message { message }] if matches!(
            message.elements.as_slice(), [MessageElement::Opaque(element)]
            if element.scope == OpaqueScope::MessageBody && element.field == 2
        )
    ));
}

fn direct_gray_packet(sub_type: u64, parameters: &[(&str, &str)]) -> IncomingPacket {
    packet(rpc::CommonMessage {
        routing_head: Some(rpc::RoutingHead {
            sender_uin: Some(999),
            recipient_uin: Some(888),
            ..Default::default()
        }),
        content_head: Some(rpc::ContentHead {
            message_type: Some(528),
            sub_type: Some(sub_type),
            ..Default::default()
        }),
        message_body: rpc::MessageBody {
            content: Some(
                rpc::GrayTipPush {
                    r#type: 12,
                    parameters: parameters
                        .iter()
                        .map(|(key, value)| rpc::GrayTipParameter {
                            key: Some((*key).into()),
                            value: (*value).into(),
                        })
                        .collect(),
                }
                .encode_to_vec()
                .into(),
            ),
            ..Default::default()
        }
        .encode_to_vec()
        .into(),
    })
}

#[tokio::test]
async fn direct_poke_preserves_actor_target_and_template_without_contact_requests() {
    let messaging = service(Mock::new(|_, _, _| {
        panic!("poke decoding must not resolve contacts")
    }));
    for sub_type in [290, 291] {
        for (actor, target) in [("200", "100"), ("100", "200"), ("100", "100")] {
            let input = direct_gray_packet(
                sub_type,
                &[
                    ("uin_str1", actor),
                    ("uin_str2", target),
                    ("action_str", "戳了戳"),
                    ("suffix_str", "的肩膀"),
                    ("action_img_url", "https://example.invalid/poke.png"),
                    ("unknown_parameter", "preserved"),
                ],
            );
            let common = rpc::MessagePush::decode(input.body.clone()).unwrap();
            let common = rpc::CommonMessage::decode(common.common_message).unwrap();
            let expected_raw = rpc::MessageBody::decode(common.message_body)
                .unwrap()
                .content
                .unwrap();
            let events = messaging.decode_push(input).await;
            let [
                PushEvent::Poke {
                    group_uin,
                    actor_uin,
                    target_uin,
                    parameters,
                    raw,
                },
            ] = events.as_slice()
            else {
                panic!("expected direct poke, got {events:?}");
            };
            assert_eq!(*group_uin, None);
            assert_eq!(*actor_uin, Some(actor.parse().unwrap()));
            assert_eq!(*target_uin, Some(target.parse().unwrap()));
            assert_eq!(
                parameters.get("action_str").map(String::as_str),
                Some("戳了戳")
            );
            assert_eq!(
                parameters.get("suffix_str").map(String::as_str),
                Some("的肩膀")
            );
            assert_eq!(
                parameters.get("unknown_parameter").map(String::as_str),
                Some("preserved")
            );
            assert_eq!(raw.as_slice(), expected_raw.as_ref());
        }
    }
}

#[tokio::test]
async fn direct_gray_tips_without_a_valid_actor_stay_opaque() {
    let messaging = service(Mock::new(|_, _, _| {
        panic!("gray-tip decoding must not issue requests")
    }));
    for sub_type in [290, 291] {
        for actor in ["", "0", "-1", "invalid", "18446744073709551616"] {
            let input = direct_gray_packet(sub_type, &[("uin_str1", actor), ("uin_str2", "100")]);
            let raw = input.body.to_vec();
            let events = messaging.decode_push(input).await;
            assert!(matches!(events.as_slice(),
                [PushEvent::Opaque { message_type: Some(528), sub_type: Some(sub), payload, .. }]
                if *sub == sub_type && payload == &raw
            ));
        }
    }
    let input = direct_gray_packet(292, &[("uin_str1", "200"), ("uin_str2", "100")]);
    let raw = input.body.to_vec();
    assert!(matches!(messaging.decode_push(input).await.as_slice(),
        [PushEvent::Opaque { sub_type: Some(292), payload, .. }] if payload == &raw
    ));
}

fn buddy_request_packet(content: &[u8]) -> IncomingPacket {
    packet(rpc::CommonMessage {
        routing_head: Some(rpc::RoutingHead {
            sender_uin: Some(100),
            sender_uid: "self-uid".into(),
            recipient_uin: Some(100),
            recipient_uid: "self-uid".into(),
            ..Default::default()
        }),
        content_head: Some(rpc::ContentHead {
            message_type: Some(528),
            sub_type: Some(35),
            c2c_command: Some(35),
            ..Default::default()
        }),
        message_body: rpc::MessageBody {
            content: Some(Bytes::copy_from_slice(content)),
            ..Default::default()
        }
        .encode_to_vec()
        .into(),
    })
}

#[tokio::test]
async fn friend_request_control_notice_preserves_type_and_payload() {
    let messaging = service(Mock::new(|_, _, _| {
        panic!("push decoding must not issue requests")
    }));
    let input = buddy_request_packet(&[0x1a, 0x02, 0x08, 0x00]);
    let raw = input.body.to_vec();
    let events = messaging.decode_push(input).await;
    assert!(matches!(
        events.as_slice(),
        [PushEvent::Opaque {
            message_type: Some(528),
            sub_type: Some(35),
            payload,
            ..
        }] if payload == &raw
    ));
}

#[tokio::test]
async fn friend_request_push_emits_every_request_in_order() {
    let messaging = service(Mock::new(|_, _, _| {
        panic!("push decoding must not issue requests")
    }));
    let content = rpc::FriendRequestPush {
        requests: vec![
            rpc::FriendRequestInfo {
                target_uid: "self-uid".into(),
                source_uid: "requester-a".into(),
                message: "first request".into(),
                source: "source-a".into(),
            },
            rpc::FriendRequestInfo {
                target_uid: "self-uid".into(),
                source_uid: "requester-b".into(),
                message: "second request".into(),
                source: "source-b".into(),
            },
        ],
    }
    .encode_to_vec();
    let events = messaging.decode_push(buddy_request_packet(&content)).await;
    assert!(matches!(
        events.as_slice(),
        [
            PushEvent::FriendRequest {
                source_uid: first,
                target_uid: first_target,
                message: first_message,
                source: first_source,
                raw: first_raw,
                ..
            },
            PushEvent::FriendRequest {
                source_uid: second,
                target_uid: second_target,
                message: second_message,
                source: second_source,
                raw: second_raw,
                ..
            }
        ] if first == "requester-a"
            && second == "requester-b"
            && first_target == "self-uid"
            && second_target == "self-uid"
            && first_message == "first request"
            && second_message == "second request"
            && first_source == "source-a"
            && second_source == "source-b"
            && first_raw == &content
            && second_raw == &content
    ));
}

#[tokio::test]
async fn malformed_friend_request_content_keeps_error_fallback() {
    let messaging = service(Mock::new(|_, _, _| {
        panic!("push decoding must not issue requests")
    }));
    let input = buddy_request_packet(&[0x0a, 0x04, 0x12]);
    let raw = input.body.to_vec();
    let events = messaging.decode_push(input).await;
    assert!(matches!(
        events.as_slice(),
        [PushEvent::Opaque {
            message_type: None,
            sub_type: None,
            payload,
            ..
        }] if payload == &raw
    ));
}
