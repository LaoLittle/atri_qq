use super::models::{GuildElement, GuildMessage};
use crate::proto::{guild as guild_pb, messages as pb};
#[cfg(test)]
use bytes::Bytes;
use prost::Message;
use prost_reflect::DynamicMessage;

pub(super) fn text_body(text: &str) -> guild_pb::TextMessageBody {
    guild_pb::TextMessageBody {
        rich_text: Some(guild_pb::TextRichText {
            elems: vec![guild_pb::TextElement {
                text: Some(pb::Text {
                    text: Some(text.to_owned()),
                    ..Default::default()
                }),
            }],
        }),
    }
}

#[cfg(test)]
pub(super) fn encode_text(text: &str) -> Bytes {
    text_body(text).encode_to_vec().into()
}

fn retain_opaque(
    elements: &mut Vec<GuildElement>,
    name: &str,
    raw: &[u8],
    interpreted: &[u32],
) -> crate::Result<()> {
    let descriptor = crate::proto::descriptor_pool()
        .get_message_by_name(name)
        .expect("compiled message descriptor");
    let message = DynamicMessage::decode(descriptor.clone(), raw)?;
    for (field, value) in message.fields() {
        if !interpreted.contains(&field.number()) {
            let mut retained = DynamicMessage::new(descriptor.clone());
            retained.set_field(&field, value.clone());
            elements.push(GuildElement::Opaque {
                field: field.number(),
                payload: retained.encode_to_vec(),
            });
        }
    }
    for field in message.unknown_fields() {
        let mut payload = Vec::new();
        field.encode(&mut payload);
        elements.push(GuildElement::Opaque {
            field: field.number(),
            payload,
        });
    }
    Ok(())
}

fn decode_elements(raw: &[u8]) -> crate::Result<Vec<GuildElement>> {
    let body: pb::MessageBody = crate::proto::decode(raw)?;
    let rich: pb::RichText = crate::proto::decode(body.rich_text.as_ref())?;
    let mut elements = Vec::new();
    for raw_element in &rich.elems {
        let element: pb::Elem = crate::proto::decode(raw_element.as_ref())?;
        for raw_text in element.text {
            let text: pb::Text = crate::proto::decode(raw_text.as_ref())?;
            let reserve: guild_pb::MentionReserve = crate::proto::decode(text.reserve.as_ref())?;
            let Some(display) = text.text else {
                elements.push(GuildElement::Opaque {
                    field: 1,
                    payload: pb::Elem {
                        text: vec![raw_text],
                        ..Default::default()
                    }
                    .encode_to_vec(),
                });
                continue;
            };
            match (reserve.kind, reserve.tiny_id.filter(|id| *id > 0)) {
                (Some(1), _) => elements.push(GuildElement::Mention {
                    tiny_id: None,
                    display,
                    everyone: true,
                }),
                (Some(2), Some(tiny_id)) => elements.push(GuildElement::Mention {
                    tiny_id: Some(tiny_id),
                    display,
                    everyone: false,
                }),
                _ => elements.push(GuildElement::Text { text: display }),
            }
            retain_opaque(
                &mut elements,
                "atri.qq.messages.Text",
                raw_text.as_ref(),
                &[1, 12],
            )?;
        }
        retain_opaque(
            &mut elements,
            "atri.qq.messages.Elem",
            raw_element.as_ref(),
            &[1, 9, 16, 37],
        )?;
    }
    retain_opaque(
        &mut elements,
        "atri.qq.messages.RichText",
        body.rich_text.as_ref(),
        &[1, 2],
    )?;
    retain_opaque(&mut elements, "atri.qq.messages.MessageBody", raw, &[1])?;
    Ok(elements)
}

pub(super) fn decode_message(
    raw: &[u8],
    self_tiny_id: Option<u64>,
    own_uin: u64,
) -> crate::Result<Option<GuildMessage>> {
    let message: guild_pb::ChannelMessage = crate::proto::decode(raw)?;
    let Some(head) = message.head else {
        return Ok(None);
    };
    let (Some(routing), Some(content)) = (head.routing, head.content) else {
        return Ok(None);
    };
    let (Some(guild_id), Some(channel_id)) = (
        routing.guild_id.filter(|id| *id > 0),
        routing.channel_id.filter(|id| *id > 0),
    ) else {
        return Ok(None);
    };
    if content.message_type != Some(3840)
        || routing.direct_message_flag.unwrap_or_default() != 0
        || (!content.sequence.is_some_and(|value| value > 0)
            && !content.random.is_some_and(|value| value > 0))
    {
        return Ok(None);
    }
    let body = message
        .body
        .ok_or_else(|| crate::Error::Malformed("Guild channel message has no body".into()))?;
    let elements = decode_elements(&body)?;
    if elements.is_empty() {
        return Ok(None);
    }
    let sender_tiny_id = routing.sender_tiny_id.filter(|id| *id > 0);
    let is_self = match self_tiny_id.filter(|id| *id > 0) {
        Some(tiny_id) => sender_tiny_id == Some(tiny_id),
        None => own_uin > 0 && routing.sender_uin == Some(own_uin),
    };
    let sender_name = message
        .extension
        .and_then(|extension| {
            extension
                .member_name
                .filter(|name| !name.is_empty())
                .or(extension.sender_name)
        })
        .map(|name| String::from_utf8_lossy(&name).into_owned())
        .unwrap_or_default();
    Ok(Some(GuildMessage {
        guild_id,
        channel_id,
        sender_tiny_id,
        sender_name,
        is_self,
        sequence: content.sequence,
        count_sequence: content.count_sequence,
        random: content.random,
        time: content.time,
        elements,
        raw: raw.to_vec(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn channel_message(body: Bytes) -> guild_pb::ChannelMessage {
        guild_pb::ChannelMessage {
            head: Some(guild_pb::MessageHead {
                routing: Some(guild_pb::RoutingHead {
                    guild_id: Some(100),
                    channel_id: Some(200),
                    sender_uin: Some(300),
                    sender_tiny_id: Some(400),
                    direct_message_flag: Some(0),
                    ..Default::default()
                }),
                content: Some(guild_pb::ContentHead {
                    message_type: Some(3840),
                    sequence: Some(12),
                    ..Default::default()
                }),
            }),
            body: Some(body),
            ..Default::default()
        }
    }

    fn body(elems: Vec<Bytes>) -> Bytes {
        pb::MessageBody {
            rich_text: pb::RichText {
                elems,
                ..Default::default()
            }
            .encode_to_vec()
            .into(),
            ..Default::default()
        }
        .encode_to_vec()
        .into()
    }

    fn text(display: &str, reserve: guild_pb::MentionReserve) -> Bytes {
        pb::Elem {
            text: vec![
                pb::Text {
                    text: Some(display.to_owned()),
                    reserve: reserve.encode_to_vec().into(),
                }
                .encode_to_vec()
                .into(),
            ],
            ..Default::default()
        }
        .encode_to_vec()
        .into()
    }

    #[test]
    fn outbound_text_has_exact_message_body_framing() {
        let encoded = encode_text("hello");
        assert_eq!(encoded.as_ref(), b"\x0a\x0b\x12\x09\x0a\x07\x0a\x05hello");
        let raw = channel_message(encoded).encode_to_vec();
        let decoded = decode_message(&raw, None, 300).unwrap().unwrap();
        assert_eq!(
            decoded.elements,
            vec![GuildElement::Text {
                text: "hello".into()
            }]
        );
        assert_eq!(decoded.raw, raw);
    }

    #[test]
    fn guild_mentions_use_tiny_ids_and_ignore_protocol_metadata() {
        let mut member: pb::Elem = crate::proto::decode(
            text(
                "@member",
                guild_pb::MentionReserve {
                    kind: Some(2),
                    member_uin: Some(999),
                    tiny_id: Some(42),
                },
            )
            .as_ref(),
        )
        .unwrap();
        member.flags2.push(Bytes::from_static(b"flags"));
        member.extra_info.push(Bytes::from_static(b"extra"));
        member.general_flags.push(Bytes::from_static(b"general"));
        let metadata = pb::Elem {
            flags2: vec![Bytes::from_static(b"not content")],
            extra_info: vec![Bytes::from_static(b"not content")],
            general_flags: vec![Bytes::from_static(b"not content")],
            ..Default::default()
        };
        let raw = channel_message(body(vec![
            text("before", Default::default()),
            member.encode_to_vec().into(),
            metadata.encode_to_vec().into(),
            text(
                "@everyone",
                guild_pb::MentionReserve {
                    kind: Some(1),
                    tiny_id: Some(999),
                    ..Default::default()
                },
            ),
            text("after", Default::default()),
        ]))
        .encode_to_vec();
        let decoded = decode_message(&raw, None, 300).unwrap().unwrap();
        assert_eq!(
            decoded.elements,
            vec![
                GuildElement::Text {
                    text: "before".into()
                },
                GuildElement::Mention {
                    tiny_id: Some(42),
                    display: "@member".into(),
                    everyone: false
                },
                GuildElement::Mention {
                    tiny_id: None,
                    display: "@everyone".into(),
                    everyone: true
                },
                GuildElement::Text {
                    text: "after".into()
                },
            ]
        );
        assert_eq!(decoded.raw, raw);
    }

    #[test]
    fn invalid_and_unknown_mentions_stay_text() {
        let elems = [
            guild_pb::MentionReserve {
                kind: Some(2),
                member_uin: Some(42),
                tiny_id: None,
            },
            guild_pb::MentionReserve {
                kind: Some(2),
                member_uin: Some(42),
                tiny_id: Some(0),
            },
            guild_pb::MentionReserve {
                kind: Some(3),
                member_uin: None,
                tiny_id: Some(42),
            },
            guild_pb::MentionReserve {
                kind: None,
                member_uin: None,
                tiny_id: Some(42),
            },
        ]
        .into_iter()
        .map(|reserve| text("@visible", reserve))
        .collect();
        let decoded = decode_message(&channel_message(body(elems)).encode_to_vec(), None, 300)
            .unwrap()
            .unwrap();
        assert_eq!(
            decoded.elements,
            vec![
                GuildElement::Text {
                    text: "@visible".into()
                };
                4
            ]
        );
    }

    #[test]
    fn protocol_metadata_without_renderable_elements_is_not_a_user_message() {
        let body = pb::MessageBody {
            rich_text: pb::RichText {
                attr: vec![Bytes::from_static(b"\x08\x01")],
                ..Default::default()
            }
            .encode_to_vec()
            .into(),
            ..Default::default()
        }
        .encode_to_vec()
        .into();
        assert_eq!(
            decode_message(&channel_message(body).encode_to_vec(), None, 300).unwrap(),
            None
        );
    }

    #[test]
    fn unsupported_and_unknown_elements_do_not_swallow_adjacent_text() {
        let unsupported = pb::Elem {
            common: vec![Bytes::from_static(b"unsupported media")],
            ..Default::default()
        }
        .encode_to_vec();
        let unknown = b"\xba\x3e\x06future".to_vec();
        let decoded = decode_message(
            &channel_message(body(vec![
                text("left", Default::default()),
                unsupported.clone().into(),
                unknown.clone().into(),
                text("right", Default::default()),
            ]))
            .encode_to_vec(),
            None,
            300,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            decoded.elements,
            vec![
                GuildElement::Text {
                    text: "left".into()
                },
                GuildElement::Opaque {
                    field: 53,
                    payload: unsupported
                },
                GuildElement::Opaque {
                    field: 999,
                    payload: unknown
                },
                GuildElement::Text {
                    text: "right".into()
                },
            ]
        );
    }

    #[test]
    fn sender_identity_never_compares_tiny_id_to_uin() {
        let mut message = channel_message(encode_text("identity"));
        let routing = message.head.as_mut().unwrap().routing.as_mut().unwrap();
        routing.sender_tiny_id = Some(300);
        routing.sender_uin = Some(500);
        let raw = message.encode_to_vec();
        assert!(!decode_message(&raw, None, 300).unwrap().unwrap().is_self);
        assert!(
            decode_message(&raw, Some(300), 500)
                .unwrap()
                .unwrap()
                .is_self
        );
        assert!(
            !decode_message(&raw, Some(400), 500)
                .unwrap()
                .unwrap()
                .is_self
        );
        message
            .head
            .as_mut()
            .unwrap()
            .routing
            .as_mut()
            .unwrap()
            .sender_tiny_id = Some(0);
        let raw = message.encode_to_vec();
        let decoded = decode_message(&raw, None, 500).unwrap().unwrap();
        assert_eq!(decoded.sender_tiny_id, None);
        assert!(decoded.is_self);
        assert!(
            !decode_message(&raw, Some(400), 500)
                .unwrap()
                .unwrap()
                .is_self
        );
        message
            .head
            .as_mut()
            .unwrap()
            .routing
            .as_mut()
            .unwrap()
            .sender_uin = Some(0);
        assert!(
            !decode_message(&message.encode_to_vec(), None, 0)
                .unwrap()
                .unwrap()
                .is_self
        );
    }

    #[test]
    fn direct_messages_and_non_chat_notifications_stay_opaque() {
        let mut message = channel_message(Bytes::from_static(b"\x80"));
        message
            .head
            .as_mut()
            .unwrap()
            .routing
            .as_mut()
            .unwrap()
            .direct_message_flag = Some(1);
        assert!(
            decode_message(&message.encode_to_vec(), None, 300)
                .unwrap()
                .is_none()
        );
        message
            .head
            .as_mut()
            .unwrap()
            .routing
            .as_mut()
            .unwrap()
            .direct_message_flag = Some(0);
        message
            .head
            .as_mut()
            .unwrap()
            .content
            .as_mut()
            .unwrap()
            .message_type = Some(3841);
        assert!(
            decode_message(&message.encode_to_vec(), None, 300)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn routing_and_positive_reference_are_required_before_decoding_body() {
        let message = channel_message(Bytes::from_static(b"\x80"));
        for id in [None, Some(0)] {
            let mut invalid = message.clone();
            invalid
                .head
                .as_mut()
                .unwrap()
                .routing
                .as_mut()
                .unwrap()
                .guild_id = id;
            assert!(
                decode_message(&invalid.encode_to_vec(), None, 300)
                    .unwrap()
                    .is_none()
            );
            let mut invalid = message.clone();
            invalid
                .head
                .as_mut()
                .unwrap()
                .routing
                .as_mut()
                .unwrap()
                .channel_id = id;
            assert!(
                decode_message(&invalid.encode_to_vec(), None, 300)
                    .unwrap()
                    .is_none()
            );
        }
        let mut invalid = message.clone();
        invalid.head = None;
        assert!(
            decode_message(&invalid.encode_to_vec(), None, 300)
                .unwrap()
                .is_none()
        );
        let mut invalid = message.clone();
        invalid.head.as_mut().unwrap().routing = None;
        assert!(
            decode_message(&invalid.encode_to_vec(), None, 300)
                .unwrap()
                .is_none()
        );
        let mut invalid = message.clone();
        invalid.head.as_mut().unwrap().content = None;
        assert!(
            decode_message(&invalid.encode_to_vec(), None, 300)
                .unwrap()
                .is_none()
        );
        for sequence in [None, Some(0)] {
            for random in [None, Some(0)] {
                let mut invalid = message.clone();
                let content = invalid.head.as_mut().unwrap().content.as_mut().unwrap();
                content.sequence = sequence;
                content.random = random;
                assert!(
                    decode_message(&invalid.encode_to_vec(), None, 300)
                        .unwrap()
                        .is_none()
                );
            }
        }
    }

    #[test]
    fn random_only_messages_preserve_absent_and_zero_server_values() {
        let mut message = channel_message(encode_text("pending"));
        let content = message.head.as_mut().unwrap().content.as_mut().unwrap();
        content.sequence = None;
        content.random = Some(99);
        content.time = None;
        let decoded = decode_message(&message.encode_to_vec(), None, 300)
            .unwrap()
            .unwrap();
        assert_eq!(decoded.sequence, None);
        assert_eq!(decoded.time, None);
        assert_eq!(decoded.random, Some(99));
        let content = message.head.as_mut().unwrap().content.as_mut().unwrap();
        content.sequence = Some(0);
        content.time = Some(0);
        let decoded = decode_message(&message.encode_to_vec(), None, 300)
            .unwrap()
            .unwrap();
        assert_eq!(decoded.sequence, Some(0));
        assert_eq!(decoded.time, Some(0));
    }

    #[test]
    fn member_name_precedes_sender_name_and_empty_member_falls_back() {
        let mut message = channel_message(encode_text("names"));
        message.extension = Some(guild_pb::MessageExtension {
            member_name: Some(Bytes::from_static(b"member")),
            sender_name: Some(Bytes::from_static(b"sender")),
            ..Default::default()
        });
        assert_eq!(
            decode_message(&message.encode_to_vec(), None, 300)
                .unwrap()
                .unwrap()
                .sender_name,
            "member"
        );
        message.extension.as_mut().unwrap().member_name = Some(Bytes::new());
        assert_eq!(
            decode_message(&message.encode_to_vec(), None, 300)
                .unwrap()
                .unwrap()
                .sender_name,
            "sender"
        );
    }

    #[test]
    fn malformed_protobuf_at_each_interpreted_boundary_is_an_error() {
        assert!(decode_message(b"\x80", None, 300).is_err());
        let malformed = Bytes::from_static(b"\x80");
        let malformed_text = pb::Elem {
            text: vec![malformed.clone()],
            ..Default::default()
        }
        .encode_to_vec()
        .into();
        let malformed_reserve = pb::Elem {
            text: vec![
                pb::Text {
                    text: Some("@broken".into()),
                    reserve: malformed.clone(),
                }
                .encode_to_vec()
                .into(),
            ],
            ..Default::default()
        }
        .encode_to_vec()
        .into();
        let malformed_rich = pb::MessageBody {
            rich_text: malformed.clone(),
            ..Default::default()
        }
        .encode_to_vec()
        .into();
        for invalid_body in [
            malformed.clone(),
            malformed_rich,
            body(vec![malformed]),
            body(vec![malformed_text]),
            body(vec![malformed_reserve]),
        ] {
            assert!(
                decode_message(&channel_message(invalid_body).encode_to_vec(), None, 300).is_err()
            );
        }
        let mut missing_body = channel_message(Bytes::new());
        missing_body.body = None;
        assert!(decode_message(&missing_body.encode_to_vec(), None, 300).is_err());
    }
}
