use crate::adapter::{Services, protocol_error};
use atri_core::{
    ApiError, ConversationKind, ConversationRef, EventKind, MessageAuthor, MessageContent,
    MessageReceived, MessageRef, SendMessage, UserIdentity, Value, encode, to_value,
};
use atri_extensions::Context;
use atri_qq_protocol::guild::{GuildElement, GuildEvent, GuildMessage, SendReceipt};
use std::{collections::BTreeMap, future::Future};

const ELEMENT_FORMAT: &str = "qq.guild.element.cbor";

fn user(account: &str, tiny_id: Option<u64>, name: &str) -> Option<UserIdentity> {
    tiny_id.filter(|id| *id != 0).map(|id| UserIdentity {
        account: account.into(),
        id: format!("tiny:{id}"),
        display_name: (!name.is_empty()).then(|| name.to_owned()),
    })
}

fn message_id(sequence: Option<u64>, random: Option<u64>) -> Option<String> {
    sequence
        .filter(|value| *value != 0)
        .map(|value| format!("seq:{value}"))
        .or_else(|| {
            random
                .filter(|value| *value != 0)
                .map(|value| format!("random:{value}"))
        })
}

fn content(account: &str, elements: &[GuildElement]) -> Result<MessageContent, ApiError> {
    let mut parts = Vec::with_capacity(elements.len());
    for element in elements {
        let part = match element {
            GuildElement::Text { text } => MessageContent::Text(text.clone()),
            GuildElement::Mention {
                tiny_id,
                display,
                everyone,
            } if *everyone || tiny_id.is_some_and(|id| id != 0) => MessageContent::Mention {
                user: user(account, *tiny_id, display),
                everyone: *everyone,
            },
            _ => MessageContent::Opaque {
                format: ELEMENT_FORMAT.into(),
                data: encode(element)?,
            },
        };
        parts.push(part);
    }
    Ok(if parts.len() == 1 {
        parts.pop().expect("one guild content part")
    } else {
        MessageContent::Composite(parts)
    })
}

fn received(account: &str, message: &GuildMessage) -> Result<Option<MessageReceived>, ApiError> {
    let Some(id) = message_id(message.sequence, message.random) else {
        return Ok(None);
    };
    if message.guild_id == 0 || message.channel_id == 0 {
        return Ok(None);
    }
    let identity = user(account, message.sender_tiny_id, &message.sender_name);
    let mut metadata = BTreeMap::new();
    metadata.insert("qq.guild.id".into(), to_value(&message.guild_id)?);
    metadata.insert("qq.guild.channel_id".into(), to_value(&message.channel_id)?);
    metadata.insert("qq.guild.sequence".into(), to_value(&message.sequence)?);
    metadata.insert(
        "qq.guild.count_sequence".into(),
        to_value(&message.count_sequence)?,
    );
    metadata.insert("qq.guild.random".into(), to_value(&message.random)?);
    metadata.insert("qq.guild.time".into(), to_value(&message.time)?);
    metadata.insert(
        "qq.guild.sender_tiny_id".into(),
        to_value(&message.sender_tiny_id)?,
    );
    metadata.insert(
        "qq.guild.sender_name".into(),
        Value::Text(message.sender_name.clone()),
    );
    metadata.insert("qq.guild.elements".into(), to_value(&message.elements)?);
    metadata.insert("qq.guild.raw".into(), Value::Bytes(message.raw.clone()));
    Ok(Some(MessageReceived {
        reference: MessageRef {
            conversation: ConversationRef {
                account: account.into(),
                id: format!("guild:{}:channel:{}", message.guild_id, message.channel_id),
                kind: ConversationKind::Channel,
            },
            id,
        },
        author: MessageAuthor {
            kind: if identity.is_some() {
                "user"
            } else {
                "unknown"
            }
            .into(),
            user: identity,
            is_self: message.is_self,
            is_bot: message.is_self,
        },
        content: content(account, &message.elements)?,
        metadata,
    }))
}

fn publication(account: &str, event: &GuildEvent) -> Result<(EventKind, Value), ApiError> {
    if let GuildEvent::Message { message } = event {
        if let Some(message) = received(account, message)? {
            return Ok((EventKind::MessageReceived, to_value(&message)?));
        }
    }
    Ok((
        EventKind::Custom("qq.guild.notification".into()),
        to_value(event)?,
    ))
}

pub(crate) async fn publish(
    ctx: &Context,
    account: &str,
    event: GuildEvent,
) -> Result<(), ApiError> {
    let (kind, payload) = publication(account, &event)?;
    ctx.emit(kind, Some(account), &payload).await?;
    Ok(())
}

fn positive_id(value: &str) -> Result<u64, ApiError> {
    if value.starts_with('0') || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ApiError::new(
            "qq.invalid_identity",
            "guild and channel IDs require canonical positive decimal integers",
        ));
    }
    value
        .parse()
        .map_err(|_| ApiError::new("qq.invalid_identity", "invalid guild or channel identifier"))
}

fn target(account: &str, conversation: &ConversationRef) -> Result<(u64, u64), ApiError> {
    if conversation.account != account {
        return Err(ApiError::new(
            "account_mismatch",
            "channel belongs to another QQ account",
        ));
    }
    if conversation.kind != ConversationKind::Channel {
        return Err(ApiError::new(
            "qq.invalid_identity",
            "expected a channel conversation",
        ));
    }
    let mut parts = conversation.id.split(':');
    match (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) {
        (Some("guild"), Some(guild), Some("channel"), Some(channel), None) => {
            Ok((positive_id(guild)?, positive_id(channel)?))
        }
        _ => Err(ApiError::new(
            "qq.invalid_identity",
            "expected guild:{guild_id}:channel:{channel_id} conversation",
        )),
    }
}

pub(crate) fn text_content(content: MessageContent) -> Result<String, ApiError> {
    if let MessageContent::Text(text) = content {
        return Ok(text);
    }
    let mut pending = vec![content];
    let mut text = String::new();
    while let Some(part) = pending.pop() {
        match part {
            MessageContent::Text(part) => {
                if text.is_empty() {
                    text = part;
                } else {
                    text.push_str(&part);
                }
            }
            MessageContent::Composite(parts) => pending.extend(parts.into_iter().rev()),
            _ => {
                return Err(ApiError::unsupported(
                    "QQ guild channels currently support only text and text-only composites",
                ));
            }
        }
    }
    Ok(text)
}

async fn send_with<F, Fut>(
    account: &str,
    outbound: SendMessage,
    send_text: F,
) -> Result<Value, ApiError>
where
    F: FnOnce(u64, u64, String) -> Fut,
    Fut: Future<Output = Result<SendReceipt, ApiError>>,
{
    let (guild_id, channel_id) = target(account, &outbound.conversation)?;
    let text = text_content(outbound.content)?;
    let receipt = send_text(guild_id, channel_id, text).await?;
    if receipt.guild_id != guild_id || receipt.channel_id != channel_id {
        return Err(ApiError::new(
            "qq.invalid_identity",
            "guild send receipt belongs to another channel",
        ));
    }
    let id = message_id(receipt.sequence, Some(receipt.random)).ok_or_else(|| {
        ApiError::new(
            "qq.invalid_reference",
            "guild send returned no message identifier",
        )
    })?;
    to_value(&MessageRef {
        conversation: outbound.conversation,
        id,
    })
}

pub(crate) async fn send(services: &Services, outbound: SendMessage) -> Result<Value, ApiError> {
    let account = format!("qq:{}", services.client.account_uin());
    send_with(
        &account,
        outbound,
        |guild_id, channel_id, text| async move {
            services
                .guild
                .send_text(guild_id, channel_id, &text)
                .await
                .map_err(protocol_error)
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use atri_core::{decode, from_value};
    use std::cell::Cell;

    fn channel() -> ConversationRef {
        ConversationRef {
            account: "qq:42".into(),
            id: "guild:100:channel:200".into(),
            kind: ConversationKind::Channel,
        }
    }

    fn native() -> GuildMessage {
        GuildMessage {
            guild_id: 100,
            channel_id: 200,
            sender_tiny_id: Some(42),
            sender_name: "Guild author".into(),
            is_self: false,
            sequence: Some(8),
            count_sequence: Some(7),
            random: Some(9),
            time: Some(123),
            elements: vec![GuildElement::Text {
                text: "body only".into(),
            }],
            raw: b"wire bytes, not body".to_vec(),
        }
    }

    fn receipt() -> SendReceipt {
        SendReceipt {
            guild_id: 100,
            channel_id: 200,
            sequence: Some(0),
            time: Some(0),
            random: 99,
        }
    }

    #[test]
    fn incoming_body_metadata_and_tiny_identity_are_separate() {
        let native = native();
        let received = received("qq:42", &native).unwrap().unwrap();
        assert_eq!(received.reference.conversation, channel());
        assert_eq!(received.reference.id, "seq:8");
        let author = received.author.user.unwrap();
        assert_eq!(author.account, "qq:42");
        assert_eq!(author.id, "tiny:42");
        assert!(matches!(received.content, MessageContent::Text(text) if text == "body only"));
        assert_eq!(received.metadata["qq.guild.raw"], Value::Bytes(native.raw));
        assert_eq!(
            from_value::<u64>(&received.metadata["qq.guild.id"]).unwrap(),
            100
        );
        assert_eq!(
            from_value::<u64>(&received.metadata["qq.guild.channel_id"]).unwrap(),
            200
        );
        assert_eq!(
            from_value::<Option<u64>>(&received.metadata["qq.guild.time"]).unwrap(),
            Some(123)
        );
        assert_eq!(
            from_value::<Option<u64>>(&received.metadata["qq.guild.sequence"]).unwrap(),
            Some(8)
        );
        assert_eq!(
            from_value::<Option<u64>>(&received.metadata["qq.guild.count_sequence"]).unwrap(),
            Some(7)
        );
        assert_eq!(
            from_value::<Option<u64>>(&received.metadata["qq.guild.random"]).unwrap(),
            Some(9)
        );
    }

    #[test]
    fn mentions_and_unknown_elements_preserve_their_semantics() {
        let elements = vec![
            GuildElement::Mention {
                tiny_id: Some(42),
                display: "@Guild author".into(),
                everyone: false,
            },
            GuildElement::Mention {
                tiny_id: None,
                display: "@all".into(),
                everyone: true,
            },
            GuildElement::Opaque {
                field: 37,
                payload: vec![0, 255, 7],
            },
            GuildElement::Mention {
                tiny_id: Some(0),
                display: "unresolved".into(),
                everyone: false,
            },
        ];
        let MessageContent::Composite(parts) = content("qq:84", &elements).unwrap() else {
            panic!()
        };
        assert!(
            matches!(&parts[0], MessageContent::Mention { user: Some(user), everyone: false } if user.id == "tiny:42" && user.account == "qq:84")
        );
        assert!(matches!(
            &parts[1],
            MessageContent::Mention {
                user: None,
                everyone: true
            }
        ));
        for index in [2, 3] {
            let MessageContent::Opaque { format, data } = &parts[index] else {
                panic!()
            };
            assert_eq!(format, ELEMENT_FORMAT);
            assert_eq!(decode::<GuildElement>(data).unwrap(), elements[index]);
        }
    }

    #[test]
    fn opaque_and_unreferenced_messages_remain_raw_notifications() {
        let event = GuildEvent::Opaque {
            command: "guild.push".into(),
            payload: vec![1, 2, 255],
        };
        let (kind, value) = publication("qq:42", &event).unwrap();
        assert!(matches!(kind, EventKind::Custom(name) if name == "qq.guild.notification"));
        assert_eq!(from_value::<GuildEvent>(&value).unwrap(), event);
        let mut message = native();
        message.sequence = Some(0);
        message.random = None;
        let event = GuildEvent::Message { message };
        let (kind, value) = publication("qq:42", &event).unwrap();
        assert!(matches!(kind, EventKind::Custom(name) if name == "qq.guild.notification"));
        assert_eq!(from_value::<GuildEvent>(&value).unwrap(), event);
        for (guild_id, channel_id) in [(0, 200), (100, 0)] {
            let message = GuildMessage {
                guild_id,
                channel_id,
                ..native()
            };
            let event = GuildEvent::Message { message };
            let (kind, value) = publication("qq:42", &event).unwrap();
            assert!(matches!(kind, EventKind::Custom(name) if name == "qq.guild.notification"));
            assert_eq!(from_value::<GuildEvent>(&value).unwrap(), event);
        }
    }

    #[test]
    fn zero_sequence_uses_random_and_missing_tiny_id_stays_unknown() {
        let mut message = native();
        message.sequence = Some(0);
        message.sender_tiny_id = None;
        let message = received("qq:42", &message).unwrap().unwrap();
        assert_eq!(message.reference.id, "random:9");
        assert!(message.author.user.is_none());
        assert_eq!(message.author.kind, "unknown");
    }

    #[tokio::test]
    async fn unsupported_content_never_reaches_guild_sync_or_send() {
        let calls = Cell::new(0);
        let contents = vec![
            MessageContent::Mention {
                user: Some(UserIdentity {
                    account: "qq:42".into(),
                    id: "tiny:42".into(),
                    display_name: None,
                }),
                everyone: false,
            },
            MessageContent::Reply {
                reference: MessageRef {
                    conversation: channel(),
                    id: "seq:8".into(),
                },
                content: Box::new(MessageContent::Text("reply text".into())),
            },
            MessageContent::Media {
                kind: "image".into(),
                handle: "https://example.invalid/image".into(),
                metadata: BTreeMap::new(),
            },
            MessageContent::Opaque {
                format: ELEMENT_FORMAT.into(),
                data: vec![1, 2],
            },
            MessageContent::Forward { records: vec![] },
        ];
        for content in contents {
            let outbound = SendMessage {
                conversation: channel(),
                content: MessageContent::Composite(vec![
                    MessageContent::Text("valid prefix".into()),
                    MessageContent::Composite(vec![content]),
                ]),
            };
            let error = send_with("qq:42", outbound, |_, _, _| {
                calls.set(calls.get() + 1);
                std::future::ready(Ok(receipt()))
            })
            .await
            .unwrap_err();
            assert_eq!(error.code, "unsupported");
        }
        assert_eq!(calls.get(), 0);
    }

    #[tokio::test]
    async fn account_and_identity_confusion_are_rejected_before_send() {
        let calls = Cell::new(0);
        for id in [
            "group:100",
            "dm:tiny:42",
            "guild:100:channel:tiny:200",
            "guild:0:channel:200",
            "guild:100:channel:0",
            "guild:100:channel:200:extra",
            "guild:+100:channel:200",
            "guild:01:channel:200",
            "guild:18446744073709551616:channel:200",
        ] {
            let mut conversation = channel();
            conversation.id = id.into();
            let error = send_with(
                "qq:42",
                SendMessage {
                    conversation,
                    content: "text".into(),
                },
                |_, _, _| {
                    calls.set(calls.get() + 1);
                    std::future::ready(Ok(receipt()))
                },
            )
            .await
            .unwrap_err();
            assert_eq!(error.code, "qq.invalid_identity");
        }
        let error = send_with(
            "qq:84",
            SendMessage {
                conversation: channel(),
                content: "text".into(),
            },
            |_, _, _| {
                calls.set(calls.get() + 1);
                std::future::ready(Ok(receipt()))
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "account_mismatch");
        let mut conversation = channel();
        conversation.kind = ConversationKind::Direct;
        let error = send_with(
            "qq:42",
            SendMessage {
                conversation,
                content: "text".into(),
            },
            |_, _, _| {
                calls.set(calls.get() + 1);
                std::future::ready(Ok(receipt()))
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "qq.invalid_identity");
        assert_eq!(calls.get(), 0);
    }

    #[tokio::test]
    async fn text_composites_keep_order_and_exact_conversation_in_receipts() {
        for sequence in [None, Some(0), Some(7)] {
            let outbound = SendMessage {
                conversation: channel(),
                content: MessageContent::Composite(vec![
                    "hello ".into(),
                    MessageContent::Composite(vec!["频道".into(), "!".into()]),
                ]),
            };
            let response = send_with("qq:42", outbound, |guild, channel, text| {
                assert_eq!((guild, channel), (100, 200));
                assert_eq!(text, "hello 频道!");
                std::future::ready(Ok(SendReceipt {
                    sequence,
                    ..receipt()
                }))
            })
            .await
            .unwrap();
            let reference: MessageRef = from_value(&response).unwrap();
            assert_eq!(reference.conversation, channel());
            assert_eq!(
                reference.id,
                if sequence == Some(7) {
                    "seq:7"
                } else {
                    "random:99"
                }
            );
        }
    }

    #[tokio::test]
    async fn invalid_receipts_do_not_fabricate_references() {
        for receipt in [
            SendReceipt {
                guild_id: 999,
                ..receipt()
            },
            SendReceipt {
                channel_id: 999,
                ..receipt()
            },
            SendReceipt {
                random: 0,
                ..receipt()
            },
        ] {
            assert!(
                send_with(
                    "qq:42",
                    SendMessage {
                        conversation: channel(),
                        content: "text".into()
                    },
                    |_, _, _| std::future::ready(Ok(receipt))
                )
                .await
                .is_err()
            );
        }
    }
}
