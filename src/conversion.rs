use crate::adapter::{Services, protocol_error};
use atri_core::{
    ApiError, ConversationKind, ConversationRef, EventKind, MessageAuthor, MessageContent,
    MessageReceived, MessageRef, SendMessage, UserIdentity, Value, decode, encode, from_value,
    to_value,
};
use atri_extensions::Context;
use atri_qq_protocol::{
    media::{MediaInput, MediaKind, MediaReference},
    messages::{
        Conversation, Mention, Message, MessageElement, OpaqueElement, OpaqueScope, PushEvent,
        Reply,
    },
};
use std::collections::BTreeMap;

const ELEMENT_FORMAT: &str = "qq.message-element.cbor";

fn user(account: &str, uin: u64, uid: &str, name: Option<String>) -> Option<UserIdentity> {
    let id = if !uid.is_empty() {
        format!("uid:{uid}")
    } else if uin != 0 {
        format!("uin:{uin}")
    } else {
        return None;
    };
    Some(UserIdentity {
        account: account.into(),
        id,
        display_name: name,
    })
}

fn conversation(account: &str, native: &Conversation) -> Result<ConversationRef, ApiError> {
    let peer = |uin: u64, uid: &str| -> Result<String, ApiError> {
        if !uid.is_empty() {
            Ok(format!("uid:{uid}"))
        } else if uin != 0 {
            Ok(format!("uin:{uin}"))
        } else {
            Err(ApiError::new(
                "qq.invalid_identity",
                "direct conversation has neither UID nor UIN",
            ))
        }
    };
    let (kind, id) = match native {
        Conversation::Group { uin } if *uin != 0 => {
            (ConversationKind::Group, format!("group:{uin}"))
        }
        Conversation::Friend { uin, uid } => {
            (ConversationKind::Direct, format!("dm:{}", peer(*uin, uid)?))
        }
        Conversation::Temporary { uin, uid, source } => (
            ConversationKind::Direct,
            format!("temp:{source}:{}", peer(*uin, uid)?),
        ),
        _ => return Err(ApiError::new("qq.invalid_identity", "group UIN is zero")),
    };
    Ok(ConversationRef {
        account: account.into(),
        id,
        kind,
    })
}

fn reference(account: &str, message: &Message) -> Result<MessageRef, ApiError> {
    Ok(MessageRef {
        conversation: conversation(account, &message.conversation)?,
        id: format!("seq:{}", message.sequence),
    })
}

fn opaque(element: &MessageElement) -> Result<MessageContent, ApiError> {
    Ok(MessageContent::Opaque {
        format: ELEMENT_FORMAT.into(),
        data: encode(element)?,
    })
}

fn media_content(account: &str, native: &MediaReference) -> Result<MessageContent, ApiError> {
    let kind = match native.kind {
        MediaKind::Image => "image",
        MediaKind::Voice => "voice",
        MediaKind::Video => "video",
        MediaKind::File => "file",
    };
    let mut metadata = BTreeMap::new();
    metadata.insert("qq.reference".into(), to_value(native)?);
    metadata.insert("qq.account".into(), Value::Text(account.into()));
    metadata.insert("filename".into(), Value::Text(native.name.clone()));
    metadata.insert("size".into(), to_value(&native.size)?);
    metadata.insert("width".into(), to_value(&native.width)?);
    metadata.insert("height".into(), to_value(&native.height)?);
    metadata.insert("duration".into(), to_value(&native.duration)?);
    Ok(MessageContent::Media {
        kind: kind.into(),
        handle: format!(
            "{account}:{}",
            native
                .uuid
                .as_deref()
                .or(native.file_id.as_deref())
                .unwrap_or(&native.name)
        ),
        metadata,
    })
}

fn content(account: &str, message: &Message) -> Result<MessageContent, ApiError> {
    let mut parts = Vec::with_capacity(message.elements.len());
    let mut reply = None;
    for element in &message.elements {
        let part = match element {
            MessageElement::Text(text) => MessageContent::Text(text.clone()),
            MessageElement::Mention(mention) => {
                let identity = user(
                    account,
                    mention.uin,
                    mention.uid.as_deref().unwrap_or(""),
                    Some(mention.display.clone()),
                );
                if mention.is_everyone || identity.is_some() {
                    MessageContent::Mention {
                        user: identity,
                        everyone: mention.is_everyone,
                    }
                } else {
                    opaque(element)?
                }
            }
            MessageElement::Reply(value) if reply.is_none() => {
                if let Some(sequence) = value.reference_sequence(&message.conversation) {
                    reply = Some(sequence);
                    continue;
                }
                opaque(element)?
            }
            MessageElement::Image(value)
            | MessageElement::Voice(value)
            | MessageElement::Video(value)
            | MessageElement::File(value) => media_content(account, value)?,
            // Preserve exact previews, unknown fields and wire scope rather than reducing them to text.
            _ => opaque(element)?,
        };
        parts.push(part);
    }
    let body = if parts.len() == 1 {
        parts.pop().expect("one content part")
    } else {
        MessageContent::Composite(parts)
    };
    if let Some(sequence) = reply {
        Ok(MessageContent::Reply {
            reference: MessageRef {
                conversation: conversation(account, &message.conversation)?,
                id: format!("seq:{sequence}"),
            },
            content: Box::new(body),
        })
    } else {
        Ok(body)
    }
}

fn protocol_metadata(records: &[OpaqueElement]) -> Result<BTreeMap<String, Value>, ApiError> {
    let mut metadata = BTreeMap::new();
    if !records.is_empty() {
        let records = records
            .iter()
            .map(|record| {
                Ok(Value::Map(vec![
                    (Value::Text("scope".into()), to_value(&record.scope)?),
                    (Value::Text("field".into()), to_value(&record.field)?),
                    (
                        Value::Text("payload".into()),
                        Value::Bytes(record.payload.clone()),
                    ),
                ]))
            })
            .collect::<Result<Vec<_>, ApiError>>()?;
        metadata.insert("qq.protocol".into(), Value::Array(records));
    }
    Ok(metadata)
}

fn native_metadata(metadata: &BTreeMap<String, Value>) -> Result<Vec<OpaqueElement>, ApiError> {
    #[derive(serde::Deserialize)]
    struct Record {
        scope: OpaqueScope,
        field: u32,
        payload: Value,
    }
    let Some(value) = metadata.get("qq.protocol") else {
        return Ok(vec![]);
    };
    from_value::<Vec<Record>>(value)?
        .into_iter()
        .map(|record| {
            let Value::Bytes(payload) = record.payload else {
                return Err(ApiError::new(
                    "qq.invalid_metadata",
                    "protocol payload requires bytes",
                ));
            };
            let native = OpaqueElement {
                scope: record.scope,
                field: record.field,
                payload,
            };
            atri_qq_protocol::messages::validate_metadata(&native).map_err(protocol_error)?;
            Ok(native)
        })
        .collect()
}

fn received(account: &str, message: &Message) -> Result<MessageReceived, ApiError> {
    let identity = user(
        account,
        message.sender_uin,
        &message.sender_uid,
        (!message.sender_name.is_empty()).then(|| message.sender_name.clone()),
    );
    Ok(MessageReceived {
        reference: reference(account, message)?,
        author: MessageAuthor {
            kind: if identity.is_some() {
                "user"
            } else {
                "unknown"
            }
            .into(),
            user: identity,
            is_self: message.is_self,
            is_bot: message.is_self || message.is_bot == Some(true),
        },
        content: content(account, message)?,
        metadata: protocol_metadata(&message.metadata)?,
    })
}

pub(crate) async fn publish(
    ctx: &Context,
    account: &str,
    event: PushEvent,
) -> Result<(), ApiError> {
    if let PushEvent::Message { message } = &event {
        let received = received(account, message)?;
        ctx.emit(EventKind::MessageReceived, Some(account), &received)
            .await?;
    } else {
        ctx.emit(
            EventKind::Custom("qq.notification".into()),
            Some(account),
            &event,
        )
        .await?;
    }
    Ok(())
}

fn positive_uin(value: &str) -> Result<u64, ApiError> {
    value
        .parse::<u64>()
        .ok()
        .filter(|uin| *uin != 0)
        .ok_or_else(|| ApiError::new("qq.invalid_identity", "expected a nonzero QQ UIN"))
}

async fn peer(
    services: &Services,
    account: &str,
    identity: &UserIdentity,
) -> Result<(u64, String), ApiError> {
    if identity.account != account {
        return Err(ApiError::new(
            "account_mismatch",
            "user belongs to another account",
        ));
    }
    if let Some(uid) = identity
        .id
        .strip_prefix("uid:")
        .filter(|uid| !uid.is_empty())
    {
        let uin = services
            .operations
            .resolve_uin(uid)
            .await
            .map_err(protocol_error)?;
        Ok((uin, uid.into()))
    } else if let Some(uin) = identity.id.strip_prefix("uin:") {
        let uin = positive_uin(uin)?;
        Ok((
            uin,
            services
                .operations
                .resolve_uid(uin, None)
                .await
                .map_err(protocol_error)?,
        ))
    } else {
        Err(ApiError::new(
            "qq.invalid_identity",
            "expected uid: or uin: user identity",
        ))
    }
}

async fn native_conversation(
    services: &Services,
    target: &ConversationRef,
) -> Result<Conversation, ApiError> {
    let account = format!("qq:{}", services.client.snapshot().await.keystore.uin);
    if target.account != account {
        return Err(ApiError::new(
            "account_mismatch",
            "conversation belongs to another account",
        ));
    }
    match target.kind {
        ConversationKind::Group => {
            let uin = target.id.strip_prefix("group:").ok_or_else(|| {
                ApiError::new("qq.invalid_identity", "expected group: conversation")
            })?;
            Ok(Conversation::Group {
                uin: positive_uin(uin)?,
            })
        }
        ConversationKind::Direct => {
            if target.id.starts_with("temp:") {
                return Err(ApiError::unsupported(
                    "Desktop temporary-session sending is not supported",
                ));
            }
            let id = target
                .id
                .strip_prefix("dm:")
                .ok_or_else(|| ApiError::new("qq.invalid_identity", "expected dm: conversation"))?;
            let (uin, uid) = peer(
                services,
                &account,
                &UserIdentity {
                    account: account.clone(),
                    id: id.into(),
                    display_name: None,
                },
            )
            .await?;
            Ok(Conversation::Friend { uin, uid })
        }
        _ => Err(ApiError::unsupported(
            "QQ supports direct and group conversations",
        )),
    }
}

fn validate_content(value: &MessageContent, target: &ConversationRef) -> Result<(), ApiError> {
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            MessageContent::Composite(parts) => pending.extend(parts),
            MessageContent::Reply { reference, content } => {
                if reference.conversation != *target {
                    return Err(ApiError::unsupported(
                        "reply target belongs to another conversation",
                    ));
                }
                reference
                    .id
                    .strip_prefix("seq:")
                    .and_then(|seq| seq.parse::<u64>().ok())
                    .ok_or_else(|| {
                        ApiError::new("qq.invalid_identity", "reply requires a seq: reference")
                    })?;
                pending.push(content);
            }
            MessageContent::Mention { user, everyone } => {
                if *everyone && target.kind != ConversationKind::Group {
                    return Err(ApiError::unsupported("everyone mentions require a group"));
                }
                if !*everyone && user.is_none() {
                    return Err(ApiError::unsupported("mention has no user"));
                }
                if let Some(user) = user {
                    if user.account != target.account {
                        return Err(ApiError::new(
                            "account_mismatch",
                            "mention belongs to another account",
                        ));
                    }
                }
            }
            MessageContent::Media { kind, metadata, .. } => {
                media_kind(kind)?;
                if let Some(account) = metadata.get("qq.account") {
                    if from_value::<String>(account)? != target.account {
                        return Err(ApiError::new(
                            "account_mismatch",
                            "media belongs to another account",
                        ));
                    }
                }
            }
            MessageContent::Forward { records } => {
                for record in records {
                    let user = record.author.user.as_ref().ok_or_else(|| {
                        ApiError::unsupported("forward records require a concrete user")
                    })?;
                    if user.account != target.account {
                        return Err(ApiError::new(
                            "account_mismatch",
                            "forward author belongs to another account",
                        ));
                    }
                    pending.push(&record.content);
                    native_metadata(&record.metadata)?;
                }
            }
            MessageContent::Opaque { format, data } => {
                if format != ELEMENT_FORMAT {
                    return Err(ApiError::unsupported(format!(
                        "unsupported opaque content format {format}"
                    )));
                }
                decode::<MessageElement>(data)?;
            }
            MessageContent::Text(_) => {}
        }
    }
    // QQ file notices are dedicated sends, not composable rich-text elements.
    let mut pending = vec![value];
    let (mut files, mut others) = (0usize, 0usize);
    while let Some(value) = pending.pop() {
        match value {
            MessageContent::Composite(parts) => pending.extend(parts),
            MessageContent::Reply { content, .. } => {
                others += 1;
                pending.push(content);
            }
            MessageContent::Media { kind, .. } if kind == "file" => files += 1,
            _ => others += 1,
        }
    }
    if files != 0 && (files != 1 || others != 0) {
        return Err(ApiError::unsupported(
            "QQ file notices cannot be combined with other content",
        ));
    }
    Ok(())
}

fn media_kind(kind: &str) -> Result<MediaKind, ApiError> {
    match kind {
        "image" => Ok(MediaKind::Image),
        "voice" => Ok(MediaKind::Voice),
        "video" => Ok(MediaKind::Video),
        "file" => Ok(MediaKind::File),
        _ => Err(ApiError::unsupported(format!(
            "unsupported QQ media kind {kind}"
        ))),
    }
}

async fn media_reference(
    services: &Services,
    target: &Conversation,
    account: &str,
    kind: &str,
    handle: &str,
    metadata: &BTreeMap<String, Value>,
) -> Result<MediaReference, ApiError> {
    let kind = media_kind(kind)?;
    let conversation = target.media_conversation().map_err(protocol_error)?;
    let input = if let Some(value) = metadata.get("qq.reference") {
        let native: MediaReference = from_value(value)?;
        if native.kind != kind {
            return Err(ApiError::unsupported(
                "media reference has a different kind",
            ));
        }
        if native.conversation == conversation {
            return Ok(native);
        }
        MediaInput::Url {
            url: services
                .media
                .download_url(&native)
                .await
                .map_err(protocol_error)?,
        }
    } else if let Some(value) = metadata.get("qq.input") {
        from_value::<MediaInput>(value)?
    } else if handle.starts_with("https://") || handle.starts_with("http://") {
        MediaInput::Url { url: handle.into() }
    } else {
        return Err(ApiError::unsupported(format!(
            "media handle for {account} needs qq.reference, qq.input or an HTTP(S) URL"
        )));
    };
    let number = |name: &str| -> Result<u32, ApiError> {
        metadata
            .get(name)
            .map(from_value)
            .transpose()
            .map(|n| n.unwrap_or(0))
    };
    match kind {
        MediaKind::Image => {
            services
                .media
                .upload_image(input, conversation, "[图片]")
                .await
        }
        MediaKind::Voice => services.media.upload_voice(input, conversation).await,
        MediaKind::Video => {
            let thumbnail = metadata
                .get("thumbnail")
                .map(from_value::<MediaInput>)
                .transpose()?;
            services
                .media
                .upload_video(
                    input,
                    thumbnail,
                    conversation,
                    number("width")?,
                    number("height")?,
                    number("duration")?,
                )
                .await
        }
        MediaKind::File => services.media.upload_file(input, conversation, "/").await,
    }
    .map_err(protocol_error)
}

async fn original(
    services: &Services,
    target: &Conversation,
    reference: &MessageRef,
) -> Result<Message, ApiError> {
    let sequence = reference
        .id
        .strip_prefix("seq:")
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| ApiError::new("qq.invalid_identity", "expected seq: message reference"))?;
    let messages = match target {
        Conversation::Group { uin } => {
            services
                .messaging
                .history_group(*uin, sequence, sequence)
                .await
        }
        Conversation::Friend { uid, .. } => {
            services
                .messaging
                .history_c2c(uid, sequence, sequence)
                .await
        }
        Conversation::Temporary { .. } => {
            return Err(ApiError::unsupported(
                "temporary-session history is not supported",
            ));
        }
    }
    .map_err(protocol_error)?;
    messages
        .into_iter()
        .find(|message| message.sequence == sequence)
        .ok_or_else(|| ApiError::new("not_found", "reply target was not returned by QQ history"))
}

async fn encode_content(
    services: &Services,
    target: &Conversation,
    reference: &ConversationRef,
    value: &MessageContent,
) -> Result<Vec<MessageElement>, ApiError> {
    let mut result = Vec::new();
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            MessageContent::Text(text) => result.push(MessageElement::Text(text.clone())),
            MessageContent::Composite(parts) => pending.extend(parts.iter().rev()),
            MessageContent::Reply { reference, content } => {
                result.push(MessageElement::Reply(Reply::from(
                    &original(services, target, reference).await?,
                )));
                pending.push(content);
            }
            MessageContent::Mention { user, everyone } => {
                let (uin, uid, display) = if *everyone {
                    (0, None, "@全体成员".into())
                } else {
                    let user = user
                        .as_ref()
                        .ok_or_else(|| ApiError::unsupported("mention has no user"))?;
                    let (uin, uid) = peer(services, &reference.account, user).await?;
                    (
                        uin,
                        Some(uid),
                        format!("@{}", user.display_name.as_deref().unwrap_or(&user.id)),
                    )
                };
                result.push(MessageElement::Mention(Mention {
                    uin,
                    uid,
                    display,
                    is_everyone: *everyone,
                }));
            }
            MessageContent::Media {
                kind,
                handle,
                metadata,
            } => {
                let native =
                    media_reference(services, target, &reference.account, kind, handle, metadata)
                        .await?;
                result.push(match native.kind {
                    MediaKind::Image => MessageElement::Image(native),
                    MediaKind::Voice => MessageElement::Voice(native),
                    MediaKind::Video => MessageElement::Video(native),
                    MediaKind::File => MessageElement::File(native),
                });
            }
            MessageContent::Forward { records } => {
                let mut messages = Vec::with_capacity(records.len());
                for record in records {
                    let author = record.author.user.as_ref().ok_or_else(|| {
                        ApiError::unsupported("forward records require an author")
                    })?;
                    let (uin, uid) = peer(services, &reference.account, author).await?;
                    messages.push(Message {
                        conversation: target.clone(),
                        sender_uin: uin,
                        sender_uid: uid,
                        sender_name: author.display_name.clone().unwrap_or_default(),
                        recipient_uin: 0,
                        recipient_uid: String::new(),
                        sequence: 0,
                        client_sequence: u64::from(rand::random::<u32>() % 89999 + 10000),
                        message_id: 0,
                        random: 0,
                        time: i64::try_from(record.time_ms / 1000).map_err(ApiError::internal)?,
                        is_self: record.author.is_self,
                        is_bot: Some(record.author.is_bot),
                        raw: Vec::new(),
                        metadata: native_metadata(&record.metadata)?,
                        elements: Box::pin(encode_content(
                            services,
                            target,
                            reference,
                            &record.content,
                        ))
                        .await?,
                    });
                }
                let forward = services
                    .messaging
                    .upload_forward(target.clone(), messages)
                    .await
                    .map_err(protocol_error)?;
                result.push(MessageElement::Forward(forward));
            }
            MessageContent::Opaque { data, .. } => result.push(decode(data)?),
        }
    }
    Ok(result)
}

pub(crate) async fn send(services: &Services, outbound: SendMessage) -> Result<Value, ApiError> {
    validate_content(&outbound.content, &outbound.conversation)?;
    let target = native_conversation(services, &outbound.conversation).await?;
    let elements =
        encode_content(services, &target, &outbound.conversation, &outbound.content).await?;
    let message = services
        .messaging
        .send(target, elements)
        .await
        .map_err(protocol_error)?;
    to_value(&reference(&outbound.conversation.account, &message)?)
}
