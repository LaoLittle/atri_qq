use super::*;
use crate::media::{MediaConversation, MediaKind, MediaReference};
use crate::proto::messages as pb;
use prost::Message as ProstMessage;
use prost_reflect::DynamicMessage;
use std::{
    collections::BTreeMap,
    io::{Read, Write},
};

fn decode<T: ProstMessage + Default>(raw: &[u8]) -> Result<T> {
    crate::proto::decode(raw)
}
fn descriptor(name: &str) -> prost_reflect::MessageDescriptor {
    crate::proto::descriptor_pool()
        .get_message_by_name(name)
        .expect("compiled message descriptor")
}
fn unknown_bytes(name: &str, raw: &[u8]) -> Result<Vec<u8>> {
    let message = DynamicMessage::decode(descriptor(name), raw)?;
    let mut bytes = Vec::new();
    for field in message.unknown_fields() {
        field.encode(&mut bytes);
    }
    Ok(bytes)
}
fn retain_unknown(
    out: &mut Vec<MessageElement>,
    scope: OpaqueScope,
    name: &str,
    raw: &[u8],
) -> Result<()> {
    let message = DynamicMessage::decode(descriptor(name), raw)?;
    let mut fields = BTreeMap::<u32, Vec<u8>>::new();
    for field in message.unknown_fields() {
        field.encode(fields.entry(field.number()).or_default());
    }
    out.extend(fields.into_iter().map(|(field, payload)| {
        MessageElement::Opaque(OpaqueElement {
            scope,
            field,
            payload,
        })
    }));
    Ok(())
}
fn retain_nested(
    out: &mut Vec<MessageElement>,
    field: u32,
    raw: Vec<u8>,
    wrap: impl FnOnce(bytes::Bytes) -> pb::Elem,
) {
    if !raw.is_empty() {
        out.push(MessageElement::Opaque(OpaqueElement {
            scope: OpaqueScope::Element,
            field,
            payload: wrap(raw.into()).encode_to_vec(),
        }));
    }
}

/// Preserve only unrelated unknown fields; raw data cannot override requested headers/content.
pub(super) fn preserve_common(raw: &[u8], mut rebuilt: pb::CommonMessage) -> Result<Vec<u8>> {
    let original: pb::CommonEnvelope = decode(raw)?;
    let mut routing = rebuilt
        .routing_head
        .take()
        .unwrap_or_default()
        .encode_to_vec();
    routing.extend(unknown_bytes(
        "atri.qq.messages.RoutingHead",
        &original.routing_head,
    )?);
    let mut head = rebuilt.content_head.take().unwrap_or_default();
    if head.sub_type.is_none() {
        head.sub_type = decode::<pb::ContentHead>(&original.content_head)?.sub_type;
    }
    let mut content_head = head.encode_to_vec();
    content_head.extend(unknown_bytes(
        "atri.qq.messages.ContentHead",
        &original.content_head,
    )?);
    let mut result = pb::CommonEnvelope {
        routing_head: routing.into(),
        content_head: content_head.into(),
        message_body: rebuilt.message_body,
    }
    .encode_to_vec();
    result.extend(unknown_bytes("atri.qq.messages.CommonMessage", raw)?);
    Ok(result)
}

/// Ancillary declarations: Attr (RichText 1), resource-free Ptt sidecars (4),
/// ElemFlags2 (9), ExtraInfo (16), and GeneralFlags (37). Ptt carrying a media
/// identity remains content; validate_metadata enforces that distinction.
pub fn is_protocol_metadata(scope: OpaqueScope, field: u32) -> bool {
    matches!(
        (scope, field),
        (OpaqueScope::RichText, 1 | 4) | (OpaqueScope::Element, 9 | 16 | 37)
    )
}
fn metadata_ptt(raw: &[u8]) -> Result<bool> {
    let ptt: crate::proto::media::Ptt = decode(raw)?;
    Ok([
        &ptt.uuid,
        &ptt.md5,
        &ptt.file_key,
        &ptt.group_file_key,
        &ptt.url,
    ]
    .into_iter()
    .all(|value| value.as_ref().is_none_or(|bytes| bytes.is_empty()))
        && ptt.urls.iter().all(|bytes| bytes.is_empty()))
}

fn metadata_record(scope: OpaqueScope, field: u32, values: Vec<bytes::Bytes>) -> OpaqueElement {
    let payload = match (scope, field) {
        (OpaqueScope::RichText, 1) => pb::RichText {
            attr: values,
            ..Default::default()
        }
        .encode_to_vec(),
        (OpaqueScope::RichText, 4) => pb::RichText {
            voice: values,
            ..Default::default()
        }
        .encode_to_vec(),
        (OpaqueScope::Element, 9) => pb::Elem {
            flags2: values,
            ..Default::default()
        }
        .encode_to_vec(),
        (OpaqueScope::Element, 16) => pb::Elem {
            extra_info: values,
            ..Default::default()
        }
        .encode_to_vec(),
        (OpaqueScope::Element, 37) => pb::Elem {
            general_flags: values,
            ..Default::default()
        }
        .encode_to_vec(),
        _ => unreachable!("declared metadata field"),
    };
    OpaqueElement {
        scope,
        field,
        payload,
    }
}
pub fn validate_metadata(record: &OpaqueElement) -> Result<()> {
    if !is_protocol_metadata(record.scope, record.field) {
        return Err(Error::Malformed(
            "Unrecognized protocol metadata field".into(),
        ));
    }
    let valid = match record.scope {
        OpaqueScope::Element => {
            let mut element: pb::Elem = decode(&record.payload)?;
            let values = match record.field {
                9 => std::mem::take(&mut element.flags2),
                16 => std::mem::take(&mut element.extra_info),
                37 => std::mem::take(&mut element.general_flags),
                _ => unreachable!(),
            };
            !values.is_empty()
                && element == pb::Elem::default()
                && unknown_bytes("atri.qq.messages.Elem", &record.payload)?.is_empty()
        }
        OpaqueScope::RichText => {
            let mut rich: pb::RichText = decode(&record.payload)?;
            let mut content_free = true;
            let values = if record.field == 4 {
                for raw in &rich.voice {
                    content_free &= metadata_ptt(raw)?;
                }
                std::mem::take(&mut rich.voice)
            } else {
                std::mem::take(&mut rich.attr)
            };
            content_free
                && !values.is_empty()
                && rich == pb::RichText::default()
                && unknown_bytes("atri.qq.messages.RichText", &record.payload)?.is_empty()
        }
        OpaqueScope::MessageBody => false,
    };
    if valid {
        Ok(())
    } else {
        Err(Error::Malformed(
            "Protocol metadata payload does not match its field".into(),
        ))
    }
}

pub fn encode_elements(elements: &[MessageElement], metadata: &[OpaqueElement]) -> Result<Vec<u8>> {
    let mut rich = pb::RichText::default();
    let mut body = pb::MessageBody::default();
    let mut rich_unknown = Vec::new();
    let mut body_unknown = Vec::new();
    for element in elements {
        match element {
            MessageElement::Text(text) => rich.elems.push(
                pb::Elem {
                    text: vec![
                        pb::Text {
                            text: Some(text.clone()),
                            ..Default::default()
                        }
                        .encode_to_vec()
                        .into(),
                    ],
                    ..Default::default()
                }
                .encode_to_vec()
                .into(),
            ),
            MessageElement::Mention(mention) => {
                if !mention.is_everyone && mention.uid.as_ref().is_none_or(String::is_empty) {
                    return Err(Error::Malformed(
                        "Specific mention requires peer UID".into(),
                    ));
                }
                let reserve = pb::MentionReserve {
                    kind: Some(if mention.is_everyone { 1 } else { 2 }),
                    uin: Some(mention.uin),
                    zero: Some(0),
                    uid: mention.uid.clone().unwrap_or_default(),
                };
                let text = pb::Text {
                    text: Some(mention.display.clone()),
                    reserve: reserve.encode_to_vec().into(),
                };
                rich.elems.push(
                    pb::Elem {
                        text: vec![text.encode_to_vec().into()],
                        ..Default::default()
                    }
                    .encode_to_vec()
                    .into(),
                );
            }
            MessageElement::Reply(reply) => {
                if reply.sequences.is_empty() {
                    return Err(Error::Malformed("Reply requires source sequence".into()));
                }
                for raw in &reply.elements {
                    let _: pb::Elem = decode(raw)?;
                }
                let source = pb::SourceMsg {
                    sequences: reply.sequences.clone(),
                    sender_uin: Some(reply.sender_uin),
                    time: Some(reply.time),
                    has_elements: Some(u64::from(!reply.elements.is_empty())),
                    elements: reply.elements.iter().cloned().map(Into::into).collect(),
                    reserve: Some(pb::SourceReserve {
                        kind: Some(2),
                        message_id: Some(reply.message_id),
                        sender_uid: reply.sender_uid.clone(),
                        friend_sequence: reply.server_sequence,
                    }),
                };
                rich.elems.push(
                    pb::Elem {
                        source_msg: vec![source.encode_to_vec().into()],
                        ..Default::default()
                    }
                    .encode_to_vec()
                    .into(),
                );
            }
            MessageElement::Image(reference) | MessageElement::Video(reference) => rich
                .elems
                .extend(reference.encode_elements()?.into_iter().map(Into::into)),
            MessageElement::Voice(reference) => {
                if reference.message_info.is_empty() {
                    if let Some(raw) = &reference.compatibility {
                        rich.voice.push(raw.clone().into());
                    } else {
                        rich.elems
                            .extend(reference.encode_elements()?.into_iter().map(Into::into));
                    }
                } else {
                    rich.elems
                        .extend(reference.encode_elements()?.into_iter().map(Into::into));
                }
            }
            MessageElement::File(reference) => {
                if elements.len() != 1
                    || !matches!(reference.conversation, MediaConversation::Friend { .. })
                {
                    return Err(Error::Unsupported(
                        "Files require dedicated file send service".into(),
                    ));
                }
                let raw = reference
                    .compatibility
                    .as_ref()
                    .ok_or_else(|| Error::Malformed("File has no negotiated payload".into()))?;
                body.content = Some(
                    pb::FileEnvelope {
                        file: raw.clone().into(),
                    }
                    .encode_to_vec()
                    .into(),
                );
            }
            MessageElement::LightApp(json) => rich.elems.push(light_app(json)?.into()),
            MessageElement::Forward(reference) => {
                if reference.resource_id.is_empty() {
                    return Err(Error::Malformed("Forward resource ID empty".into()));
                }
                if let Some(raw) = reference.raw_element.as_ref().filter(|raw| {
                    forward_resource(raw).ok().as_deref() == Some(reference.resource_id.as_str())
                }) {
                    rich.elems.push(raw.clone().into());
                    continue;
                }
                let generated;
                let json = if let Some(json) = reference.light_app_json.as_ref().filter(|json| {
                    serde_json::from_str::<serde_json::Value>(json).is_ok_and(|root| {
                        root.pointer("/meta/detail/resid")
                            .and_then(serde_json::Value::as_str)
                            == Some(reference.resource_id.as_str())
                    })
                }) {
                    json
                } else {
                    let guid = format!("{:032x}", rand::random::<u128>());
                    generated = serde_json::json!({"app":"com.tencent.multimsg","config":{"autosize":1,"forward":1,"round":1,"type":"normal","width":300},"meta":{"detail":{"news":[],"resid":reference.resource_id,"source":"聊天记录","summary":format!("查看{}条转发消息",reference.count),"uniseq":guid}},"desc":"[聊天记录]","extra":serde_json::json!({"filename":guid,"tsum":reference.count}).to_string(),"prompt":"[聊天记录]","ver":"0.0.0.5","view":"contact"}).to_string();
                    &generated
                };
                rich.elems.push(light_app(json)?.into());
            }
            MessageElement::GroupFile(file) => {
                if file.raw_element.is_empty() {
                    return Err(Error::Unsupported(
                        "New group files must be negotiated by file service".into(),
                    ));
                }
                let _: pb::Elem = decode(&file.raw_element)?;
                rich.elems.push(file.raw_element.clone().into());
            }
            MessageElement::Opaque(record) => {
                match record.scope {
                    OpaqueScope::Element => {
                        let _: pb::Elem = decode(&record.payload)?;
                    }
                    OpaqueScope::RichText => {
                        let _: pb::RichText = decode(&record.payload)?;
                    }
                    OpaqueScope::MessageBody => {
                        let _: pb::MessageBody = decode(&record.payload)?;
                    }
                }
                match record.scope {
                    OpaqueScope::Element => rich.elems.push(record.payload.clone().into()),
                    OpaqueScope::RichText => rich_unknown.extend_from_slice(&record.payload),
                    OpaqueScope::MessageBody => body_unknown.extend_from_slice(&record.payload),
                }
            }
        }
    }
    for record in metadata {
        validate_metadata(record)?;
        match record.scope {
            OpaqueScope::Element => rich.elems.push(record.payload.clone().into()),
            OpaqueScope::RichText => rich_unknown.extend_from_slice(&record.payload),
            OpaqueScope::MessageBody => unreachable!("validated metadata scope"),
        }
    }
    let mut encoded_rich = rich.encode_to_vec();
    encoded_rich.extend(rich_unknown);
    body.rich_text = encoded_rich.into();
    let mut encoded_body = body.encode_to_vec();
    encoded_body.extend(body_unknown);
    Ok(encoded_body)
}
fn light_app(json: &str) -> Result<Vec<u8>> {
    let _: serde_json::Value =
        serde_json::from_str(json).map_err(|error| Error::Malformed(error.to_string()))?;
    let mut data = vec![1];
    data.extend(compress(json.as_bytes(), false)?);
    Ok(pb::Elem {
        light_app: vec![pb::LightApp { data: data.into() }.encode_to_vec().into()],
        ..Default::default()
    }
    .encode_to_vec())
}
fn forward_resource(raw: &[u8]) -> Result<String> {
    let element: pb::Elem = decode(raw)?;
    if let Some(raw) = element.light_app.first() {
        let app: pb::LightApp = decode(raw)?;
        let root: serde_json::Value = serde_json::from_slice(&application_payload(&app.data)?)
            .map_err(|error| Error::Malformed(error.to_string()))?;
        return root
            .pointer("/meta/detail/resid")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| Error::Malformed("Forward application has no resource ID".into()));
    }
    if let Some(raw) = element.rich_msg.first() {
        let app: pb::RichMsg = decode(raw)?;
        return forward_xml(&application_payload(&app.data)?);
    }
    Err(Error::Malformed("Forward has no supported payload".into()))
}

pub fn decode_elements(
    raw: &[u8],
    conversation: &Conversation,
    own_uin: u64,
) -> Result<DecodedElements> {
    let body: pb::MessageBody = decode(raw)?;
    let rich: pb::RichText = decode(&body.rich_text)?;
    let mut out = DecodedElements::default();
    if !rich.attr.is_empty() {
        out.metadata
            .push(metadata_record(OpaqueScope::RichText, 1, rich.attr));
    }
    for raw_element in rich.elems {
        let mut element: pb::Elem = decode(&raw_element)?;
        for (field, values) in [
            (9, std::mem::take(&mut element.flags2)),
            (16, std::mem::take(&mut element.extra_info)),
            (37, std::mem::take(&mut element.general_flags)),
        ] {
            if !values.is_empty() {
                out.metadata
                    .push(metadata_record(OpaqueScope::Element, field, values));
            }
        }
        for raw in element.text {
            let text: pb::Text = decode(&raw)?;
            if let Some(content) = text.text {
                let reserve: pb::MentionReserve = decode(&text.reserve)?;
                if matches!(reserve.kind, Some(1 | 2)) {
                    out.elements.push(MessageElement::Mention(Mention {
                        uin: reserve.uin.unwrap_or_default(),
                        uid: (!reserve.uid.is_empty()).then_some(reserve.uid),
                        display: content,
                        is_everyone: reserve.kind == Some(1),
                    }));
                    let unknown = unknown_bytes("atri.qq.messages.MentionReserve", &text.reserve)?;
                    if !unknown.is_empty() {
                        let remainder = pb::Text {
                            reserve: unknown.into(),
                            ..Default::default()
                        }
                        .encode_to_vec();
                        retain_nested(&mut out.elements, 1, remainder, |raw| pb::Elem {
                            text: vec![raw],
                            ..Default::default()
                        });
                    }
                } else {
                    out.elements.push(MessageElement::Text(content));
                    if !text.reserve.is_empty() {
                        retain_nested(
                            &mut out.elements,
                            1,
                            pb::Text {
                                reserve: text.reserve,
                                ..Default::default()
                            }
                            .encode_to_vec(),
                            |raw| pb::Elem {
                                text: vec![raw],
                                ..Default::default()
                            },
                        );
                    }
                }
                retain_nested(
                    &mut out.elements,
                    1,
                    unknown_bytes("atri.qq.messages.Text", &raw)?,
                    |raw| pb::Elem {
                        text: vec![raw],
                        ..Default::default()
                    },
                );
            } else {
                out.elements.push(MessageElement::Opaque(OpaqueElement {
                    scope: OpaqueScope::Element,
                    field: 1,
                    payload: pb::Elem {
                        text: vec![raw],
                        ..Default::default()
                    }
                    .encode_to_vec(),
                }));
            }
        }
        for raw in element.source_msg {
            let source: pb::SourceMsg = decode(&raw)?;
            if source.sequences.is_empty() {
                out.elements.push(MessageElement::Opaque(OpaqueElement {
                    scope: OpaqueScope::Element,
                    field: 45,
                    payload: pb::Elem {
                        source_msg: vec![raw],
                        ..Default::default()
                    }
                    .encode_to_vec(),
                }));
                continue;
            }
            let reserve = source.reserve.unwrap_or_default();
            out.elements.push(MessageElement::Reply(Reply {
                sequences: source.sequences,
                server_sequence: reserve.friend_sequence,
                message_id: reserve.message_id.unwrap_or_default(),
                sender_uin: source.sender_uin.unwrap_or_default(),
                sender_uid: reserve.sender_uid,
                time: source.time.unwrap_or_default(),
                elements: source
                    .elements
                    .into_iter()
                    .map(|raw| raw.to_vec())
                    .collect(),
            }));
            let envelope: pb::SourceEnvelope = decode(&raw)?;
            let nested_unknown =
                unknown_bytes("atri.qq.messages.SourceReserve", &envelope.reserve)?;
            if !nested_unknown.is_empty() {
                retain_nested(
                    &mut out.elements,
                    45,
                    pb::SourceEnvelope {
                        reserve: nested_unknown.into(),
                    }
                    .encode_to_vec(),
                    |raw| pb::Elem {
                        source_msg: vec![raw],
                        ..Default::default()
                    },
                );
            }
            retain_nested(
                &mut out.elements,
                45,
                unknown_bytes("atri.qq.messages.SourceMsg", &raw)?,
                |raw| pb::Elem {
                    source_msg: vec![raw],
                    ..Default::default()
                },
            );
        }
        for raw in element.light_app {
            let app: pb::LightApp = decode(&raw)?;
            if !matches!(app.data.first(), Some(0 | 1)) {
                out.elements.push(MessageElement::Opaque(OpaqueElement {
                    scope: OpaqueScope::Element,
                    field: 51,
                    payload: pb::Elem {
                        light_app: vec![raw],
                        ..Default::default()
                    }
                    .encode_to_vec(),
                }));
                continue;
            }
            let json = String::from_utf8(application_payload(&app.data)?)
                .map_err(|error| Error::Malformed(error.to_string()))?;
            let root: serde_json::Value =
                serde_json::from_str(&json).map_err(|error| Error::Malformed(error.to_string()))?;
            if root.get("app").and_then(serde_json::Value::as_str) == Some("com.tencent.multimsg") {
                if let Some(id) = root
                    .pointer("/meta/detail/resid")
                    .and_then(serde_json::Value::as_str)
                {
                    out.elements.push(MessageElement::Forward(ForwardReference {
                        resource_id: id.to_owned(),
                        count: root
                            .pointer("/meta/detail/news")
                            .and_then(serde_json::Value::as_array)
                            .map_or(0, Vec::len),
                        light_app_json: Some(json),
                        raw_element: Some(
                            pb::Elem {
                                light_app: vec![raw],
                                ..Default::default()
                            }
                            .encode_to_vec(),
                        ),
                    }));
                    continue;
                }
            }
            out.elements.push(MessageElement::LightApp(json));
            retain_nested(
                &mut out.elements,
                51,
                unknown_bytes("atri.qq.messages.LightApp", &raw)?,
                |raw| pb::Elem {
                    light_app: vec![raw],
                    ..Default::default()
                },
            );
        }
        for raw in element.rich_msg {
            let app: pb::RichMsg = decode(&raw)?;
            if app.service_id == Some(35) && matches!(app.data.first(), Some(0 | 1)) {
                let id = forward_xml(&application_payload(&app.data)?)?;
                out.elements.push(MessageElement::Forward(ForwardReference {
                    resource_id: id,
                    count: 0,
                    light_app_json: None,
                    raw_element: Some(
                        pb::Elem {
                            rich_msg: vec![raw],
                            ..Default::default()
                        }
                        .encode_to_vec(),
                    ),
                }));
            } else {
                out.elements.push(MessageElement::Opaque(OpaqueElement {
                    scope: OpaqueScope::Element,
                    field: 12,
                    payload: pb::Elem {
                        rich_msg: vec![raw],
                        ..Default::default()
                    }
                    .encode_to_vec(),
                }));
            }
        }
        let friend_images = element.friend_image;
        let group_images = element.group_image;
        let videos = element.video;
        for raw in element.common {
            let common: pb::CommonElem = decode(&raw)?;
            let kind = if common.service_type == Some(48) {
                match common.business_type {
                    Some(10 | 20) => Some(MediaKind::Image),
                    Some(11 | 21) => Some(MediaKind::Video),
                    Some(12 | 22) => Some(MediaKind::Voice),
                    _ => None,
                }
            } else {
                None
            };
            if let Some(kind) = kind {
                let reference = MediaReference::from_message_info(
                    common.payload.to_vec(),
                    kind,
                    conversation.received_media_conversation(),
                    None,
                )?;
                append_media(&mut out.elements, media_element(reference));
                retain_nested(
                    &mut out.elements,
                    53,
                    unknown_bytes("atri.qq.messages.CommonElem", &raw)?,
                    |raw| pb::Elem {
                        common: vec![raw],
                        ..Default::default()
                    },
                );
            } else {
                out.elements.push(MessageElement::Opaque(OpaqueElement {
                    scope: OpaqueScope::Element,
                    field: 53,
                    payload: pb::Elem {
                        common: vec![raw],
                        ..Default::default()
                    }
                    .encode_to_vec(),
                }));
            }
        }
        for (field, values) in [(4, friend_images), (8, group_images), (19, videos)] {
            for raw in values {
                let element = match field {
                    4 => pb::Elem {
                        friend_image: vec![raw],
                        ..Default::default()
                    },
                    8 => pb::Elem {
                        group_image: vec![raw],
                        ..Default::default()
                    },
                    _ => pb::Elem {
                        video: vec![raw],
                        ..Default::default()
                    },
                }
                .encode_to_vec();
                if let Some(reference) = MediaReference::decode_element(
                    &element,
                    conversation.received_media_conversation(),
                )? {
                    append_media(&mut out.elements, media_element(reference));
                } else {
                    out.elements.push(MessageElement::Opaque(OpaqueElement {
                        scope: OpaqueScope::Element,
                        field,
                        payload: element,
                    }));
                }
            }
        }
        for raw in element.trans {
            let trans: pb::TransElem = decode(&raw)?;
            if trans.kind == Some(24) {
                let data = trans.data;
                if data.len() < 3 {
                    return Err(Error::Malformed("Truncated group file notification".into()));
                }
                let len = u16::from_be_bytes([data[1], data[2]]) as usize;
                let bytes = data
                    .get(3..3 + len)
                    .ok_or_else(|| Error::Malformed("Truncated group file body".into()))?;
                let extra: pb::GroupFileEnvelope = decode(bytes)?;
                let info = extra
                    .body
                    .and_then(|body| body.info)
                    .ok_or_else(|| Error::Malformed("Group file lacks info".into()))?;
                out.elements
                    .push(MessageElement::GroupFile(GroupFileMessage {
                        business_id: info.business_id.unwrap_or_default(),
                        file_id: info.file_id,
                        name: info.name,
                        size: info.size.unwrap_or_default(),
                        md5: info.md5,
                        raw_element: pb::Elem {
                            trans: vec![raw],
                            ..Default::default()
                        }
                        .encode_to_vec(),
                    }));
            } else {
                out.elements.push(MessageElement::Opaque(OpaqueElement {
                    scope: OpaqueScope::Element,
                    field: 5,
                    payload: pb::Elem {
                        trans: vec![raw],
                        ..Default::default()
                    }
                    .encode_to_vec(),
                }));
            }
        }
        retain_unknown(
            &mut out.elements,
            OpaqueScope::Element,
            "atri.qq.messages.Elem",
            &raw_element,
        )?;
    }
    for raw in rich.voice {
        if metadata_ptt(&raw)? {
            out.metadata
                .push(metadata_record(OpaqueScope::RichText, 4, vec![raw]));
        } else {
            append_media(
                &mut out.elements,
                MessageElement::Voice(MediaReference::decode_ptt(
                    &raw,
                    conversation.received_media_conversation(),
                    own_uin,
                )?),
            );
        }
    }
    for raw in rich.file {
        if let Some(reference) = file_reference(&raw, conversation)? {
            out.elements.push(MessageElement::File(reference));
        } else {
            out.elements.push(MessageElement::Opaque(OpaqueElement {
                scope: OpaqueScope::RichText,
                field: 3,
                payload: pb::RichText {
                    file: vec![raw],
                    ..Default::default()
                }
                .encode_to_vec(),
            }));
        }
    }
    retain_unknown(
        &mut out.elements,
        OpaqueScope::RichText,
        "atri.qq.messages.RichText",
        &body.rich_text,
    )?;
    if let Some(content) = body.content {
        let parsed = decode::<pb::FileEnvelope>(&content).ok();
        let reference = match parsed {
            Some(extra) => file_reference(&extra.file, conversation)?,
            None => None,
        };
        if let Some(reference) = reference {
            out.elements.push(MessageElement::File(reference));
            let unknown = unknown_bytes("atri.qq.messages.FileEnvelope", &content)?;
            if !unknown.is_empty() {
                out.elements.push(MessageElement::Opaque(OpaqueElement {
                    scope: OpaqueScope::MessageBody,
                    field: 2,
                    payload: pb::MessageBody {
                        content: Some(unknown.into()),
                        ..Default::default()
                    }
                    .encode_to_vec(),
                }));
            }
        } else {
            out.elements.push(MessageElement::Opaque(OpaqueElement {
                scope: OpaqueScope::MessageBody,
                field: 2,
                payload: pb::MessageBody {
                    content: Some(content),
                    ..Default::default()
                }
                .encode_to_vec(),
            }));
        }
    }
    if let Some(content) = body.encrypted_content {
        out.elements.push(MessageElement::Opaque(OpaqueElement {
            scope: OpaqueScope::MessageBody,
            field: 3,
            payload: pb::MessageBody {
                encrypted_content: Some(content),
                ..Default::default()
            }
            .encode_to_vec(),
        }));
    }
    retain_unknown(
        &mut out.elements,
        OpaqueScope::MessageBody,
        "atri.qq.messages.MessageBody",
        raw,
    )?;
    Ok(out)
}
fn file_reference(raw: &[u8], conversation: &Conversation) -> Result<Option<MediaReference>> {
    let file: pb::FileReference = decode(raw)?;
    let (Some(uuid), Some(name)) = (file.uuid, file.name) else {
        return Ok(None);
    };
    let mut reference =
        MediaReference::new(MediaKind::File, conversation.received_media_conversation());
    reference.compatibility = Some(raw.to_vec());
    reference.file_id = Some(uuid.clone());
    reference.uuid = Some(uuid);
    reference.file_id_crc = file.crc;
    reference.name = name;
    reference.size = file.size.unwrap_or_default();
    reference.md5 = file.md5.to_vec();
    Ok(Some(reference))
}
fn media_element(reference: MediaReference) -> MessageElement {
    match reference.kind {
        MediaKind::Image => MessageElement::Image(reference),
        MediaKind::Voice => MessageElement::Voice(reference),
        MediaKind::Video => MessageElement::Video(reference),
        MediaKind::File => MessageElement::File(reference),
    }
}
fn media_ref(element: &MessageElement) -> Option<&MediaReference> {
    match element {
        MessageElement::Image(reference)
        | MessageElement::Voice(reference)
        | MessageElement::Video(reference) => Some(reference),
        _ => None,
    }
}
fn append_media(out: &mut Vec<MessageElement>, incoming: MessageElement) {
    if let Some(reference) = media_ref(&incoming).filter(|reference| !reference.md5.is_empty()) {
        for existing in out.iter_mut().rev() {
            let Some(old) = media_ref(existing) else {
                continue;
            };
            if old.kind != reference.kind || old.md5 != reference.md5 {
                continue;
            }
            if old.kind == MediaKind::Video
                && matches!((&old.uuid, &reference.uuid), (Some(a), Some(b)) if a != b)
            {
                continue;
            }
            let mut combined = if reference.message_info.is_empty()
                && reference.compatibility.is_some()
                && !old.message_info.is_empty()
                && old.compatibility.is_none()
            {
                let mut combined = old.clone();
                combined.compatibility = reference.compatibility.clone();
                combined
            } else if !reference.message_info.is_empty()
                && reference.compatibility.is_none()
                && old.message_info.is_empty()
                && old.compatibility.is_some()
            {
                let mut combined = reference.clone();
                combined.compatibility = old.compatibility.clone();
                combined
            } else {
                continue;
            };
            if combined.download_url.is_none() {
                combined.download_url = old
                    .download_url
                    .clone()
                    .or_else(|| reference.download_url.clone());
            }
            *existing = media_element(combined);
            return;
        }
    }
    out.push(incoming);
}
fn forward_xml(data: &[u8]) -> Result<String> {
    use quick_xml::events::Event;
    let mut reader = quick_xml::Reader::from_reader(data);
    loop {
        match reader
            .read_event()
            .map_err(|error| Error::Malformed(error.to_string()))?
        {
            Event::Start(element) | Event::Empty(element) if element.name().as_ref() == b"msg" => {
                for attribute in element.attributes() {
                    let attribute =
                        attribute.map_err(|error| Error::Malformed(error.to_string()))?;
                    if attribute.key.as_ref() == b"m_resid" {
                        return attribute
                            .decode_and_unescape_value(reader.decoder())
                            .map(|value| value.into_owned())
                            .map_err(|error| Error::Malformed(error.to_string()));
                    }
                }
            }
            Event::Eof => break,
            Event::DocType(_) => {
                return Err(Error::Malformed(
                    "Forward XML document types are forbidden".into(),
                ));
            }
            _ => {}
        }
    }
    Err(Error::Malformed("Forward XML has no resource ID".into()))
}
fn application_payload(bytes: &[u8]) -> Result<Vec<u8>> {
    match bytes.split_first() {
        Some((0, rest)) => Ok(rest.to_vec()),
        Some((1, rest)) => decompress(rest, false),
        _ => Err(Error::Malformed(
            "Unknown application compression mode".into(),
        )),
    }
}
pub(crate) fn compress(data: &[u8], gzip: bool) -> Result<Vec<u8>> {
    if gzip {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data)?;
        Ok(encoder.finish()?)
    } else {
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data)?;
        Ok(encoder.finish()?)
    }
}
pub(crate) fn decompress(data: &[u8], gzip: bool) -> Result<Vec<u8>> {
    if gzip {
        read_compressed(flate2::read::GzDecoder::new(data))
    } else {
        read_compressed(flate2::read::ZlibDecoder::new(data))
    }
}
fn read_compressed(reader: impl Read) -> Result<Vec<u8>> {
    const MAX: u64 = 64 * 1024 * 1024;
    let mut out = Vec::new();
    reader.take(MAX + 1).read_to_end(&mut out)?;
    if out.len() as u64 > MAX {
        return Err(Error::Malformed(
            "Message decompression exceeds 64 MiB".into(),
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNKNOWN_BUSINESS: &[u8] = &[0xba, 0x3e, 3, 1, 2, 3, 0xba, 0x3e, 3, 4, 5, 6];
    const ANCILLARY: &[u8] = &[0x10, 123, 0x10, 124, 0xba, 0x3e, 2, 0, 255];

    fn wire_body(element: Vec<u8>, attrs: Vec<bytes::Bytes>) -> Vec<u8> {
        pb::MessageBody {
            rich_text: pb::RichText {
                attr: attrs,
                elems: vec![element.into()],
                ..Default::default()
            }
            .encode_to_vec()
            .into(),
            ..Default::default()
        }
        .encode_to_vec()
    }
    fn text_element() -> pb::Elem {
        pb::Elem {
            text: vec![
                pb::Text {
                    text: Some("/ping".into()),
                    ..Default::default()
                }
                .encode_to_vec()
                .into(),
            ],
            ..Default::default()
        }
    }
    fn parsed(raw: &[u8]) -> DecodedElements {
        decode_elements(raw, &Conversation::Group { uin: 42 }, 100).unwrap()
    }

    #[test]
    fn ping_metadata_keeps_payloads_scopes_and_duplicate_wire_values() {
        let mut element = text_element();
        element.flags2 = vec![ANCILLARY.into(), ANCILLARY.into()];
        element.extra_info = vec![ANCILLARY.into()];
        element.general_flags = vec![ANCILLARY.into()];
        let body = wire_body(
            element.encode_to_vec(),
            vec![ANCILLARY.into(), ANCILLARY.into()],
        );
        let decoded = parsed(&body);
        assert!(
            matches!(decoded.elements.as_slice(), [MessageElement::Text(text)] if text == "/ping")
        );
        assert_eq!(decoded.metadata.len(), 4);
        let attrs = decoded
            .metadata
            .iter()
            .find(|record| record.scope == OpaqueScope::RichText)
            .unwrap();
        assert_eq!(
            decode::<pb::RichText>(&attrs.payload).unwrap().attr,
            vec![bytes::Bytes::from_static(ANCILLARY); 2]
        );
        let flags = decoded
            .metadata
            .iter()
            .find(|record| record.field == 9)
            .unwrap();
        assert_eq!(
            decode::<pb::Elem>(&flags.payload).unwrap().flags2,
            vec![bytes::Bytes::from_static(ANCILLARY); 2]
        );
        let again = parsed(&encode_elements(&decoded.elements, &decoded.metadata).unwrap());
        assert!(
            matches!(again.elements.as_slice(), [MessageElement::Text(text)] if text == "/ping")
        );
        for original in &decoded.metadata {
            assert!(
                again
                    .metadata
                    .iter()
                    .any(|record| record.scope == original.scope
                        && record.field == original.field
                        && record.payload == original.payload)
            );
        }
    }

    #[test]
    fn known_metadata_and_unknown_business_in_one_element_do_not_hide_each_other() {
        let mut element = text_element();
        element.general_flags = vec![ANCILLARY.into()];
        let mut raw = element.encode_to_vec();
        raw.extend_from_slice(UNKNOWN_BUSINESS);
        let decoded = parsed(&wire_body(raw, vec![ANCILLARY.into()]));
        assert_eq!(decoded.metadata.len(), 2);
        assert!(matches!(&decoded.elements[0], MessageElement::Text(text) if text == "/ping"));
        let MessageElement::Opaque(unknown) = &decoded.elements[1] else {
            panic!("business content expected")
        };
        assert_eq!(unknown.scope, OpaqueScope::Element);
        assert_eq!(unknown.field, 999);
        assert_eq!(unknown.payload, UNKNOWN_BUSINESS);
        let again = parsed(&encode_elements(&decoded.elements, &decoded.metadata).unwrap());
        assert!(
            matches!(&again.elements[1], MessageElement::Opaque(value) if value.payload == UNKNOWN_BUSINESS)
        );
    }

    #[test]
    fn unknown_business_is_retained_at_each_scope() {
        let mut element = text_element().encode_to_vec();
        element.extend_from_slice(UNKNOWN_BUSINESS);
        let mut rich = pb::RichText {
            elems: vec![element.into()],
            ..Default::default()
        }
        .encode_to_vec();
        rich.extend_from_slice(UNKNOWN_BUSINESS);
        let mut body = pb::MessageBody {
            rich_text: rich.into(),
            ..Default::default()
        }
        .encode_to_vec();
        body.extend_from_slice(UNKNOWN_BUSINESS);
        let decoded = parsed(&body);
        assert!(decoded.metadata.is_empty());
        for scope in [
            OpaqueScope::Element,
            OpaqueScope::RichText,
            OpaqueScope::MessageBody,
        ] {
            assert!(decoded.elements.iter().any(|element| matches!(element, MessageElement::Opaque(value) if value.scope == scope && value.payload == UNKNOWN_BUSINESS)));
        }
        let again = parsed(&encode_elements(&decoded.elements, &decoded.metadata).unwrap());
        assert_eq!(
            again
                .elements
                .iter()
                .filter(|element| matches!(element, MessageElement::Opaque(_)))
                .count(),
            3
        );
    }

    #[test]
    fn nested_unknown_text_content_is_not_misclassified_as_metadata() {
        let mut text = pb::Text {
            text: Some("/ping".into()),
            ..Default::default()
        }
        .encode_to_vec();
        text.extend_from_slice(UNKNOWN_BUSINESS);
        let element = pb::Elem {
            text: vec![text.into()],
            ..Default::default()
        };
        let decoded = parsed(&wire_body(element.encode_to_vec(), vec![]));
        assert!(decoded.metadata.is_empty());
        assert!(matches!(&decoded.elements[0], MessageElement::Text(text) if text == "/ping"));
        let MessageElement::Opaque(unknown) = &decoded.elements[1] else {
            panic!("unknown text data expected")
        };
        assert_eq!(
            decode::<pb::Elem>(&unknown.payload).unwrap().text[0].as_ref(),
            UNKNOWN_BUSINESS
        );
        let again = parsed(&encode_elements(&decoded.elements, &[]).unwrap());
        assert!(
            matches!(&again.elements[1], MessageElement::Opaque(value) if value.payload == unknown.payload)
        );
    }

    #[test]
    fn unsupported_media_and_unproven_flags_remain_business_content() {
        let common = pb::CommonElem {
            service_type: Some(48),
            business_type: Some(999),
            payload: vec![0, 255].into(),
        };
        let mut element = pb::Elem {
            common: vec![common.encode_to_vec().into()],
            ..Default::default()
        }
        .encode_to_vec();
        // Field 7 has no verified declaration in the local current schema.
        element.extend_from_slice(&[0x3a, 2, 8, 1]);
        let decoded = parsed(&wire_body(element, vec![]));
        assert!(decoded.metadata.is_empty());
        assert_eq!(decoded.elements.len(), 2);
        assert!(
            decoded
                .elements
                .iter()
                .all(|element| matches!(element, MessageElement::Opaque(_)))
        );
        let again = parsed(&encode_elements(&decoded.elements, &[]).unwrap());
        assert_eq!(again.elements.len(), 2);
    }

    #[test]
    fn real_application_and_xml_forward_wire_are_not_metadata_or_mock_echoes() {
        let app =
            MessageElement::LightApp(r#"{"app":"business.custom","meta":{"value":1}}"#.into());
        let decoded = parsed(&encode_elements(&[app], &[]).unwrap());
        assert!(
            matches!(&decoded.elements[0], MessageElement::LightApp(value) if value.contains("business.custom"))
        );
        let mut payload = vec![0];
        payload.extend_from_slice(br#"<msg serviceID="35" m_resid="original" extra="retained"/>"#);
        let mut rich_msg = pb::RichMsg {
            data: payload.into(),
            service_id: Some(35),
        }
        .encode_to_vec();
        rich_msg.extend_from_slice(UNKNOWN_BUSINESS);
        let element = pb::Elem {
            rich_msg: vec![rich_msg.into()],
            ..Default::default()
        }
        .encode_to_vec();
        let mut decoded = parsed(&wire_body(element.clone(), vec![]));
        assert!(decoded.metadata.is_empty());
        let MessageElement::Forward(reference) = &mut decoded.elements[0] else {
            panic!("real XML forward expected")
        };
        assert_eq!(reference.raw_element.as_deref(), Some(element.as_slice()));
        let encoded = encode_elements(&decoded.elements, &[]).unwrap();
        let body: pb::MessageBody = decode(&encoded).unwrap();
        assert_eq!(
            decode::<pb::RichText>(&body.rich_text).unwrap().elems[0].as_ref(),
            element
        );
        let MessageElement::Forward(reference) = &mut decoded.elements[0] else {
            unreachable!()
        };
        reference.resource_id = "requested".into();
        let rebuilt = parsed(&encode_elements(&decoded.elements, &[]).unwrap());
        assert!(
            matches!(&rebuilt.elements[0], MessageElement::Forward(value) if value.resource_id == "requested")
        );
    }

    #[test]
    fn metadata_cannot_smuggle_unknown_or_known_business_fields() {
        let mut element = pb::Elem {
            general_flags: vec![ANCILLARY.into()],
            ..Default::default()
        }
        .encode_to_vec();
        element.extend_from_slice(UNKNOWN_BUSINESS);
        assert!(
            validate_metadata(&OpaqueElement {
                scope: OpaqueScope::Element,
                field: 37,
                payload: element
            })
            .is_err()
        );
        let element = pb::Elem {
            flags2: vec![ANCILLARY.into()],
            text: text_element().text,
            ..Default::default()
        }
        .encode_to_vec();
        assert!(
            validate_metadata(&OpaqueElement {
                scope: OpaqueScope::Element,
                field: 9,
                payload: element
            })
            .is_err()
        );
        assert!(
            validate_metadata(&OpaqueElement {
                scope: OpaqueScope::Element,
                field: 53,
                payload: vec![]
            })
            .is_err()
        );
    }

    #[test]
    fn specific_mentions_and_invalid_packed_reply_sequences_are_rejected() {
        assert!(
            encode_elements(
                &[MessageElement::Mention(Mention {
                    uin: 42,
                    uid: None,
                    display: "@peer".into(),
                    is_everyone: false
                })],
                &[]
            )
            .is_err()
        );
        let element = pb::Elem {
            source_msg: vec![vec![0x0a, 1, 0x80].into()],
            ..Default::default()
        };
        assert!(
            decode_elements(
                &wire_body(element.encode_to_vec(), vec![]),
                &Conversation::Group { uin: 42 },
                100
            )
            .is_err()
        );
    }
}
