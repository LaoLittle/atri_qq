use atri_core::{
    ApiError, CallerKind, MessageContent, SendMessage, ServiceCall, decode, from_value,
};
use atri_qq_api::signing::SIGNING_SERVICE;
use atri_qq_protocol::{
    media::{MediaInput, MediaReference},
    messages::{Message, MessageElement},
};
use serde::Deserialize;

pub(crate) fn trusted(kind: CallerKind) -> bool {
    matches!(kind, CallerKind::Native | CallerKind::Runtime)
}

fn denied() -> ApiError {
    ApiError::new(
        "permission_denied",
        "local QQ filesystem and signing resources require a trusted native or runtime caller",
    )
}

pub(crate) fn require_trusted(kind: CallerKind) -> Result<(), ApiError> {
    if trusted(kind) { Ok(()) } else { Err(denied()) }
}

fn input(input: &MediaInput) -> Result<(), ApiError> {
    match input {
        MediaInput::File { .. } => Err(denied()),
        MediaInput::Data { .. } => Ok(()),
        MediaInput::Url { url } => remote_url(url),
    }
}

fn remote_url(url: &str) -> Result<(), ApiError> {
    if url.starts_with("https://") || url.starts_with("http://") {
        Ok(())
    } else {
        Err(denied())
    }
}

fn reference(value: &MediaReference) -> Result<(), ApiError> {
    if let Some(url) = &value.download_url {
        remote_url(url)?;
    }
    Ok(())
}

fn element(value: &MessageElement) -> Result<(), ApiError> {
    match value {
        MessageElement::Image(value)
        | MessageElement::Voice(value)
        | MessageElement::Video(value)
        | MessageElement::File(value) => reference(value),
        // These are wire bytes/references only; the native codec does not open paths.
        _ => Ok(()),
    }
}

fn content(root: &MessageContent) -> Result<(), ApiError> {
    let mut pending = vec![root];
    while let Some(value) = pending.pop() {
        match value {
            MessageContent::Composite(parts) => pending.extend(parts),
            MessageContent::Reply { content, .. } => pending.push(content),
            MessageContent::Forward { records } => {
                pending.extend(records.iter().map(|r| &r.content))
            }
            MessageContent::Media {
                metadata, handle, ..
            } => {
                // Check every supplied input, even one shadowed by a reference. Validate the
                // entire tree before conversation/mention lookup or the first upload.
                for key in ["qq.input", "thumbnail"] {
                    if let Some(value) = metadata.get(key) {
                        input(&from_value::<MediaInput>(value)?)?;
                    }
                }
                if let Some(value) = metadata.get("qq.reference") {
                    reference(&from_value::<MediaReference>(value)?)?;
                } else if !metadata.contains_key("qq.input") {
                    remote_url(handle)?;
                }
            }
            MessageContent::Opaque { format, data } if format == "qq.message-element.cbor" => {
                element(&decode::<MessageElement>(data)?)?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Must run before taking service state or doing any protocol lookup/network/I/O.
/// The generic send is decoded once and handed to the existing conversion path.
pub(crate) fn prepare(call: &ServiceCall) -> Result<Option<SendMessage>, ApiError> {
    if call.service == SIGNING_SERVICE {
        require_trusted(call.caller_kind)?;
    }
    let outbound = if call.service == "atri.messaging" && call.method == "send" {
        Some(from_value::<SendMessage>(&call.args)?)
    } else {
        None
    };
    if trusted(call.caller_kind) {
        return Ok(outbound);
    }
    if let Some(outbound) = &outbound {
        content(&outbound.content)?;
    }
    match (call.service.as_str(), call.method.as_str()) {
        ("qq.media", "download") => return Err(denied()),
        (
            "qq.media",
            "upload_image" | "upload_voice" | "upload_video" | "upload_avatar" | "upload_file",
        ) => {
            #[derive(Deserialize)]
            struct Inputs {
                input: MediaInput,
                thumbnail: Option<MediaInput>,
            }
            let args: Inputs = from_value(&call.args)?;
            input(&args.input)?;
            if let Some(thumbnail) = &args.thumbnail {
                input(thumbnail)?;
            }
        }
        (
            "qq.media",
            "send_file" | "download_url" | "file_download_url" | "legacy_video_play_url",
        ) => {
            #[derive(Deserialize)]
            struct Reference {
                reference: MediaReference,
            }
            reference(&from_value::<Reference>(&call.args)?.reference)?;
        }
        ("qq.messaging", "send") => {
            #[derive(Deserialize)]
            struct Elements {
                elements: Vec<MessageElement>,
            }
            for value in &from_value::<Elements>(&call.args)?.elements {
                element(value)?;
            }
        }
        ("qq.messaging", "upload_forward") => {
            #[derive(Deserialize)]
            struct Messages {
                messages: Vec<Message>,
            }
            for message in &from_value::<Messages>(&call.args)?.messages {
                for value in &message.elements {
                    element(value)?;
                }
            }
        }
        _ => {}
    }
    Ok(outbound)
}
