use super::{Media, MediaConversation, MediaKind, MediaReference, valid_http_url};
use crate::{Error, Result, proto::media as pb};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LegacyVideoPlayContext {
    /// Original message sender, not necessarily the logged-in account.
    pub from_uin: u64,
    /// Original receiver for a private message; group UIN for a group message.
    pub to_uin: u64,
    pub client_type: u32,
    /// The old API's request-way value: 1 maps to down_type 1, all others to 2.
    #[serde(default)]
    pub video_request_way: u32,
    #[serde(default)]
    pub business_type: u32,
    #[serde(default)]
    pub sub_business_type: u32,
    #[serde(default)]
    pub target_codec_format: u32,
    #[serde(default)]
    pub source_format: u32,
    #[serde(default)]
    pub device_codec_info: Option<pb::LegacyVideoDeviceCodecInfo>,
}

impl Media {
    /// Request the old ShortVideoDownReq/GroupShortVideoDownReq protocol only.
    ///
    /// Requires the old VideoFile in `reference.compatibility`. Identity fields
    /// cannot be inferred from a peer UID; no UID lookup or NTV2 fallback occurs.
    pub async fn legacy_video_play_url(
        &self,
        reference: &MediaReference,
        context: LegacyVideoPlayContext,
    ) -> Result<String> {
        let (command, request) = legacy_request(reference, context)?;
        let response: pb::LegacyVideoPlayResponse = self.request(command, request).await?;
        legacy_url(response)
    }
}

fn legacy_request(
    reference: &MediaReference,
    context: LegacyVideoPlayContext,
) -> Result<(&'static str, pb::LegacyVideoPlayRequest)> {
    if reference.kind != MediaKind::Video {
        return Err(Error::Malformed("Expected video reference".into()));
    }
    if context.from_uin == 0 || context.to_uin == 0 {
        return Err(Error::Malformed(
            "Legacy playback requires original sender and receiver UINs".into(),
        ));
    }
    let (command, chat_type, group_uin) = match &reference.conversation {
        MediaConversation::Friend { .. } => ("PttCenterSvr.ShortVideoDownReq", 0, None),
        MediaConversation::Group { uin } => {
            if *uin == 0 || context.to_uin != *uin {
                return Err(Error::Malformed(
                    "Legacy video receiver must match the group UIN".into(),
                ));
            }
            ("PttCenterSvr.GroupShortVideoDownReq", 1, Some(*uin))
        }
    };
    let raw = reference.compatibility.as_ref().ok_or_else(|| {
        Error::Unsupported(
            "Legacy playback requires the original VideoFile; MsgInfo UUID is not interchangeable"
                .into(),
        )
    })?;
    let video: pb::VideoFile = crate::proto::decode(raw.as_slice())?;
    let file_id = video
        .uuid
        .filter(|id| !id.is_empty())
        .ok_or_else(|| Error::Malformed("Original VideoFile has no legacy UUID".into()))?;
    Ok((
        command,
        pb::LegacyVideoPlayRequest {
            command: Some(400),
            sequence: Some(0),
            download: Some(pb::LegacyVideoDownloadRequest {
                from_uin: Some(context.from_uin),
                to_uin: Some(context.to_uin),
                chat_type: Some(chat_type),
                client_type: Some(context.client_type),
                file_id: Some(file_id),
                group_uin,
                agent_type: Some(0),
                file_md5: Some(video.md5.unwrap_or_default()),
                business_type: Some(context.business_type),
                file_type: Some(2),
                down_type: Some(if context.video_request_way == 1 { 1 } else { 2 }),
                scene_type: Some(0),
                need_inner_address: Some(0),
                request_transfer_type: Some(2),
                request_host_type: Some(11),
                supports_large_size: Some(1),
                client_quic_enabled: Some(0),
                target_codec_format: Some(context.target_codec_format),
                device_codec_info: context.device_codec_info,
                source_format: Some(context.source_format),
            }),
            extension: vec![pb::LegacyVideoExtension {
                sub_business_type: Some(context.sub_business_type),
            }],
        },
    ))
}

fn legacy_url(response: pb::LegacyVideoPlayResponse) -> Result<String> {
    if response.command != Some(410) {
        return Err(Error::Malformed(
            "Unexpected legacy video response command".into(),
        ));
    }
    let download = response
        .download
        .ok_or_else(|| Error::Malformed("Legacy video response has no download result".into()))?;
    let code = download.code.unwrap_or_default();
    if code != 0 {
        return Err(Error::Server {
            code,
            message: download
                .message
                .and_then(|v| String::from_utf8(v.to_vec()).ok())
                .unwrap_or_else(|| "Legacy video request failed".into()),
        });
    }
    let address = download
        .address
        .ok_or_else(|| Error::Malformed("Legacy video response has no download address".into()))?;
    let args = address.url_args.unwrap_or_default();
    for host in address
        .domain_hosts
        .into_iter()
        .chain(address.ipv4_hosts)
        .chain(address.ipv6_hosts)
    {
        // Do not add a scheme or normalize/re-encode signed query parameters.
        let url = format!("{host}{args}&filename=1.mp4");
        if valid_http_url(&url).is_ok() {
            return Ok(url);
        }
    }
    Err(Error::Malformed(
        "Legacy video response has no usable HTTP(S) URL".into(),
    ))
}

#[cfg(test)]
mod tests;
