use super::*;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaKind {
    Image,
    Voice,
    Video,
    File,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MediaConversation {
    Friend { uid: String },
    Group { uin: u64 },
}
impl MediaConversation {
    pub fn is_group(&self) -> bool {
        matches!(self, Self::Group { .. })
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MediaInput {
    Data { data: Vec<u8>, name: String },
    File { path: PathBuf },
    Url { url: String },
}

/// The server-negotiated reference describes original bytes, never a conversion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaReference {
    pub kind: MediaKind,
    pub conversation: MediaConversation,
    #[serde(default)]
    pub message_info: Vec<u8>,
    pub compatibility: Option<Vec<u8>>,
    pub file_id: Option<String>,
    pub file_id_crc: Option<String>,
    pub uuid: Option<String>,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub md5: Vec<u8>,
    #[serde(default)]
    pub sha1: Vec<u8>,
    #[serde(default)]
    pub width: u32,
    #[serde(default)]
    pub height: u32,
    #[serde(default)]
    pub duration: u32,
    pub download_url: Option<String>,
}
impl MediaReference {
    pub fn new(kind: MediaKind, conversation: MediaConversation) -> Self {
        Self {
            kind,
            conversation,
            message_info: vec![],
            compatibility: None,
            file_id: None,
            file_id_crc: None,
            uuid: None,
            name: String::new(),
            size: 0,
            md5: vec![],
            sha1: vec![],
            width: 0,
            height: 0,
            duration: 0,
            download_url: None,
        }
    }
    pub fn encode_elements(&self) -> Result<Vec<Vec<u8>>> {
        if self.kind == MediaKind::File {
            return Err(Error::Unsupported(
                "Files require the dedicated send service".into(),
            ));
        }
        let mut out = Vec::new();
        if self.kind == MediaKind::Image
            || (self.kind == MediaKind::Video && self.message_info.is_empty())
        {
            if let Some(raw) = self.compatibility.as_ref().filter(|v| !v.is_empty()) {
                let mut element = pb::MediaElement::default();
                if self.kind == MediaKind::Video {
                    let _: pb::VideoFile = crate::proto::decode(raw.as_slice())?;
                    element.video = Some(Bytes::copy_from_slice(raw));
                } else if self.conversation.is_group() {
                    let _: pb::CustomFace = crate::proto::decode(raw.as_slice())?;
                    element.group_image = Some(Bytes::copy_from_slice(raw));
                } else {
                    let _: pb::NotOnlineImage = crate::proto::decode(raw.as_slice())?;
                    element.direct_image = Some(Bytes::copy_from_slice(raw));
                }
                out.push(element.encode_to_vec());
            }
        }
        if !self.message_info.is_empty() {
            let business = (if self.conversation.is_group() { 20 } else { 10 })
                + match self.kind {
                    MediaKind::Voice => 2,
                    MediaKind::Video => 1,
                    _ => 0,
                };
            out.push(
                pb::MediaElement {
                    common: Some(pb::MediaCommonElement {
                        service_type: Some(48),
                        payload: Some(Bytes::copy_from_slice(&self.message_info)),
                        business_type: Some(business),
                    }),
                    ..Default::default()
                }
                .encode_to_vec(),
            );
        }
        if out.is_empty() {
            return Err(Error::Malformed(
                "Media reference has no negotiated payload".into(),
            ));
        }
        Ok(out)
    }
    pub fn from_message_info(
        data: Vec<u8>,
        kind: MediaKind,
        conversation: MediaConversation,
        compatibility: Option<Vec<u8>>,
    ) -> Result<Self> {
        let info: pb::MediaMessageInfo = crate::proto::decode(data.as_slice())?;
        let body: pb::MediaMessageInfoBody = crate::proto::decode(
            info.bodies
                .into_iter()
                .next()
                .ok_or_else(|| Error::Malformed("Media has no index body".into()))?,
        )?;
        let index: pb::MediaIndex = crate::proto::decode(
            body.index
                .ok_or_else(|| Error::Malformed("Missing protobuf field 1".into()))?,
        )?;
        let file = index
            .file
            .ok_or_else(|| Error::Malformed("Missing protobuf field 1".into()))?;
        let uuid = index
            .uuid
            .and_then(|v| String::from_utf8(v.to_vec()).ok())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Error::Malformed("Media has no UUID".into()))?;
        let mut result = Self::new(kind, conversation);
        result.message_info = data;
        result.compatibility = compatibility;
        result.uuid = Some(uuid);
        result.name = file
            .name
            .and_then(|v| String::from_utf8(v.to_vec()).ok())
            .unwrap_or_default();
        result.size = file.size.unwrap_or_default();
        result.md5 = hex::decode(
            file.md5
                .and_then(|v| String::from_utf8(v.to_vec()).ok())
                .unwrap_or_default(),
        )
        .map_err(|e| Error::Malformed(e.to_string()))?;
        result.sha1 = hex::decode(
            file.sha1
                .and_then(|v| String::from_utf8(v.to_vec()).ok())
                .unwrap_or_default(),
        )
        .map_err(|e| Error::Malformed(e.to_string()))?;
        result.width = file.width.unwrap_or_default();
        result.height = file.height.unwrap_or_default();
        result.duration = file.duration.unwrap_or_default();
        Ok(result)
    }
    pub fn decode_element(data: &[u8], conversation: MediaConversation) -> Result<Option<Self>> {
        let elem: pb::MediaElement = crate::proto::decode(data)?;
        if let Some(common) = elem.common {
            if common.service_type.unwrap_or_default() == 48 {
                let kind = match common.business_type.unwrap_or_default() {
                    10 | 20 => MediaKind::Image,
                    11 | 21 => MediaKind::Video,
                    12 | 22 => MediaKind::Voice,
                    _ => return Ok(None),
                };
                let info = common
                    .payload
                    .ok_or_else(|| Error::Malformed("Rich media has no MsgInfo".into()))?;
                let compatibility = match kind {
                    MediaKind::Voice => None,
                    MediaKind::Video => elem.video,
                    _ if conversation.is_group() => elem.group_image,
                    _ => elem.direct_image,
                }
                .map(|v| v.to_vec());
                return Self::from_message_info(info.to_vec(), kind, conversation, compatibility)
                    .map(Some);
            }
        }
        if let Some(raw) = elem.direct_image {
            let compatibility: pb::NotOnlineImage = crate::proto::decode(raw.clone())?;
            let mut r = Self::new(MediaKind::Image, conversation);
            r.compatibility = Some(raw.to_vec());
            r.name = compatibility
                .name
                .and_then(|v| String::from_utf8(v.to_vec()).ok())
                .unwrap_or_default();
            r.size = compatibility.size.unwrap_or_default();
            r.md5 = compatibility.md5.unwrap_or_default().to_vec();
            r.width = compatibility.width.unwrap_or_default() as u32;
            r.height = compatibility.height.unwrap_or_default() as u32;
            r.uuid = compatibility
                .uuid
                .and_then(|v| String::from_utf8(v.to_vec()).ok());
            r.download_url = compatibility
                .original_url
                .and_then(|v| String::from_utf8(v.to_vec()).ok())
                .filter(|v| v.starts_with('/'))
                .map(|v| format!("https://c2cpicdw.qpic.cn{v}"));
            return Ok(Some(r));
        }
        if let Some(raw) = elem.group_image {
            let compatibility: pb::CustomFace = crate::proto::decode(raw.clone())?;
            let mut r = Self::new(MediaKind::Image, conversation);
            r.compatibility = Some(raw.to_vec());
            r.name = compatibility
                .name
                .and_then(|v| String::from_utf8(v.to_vec()).ok())
                .unwrap_or_default();
            r.md5 = compatibility.md5.unwrap_or_default().to_vec();
            r.size = compatibility.size.unwrap_or_default();
            r.width = compatibility.width.unwrap_or_default() as u32;
            r.height = compatibility.height.unwrap_or_default() as u32;
            r.download_url = compatibility
                .original_url
                .and_then(|v| String::from_utf8(v.to_vec()).ok())
                .filter(|v| v.starts_with('/'))
                .map(|v| format!("https://gchat.qpic.cn{v}"));
            return Ok(Some(r));
        }
        if let Some(raw) = elem.video {
            let compatibility: pb::VideoFile = crate::proto::decode(raw.clone())?;
            let mut r = Self::new(MediaKind::Video, conversation);
            r.compatibility = Some(raw.to_vec());
            r.uuid = compatibility
                .uuid
                .and_then(|v| String::from_utf8(v.to_vec()).ok());
            r.md5 = compatibility.md5.unwrap_or_default().to_vec();
            r.name = compatibility
                .name
                .and_then(|v| String::from_utf8(v.to_vec()).ok())
                .unwrap_or_default();
            r.duration = compatibility.duration.unwrap_or_default() as u32;
            r.size = compatibility.size.unwrap_or_default();
            r.width = compatibility.width.unwrap_or_default();
            r.height = compatibility.height.unwrap_or_default();
            r.download_url = compatibility
                .urls
                .iter()
                .filter_map(|v| std::str::from_utf8(v).ok())
                .find_map(|v| valid_http_url(v).ok().map(|_| v.to_owned()));
            return Ok(Some(r));
        }
        Ok(None)
    }
    pub fn decode_ptt(data: &[u8], conversation: MediaConversation, own_uin: u64) -> Result<Self> {
        let ptt: pb::Ptt = crate::proto::decode(data)?;
        let url = ptt
            .url
            .iter()
            .chain(ptt.urls.iter())
            .filter_map(|raw| std::str::from_utf8(raw).ok())
            .find_map(|url| {
                if url.starts_with("http://") || url.starts_with("https://") {
                    Some(url.to_owned())
                } else if url.starts_with('/') && !url.starts_with("//") {
                    Some(format!("https://grouptalk.c2c.qq.com{url}"))
                } else {
                    None
                }
            });
        let key = ptt
            .group_file_key
            .as_ref()
            .filter(|key| !key.is_empty())
            .or_else(|| ptt.file_key.as_ref().filter(|key| !key.is_empty()))
            .or_else(|| ptt.uuid.as_ref().filter(|key| !key.is_empty()));
        let download_url = url.or_else(|| {
            key.map(|key| {
                let mut kv = Vec::new();
                for item in ["filetype", "0", "codec", "1"] {
                    kv.extend_from_slice(&(item.len() as u32).to_be_bytes());
                    kv.extend_from_slice(item.as_bytes());
                }
                let mut inner = Vec::new();
                for value in [1, 0, own_uin as u32 as i32 as i64] {
                    inner.extend(der_integer(value));
                }
                inner.extend(der(4, key));
                inner.extend(der_integer(now_seconds() as i64));
                inner.extend(der(4, &kv));
                let mut outer = der_integer(1);
                outer.extend(der(4, &der(0x30, &inner)));
                outer.extend(der(4, &[]));
                format!(
                    "https://grouptalk.c2c.qq.com/?ver=2&rkey={}&voice_codec=1&filetype=0",
                    hex::encode_upper(der(0x30, &outer))
                )
            })
        });
        let mut r = Self::new(MediaKind::Voice, conversation);
        r.compatibility = Some(data.to_vec());
        r.uuid = ptt.uuid.and_then(|v| String::from_utf8(v.to_vec()).ok());
        r.name = ptt
            .name
            .and_then(|v| String::from_utf8(v.to_vec()).ok())
            .unwrap_or_default();
        r.size = ptt.size.unwrap_or_default();
        r.md5 = ptt.md5.unwrap_or_default().to_vec();
        r.duration = ptt.duration.unwrap_or_default() as u32;
        r.download_url = download_url;
        Ok(r)
    }
}
fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if body.len() < 128 {
        out.push(body.len() as u8)
    } else {
        let n = body.len().to_be_bytes();
        let start = n.iter().position(|v| *v != 0).unwrap_or(n.len() - 1);
        out.push(0x80 | (n.len() - start) as u8);
        out.extend_from_slice(&n[start..]);
    }
    out.extend_from_slice(body);
    out
}
fn der_integer(value: i64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let mut start = 0;
    while start < 7
        && ((bytes[start] == 0 && bytes[start + 1] & 0x80 == 0)
            || (bytes[start] == 255 && bytes[start + 1] & 0x80 != 0))
    {
        start += 1
    }
    der(2, &bytes[start..])
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSendReceipt {
    pub sequence: Option<u64>,
    pub client_sequence: Option<u64>,
    pub random: u32,
    pub time: Option<u32>,
    pub file_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn standalone_video_file_retains_first_valid_field21_url() {
        let video = pb::VideoFile {
            uuid: Some(Bytes::from_static(b"uuid")),
            name: Some(Bytes::from_static(b"clip.mp4")),
            urls: vec![
                Bytes::from_static(b"not a URL"),
                Bytes::from_static(b"https://media.example/clip?token=x"),
                Bytes::from_static(b"http://other.example/unused"),
            ],
            ..Default::default()
        }
        .encode_to_vec();
        let decoded = MediaReference::decode_element(
            &pb::MediaElement {
                video: Some(video.clone().into()),
                ..Default::default()
            }
            .encode_to_vec(),
            MediaConversation::Group { uin: 42 },
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            decoded.download_url.as_deref(),
            Some("https://media.example/clip?token=x")
        );
        assert!(decoded.message_info.is_empty());
        assert_eq!(decoded.compatibility, Some(video));
    }
    #[test]
    fn rich_reference_preserves_unknown_metadata_and_compatibility_bytes() {
        let index = pb::MediaIndex {
            file: Some(pb::MediaFileInfo {
                size: Some(7),
                md5: Some(Bytes::from_static(b"0102")),
                sha1: Some(Bytes::from_static(b"0304")),
                name: Some(Bytes::from_static(b"photo.png")),
                width: Some(2),
                height: Some(3),
                ..Default::default()
            }),
            uuid: Some(Bytes::from_static(b"server-uuid")),
            ..Default::default()
        }
        .encode_to_vec();
        let mut body = pb::MediaMessageInfoBody {
            index: Some(index.into()),
            ..Default::default()
        }
        .encode_to_vec();
        // Unknown server extension on MsgInfoBody.
        body.extend_from_slice(&[0xb8, 0x3e, 0x07]);
        let mut info = pb::MediaMessageInfo {
            bodies: vec![body.into()],
            ..Default::default()
        }
        .encode_to_vec();
        // Unknown top-level MsgInfo extension.
        info.extend_from_slice(&[0xc2, 0x3e, 0x03, b'n', b'e', b'w']);
        let mut compatibility = pb::CustomFace {
            name: Some(Bytes::from_static(b"photo.png")),
            ..Default::default()
        }
        .encode_to_vec();
        compatibility.extend_from_slice(&[0xc8, 0x3e, 0x09]);
        let reference = MediaReference::from_message_info(
            info.clone(),
            MediaKind::Image,
            MediaConversation::Group { uin: 42 },
            Some(compatibility.clone()),
        )
        .unwrap();
        assert_eq!(reference.size, 7);
        assert_eq!(reference.md5, [1, 2]);
        assert_eq!((reference.width, reference.height), (2, 3));
        let elements = reference.encode_elements().unwrap();
        let element: pb::MediaElement = crate::proto::decode(elements[0].as_slice()).unwrap();
        assert_eq!(
            element.group_image.as_deref(),
            Some(compatibility.as_slice())
        );
        let common: pb::MediaElement = crate::proto::decode(elements[1].as_slice()).unwrap();
        assert_eq!(
            common.common.unwrap().payload.as_deref(),
            Some(info.as_slice())
        );
    }
}
