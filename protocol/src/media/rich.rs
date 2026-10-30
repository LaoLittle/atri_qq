use super::payload::MediaPayload;
use super::{
    Media, MediaConversation, MediaInput, MediaKind, MediaReference, ipv4, media_command,
    media_head,
};
use crate::{Error, Result, proto::media as pb};
use bytes::Bytes;
use prost::Message;

const DEFAULT_THUMBNAIL: &[u8] = include_bytes!("default_thumbnail.jpg");

impl Media {
    pub async fn upload_image(
        &self,
        input: MediaInput,
        conversation: MediaConversation,
        summary: &str,
    ) -> Result<MediaReference> {
        let mut payload = self.prepare(input, false, false).await?;
        let result = async {
            let info = payload.image_info().await?;
            let file = rich_file(
                &payload,
                MediaKind::Image,
                info.format,
                info.width,
                info.height,
                0,
                &info.suffix,
            )?;
            self.rich_upload(
                &payload,
                MediaKind::Image,
                conversation,
                file,
                summary,
                None,
            )
            .await
        }
        .await;
        payload.dispose().await;
        result
    }

    pub async fn upload_voice(
        &self,
        input: MediaInput,
        conversation: MediaConversation,
    ) -> Result<MediaReference> {
        let mut payload = self.prepare(input, false, false).await?;
        let result = async {
            let duration = payload.silk_duration().await?;
            let file = rich_file(&payload, MediaKind::Voice, 1, 0, 0, duration, "silk")?;
            self.rich_upload(&payload, MediaKind::Voice, conversation, file, "", None)
                .await
        }
        .await;
        payload.dispose().await;
        result
    }

    /// Upload a pre-encoded, nonfragmented MP4 with a recognized video track
    /// (currently avc1/H.264, hev1/H.265, or vp09/VP9).
    ///
    /// Zero metadata arguments are derived from the container. Nonzero arguments
    /// must match its display dimensions and duration rounded up to whole seconds;
    /// conflicts fail before negotiation. This validates container metadata and
    /// sample extents, not codec decodability or recipient playback support.
    pub async fn upload_video(
        &self,
        input: MediaInput,
        thumbnail: Option<MediaInput>,
        conversation: MediaConversation,
        width: u32,
        height: u32,
        duration: u32,
    ) -> Result<MediaReference> {
        let mut payload = self.prepare(input, false, true).await?;
        let result = async {
            let metadata = payload.video_info().await?;
            for (field, supplied, actual) in [
                ("width", width, metadata.width),
                ("height", height, metadata.height),
                ("duration", duration, metadata.duration),
            ] {
                if supplied != 0 && supplied != actual {
                    return Err(malformed(&format!(
                        "Video {field} conflicts with MP4 metadata: supplied {supplied}, actual {actual}"
                    )));
                }
            }
            let thumbnail = thumbnail.unwrap_or_else(|| MediaInput::Data {
                data: DEFAULT_THUMBNAIL.to_vec(),
                name: "desktop-video-cover.jpg".into(),
            });
            let mut thumb = self.prepare(thumbnail, false, false).await?;
            let result = async {
                let info = thumb.image_info().await?;
                let file = rich_file(
                    &payload,
                    MediaKind::Video,
                    0,
                    metadata.width,
                    metadata.height,
                    metadata.duration,
                    "mp4",
                )?;
                let thumb_file = rich_file(
                    &thumb,
                    MediaKind::Image,
                    info.format,
                    info.width,
                    info.height,
                    0,
                    &info.suffix,
                )?;
                self.rich_upload(
                    &payload,
                    MediaKind::Video,
                    conversation,
                    file,
                    "",
                    Some((&thumb, thumb_file)),
                )
                .await
            }
            .await;
            thumb.dispose().await;
            result
        }
        .await;
        payload.dispose().await;
        result
    }

    async fn rich_upload(
        &self,
        payload: &MediaPayload,
        kind: MediaKind,
        conversation: MediaConversation,
        file: pb::MediaFileInfo,
        summary: &str,
        thumbnail: Option<(&MediaPayload, pb::MediaFileInfo)>,
    ) -> Result<MediaReference> {
        let mut upload = upload_request(kind, &conversation, file, summary);
        let thumbnail = thumbnail.map(|(thumb, thumb_file)| {
            upload.files.push(pb::MediaUploadFile {
                file: Some(thumb_file),
                subfile_type: Some(100),
            });
            thumb
        });
        let request = pb::MediaRichUploadRequest {
            head: Some(media_head(kind, &conversation, 100, 2)?),
            upload: Some(upload),
        };
        let response: pb::MediaRichUploadResponse = self
            .oidb(media_command(kind, &conversation), 100, request, 1, None)
            .await?;
        let head = response
            .head
            .ok_or_else(|| malformed("Missing protobuf field 1"))?;
        let code = head.code.unwrap_or_default() as i32;
        if code != 0 {
            return Err(Error::Server {
                code,
                message: head
                    .message
                    .and_then(|value| String::from_utf8(value.to_vec()).ok())
                    .unwrap_or_else(|| "QQ request failed".into()),
            });
        }
        let negotiated = response
            .negotiation
            .ok_or_else(|| malformed("Missing protobuf field 2"))?;
        let info = negotiated
            .message_info
            .as_ref()
            .ok_or_else(|| malformed("Upload negotiation returned no MsgInfo"))?;
        let mut result = MediaReference::from_message_info(
            info.to_vec(),
            kind,
            conversation.clone(),
            negotiated
                .compatibility
                .as_ref()
                .map(|value| value.to_vec()),
        )?;
        let bodies = crate::proto::decode::<pb::MediaMessageInfo>(info.clone())?.bodies;
        if bodies.is_empty() {
            return Err(malformed("Upload negotiation returned no MsgInfoBody"));
        }
        if let Some(key) = negotiated
            .upload_key
            .as_ref()
            .filter(|value| !value.is_empty() && std::str::from_utf8(value).is_ok())
        {
            let hashes = if matches!(kind, MediaKind::Video) {
                payload.video_hashes.as_slice()
            } else {
                std::slice::from_ref(&payload.sha1)
            };
            let ext = highway_rich_ext(key, &negotiated.addresses, &bodies, 0, hashes)?;
            let command = match kind {
                MediaKind::Image => {
                    if conversation.is_group() {
                        1004
                    } else {
                        1003
                    }
                }
                MediaKind::Voice => {
                    if conversation.is_group() {
                        1008
                    } else {
                        1007
                    }
                }
                MediaKind::Video => {
                    if conversation.is_group() {
                        1005
                    } else {
                        1001
                    }
                }
                MediaKind::File => {
                    return Err(Error::Unsupported("Files do not use rich upload".into()));
                }
            };
            self.highway_upload(payload, command, ext).await?;
        }
        if let Some(thumb) = thumbnail {
            if bodies.len() < 2 {
                return Err(malformed("Video negotiation omitted thumbnail index"));
            }
            let subfile = negotiated
                .subfiles
                .iter()
                .find(|value| value.subfile_type == Some(100))
                .ok_or_else(|| malformed("Video negotiation omitted thumbnail upload state"))?;
            if let Some(key) = subfile
                .upload_key
                .as_ref()
                .filter(|value| !value.is_empty() && std::str::from_utf8(value).is_ok())
            {
                // The extension identifies the thumbnail subfile while retaining
                // the complete negotiated MsgInfo body list.
                let ext = highway_rich_ext(
                    key,
                    &subfile.addresses,
                    &bodies,
                    1,
                    std::slice::from_ref(&thumb.sha1),
                )?;
                self.highway_upload(
                    thumb,
                    if conversation.is_group() { 1006 } else { 1002 },
                    ext,
                )
                .await?;
            }
        }
        result.name.clone_from(&payload.name);
        Ok(result)
    }
}

fn rich_file(
    payload: &MediaPayload,
    kind: MediaKind,
    format: u32,
    width: u32,
    height: u32,
    duration: u32,
    suffix: &str,
) -> Result<pb::MediaFileInfo> {
    if payload.size > u32::MAX as u64 {
        return Err(Error::Unsupported(
            "NTV2 media size exceeds its UInt32 file-size field".into(),
        ));
    }
    let mut media_type = pb::MediaFileType::default();
    match kind {
        MediaKind::Image => {
            media_type.kind = Some(1);
            media_type.image_format = Some(format);
        }
        MediaKind::Video => {
            media_type.kind = Some(2);
            media_type.video_format = Some(format);
        }
        MediaKind::Voice => {
            media_type.kind = Some(3);
            media_type.voice_format = Some(format);
        }
        MediaKind::File => return Err(Error::Unsupported("Files do not use rich upload".into())),
    }
    let md5 = hex::encode_upper(&payload.md5);
    let name = format!("{md5}.{suffix}");
    Ok(pb::MediaFileInfo {
        size: Some(payload.size),
        md5: Some(md5.into()),
        sha1: Some(hex::encode_upper(&payload.sha1).into()),
        name: Some(name.into()),
        media_type: Some(media_type),
        width: Some(width),
        height: Some(height),
        duration: Some(duration),
        original: Some(u32::from(matches!(kind, MediaKind::Image))),
    })
}

fn upload_request(
    kind: MediaKind,
    conversation: &MediaConversation,
    file: pb::MediaFileInfo,
    summary: &str,
) -> pb::MediaRichUpload {
    let group = conversation.is_group();
    let picture_reserve = if matches!(kind, MediaKind::Image) {
        let client = pb::MediaPictureClientReserve {
            flag: Some(0),
            text: Some(Bytes::new()),
            r#type: Some(0),
            subtype: Some(0),
            source: Some(0),
            extension: Some(Bytes::new()),
        };
        let (friend_client, group_client) = if group {
            (None, Some(client))
        } else {
            (Some(client), None)
        };
        Some(pb::MediaPictureReserve {
            flag: Some(0),
            r#type: Some(0),
            subtype: Some(0),
            friend_extension: (!group).then(Bytes::new),
            group_extension: group.then(Bytes::new),
            source: Some(0),
            extension: Some(Bytes::new()),
            text: Some(Bytes::new()),
            metadata: Some(Bytes::new()),
            friend_client,
            group_client,
        })
    } else {
        None
    };
    let voice = matches!(kind, MediaKind::Voice);
    let voice_reserve = || pb::MediaVoiceReserve {
        flag: Some(0),
        source: Some(0),
    };
    // All three ExtBizInfo nodes, including their empty reserves, are required.
    let business_info = pb::MediaUploadBusinessInfo {
        picture: Some(pb::MediaPictureBusinessInfo {
            biz_type: Some(0),
            summary: Some(Bytes::copy_from_slice(summary.as_bytes())),
            reserve: picture_reserve,
        }),
        video: Some(pb::MediaVideoBusinessInfo {
            reserve: Some(pb::MediaVideoReserve {
                flag: matches!(kind, MediaKind::Video).then_some(0),
            }),
        }),
        voice: Some(pb::MediaVoiceBusinessInfo {
            friend_reserve: Some(if voice && !group {
                voice_reserve()
            } else {
                pb::MediaVoiceReserve::default()
            }),
            group_reserve: Some(if voice && group {
                voice_reserve()
            } else {
                pb::MediaVoiceReserve::default()
            }),
            general_reserve: Some(pb::MediaVoiceGeneralReserve {
                flags: voice.then(|| pb::MediaVoiceGeneralFlags {
                    format: Some(pb::MediaVoiceFormat {
                        codec: Some(if group { 8 } else { 4 }),
                        parameters: Some(if group {
                            Bytes::new()
                        } else {
                            Bytes::from_static(&[0, 0, 0, 0])
                        }),
                    }),
                }),
            }),
        }),
    };
    pb::MediaRichUpload {
        files: vec![pb::MediaUploadFile {
            file: Some(file),
            subfile_type: Some(0),
        }],
        try_fast_upload: Some(1),
        server_send: Some(0),
        client_random_id: Some(rand::random::<u32>() & 0x7fff_ffff),
        compatibility_scene: Some(if group { 2 } else { 1 }),
        business_info: Some(business_info),
        client_sequence: Some(10),
        no_compatibility_message: Some(0),
    }
}

fn highway_rich_ext(
    key: &Bytes,
    addresses: &[pb::MediaUploadAddress],
    bodies: &[Bytes],
    index: usize,
    hashes: &[Vec<u8>],
) -> Result<Vec<u8>> {
    let body = bodies
        .get(index)
        .ok_or_else(|| malformed("No Highway MsgInfoBody index"))?;
    let body: pb::MediaMessageInfoBody = crate::proto::decode(body.clone())?;
    let index: pb::MediaIndex = crate::proto::decode(
        body.index
            .ok_or_else(|| malformed("Missing protobuf field 1"))?,
    )?;
    let uuid = index
        .uuid
        .filter(|value| !value.is_empty() && std::str::from_utf8(value).is_ok())
        .ok_or_else(|| malformed("No Highway file UUID"))?;
    let network = pb::MediaHighwayNetwork {
        endpoints: addresses
            .iter()
            .map(|address| pb::MediaHighwayEndpoint {
                host: Some(pb::MediaHighwayHost {
                    r#type: Some(1),
                    address: Some(ipv4(address.ipv4.unwrap_or_default()).into()),
                }),
                port: Some(address.port.unwrap_or_default()),
            })
            .collect(),
    };
    Ok(pb::MediaHighwayRichExtension {
        uuid: Some(uuid),
        upload_key: Some(key.clone()),
        network: Some(network),
        bodies: bodies.to_vec(),
        block_size: Some(1024 * 1024),
        hashes: Some(pb::MediaHighwayHashes {
            sha1: hashes
                .iter()
                .map(|value| Bytes::copy_from_slice(value))
                .collect(),
        }),
    }
    .encode_to_vec())
}
fn malformed(message: &str) -> Error {
    Error::Malformed(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ServiceClient,
        models::{Encryption, IncomingPacket, Keystore, Profile, RequestType, SessionState},
    };
    use bytes::Bytes;
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tokio::sync::broadcast;

    struct NegotiationClient {
        requests: Mutex<Vec<(String, pb::MediaRichUploadRequest)>>,
        incoming: broadcast::Sender<IncomingPacket>,
        main_upload: bool,
        cover_upload: bool,
    }
    impl NegotiationClient {
        fn new() -> Arc<Self> {
            Self::with_uploads(false, false)
        }
        fn with_uploads(main_upload: bool, cover_upload: bool) -> Arc<Self> {
            Arc::new(Self {
                requests: Mutex::new(Vec::new()),
                incoming: broadcast::channel(4).0,
                main_upload,
                cover_upload,
            })
        }
    }
    #[async_trait::async_trait]
    impl ServiceClient for NegotiationClient {
        async fn request(
            &self,
            command: &str,
            body: Bytes,
            _: RequestType,
            _: Encryption,
            _: Duration,
        ) -> Result<Bytes> {
            let envelope: pb::MediaOidbEnvelope = crate::proto::decode(body)?;
            let request: pb::MediaRichUploadRequest = crate::proto::decode(
                envelope
                    .body
                    .ok_or_else(|| malformed("Missing protobuf field 4"))?,
            )?;
            self.requests
                .lock()
                .unwrap()
                .push((command.into(), request.clone()));
            // Upload keys independently select fast upload for each subfile.
            let upload = request
                .upload
                .ok_or_else(|| malformed("Missing protobuf field 2"))?;
            let mut info = pb::MediaMessageInfo::default();
            let mut negotiated = pb::MediaUploadNegotiation::default();
            if self.main_upload {
                negotiated.upload_key = Some(Bytes::from_static(b"main-upload-key"));
                negotiated.addresses.push(pb::MediaUploadAddress {
                    ipv4: Some(0x04030201),
                    port: Some(8080),
                });
            }
            for (index, file) in upload.files.into_iter().enumerate() {
                let node = pb::MediaIndex {
                    file: Some(
                        file.file
                            .ok_or_else(|| malformed("Missing protobuf field 1"))?,
                    ),
                    uuid: Some(format!("negotiated-uuid-{index}").into()),
                    ..Default::default()
                };
                let body = pb::MediaMessageInfoBody {
                    index: Some(node.encode_to_vec().into()),
                };
                let mut raw_body = body.encode_to_vec();
                raw_body.extend_from_slice(b"\xf8\x07\x01");
                info.bodies.push(raw_body.into());
                if file.subfile_type == Some(100) {
                    negotiated.subfiles.push(pb::MediaUploadSubfile {
                        subfile_type: Some(100),
                        upload_key: Some(if self.cover_upload {
                            Bytes::from_static(b"cover-upload-key")
                        } else {
                            Bytes::new()
                        }),
                        addresses: vec![pb::MediaUploadAddress {
                            ipv4: Some(0x08070605),
                            port: Some(9090),
                        }],
                        ..Default::default()
                    });
                }
            }
            let mut raw_info = info.encode_to_vec();
            raw_info.extend_from_slice(b"\xf8\x07\x01");
            negotiated.message_info = Some(raw_info.into());
            negotiated.compatibility = Some(Bytes::from_static(b"\xfa\x07\x03raw"));
            let response = pb::MediaRichUploadResponse {
                head: Some(pb::MediaRichResponseHead::default()),
                negotiation: Some(negotiated),
            };
            Ok(pb::MediaOidbEnvelope {
                result: Some(0),
                body: Some(response.encode_to_vec().into()),
                ..Default::default()
            }
            .encode_to_vec()
            .into())
        }
        async fn snapshot(&self) -> SessionState {
            SessionState {
                profile: Profile::default(),
                keystore: Keystore::default(),
                platform: crate::models::PlatformState::Linux {
                    machine_id: String::new(),
                },
                online: true,
            }
        }
        async fn replace_state(&self, _: SessionState) {}
        fn subscribe(&self) -> broadcast::Receiver<IncomingPacket> {
            self.incoming.subscribe()
        }
    }

    fn data(bytes: &[u8], name: &str) -> MediaInput {
        MediaInput::Data {
            data: bytes.to_vec(),
            name: name.into(),
        }
    }
    fn friend() -> MediaConversation {
        MediaConversation::Friend {
            uid: "peer-uid".into(),
        }
    }

    #[tokio::test]
    async fn invalid_formats_never_negotiate() {
        let client = NegotiationClient::new();
        let media = Media::new(client.clone());
        assert!(
            media
                .upload_image(data(b"not an image", "image.png"), friend(), "[图片]")
                .await
                .is_err()
        );
        assert!(
            media
                .upload_voice(data(b"RIFFnot silk", "voice.wav"), friend())
                .await
                .is_err()
        );
        assert!(
            media
                .upload_video(data(b"not mp4 file", "video.mp4"), None, friend(), 0, 0, 0)
                .await
                .is_err()
        );
        assert!(
            media
                .upload_video(
                    data(&super::super::video::fixture(), "video.mp4"),
                    Some(data(b"bad cover", "cover.jpg")),
                    friend(),
                    0,
                    0,
                    0
                )
                .await
                .is_err()
        );
        assert!(client.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn malformed_mp4_and_metadata_conflicts_never_negotiate() {
        let client = NegotiationClient::new();
        let media = Media::new(client.clone());
        let valid = super::super::video::fixture();
        let mut unsupported = valid.clone();
        let entry = unsupported
            .windows(4)
            .position(|bytes| bytes == b"avc1")
            .and_then(|first| {
                unsupported[first + 4..]
                    .windows(4)
                    .position(|bytes| bytes == b"avc1")
                    .map(|next| first + 4 + next)
            })
            .unwrap();
        unsupported[entry..entry + 4].copy_from_slice(b"xxxx");
        for invalid in [
            b"\0\0\0\x18ftypisom".to_vec(),
            valid[..valid.len() - 1].to_vec(),
            unsupported,
            super::super::video::audio_only_fixture(),
        ] {
            assert!(
                media
                    .upload_video(data(&invalid, "invalid.mp4"), None, friend(), 0, 0, 0)
                    .await
                    .is_err()
            );
        }
        for (width, height, duration) in [(321, 0, 0), (0, 241, 0), (0, 0, 2)] {
            let error = media
                .upload_video(
                    data(&valid, "conflict.mp4"),
                    None,
                    friend(),
                    width,
                    height,
                    duration,
                )
                .await
                .unwrap_err();
            assert!(matches!(error, Error::Malformed(message) if message.contains("conflicts")));
        }
        assert!(client.requests.lock().unwrap().is_empty());
    }

    async fn receive_highway(stream: tokio::net::TcpStream) -> Vec<u8> {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
        let mut reader = tokio::io::BufReader::new(stream);
        let mut content_length = None;
        let mut chunked = false;
        loop {
            let mut line = String::new();
            assert_ne!(reader.read_line(&mut line).await.unwrap(), 0);
            if line == "\r\n" {
                break;
            }
            let line = line.to_ascii_lowercase();
            if let Some(value) = line.strip_prefix("content-length:") {
                content_length = Some(value.trim().parse::<usize>().unwrap());
            }
            chunked |= line.starts_with("transfer-encoding:") && line.contains("chunked");
        }
        let mut body = Vec::new();
        if chunked {
            loop {
                let mut line = String::new();
                assert_ne!(reader.read_line(&mut line).await.unwrap(), 0);
                let length =
                    usize::from_str_radix(line.trim().split(';').next().unwrap(), 16).unwrap();
                if length == 0 {
                    let mut ending = [0; 2];
                    reader.read_exact(&mut ending).await.unwrap();
                    assert_eq!(&ending, b"\r\n");
                    break;
                }
                let start = body.len();
                body.resize(start + length, 0);
                reader.read_exact(&mut body[start..]).await.unwrap();
                let mut ending = [0; 2];
                reader.read_exact(&mut ending).await.unwrap();
                assert_eq!(&ending, b"\r\n");
            }
        } else {
            body.resize(content_length.unwrap(), 0);
            reader.read_exact(&mut body).await.unwrap();
        }
        let acknowledgement = pb::HighwayAcknowledgement {
            result: Some(0),
            ..Default::default()
        }
        .encode_to_vec();
        let mut frame = vec![0x28];
        frame.extend_from_slice(&(acknowledgement.len() as u32).to_be_bytes());
        frame.extend_from_slice(&0u32.to_be_bytes());
        frame.extend_from_slice(&acknowledgement);
        frame.push(0x29);
        reader
            .get_mut()
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    frame.len(),
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        reader.get_mut().write_all(&frame).await.unwrap();
        body
    }

    #[tokio::test]
    async fn video_nonfast_cover_uses_its_own_uuid_hash_key_and_addresses() {
        use md5::{Digest, Md5};
        use sha1::Sha1;
        for conversation in [friend(), MediaConversation::Group { uin: 42 }] {
            for (main_upload, cover_upload) in [(false, true), (true, false), (true, true)] {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let count = usize::from(main_upload) + usize::from(cover_upload);
                let server = tokio::spawn(async move {
                    let mut frames = Vec::new();
                    for _ in 0..count {
                        let (stream, _) = listener.accept().await.unwrap();
                        frames.push(receive_highway(stream).await);
                    }
                    frames
                });
                let client = NegotiationClient::with_uploads(main_upload, cover_upload);
                let media = Media::new(client.clone());
                *media.highway.lock().await = Some(super::super::HighwaySession {
                    ticket: vec![0x11],
                    endpoint: format!("http://{address}/cgi-bin/httpconn"),
                    created: std::time::Instant::now(),
                    uin: 0,
                });
                let video_bytes = super::super::video::fixture();
                let video = tokio::time::timeout(
                    Duration::from_secs(5),
                    media.upload_video(
                        data(&video_bytes, "clip.mp4"),
                        Some(data(DEFAULT_THUMBNAIL, "cover.jpg")),
                        conversation.clone(),
                        320,
                        240,
                        1,
                    ),
                )
                .await
                .unwrap()
                .unwrap();
                let frames = tokio::time::timeout(Duration::from_secs(5), server)
                    .await
                    .unwrap()
                    .unwrap();
                let info: pb::MediaMessageInfo =
                    crate::proto::decode(video.message_info.as_slice()).unwrap();
                assert_eq!(client.requests.lock().unwrap().len(), 1);
                for frame in frames {
                    assert_eq!(frame[0], 0x28);
                    assert_eq!(*frame.last().unwrap(), 0x29);
                    let header_size = u32::from_be_bytes(frame[1..5].try_into().unwrap()) as usize;
                    let header =
                        pb::HighwayUploadHeader::decode(&frame[9..9 + header_size]).unwrap();
                    let payload = &frame[9 + header_size..frame.len() - 1];
                    let command = header.base.unwrap().command_id.unwrap();
                    let cover = matches!(command, 1002 | 1006);
                    assert_eq!(
                        command,
                        if cover {
                            if conversation.is_group() { 1006 } else { 1002 }
                        } else if conversation.is_group() {
                            1005
                        } else {
                            1001
                        }
                    );
                    let expected = if cover {
                        DEFAULT_THUMBNAIL
                    } else {
                        &video_bytes
                    };
                    assert_eq!(payload, expected);
                    let segment = header.segment.unwrap();
                    assert_eq!(
                        segment.file_md5.unwrap().as_ref(),
                        Md5::digest(expected).as_slice()
                    );
                    assert_eq!(
                        segment.chunk_md5.unwrap().as_ref(),
                        Md5::digest(expected).as_slice()
                    );
                    let extension =
                        pb::MediaHighwayRichExtension::decode(header.extension.unwrap()).unwrap();
                    assert_eq!(extension.bodies, info.bodies);
                    assert_eq!(
                        extension.uuid.as_deref(),
                        Some(if cover {
                            &b"negotiated-uuid-1"[..]
                        } else {
                            &b"negotiated-uuid-0"[..]
                        })
                    );
                    assert_eq!(
                        extension.upload_key.as_deref(),
                        Some(if cover {
                            &b"cover-upload-key"[..]
                        } else {
                            &b"main-upload-key"[..]
                        })
                    );
                    assert_eq!(
                        extension.hashes.unwrap().sha1,
                        vec![Bytes::copy_from_slice(&Sha1::digest(expected))]
                    );
                    let endpoint = &extension.network.unwrap().endpoints[0];
                    assert_eq!(endpoint.port, Some(if cover { 9090 } else { 8080 }));
                    assert_eq!(
                        endpoint.host.as_ref().unwrap().address.as_deref(),
                        Some(if cover {
                            &b"5.6.7.8"[..]
                        } else {
                            &b"1.2.3.4"[..]
                        })
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn public_uploads_negotiate_all_kinds_and_conversations() {
        for conversation in [friend(), MediaConversation::Group { uin: 42 }] {
            let client = NegotiationClient::new();
            let media = Media::new(client.clone());
            let image = media
                .upload_image(
                    data(DEFAULT_THUMBNAIL, "original.jpg"),
                    conversation.clone(),
                    "cover summary",
                )
                .await
                .unwrap();
            assert_eq!(image.name, "original.jpg");
            assert_eq!((image.width, image.height, image.size), (240, 383, 3894));
            assert_eq!(hex::encode(&image.md5), "fd2a0981525d78edb833f17e028e9140");
            assert_eq!(
                hex::encode(&image.sha1),
                "2541aa60e311b01d562eed81521960ec4bd50abb"
            );
            assert_eq!(image.uuid.as_deref(), Some("negotiated-uuid-0"));
            assert!(image.message_info.ends_with(b"\xf8\x07\x01"));
            assert_eq!(
                image.compatibility.as_deref(),
                Some(&b"\xfa\x07\x03raw"[..])
            );
            let silk = include_bytes!("../../../silk/tests/fixtures/legacy_16000.silk");
            let voice = media
                .upload_voice(data(silk, "speech.silk"), conversation.clone())
                .await
                .unwrap();
            assert_eq!(voice.duration, 0);
            let video_bytes = super::super::video::fixture();
            let video = media
                .upload_video(
                    data(&video_bytes, "clip.mp4"),
                    None,
                    conversation.clone(),
                    0,
                    0,
                    0,
                )
                .await
                .unwrap();
            assert_eq!((video.width, video.height, video.duration), (320, 240, 1));
            assert_eq!(video.name, "clip.mp4");
            assert_eq!(video.size, video_bytes.len() as u64);
            let requests = client.requests.lock().unwrap();
            assert_eq!(requests.len(), 3);
            for (index, kind) in [MediaKind::Image, MediaKind::Voice, MediaKind::Video]
                .into_iter()
                .enumerate()
            {
                assert_eq!(
                    requests[index].0,
                    format!(
                        "OidbSvcTrpcTcp.0x{:x}_100",
                        media_command(kind, &conversation)
                    )
                );
                let upload = requests[index].1.upload.as_ref().unwrap();
                assert_eq!(
                    upload.compatibility_scene,
                    Some(if conversation.is_group() { 2 } else { 1 })
                );
                let ext = upload.business_info.as_ref().unwrap();
                assert!(ext.picture.is_some());
                assert!(ext.video.is_some());
                assert!(ext.voice.is_some());
            }
            let video_files = &requests[2].1.upload.as_ref().unwrap().files;
            assert_eq!(video_files.len(), 2);
            assert_eq!(video_files[1].subfile_type, Some(100));
            let cover = video_files[1].file.as_ref().unwrap();
            assert_eq!(
                (cover.width, cover.height, cover.size),
                (Some(240), Some(383), Some(3894))
            );
        }
    }

    #[test]
    fn rich_extensions_preserve_empty_nodes_and_desktop_reserves() {
        for conversation in [friend(), MediaConversation::Group { uin: 42 }] {
            for kind in [MediaKind::Image, MediaKind::Voice, MediaKind::Video] {
                let upload =
                    upload_request(kind, &conversation, pb::MediaFileInfo::default(), "summary");
                // Round-trip so these assertions check presence on the wire.
                let upload =
                    pb::MediaRichUpload::decode(upload.encode_to_vec().as_slice()).unwrap();
                assert_eq!(upload.try_fast_upload, Some(1));
                assert_eq!(upload.server_send, Some(0));
                assert_eq!(upload.no_compatibility_message, Some(0));
                assert_eq!(upload.files[0].subfile_type, Some(0));
                assert_eq!(upload.client_sequence, Some(10));
                assert!(upload.client_random_id.unwrap() <= i32::MAX as u32);
                let ext = upload.business_info.unwrap();
                let picture = ext.picture.unwrap();
                let video = ext.video.unwrap();
                let voice = ext.voice.unwrap();
                assert_eq!(picture.biz_type, Some(0));
                assert_eq!(picture.summary.as_deref(), Some(&b"summary"[..]));
                assert_eq!(
                    video.reserve.unwrap().encode_to_vec(),
                    if kind == MediaKind::Video {
                        &b"\x80\x01\x00"[..]
                    } else {
                        &[][..]
                    }
                );
                assert!(voice.friend_reserve.is_some());
                assert!(voice.group_reserve.is_some());
                assert!(voice.general_reserve.is_some());
                if kind == MediaKind::Image {
                    assert_eq!(
                        hex::encode_upper(picture.reserve.unwrap().encode_to_vec()),
                        if conversation.is_group() {
                            "0800180020004A00500062009201009A0100AA010C080012001800200028003A00"
                        } else {
                            "0800180020004200500062009201009A0100A2010C080012001800200028003A00"
                        }
                    );
                } else {
                    assert!(picture.reserve.is_none());
                }
                if kind == MediaKind::Voice {
                    let reserve = if conversation.is_group() {
                        voice.group_reserve.unwrap()
                    } else {
                        voice.friend_reserve.unwrap()
                    };
                    assert_eq!(reserve.encode_to_vec().as_slice(), b"\x08\x00\x38\x00");
                    assert_eq!(
                        hex::encode_upper(voice.general_reserve.unwrap().encode_to_vec()),
                        if conversation.is_group() {
                            "9A0107AA030408081200"
                        } else {
                            "9A010BAA03080804120400000000"
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn highway_extension_preserves_video_index_hashes_and_all_bodies() {
        let video_index = pb::MediaIndex {
            uuid: Some(Bytes::from_static(b"main-video-uuid")),
            ..Default::default()
        };
        let cover_index = pb::MediaIndex {
            uuid: Some(Bytes::from_static(b"cover-uuid")),
            ..Default::default()
        };
        let mut main_index = video_index.encode_to_vec();
        // Unknown server index metadata must survive alongside body metadata.
        main_index.extend_from_slice(b"\xf8\x07\x01");
        let mut main = pb::MediaMessageInfoBody {
            index: Some(main_index.into()),
        }
        .encode_to_vec();
        main.extend_from_slice(b"\xfa\x07\x03raw");
        let main = Bytes::from(main);
        let cover = Bytes::from(
            pb::MediaMessageInfoBody {
                index: Some(cover_index.encode_to_vec().into()),
            }
            .encode_to_vec(),
        );
        let address = pb::MediaUploadAddress {
            ipv4: Some(0x04030201),
            port: Some(8080),
        };
        let hashes = vec![vec![1; 20], vec![2; 20]];
        let ext = pb::MediaHighwayRichExtension::decode(
            highway_rich_ext(
                &Bytes::from_static(b"upload-key"),
                &[address],
                &[main.clone(), cover.clone()],
                0,
                &hashes,
            )
            .unwrap()
            .as_slice(),
        )
        .unwrap();
        assert_eq!(ext.uuid.as_deref(), Some(&b"main-video-uuid"[..]));
        assert_eq!(ext.upload_key.as_deref(), Some(&b"upload-key"[..]));
        assert_eq!(ext.block_size, Some(1024 * 1024));
        assert_eq!(ext.bodies, vec![main, cover]);
        let hash = ext.hashes.unwrap();
        assert_eq!(hash.sha1.len(), 2);
        assert_eq!(hash.sha1[0].as_ref(), hashes[0].as_slice());
        assert_eq!(hash.sha1[1].as_ref(), hashes[1].as_slice());
        let endpoint = ext.network.unwrap().endpoints.remove(0);
        assert_eq!(
            endpoint.host.unwrap().address.as_deref(),
            Some(&b"1.2.3.4"[..])
        );
        assert_eq!(endpoint.port, Some(8080));
    }
}
