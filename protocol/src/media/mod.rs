mod files;
mod group_fs;
mod legacy_video;
mod models;
mod payload;
mod rich;
#[cfg(test)]
mod tests;
mod video;
use crate::models::{Encryption, RequestType};
use crate::proto::media as pb;
use crate::{Error, Result, ServiceClient};
use bytes::Bytes;
pub use group_fs::*;
pub use legacy_video::LegacyVideoPlayContext;
use md5::{Digest, Md5};
pub use models::*;
use payload::MediaPayload;
use prost::Message;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};

pub const MEDIA_METHODS: &[&str] = &[
    "upload_image",
    "upload_voice",
    "upload_video",
    "upload_avatar",
    "upload_file",
    "send_file",
    "download_url",
    "legacy_video_play_url",
    "download",
    "file_download_url",
    "group_file_download_url",
    "group_file_list",
    "group_files",
    "group_file_info",
    "group_file_count",
    "group_file_space",
    "delete_group_file",
    "move_group_file",
    "rename_group_file",
    "create_group_folder",
    "delete_group_folder",
    "rename_group_folder",
    "move_group_folder",
];
struct HighwaySession {
    ticket: Vec<u8>,
    endpoint: String,
    created: Instant,
    uin: u64,
}
pub struct Media {
    pub(crate) client: Arc<dyn ServiceClient>,
    pub(crate) http: reqwest::Client,
    highway: Mutex<Option<HighwaySession>>,
    sequence: AtomicU32,
}
fn image_key_type(url: &reqwest::Url) -> Option<u32> {
    if url.scheme() != "https"
        || url.host_str() != Some("multimedia.nt.qq.com.cn")
        || url.path() != "/download"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some_and(|port| port != 443)
    {
        return None;
    }
    let mut app_id = None;
    let mut file_id = None;
    for (name, value) in url.query_pairs() {
        match name.as_ref() {
            "appid" if app_id.is_none() => app_id = Some(value),
            "fileid" if file_id.is_none() => file_id = Some(value),
            "appid" | "fileid" => return None,
            _ => {},
        }
    }
    if file_id.is_none_or(|value| value.is_empty()) {
        return None;
    }
    match app_id.as_deref() {
        Some("1406") => Some(10),
        Some("1407") => Some(20),
        _ => None,
    }
}
fn authorize_image_url(mut url: reqwest::Url, key: &MediaDownloadKey) -> Result<String> {
    if image_key_type(&url) != Some(key.business_type) || key.store_id != 1 {
        return Err(Error::Malformed("Media key does not match image URL".into()));
    }
    let parameter = key.parameter.strip_prefix('&').unwrap_or(&key.parameter);
    let parameter = reqwest::Url::parse(&format!("https://localhost/?{parameter}"))
        .map_err(|_| Error::Malformed("Invalid media key parameter".into()))?;
    let mut pairs = parameter.query_pairs();
    let (name, value) = pairs.next().ok_or_else(|| Error::Malformed("Missing media key parameter".into()))?;
    if name != "rkey" || value.is_empty() || pairs.next().is_some() {
        return Err(Error::Malformed("Invalid media key parameter".into()));
    }
    let retained: Vec<_> = url.query_pairs().filter(|(name, _)| name != "rkey")
        .map(|(name, value)| (name.into_owned(), value.into_owned())).collect();
    url.query_pairs_mut().clear().extend_pairs(retained).append_pair("rkey", &value);
    Ok(url.into())
}
impl Media {
    pub fn new(client: Arc<dyn ServiceClient>) -> Self {
        Self {
            client,
            http: crate::http::client_builder()
                .build()
                .expect("HTTP client initialization failed"),
            highway: Mutex::new(None),
            sequence: AtomicU32::new(0),
        }
    }
    pub(crate) async fn request<
        Q: Message,
        R: Message + Default + prost::Name + std::fmt::Debug,
    >(
        &self,
        command: &str,
        body: Q,
    ) -> Result<R> {
        crate::diagnostics::decode_response(
            command,
            self.client
                .request(
                    command,
                    body.encode_to_vec().into(),
                    RequestType::D2,
                    Encryption::D2,
                    Duration::from_secs(60),
                )
                .await?,
        )
    }
    pub(crate) async fn prepare(
        &self,
        input: MediaInput,
        file_checksums: bool,
        video_checkpoints: bool,
    ) -> Result<MediaPayload> {
        let (path, name, temporary) = match input {
            MediaInput::File { path } => {
                let name = path
                    .file_name()
                    .and_then(|v| v.to_str())
                    .unwrap_or("media")
                    .to_owned();
                (path, name, false)
            }
            MediaInput::Data { data, name } => {
                let path = temp_path();
                let mut cleanup = TemporaryFile::new(path.clone());
                fs::write(&path, data).await?;
                let result = MediaPayload::inspect(
                    path,
                    name,
                    true,
                    file_checksums,
                    video_checkpoints,
                    false,
                )
                .await;
                cleanup.disarm();
                return result;
            }
            MediaInput::Url { url } => {
                let parsed = valid_http_url(&url)?;
                let name = parsed
                    .path_segments()
                    .and_then(|mut v| v.next_back())
                    .filter(|v| !v.is_empty())
                    .unwrap_or("media")
                    .to_owned();
                let path = temp_path();
                let mut cleanup = TemporaryFile::new(path.clone());
                self.fetch_to(&url, &path).await?;
                let result = MediaPayload::inspect(
                    path,
                    name,
                    true,
                    file_checksums,
                    video_checkpoints,
                    false,
                )
                .await;
                cleanup.disarm();
                return result;
            }
        };
        let mut cleanup = temporary.then(|| TemporaryFile::new(path.clone()));
        let result = MediaPayload::inspect(
            path,
            name,
            temporary,
            file_checksums,
            video_checkpoints,
            false,
        )
        .await;
        if let Some(cleanup) = cleanup.as_mut() {
            cleanup.disarm();
        }
        result
    }
    async fn fetch_to(&self, url: &str, path: &Path) -> Result<()> {
        valid_http_url(url)?;
        tracing::debug!(target: "atri_qq_protocol::packet_trace", direction = "send", transport = "http", method = "GET", url, "QQ media request");
        let mut response = self
            .http
            .get(url)
            .timeout(Duration::from_secs(1800))
            .send()
            .await?;
        tracing::debug!(target: "atri_qq_protocol::packet_trace", direction = "receive", transport = "http", url = %response.url(), status = response.status().as_u16(), headers = ?response.headers(), "QQ media response");
        http_check(&mut response).await?;
        let mut file = fs::File::create(path).await?;
        let mut offset = 0u64;
        while let Some(chunk) = response.chunk().await? {
            tracing::debug!(target: "atri_qq_protocol::packet_trace", direction = "receive", transport = "http", url, offset, length = chunk.len(), body_hex = %hex::encode(&chunk), "QQ media body");
            offset += chunk.len() as u64;
            file.write_all(&chunk).await?;
        }
        tracing::debug!(target: "atri_qq_protocol::packet_trace", direction = "receive", transport = "http", url, length = offset, stage = "complete", "QQ media response");
        file.flush().await?;
        Ok(())
    }
    pub(crate) async fn oidb<Q: Message, R: Message + Default + prost::Name + std::fmt::Debug>(
        &self,
        command: u32,
        service: u32,
        body: Q,
        reserved: u64,
        transport_service: Option<u32>,
    ) -> Result<R> {
        let envelope = pb::MediaOidbEnvelope {
            command: Some(command as u64),
            service: Some(service as u64),
            body: Some(body.encode_to_vec().into()),
            reserved: Some(reserved),
            ..Default::default()
        };
        let response: pb::MediaOidbEnvelope = self
            .request(
                &format!(
                    "OidbSvcTrpcTcp.0x{command:x}_{}",
                    transport_service.unwrap_or(service)
                ),
                envelope,
            )
            .await?;
        let code = response.result.unwrap_or_default() as i32;
        if code != 0 {
            return Err(Error::Server {
                code,
                message: response
                    .message
                    .and_then(|v| String::from_utf8(v.to_vec()).ok())
                    .unwrap_or_else(|| "QQ request failed".into()),
            });
        }
        crate::diagnostics::decode_response(
            &format!(
                "OidbSvcTrpcTcp.0x{command:x}_{}",
                transport_service.unwrap_or(service)
            ),
            response
                .body
                .ok_or_else(|| Error::Malformed("Missing protobuf field 4".into()))?,
        )
    }
    async fn highway_session(&self) -> Result<(Vec<u8>, String)> {
        let state = self.client.snapshot().await;
        let mut cached = self.highway.lock().await;
        if let Some(session) = cached.as_ref().filter(|v| {
            v.uin == state.keystore.uin && v.created.elapsed() < Duration::from_secs(43_200)
        }) {
            return Ok((session.ticket.clone(), session.endpoint.clone()));
        }
        let req = pb::HighwaySessionApply {
            net_type: Some(0),
            subcommand: Some(0),
            idc_id: Some(16),
            request_ip: Some(1),
            ticket: Some(state.keystore.a2.clone().into()),
            app_id: Some(3),
            service_types: vec![1, 5, 10, 21],
            uin_type: Some(2),
            protocol_type: Some(9),
            terminal_type: Some(8),
            version: Some("1.0.1".into()),
        };
        let packet: pb::HighwaySessionResponse = self
            .request(
                "HttpConn.0x6ff_501",
                pb::HighwaySessionRequest { apply: Some(req) },
            )
            .await?;
        let response = packet
            .result
            .ok_or_else(|| Error::Malformed("Missing protobuf field 1281".into()))?;
        let ticket = response
            .ticket
            .filter(|v| !v.is_empty())
            .ok_or_else(|| Error::Malformed("Highway returned no session ticket".into()))?
            .to_vec();
        for server in response
            .servers
            .iter()
            .filter(|v| v.service_type.unwrap_or_default() == 1)
        {
            for address in &server.addresses {
                let ip = address.ip.unwrap_or_default();
                let port = address.port.unwrap_or_default();
                if ip == 0 || !(1..=65535).contains(&port) {
                    continue;
                }
                let endpoint = format!(
                    "http://{}:{port}/cgi-bin/httpconn?htcmd=0x6FF0087&uin={}",
                    ipv4(u64::from(ip)),
                    state.keystore.uin
                );
                *cached = Some(HighwaySession {
                    ticket: ticket.clone(),
                    endpoint: endpoint.clone(),
                    created: Instant::now(),
                    uin: state.keystore.uin,
                });
                return Ok((ticket, endpoint));
            }
        }
        Err(Error::Malformed("Highway returned no HTTP endpoint".into()))
    }
    pub(crate) async fn highway_upload(
        &self,
        payload: &MediaPayload,
        command: u32,
        ext: Vec<u8>,
    ) -> Result<()> {
        let (ticket, endpoint) = self.highway_session().await?;
        let state = self.client.snapshot().await;
        let ticket = Bytes::from(ticket);
        let ext = Bytes::from(ext);
        let file_md5 = Bytes::copy_from_slice(&payload.md5);
        let signature = Bytes::copy_from_slice(&state.keystore.a2);
        let mut file = fs::File::open(&payload.path).await?;
        let mut offset = 0;
        while offset < payload.size {
            let count = (payload.size - offset).min(1024 * 1024) as usize;
            let mut chunk = vec![0; count];
            file.read_exact(&mut chunk).await?;
            let sequence = self.sequence.fetch_add(1, Ordering::Relaxed) % 100_000 + 1;
            let header = pb::HighwayUploadHeader {
                base: Some(pb::HighwayBaseHeader {
                    version: Some(1),
                    uin: Some(state.keystore.uin.to_string()),
                    command: Some("PicUp.DataUp".into()),
                    sequence: Some(sequence as u64),
                    app_id: Some(state.profile.app_id as u64),
                    data_flag: Some(16),
                    command_id: Some(command as u64),
                }),
                segment: Some(pb::HighwaySegmentHeader {
                    total_size: Some(payload.size),
                    offset: Some(offset),
                    length: Some(count as u64),
                    service_ticket: Some(ticket.clone()),
                    chunk_md5: Some(Md5::digest(&chunk).to_vec().into()),
                    file_md5: Some(file_md5.clone()),
                }),
                extension: Some(ext.clone()),
                timestamp: Some(0),
                login: Some(pb::HighwayLoginSignature {
                    r#type: Some(8),
                    signature: Some(signature.clone()),
                    app_id: Some(state.profile.app_id as u64),
                }),
            }
            .encode_to_vec();
            let mut prefix = Vec::with_capacity(9 + header.len());
            prefix.push(0x28);
            prefix.extend_from_slice(&(header.len() as u32).to_be_bytes());
            prefix.extend_from_slice(&(count as u32).to_be_bytes());
            prefix.extend_from_slice(&header);
            tracing::debug!(target: "atri_qq_protocol::packet_trace", direction = "send", transport = "highway", command = "PicUp.DataUp", command_id = command, sequence, endpoint, offset, prefix_hex = %hex::encode(&prefix), body_hex = %hex::encode(&chunk), suffix_hex = "29", "QQ Highway frame");
            let body = reqwest::Body::wrap_stream(futures_util::stream::iter([
                Ok::<_, std::io::Error>(Bytes::from(prefix)),
                Ok(Bytes::from(chunk)),
                Ok(Bytes::from_static(&[0x29])),
            ]));
            let response = self
                .http
                .post(&endpoint)
                .timeout(Duration::from_secs(1800))
                .header("Content-Type", "application/octet-stream")
                .header("Content-Length", 9 + header.len() + count + 1)
                .header("Accept-Encoding", "identity")
                .header(
                    "User-Agent",
                    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2)",
                )
                .header(
                    "Connection",
                    if offset + count as u64 == payload.size {
                        "close"
                    } else {
                        "keep-alive"
                    },
                )
                .body(body)
                .send()
                .await?;
            tracing::debug!(target: "atri_qq_protocol::packet_trace", direction = "receive", transport = "highway", command = "PicUp.DataUp", command_id = command, sequence, endpoint, status = response.status().as_u16(), headers = ?response.headers(), "QQ Highway response");
            let acknowledgement = bounded_acknowledgement(response).await?;
            tracing::debug!(target: "atri_qq_protocol::packet_trace", direction = "receive", transport = "highway", command = "PicUp.DataUp", command_id = command, sequence, endpoint, body_hex = %hex::encode(&acknowledgement), "QQ Highway frame");
            decode_highway_ack(&acknowledgement)?;
            offset += count as u64;
        }
        let mut extra = [0; 1];
        if file.read(&mut extra).await? != 0 {
            return Err(Error::Malformed(
                "Upload source grew during transfer".into(),
            ));
        }
        Ok(())
    }
    pub async fn upload_avatar(&self, input: MediaInput) -> Result<()> {
        let mut payload = self.prepare(input, false, false).await?;
        let result = async {
            payload.image_info().await?;
            self.highway_upload(&payload, 90, vec![]).await
        }
        .await;
        payload.dispose().await;
        result
    }

    pub async fn download_url(&self, reference: &MediaReference) -> Result<String> {
        if reference.kind == MediaKind::File {
            return self.file_download_url(reference).await;
        }
        if reference.message_info.is_empty() {
            let url = reference.download_url.as_ref().ok_or_else(|| {
                Error::Unsupported("Media reference has neither MsgInfo nor a download URL".into())
            })?;
            return self.authorize_download_url(url).await;
        }
        self.download_message_info_url(reference, 0).await
    }
    async fn authorize_download_url(&self, url: &str) -> Result<String> {
        valid_http_url(url)?;
        let parsed = reqwest::Url::parse(url).map_err(|_| Error::Malformed("Invalid media URL".into()))?;
        let Some(business_type) = image_key_type(&parsed) else { return Ok(url.to_owned()) };
        let key = self.client.media_download_key(business_type, 1).await?;
        authorize_image_url(parsed, &key)
    }
    pub async fn video_thumbnail_url(&self, reference: &MediaReference) -> Result<String> {
        if reference.kind != MediaKind::Video {
            return Err(Error::Malformed("Expected video reference".into()));
        }
        if reference.message_info.is_empty() {
            let raw = reference
                .compatibility
                .as_ref()
                .ok_or_else(|| Error::Unsupported("Video has no thumbnail metadata".into()))?;
            let video: pb::VideoFile = crate::proto::decode(raw.as_slice())?;
            return video
                .thumbnail_urls
                .iter()
                .filter_map(|value| std::str::from_utf8(value).ok())
                .find_map(|value| valid_http_url(value).ok().map(|_| value.to_owned()))
                .ok_or_else(|| Error::Unsupported("VideoFile has no thumbnail URL".into()));
        }
        self.download_message_info_url(reference, 1).await
    }
    async fn download_message_info_url(
        &self,
        reference: &MediaReference,
        body_index: usize,
    ) -> Result<String> {
        let info: pb::MediaMessageInfo = crate::proto::decode(reference.message_info.as_slice())?;
        let body: pb::MediaMessageInfoBody = crate::proto::decode(
            info.bodies
                .get(body_index)
                .ok_or_else(|| Error::Unsupported("Media has no requested index".into()))?
                .as_ref(),
        )?;
        let index = body
            .index
            .ok_or_else(|| Error::Malformed("Media has no index".into()))?;
        let companion = if reference.kind == MediaKind::Video {
            let body: pb::MediaMessageInfoBody = crate::proto::decode(
                info.bodies
                    .get(if body_index == 0 { 1 } else { 0 })
                    .ok_or_else(|| Error::Unsupported("Video has no companion index".into()))?
                    .as_ref(),
            )?;
            let index: pb::MediaIndex = crate::proto::decode(
                body.index
                    .ok_or_else(|| Error::Malformed("Video companion has no index".into()))?,
            )?;
            Some((
                index.subtype.unwrap_or_default(),
                index.file.ok_or_else(|| {
                    Error::Malformed("Video companion has no file metadata".into())
                })?,
            ))
        } else {
            None
        };
        let request_type = match (reference.kind, body_index) {
            (MediaKind::Video, 0) | (MediaKind::Image, _) => 2,
            _ => 1,
        };
        let req = pb::MediaDownloadRequest {
            head: Some(media_head(
                reference.kind,
                &reference.conversation,
                200,
                request_type,
            )?),
            request: Some(pb::MediaDownloadInfo {
                index: Some(index),
                ext: Some(
                    download_extension(reference.kind, companion)
                        .encode_to_vec()
                        .into(),
                ),
                reserved_3: (reference.kind != MediaKind::Image).then_some(0),
            }),
        };
        let response: pb::MediaDownloadResponse = self
            .oidb(
                media_command(reference.kind, &reference.conversation),
                200,
                req,
                1,
                None,
            )
            .await?;
        let head = response
            .head
            .ok_or_else(|| Error::Malformed("Missing protobuf field 1".into()))?;
        let code = head.code.unwrap_or_default() as i32;
        if code != 0 {
            return Err(Error::Server {
                code,
                message: head
                    .message
                    .and_then(|v| String::from_utf8(v.to_vec()).ok())
                    .unwrap_or_else(|| "QQ request failed".into()),
            });
        }
        let download = response
            .download
            .ok_or_else(|| Error::Malformed("Missing protobuf field 3".into()))?;
        let location = download
            .location
            .ok_or_else(|| Error::Malformed("Missing protobuf field 3".into()))?;
        let domain = location
            .domain
            .and_then(|v| String::from_utf8(v.to_vec()).ok())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| Error::Malformed("Missing download domain".into()))?;
        let path = location
            .path
            .and_then(|v| String::from_utf8(v.to_vec()).ok())
            .filter(|v| v.starts_with('/'))
            .ok_or_else(|| Error::Malformed("Missing download path".into()))?;
        let port = location.port.unwrap_or_default();
        if port > 65535 {
            return Err(Error::Malformed("Invalid media port".into()));
        }
        let url = format!(
            "https://{domain}{}{path}{}",
            if port != 0 && port != 443 {
                format!(":{port}")
            } else {
                String::new()
            },
            download
                .query
                .and_then(|v| String::from_utf8(v.to_vec()).ok())
                .unwrap_or_default()
        );
        self.authorize_download_url(&url).await
    }
    pub async fn download(&self, reference: &MediaReference, destination: &Path) -> Result<()> {
        let url = self.download_url(reference).await?;
        let path = temp_path();
        let _cleanup = TemporaryFile::new(path.clone());
        self.fetch_to(&url, &path).await?;
        let first_ten = reference.kind == MediaKind::File && !reference.conversation.is_group();
        let actual = MediaPayload::inspect(
            path.clone(),
            "download".into(),
            false,
            first_ten,
            false,
            reference.kind == MediaKind::File,
        )
        .await?;
        if reference.size != 0 && actual.size != reference.size {
            return Err(Error::Malformed("Downloaded media size mismatch".into()));
        }
        if !reference.md5.is_empty()
            && reference.md5 != actual.md5
            && !(first_ten && reference.md5 == actual.md5_10m)
        {
            return Err(Error::Malformed("Downloaded media MD5 mismatch".into()));
        }
        if !reference.sha1.is_empty() && reference.sha1 != actual.sha1 {
            return Err(Error::Malformed("Downloaded media SHA1 mismatch".into()));
        }
        let parent = destination.parent().unwrap_or_else(|| Path::new("."));
        let staging = parent.join(format!(".qq-{:032x}", rand::random::<u128>()));
        let _staging = TemporaryFile::new(staging.clone());
        fs::copy(&path, &staging).await?;
        fs::rename(&staging, destination).await?;
        Ok(())
    }
    pub async fn call(&self, method: &str, args: ciborium::Value) -> Result<ciborium::Value> {
        let args = serde_json::to_value(args).map_err(|e| Error::Malformed(e.to_string()))?;
        let result = match method {
            "upload_image" => {
                #[derive(serde::Deserialize)]
                struct A {
                    input: MediaInput,
                    conversation: MediaConversation,
                    #[serde(default = "default_summary")]
                    summary: String,
                }
                let a: A = parse_args(args)?;
                json_value(
                    self.upload_image(a.input, a.conversation, &a.summary)
                        .await?,
                )?
            }
            "upload_voice" => {
                #[derive(serde::Deserialize)]
                struct A {
                    input: MediaInput,
                    conversation: MediaConversation,
                }
                let a: A = parse_args(args)?;
                json_value(self.upload_voice(a.input, a.conversation).await?)?
            }
            "upload_video" => {
                #[derive(serde::Deserialize)]
                struct A {
                    input: MediaInput,
                    thumbnail: Option<MediaInput>,
                    conversation: MediaConversation,
                    #[serde(default)]
                    width: u32,
                    #[serde(default)]
                    height: u32,
                    #[serde(default)]
                    duration: u32,
                }
                let a: A = parse_args(args)?;
                json_value(
                    self.upload_video(
                        a.input,
                        a.thumbnail,
                        a.conversation,
                        a.width,
                        a.height,
                        a.duration,
                    )
                    .await?,
                )?
            }
            "upload_avatar" => {
                #[derive(serde::Deserialize)]
                struct A {
                    input: MediaInput,
                }
                let a: A = parse_args(args)?;
                self.upload_avatar(a.input).await?;
                Value::Null
            }
            "download_url" => {
                #[derive(serde::Deserialize)]
                struct A {
                    reference: MediaReference,
                }
                let a: A = parse_args(args)?;
                json_value(self.download_url(&a.reference).await?)?
            }
            "legacy_video_play_url" => {
                #[derive(serde::Deserialize)]
                struct A {
                    reference: MediaReference,
                    context: LegacyVideoPlayContext,
                }
                let a: A = parse_args(args)?;
                json_value(self.legacy_video_play_url(&a.reference, a.context).await?)?
            }
            "download" => {
                #[derive(serde::Deserialize)]
                struct A {
                    reference: MediaReference,
                    destination: PathBuf,
                }
                let a: A = parse_args(args)?;
                self.download(&a.reference, &a.destination).await?;
                Value::Null
            }
            m if files::FILE_METHODS.contains(&m) => self.dispatch_files(m, args).await?,
            m if group_fs::GROUP_FS_METHODS.contains(&m) => self.dispatch_group_fs(m, args).await?,
            _ => return Err(Error::Unsupported(format!("Unknown media method {method}"))),
        };
        to_cbor(result)
    }
}
fn default_summary() -> String {
    "[图片]".into()
}
pub(crate) fn ipv4(value: u64) -> String {
    format!(
        "{}.{}.{}.{}",
        value & 255,
        (value >> 8) & 255,
        (value >> 16) & 255,
        (value >> 24) & 255
    )
}
pub(crate) fn media_command(kind: MediaKind, conversation: &MediaConversation) -> u32 {
    match kind {
        MediaKind::Image => {
            if conversation.is_group() {
                0x11c4
            } else {
                0x11c5
            }
        }
        MediaKind::Voice => {
            if conversation.is_group() {
                0x126e
            } else {
                0x126d
            }
        }
        MediaKind::Video => {
            if conversation.is_group() {
                0x11ea
            } else {
                0x11e9
            }
        }
        MediaKind::File => 0xe37,
    }
}
pub(crate) fn media_head(
    kind: MediaKind,
    conversation: &MediaConversation,
    command: u64,
    request_type: u64,
) -> Result<pb::MediaRequestHead> {
    let mut scene = pb::MediaSceneInfo {
        request_type: Some(request_type),
        reserved_103: (command == 200 && kind != MediaKind::Image).then_some(0),
        business_type: Some(match kind {
            MediaKind::Image => 1,
            MediaKind::Video => 2,
            _ => 3,
        }),
        scene_type: Some(if conversation.is_group() { 2 } else { 1 }),
        ..Default::default()
    };
    match conversation {
        MediaConversation::Friend { uid } => {
            if uid.is_empty() {
                return Err(Error::Malformed("Empty media peer UID".into()));
            }
            scene.direct_peer = Some(pb::MediaDirectPeer {
                account_type: Some(2),
                uid: Some(uid.clone()),
            });
        }
        MediaConversation::Group { uin } => {
            if *uin == 0 {
                return Err(Error::Malformed("Invalid media group UIN".into()));
            }
            scene.group_peer = Some(pb::MediaGroupPeer { uin: Some(*uin) });
        }
    }
    Ok(pb::MediaRequestHead {
        common: Some(pb::MediaCommonRequestHead {
            request_id: Some(1),
            command: Some(command),
        }),
        scene: Some(scene),
        client: Some(pb::MediaClientMeta {
            agent_type: Some(2),
        }),
    })
}

fn download_extension(
    kind: MediaKind,
    companion: Option<(u32, pb::MediaFileInfo)>,
) -> pb::MediaDownloadExtension {
    if kind == MediaKind::Image {
        return pb::MediaDownloadExtension::default();
    }
    let (subtype, file) = companion.unwrap_or_default();
    pb::MediaDownloadExtension {
        video: Some(pb::MediaVideoDownloadExtension {
            business_type: Some(0),
            scene_type: None,
            sub_business_type: Some(0),
            reserved_5: Some(0),
            reserved_6: Some(pb::MediaDownloadReserved6 {
                reserved_1: Some(subtype),
                file_md5: Some(file.md5.unwrap_or_default()),
                file_sha1: Some(file.sha1.unwrap_or_default()),
                file_size: Some(file.size.unwrap_or_default()),
            }),
        }),
        reserved_4: Some(pb::MediaDownloadReserved4 {
            reserved_1: Some(0),
        }),
    }
}
pub(crate) fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub(crate) fn valid_http_url(value: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(value).map_err(|e| Error::Malformed(e.to_string()))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(Error::Malformed("Expected HTTP(S) URL".into()));
    }
    Ok(url)
}
fn temp_path() -> PathBuf {
    std::env::temp_dir().join(format!("atri-qq-media-{:032x}", rand::random::<u128>()))
}
struct TemporaryFile(Option<PathBuf>);
impl TemporaryFile {
    fn new(path: PathBuf) -> Self {
        Self(Some(path))
    }
    fn disarm(&mut self) {
        self.0 = None;
    }
}
impl Drop for TemporaryFile {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    let _ = fs::remove_file(path).await;
                });
            }
        }
    }
}
async fn http_check(response: &mut reqwest::Response) -> Result<()> {
    if response.status().is_success() {
        return Ok(());
    }
    let code = response.status().as_u16() as i32;
    let error = Error::Server {
        code,
        message: "Media HTTP request failed".into(),
    };
    let mut body = Vec::new();
    const LIMIT: usize = 4 * 1024 * 1024;
    let mut truncated = false;
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                tracing::debug!(target: "atri_qq_protocol::packet_trace", direction = "receive", transport = "http", url = %response.url(), offset = body.len(), body_hex = %hex::encode(&chunk), "QQ HTTP error body");
                let remaining = LIMIT - body.len();
                body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
                if chunk.len() > remaining {
                    truncated = true;
                    break;
                }
            }
            Ok(None) => break,
            Err(cause) => {
                tracing::error!(code, error = ?cause, "Read media HTTP error response failed");
                break;
            }
        }
    }
    tracing::error!(target: "atri_qq_protocol::packet", code, error = ?error,
        body = %String::from_utf8_lossy(&body), raw_length = body.len(),
        raw_hex = %hex::encode(&body), truncated, "QQ media HTTP error response");
    Err(error)
}
pub(crate) fn parse_args<T: DeserializeOwned>(args: Value) -> Result<T> {
    serde_json::from_value(args).map_err(|e| Error::Malformed(e.to_string()))
}
pub(crate) fn json_value<T: Serialize>(value: T) -> Result<Value> {
    serde_json::to_value(value).map_err(|e| Error::Malformed(e.to_string()))
}
pub(crate) fn to_cbor<T: Serialize>(value: T) -> Result<ciborium::Value> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&value, &mut bytes).map_err(|e| Error::Malformed(e.to_string()))?;
    ciborium::de::from_reader(bytes.as_slice()).map_err(|e| Error::Malformed(e.to_string()))
}
fn decode_highway_ack(data: &[u8]) -> Result<()> {
    decode_highway_ack_inner(data).inspect_err(|error| {
        crate::diagnostics::log_raw_error("Highway acknowledgement", data, error);
    })
}
fn decode_highway_ack_inner(data: &[u8]) -> Result<()> {
    if data.len() < 10 || data[0] != 0x28 {
        return Err(Error::Malformed("Invalid Highway frame start".into()));
    }
    let head = u32::from_be_bytes(data[1..5].try_into().unwrap()) as usize;
    let body = u32::from_be_bytes(data[5..9].try_into().unwrap()) as usize;
    let end = 9usize
        .checked_add(head)
        .and_then(|v| v.checked_add(body))
        .ok_or_else(|| Error::Malformed("Highway frame length overflow".into()))?;
    if end.checked_add(1) != Some(data.len()) || data[end] != 0x29 {
        return Err(Error::Malformed("Invalid Highway frame end".into()));
    }
    let reply: pb::HighwayAcknowledgement = crate::diagnostics::decode_response(
        "Highway acknowledgement",
        Bytes::copy_from_slice(&data[9..9 + head]),
    )?;
    let code = reply.result.unwrap_or_default() as i32;
    if code != 0 {
        return Err(Error::Server {
            code,
            message: reply
                .message
                .and_then(|v| String::from_utf8(v.to_vec()).ok())
                .unwrap_or_else(|| "QQ request failed".into()),
        });
    }
    if let Some(returned) = reply.segment {
        let code = returned.result.unwrap_or_default() as i32;
        if code != 0 {
            return Err(Error::Server {
                code,
                message: "QQ request failed".into(),
            });
        }
    }
    Ok(())
}
async fn bounded_acknowledgement(mut response: reqwest::Response) -> Result<Vec<u8>> {
    http_check(&mut response).await?;
    const LIMIT: usize = 4 * 1024 * 1024;
    if response.content_length().is_some_and(|n| n > LIMIT as u64) {
        return Err(Error::Malformed(
            "Highway acknowledgement exceeds 4 MiB".into(),
        ));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > LIMIT - bytes.len() {
            return Err(Error::Malformed(
                "Highway acknowledgement exceeds 4 MiB".into(),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
