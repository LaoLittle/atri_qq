use super::payload::MediaPayload;
use super::{
    FileSendReceipt, Media, MediaConversation, MediaInput, MediaKind, MediaReference, ipv4,
};
use crate::{Error, Result, proto::media as pb};
use prost::Message;
use serde::Deserialize;
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const FILE_METHODS: &[&str] = &[
    "upload_file",
    "send_file",
    "file_download_url",
    "group_file_download_url",
];

impl Media {
    pub async fn upload_file(
        &self,
        input: MediaInput,
        conversation: MediaConversation,
        parent_directory: &str,
    ) -> Result<MediaReference> {
        if parent_directory.is_empty() {
            return Err(Error::Malformed("Empty parent directory".into()));
        }
        let payload = self.prepare(input, true, false).await?;
        let state = self.client.snapshot().await;
        let (id, crc, key, checksum, exists, addresses) = match &conversation {
            MediaConversation::Friend { uid } => {
                if uid.is_empty() || state.keystore.uid.is_empty() {
                    return Err(Error::Malformed(
                        "Friend file upload requires peer and sender UID".into(),
                    ));
                }
                if payload.size > u32::MAX as u64 {
                    return Err(Error::Unsupported(
                        "Friend file exceeds desktop upload UInt32 size field".into(),
                    ));
                }
                let request = pb::FriendFileRequest {
                    command: Some(1700),
                    sequence: Some(0),
                    upload: Some(pb::FriendFileUploadRequest {
                        sender_uid: Some(state.keystore.uid.clone()),
                        receiver_uid: Some(uid.clone()),
                        size: Some(payload.size),
                        name: Some(payload.name.clone()),
                        md5_10m: Some(payload.md5_10m.clone().into()),
                        sha1: Some(payload.sha1.clone().into()),
                        parent_directory: Some("/".into()),
                        md5: Some(payload.md5.clone().into()),
                        tri_sha1: Some(payload.tri_sha1.clone().into()),
                    }),
                    business_id: Some(3),
                    client_type: Some(1),
                    request_flag: Some(1),
                    ..Default::default()
                };
                let response: pb::FriendFileResponse =
                    self.oidb(0xe37, 1700, request, 0, None).await?;
                let result = response
                    .upload
                    .ok_or_else(|| Error::Malformed("Missing protobuf field 19".into()))?;
                file_result(result.result_code, result.result_message)?;
                let addresses = result
                    .addresses
                    .into_iter()
                    .map(|v| (ipv4(v.ipv4.unwrap_or_default()), v.port.unwrap_or_default()))
                    .collect::<Vec<_>>();
                (
                    file_text(result.file_id.as_deref()).unwrap_or_default(),
                    file_text(result.file_id_crc.as_deref()),
                    result.upload_key.unwrap_or_default(),
                    None,
                    result.exists.unwrap_or_default() != 0,
                    addresses,
                )
            }
            MediaConversation::Group { uin } => {
                if *uin == 0 {
                    return Err(Error::Malformed("Invalid group UIN".into()));
                }
                let request = pb::GroupFileCommandRequest {
                    upload: Some(pb::GroupFileUploadRequest {
                        group_uin: Some(*uin),
                        app_id: Some(7),
                        bus_id: Some(102),
                        entrance: Some(6),
                        parent_directory: Some(parent_directory.into()),
                        name: Some(payload.name.clone()),
                        local_path: Some(format!("/{}", payload.name)),
                        size: Some(payload.size),
                        sha1: Some(payload.sha1.clone().into()),
                        tri_sha1: Some(payload.tri_sha1.clone().into()),
                        md5: Some(payload.md5.clone().into()),
                    }),
                    ..Default::default()
                };
                let response: pb::GroupFileCommandResponse =
                    self.oidb(0x6d6, 0, request, 0, None).await?;
                let result = response
                    .upload
                    .ok_or_else(|| Error::Malformed("Missing protobuf field 1".into()))?;
                file_result(result.result_code, result.result_message)?;
                (
                    file_text(result.file_id.as_deref()).unwrap_or_default(),
                    None,
                    result.upload_key.unwrap_or_default(),
                    Some(result.checksum.unwrap_or_default()),
                    result.exists.unwrap_or_default() != 0,
                    vec![(
                        file_text(result.host.as_deref()).unwrap_or_default(),
                        result.port.unwrap_or_default(),
                    )],
                )
            }
        };
        if id.is_empty() {
            return Err(Error::Malformed(
                "File negotiation returned no file ID".into(),
            ));
        }
        let checksum = checksum.as_deref().unwrap_or(&payload.sha1);
        if !exists {
            if key.is_empty()
                || checksum.is_empty()
                || addresses.is_empty()
                || addresses
                    .iter()
                    .any(|(host, port)| host.is_empty() || !(1..=65535).contains(port))
            {
                return Err(Error::Malformed(
                    "File negotiation omitted upload key or endpoint".into(),
                ));
            }
            let ext = file_upload_ext(
                &payload,
                &conversation,
                state.keystore.uin,
                &id,
                &key,
                checksum,
                &addresses,
            );
            self.highway_upload(&payload, if conversation.is_group() { 71 } else { 95 }, ext)
                .await?;
        }
        let mut reference = MediaReference::new(MediaKind::File, conversation);
        if !reference.conversation.is_group() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| Error::Malformed(e.to_string()))?
                .as_secs();
            let compatibility = pb::OfflineFileCompatibility {
                file_type: Some(0),
                file_uuid: Some(id.clone().into()),
                md5: Some(payload.md5_10m.clone().into()),
                name: Some(payload.name.clone().into()),
                size: Some(payload.size),
                subcommand: Some(1),
                danger_level: Some(0),
                expiry_time: Some(now + 7 * 86400),
                file_id_crc: crc.clone().map(Into::into),
            };
            reference.compatibility = Some(compatibility.encode_to_vec());
        }
        reference.file_id = Some(id.clone());
        reference.uuid = Some(id);
        reference.file_id_crc = crc;
        reference.name = payload.name.clone();
        reference.size = payload.size;
        reference.md5 = payload.md5.clone();
        reference.sha1 = payload.sha1.clone();
        Ok(reference)
    }

    pub async fn send_file(&self, reference: &MediaReference) -> Result<FileSendReceipt> {
        let id = reference
            .file_id
            .as_ref()
            .or(reference.uuid.as_ref())
            .filter(|id| !id.is_empty())
            .ok_or_else(|| Error::Malformed("Expected negotiated file reference".into()))?;
        if !matches!(reference.kind, MediaKind::File) {
            return Err(Error::Malformed(
                "Expected negotiated file reference".into(),
            ));
        }
        let random = rand::random::<u32>() & 0x7fffffff;
        match &reference.conversation {
            MediaConversation::Group { uin } => {
                if *uin == 0 {
                    return Err(Error::Malformed("Invalid group UIN".into()));
                }
                let request = pb::GroupFileFeedRequest {
                    body: Some(pb::GroupFileFeedBody {
                        group_uin: Some(*uin),
                        app_id: Some(2),
                        file: Some(pb::GroupFileFeed {
                            bus_id: Some(102),
                            file_id: Some(id.clone()),
                            random: Some(random as u64),
                            send_flag: Some(1),
                        }),
                    }),
                };
                let response: pb::GroupFileFeedResponse = self
                    .oidb(0x6d9, 4, request, 0, None)
                    .await
                    .map_err(|error| file_send_error(error, id))?;
                let result = response
                    .result
                    .ok_or_else(|| Error::Malformed("Missing protobuf field 5".into()))?;
                file_result(result.result_code, result.result_message)?;
                for item in result.files {
                    file_result(item.result_code, item.result_message)?;
                }
                Ok(FileSendReceipt {
                    sequence: None,
                    client_sequence: None,
                    random,
                    time: None,
                    file_id: id.clone(),
                })
            }
            MediaConversation::Friend { uid } => {
                if uid.is_empty() {
                    return Err(Error::Malformed(
                        "Friend file send requires peer UID".into(),
                    ));
                }
                let compatibility = reference.compatibility.as_ref().ok_or_else(|| {
                    Error::Malformed("Friend file has no negotiated NotOnlineFile payload".into())
                })?;
                let body = friend_file_body(compatibility)?;
                let uin = crate::contacts::Operations::new(self.client.clone())
                    .resolve_uin(uid)
                    .await?;
                let sequence = 10000 + rand::random::<u64>() % 89999;
                let request = pb::FriendFileSendRequest {
                    route: Some(pb::FriendFileRoute {
                        peer: Some(pb::FriendFilePeer {
                            uin: Some(uin),
                            command: Some(4),
                            uid: Some(uid.clone()),
                        }),
                    }),
                    content_head: Some(pb::FriendFileContentHead {
                        packages: Some(1),
                        package_index: Some(0),
                        division_sequence: Some(0),
                        auto_reply: Some(0),
                    }),
                    body: Some(body),
                    sequence: Some(sequence),
                    random: Some(random as u64),
                };
                let response: pb::FriendFileSendResponse = self
                    .request("MessageSvc.PbSendMsg", request)
                    .await
                    .map_err(|error| file_send_error(error, id))?;
                file_result(response.result_code, response.result_message.clone())?;
                Ok(friend_file_receipt(&response, id, sequence, random))
            }
        }
    }

    pub async fn file_download_url(&self, reference: &MediaReference) -> Result<String> {
        let Some(id) = reference
            .file_id
            .as_ref()
            .or(reference.uuid.as_ref())
            .filter(|id| !id.is_empty())
        else {
            return reference
                .download_url
                .as_deref()
                .ok_or_else(|| Error::Malformed("File download requires server file UUID".into()))
                .and_then(valid_http_url);
        };
        match &reference.conversation {
            MediaConversation::Group { uin } => self.group_file_download_url(*uin, id).await,
            MediaConversation::Friend { .. } => {
                let state = self.client.snapshot().await;
                let compatibility = reference
                    .compatibility
                    .as_ref()
                    .map(|v| crate::proto::decode::<pb::OfflineFileCompatibility>(v.as_slice()))
                    .transpose()?;
                let md5 = compatibility
                    .and_then(|v| v.md5)
                    .map(|v| v.to_vec())
                    .unwrap_or_else(|| reference.md5.clone());
                if state.keystore.uid.is_empty() || md5.is_empty() {
                    return Err(Error::Malformed(
                        "Friend file download requires receiver UID and file MD5".into(),
                    ));
                }
                let request = pb::FriendFileRequest {
                    command: Some(1200),
                    sequence: Some(1),
                    download: Some(pb::FriendFileDownloadRequest {
                        receiver_uid: Some(state.keystore.uid.clone()),
                        file_id: Some(id.clone()),
                        url_type: Some(2),
                        md5_hex: Some(hex(&md5, false)),
                        download_flag: Some(0),
                    }),
                    business_id: Some(3),
                    client_type: Some(103),
                    request_flag: Some(1),
                    extension: Some(vec![0xc0, 0x85, 0x2c, 1].into()),
                    ..Default::default()
                };
                let response: pb::FriendFileResponse =
                    self.oidb(0xe37, 1200, request, 0, None).await?;
                let download = response
                    .download
                    .ok_or_else(|| Error::Malformed("Missing protobuf field 14".into()))?;
                file_result(download.result_code, download.result_message)?;
                let location = download
                    .location
                    .ok_or_else(|| Error::Malformed("Missing protobuf field 30".into()))?;
                friend_download_url(&location)
            }
        }
    }

    pub async fn group_file_download_url(&self, group_uin: u64, file_id: &str) -> Result<String> {
        if group_uin == 0 || file_id.is_empty() {
            return Err(Error::Malformed("Invalid group file identity".into()));
        }
        let request = pb::GroupFileCommandRequest {
            download: Some(pb::GroupFileDownloadRequest {
                group_uin: Some(group_uin),
                app_id: Some(7),
                bus_id: Some(102),
                file_id: Some(file_id.into()),
            }),
            ..Default::default()
        };
        let response: pb::GroupFileCommandResponse = self.oidb(0x6d6, 2, request, 0, None).await?;
        let result = response
            .download
            .ok_or_else(|| Error::Malformed("Missing protobuf field 3".into()))?;
        file_result(result.result_code, result.result_message.clone())?;
        group_download_url(&result)
    }

    pub(crate) async fn dispatch_files(&self, method: &str, args: Value) -> Result<Value> {
        #[derive(Deserialize)]
        struct Upload {
            input: MediaInput,
            conversation: MediaConversation,
            #[serde(default = "root")]
            parent_directory: String,
        }
        #[derive(Deserialize)]
        struct Reference {
            reference: MediaReference,
        }
        #[derive(Deserialize)]
        struct Identity {
            group_uin: u64,
            file_id: String,
        }
        fn decode<T: serde::de::DeserializeOwned>(v: Value) -> Result<T> {
            serde_json::from_value(v).map_err(|e| Error::Malformed(e.to_string()))
        }
        fn encode<T: serde::Serialize>(v: T) -> Result<Value> {
            serde_json::to_value(v).map_err(|e| Error::Malformed(e.to_string()))
        }
        match method {
            "upload_file" => {
                let a: Upload = decode(args)?;
                encode(
                    self.upload_file(a.input, a.conversation, &a.parent_directory)
                        .await?,
                )
            }
            "send_file" => {
                let a: Reference = decode(args)?;
                encode(self.send_file(&a.reference).await?)
            }
            "file_download_url" => {
                let a: Reference = decode(args)?;
                encode(self.file_download_url(&a.reference).await?)
            }
            "group_file_download_url" => {
                let a: Identity = decode(args)?;
                encode(
                    self.group_file_download_url(a.group_uin, &a.file_id)
                        .await?,
                )
            }
            _ => Err(Error::Unsupported(format!(
                "Unknown media file method: {method}"
            ))),
        }
    }
}

fn root() -> String {
    "/".into()
}
fn hex(data: &[u8], uppercase: bool) -> String {
    const LOWER: &[u8] = b"0123456789abcdef";
    const UPPER: &[u8] = b"0123456789ABCDEF";
    let table = if uppercase { UPPER } else { LOWER };
    let mut out = String::with_capacity(data.len() * 2);
    for &v in data {
        out.push(table[(v >> 4) as usize] as char);
        out.push(table[(v & 15) as usize] as char);
    }
    out
}
fn valid_http_url(value: &str) -> Result<String> {
    let url = reqwest::Url::parse(value)
        .map_err(|e| Error::Malformed(format!("Invalid file download URL: {e}")))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(Error::Malformed("Invalid file download URL".into()));
    }
    Ok(url.into())
}
fn friend_download_url(location: &pb::FriendFileDownloadLocation) -> Result<String> {
    let host = location
        .host
        .as_deref()
        .and_then(|v| std::str::from_utf8(v).ok())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| Error::Malformed("Friend file download omitted host".into()))?;
    let path = location
        .path
        .as_deref()
        .and_then(|v| std::str::from_utf8(v).ok())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| Error::Malformed("Friend file download omitted path".into()))?;
    if let Ok(url) = reqwest::Url::parse(&path) {
        return valid_http_url(url.as_str());
    }
    let mut url =
        reqwest::Url::parse("http://placeholder/").map_err(|e| Error::Malformed(e.to_string()))?;
    url.set_host(Some(&host))
        .map_err(|_| Error::Malformed("Invalid friend file HTTP host".into()))?;
    let port = location.port.unwrap_or_default();
    if port > 65535 {
        return Err(Error::Malformed("Invalid friend file HTTP port".into()));
    }
    if port != 0 {
        url.set_port(Some(port as u16))
            .map_err(|_| Error::Malformed("Invalid friend file HTTP port".into()))?;
    }
    let url = url
        .join(&path)
        .map_err(|e| Error::Malformed(e.to_string()))?;
    valid_http_url(url.as_str())
}
fn group_download_url(result: &pb::GroupFileDownloadResponse) -> Result<String> {
    let host = result
        .host
        .as_deref()
        .and_then(|v| std::str::from_utf8(v).ok())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| Error::Malformed("Group file download omitted host".into()))?;
    let key = result
        .key
        .as_deref()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| Error::Malformed("Group file download omitted key".into()))?;
    let mut url =
        reqwest::Url::parse("https://placeholder/").map_err(|e| Error::Malformed(e.to_string()))?;
    url.set_host(Some(&host))
        .map_err(|_| Error::Malformed("Invalid group file HTTP host".into()))?;
    url.set_path(&format!("/ftn_handler/{}/", hex(&key, true)));
    url.set_query(Some("fname="));
    valid_http_url(url.as_str())
}
fn file_upload_ext(
    payload: &MediaPayload,
    conversation: &MediaConversation,
    sender: u64,
    id: &str,
    key: &[u8],
    checksum: &[u8],
    addresses: &[(String, u64)],
) -> Vec<u8> {
    let group_uin = match conversation {
        MediaConversation::Group { uin } => Some(*uin),
        MediaConversation::Friend { .. } => None,
    };
    pb::FileUploadExtension {
        command: Some(100),
        version: Some(1),
        entry: Some(pb::FileUploadEntry {
            business: Some(pb::FileUploadBusiness {
                sender_uin: Some(sender),
                group_uin,
                receiver_uin: group_uin,
            }),
            file: Some(pb::FileUploadMetadata {
                size: Some(payload.size),
                md5: Some(payload.md5.clone().into()),
                checksum: Some(checksum.to_vec().into()),
                md5_10m: Some(payload.md5_10m.clone().into()),
                tri_sha1: (!conversation.is_group()).then(|| payload.tri_sha1.clone().into()),
                file_id: Some(id.into()),
                upload_key: Some(key.to_vec().into()),
            }),
            client: Some(pb::FileUploadClient {
                client_type: Some(3),
                app_id: Some("100".into()),
                terminal_type: Some(3),
                version: Some("1.1.1".into()),
                protocol_version: Some(4),
            }),
            name: Some(pb::FileUploadName {
                name: Some(payload.name.clone()),
            }),
            hosts: Some(pb::FileUploadHosts {
                hosts: addresses
                    .iter()
                    .map(|(host, port)| pb::FileUploadHost {
                        address: Some(pb::FileUploadAddress {
                            address_type: Some(1),
                            host: Some(host.clone()),
                        }),
                        port: Some(*port),
                    })
                    .collect(),
            }),
        }),
        friend_flag: (!conversation.is_group()).then_some(1),
    }
    .encode_to_vec()
}

fn file_send_error(error: Error, file_id: &str) -> Error {
    match error {
        Error::Timeout | Error::Disconnected | Error::Io(_) => Error::UnconfirmedFileSend {
            file_id: file_id.into(),
            cause: error.to_string(),
        },
        error => error,
    }
}

fn friend_file_receipt(
    response: &pb::FriendFileSendResponse,
    id: &str,
    client_sequence: u64,
    random: u32,
) -> FileSendReceipt {
    FileSendReceipt {
        sequence: response
            .client_sequence
            .filter(|sequence| *sequence != 0)
            .or(response.sequence),
        client_sequence: Some(client_sequence),
        random,
        time: response.time.map(|v| v as u32),
        file_id: id.into(),
    }
}

fn friend_file_body(compatibility: &[u8]) -> Result<pb::FriendFileSendBody> {
    crate::proto::decode::<pb::OfflineFileCompatibility>(compatibility)?;
    Ok(pb::FriendFileSendBody {
        content: Some(pb::FriendFileRawContent {
            offline_file: Some(bytes::Bytes::copy_from_slice(compatibility)),
        }),
    })
}

fn file_result(code: Option<u64>, message: Option<bytes::Bytes>) -> Result<()> {
    let code = code.unwrap_or_default() as i32;
    if code != 0 {
        Err(Error::Server {
            code,
            message: file_text(message.as_deref()).unwrap_or_else(|| "QQ request failed".into()),
        })
    } else {
        Ok(())
    }
}

fn file_text(value: Option<&[u8]>) -> Option<String> {
    value
        .and_then(|v| std::str::from_utf8(v).ok())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn offline_file_send_preserves_unknown_fields_and_non_utf8_metadata() {
        let raw = [0x22, 2, 1, 2, 0x2a, 1, 0xff, 0xa2, 0x06, 2, 0, 0xff];
        let body = friend_file_body(&raw).unwrap();
        assert_eq!(body.content.unwrap().offline_file.unwrap().as_ref(), raw);
        assert!(friend_file_body(&[0x22, 2, 1]).is_err());
    }

    #[test]
    fn file_result_preserves_missing_invalid_and_empty_error_messages() {
        for message in [None, Some(vec![0xff].into())] {
            assert!(matches!(
                file_result(Some(7), message),
                Err(Error::Server { code: 7, message }) if message == "QQ request failed"
            ));
        }
        assert!(matches!(
            file_result(Some(7), Some(bytes::Bytes::new())),
            Err(Error::Server { code: 7, message }) if message.is_empty()
        ));
        assert!(file_result(None, None).is_ok());
    }

    #[test]
    fn uncertain_send_transport_errors_are_not_retryable_rejections() {
        for error in [
            Error::Timeout,
            Error::Disconnected,
            Error::Io("connection reset".into()),
        ] {
            assert!(
                matches!(file_send_error(error,"file-id"),Error::UnconfirmedFileSend {file_id,..} if file_id=="file-id")
            );
        }
        assert!(matches!(
            file_send_error(
                Error::Server {
                    code: 7,
                    message: "rejected".into()
                },
                "file-id"
            ),
            Error::Server { code: 7, .. }
        ));
    }
    #[test]
    fn friend_ack_does_not_invent_sequence_or_time() {
        let response = crate::proto::decode::<pb::FriendFileSendResponse>(&[][..]).unwrap();
        let receipt = friend_file_receipt(&response, "id", 12345, 17);
        assert_eq!(receipt.sequence, None);
        assert_eq!(receipt.time, None);
        assert_eq!(receipt.client_sequence, Some(12345));
        assert_eq!(receipt.random, 17);
        let response =
            crate::proto::decode::<pb::FriendFileSendResponse>(&[0x18, 0, 0x58, 0][..]).unwrap();
        let receipt = friend_file_receipt(&response, "id", 12345, 17);
        assert_eq!(receipt.sequence, Some(0));
        assert_eq!(receipt.time, Some(0));
    }
    #[test]
    fn friend_file_ack_uses_private_sequence_without_overwriting_request_sequence() {
        let response = pb::FriendFileSendResponse {
            sequence: Some(11),
            client_sequence: Some(14),
            ..Default::default()
        };
        let receipt = friend_file_receipt(&response, "id", 12345, 17);
        assert_eq!(receipt.sequence, Some(14));
        assert_eq!(receipt.client_sequence, Some(12345));
        let response = pb::FriendFileSendResponse {
            client_sequence: Some(0),
            ..response
        };
        assert_eq!(
            friend_file_receipt(&response, "id", 12345, 17).sequence,
            Some(11)
        );
    }
    #[test]
    fn urls_reject_non_http_and_credentials() {
        for url in [
            "file:///etc/passwd",
            "ftp://example.com/a",
            "https://user:pass@example.com/a",
            "https:///",
            "javascript:alert(1)",
        ] {
            assert!(valid_http_url(url).is_err(), "{url}");
        }
        assert!(valid_http_url("https://example.com/a?x=1").is_ok());
    }
    #[test]
    fn friend_locations_preserve_query_and_validate_port() {
        let v = pb::FriendFileDownloadLocation {
            host: Some("download.example.com".into()),
            path: Some("/file?a=b".into()),
            port: Some(8080),
        };
        assert_eq!(
            friend_download_url(&v).unwrap(),
            "http://download.example.com:8080/file?a=b"
        );
        let bad = pb::FriendFileDownloadLocation {
            host: Some("example.com".into()),
            path: Some("/file".into()),
            port: Some(65536),
        };
        assert!(friend_download_url(&bad).is_err());
    }
    #[test]
    fn group_locations_use_uppercase_key() {
        let v = pb::GroupFileDownloadResponse {
            host: Some("example.com".into()),
            key: Some(vec![0xab, 0x09].into()),
            ..Default::default()
        };
        assert_eq!(
            group_download_url(&v).unwrap(),
            "https://example.com/ftn_handler/AB09/?fname="
        );
    }
}
