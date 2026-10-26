use crate::{
    Error, Result, ServiceClient,
    models::{Encryption, RequestType},
    proto::sdk_share as pb,
};
use bytes::Bytes;
use ciborium::Value;
use prost::Message;
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};

pub const SDK_SHARE_METHODS: &[&str] = &["share_music"];
pub const SHARE_MUSIC_COMMAND: &str = "OidbSvc.0xb77_9";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MusicShareTarget {
    Friend { uin: u64 },
    Group { uin: u64 },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AndroidShareSource {
    pub app_id: u64,
    pub package_name: String,
    pub signature_md5: String,
    pub sdk_version: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MusicShareContent {
    pub title: String,
    pub summary: Option<String>,
    pub jump_url: String,
    pub picture_url: String,
    pub music_url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareMusicRequest {
    pub target: MusicShareTarget,
    pub source: AndroidShareSource,
    pub content: MusicShareContent,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MusicShareReceipt {
    pub jump_result: u32,
    pub jump_url: Option<String>,
    pub wording: Option<String>,
    pub developer_message: Option<String>,
    pub level: Option<u32>,
    pub sub_level: Option<u32>,
}

pub struct SdkShare {
    client: Arc<dyn ServiceClient>,
}

impl SdkShare {
    pub fn new(client: Arc<dyn ServiceClient>) -> Self {
        Self { client }
    }

    pub async fn share_music(&self, request: ShareMusicRequest) -> Result<MusicShareReceipt> {
        let client_version = {
            let state = self.client.snapshot().await;
            format!("{} {}", state.profile.os, state.profile.version)
        };
        let envelope = pb::LegacyOidbEnvelope {
            command: Some(0xb77),
            service: Some(9),
            body: Some(encode_request(request).encode_to_vec().into()),
            client_version: Some(client_version),
            ..Default::default()
        };
        let response = self
            .client
            .request(
                SHARE_MUSIC_COMMAND,
                envelope.encode_to_vec().into(),
                RequestType::D2,
                Encryption::D2,
                Duration::from_secs(10),
            )
            .await
            .map_err(|error| match error {
                Error::Timeout | Error::Disconnected | Error::Io(_) => unconfirmed(error),
                error => error,
            })?;
        decode_response(response)
    }

    pub async fn call(&self, method: &str, args: Value) -> Result<Value> {
        match method {
            "share_music" => {
                let request = args
                    .deserialized()
                    .map_err(|error| Error::Malformed(error.to_string()))?;
                Value::serialized(&self.share_music(request).await?)
                    .map_err(|error| Error::Malformed(error.to_string()))
            }
            _ => Err(Error::Unsupported(format!(
                "Unknown SDK share method: {method}"
            ))),
        }
    }
}

fn nonempty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

fn encode_request(request: ShareMusicRequest) -> pb::ShareMusicRequest {
    let (send_type, receiver_uin) = match request.target {
        MusicShareTarget::Friend { uin } => (0, uin),
        MusicShareTarget::Group { uin } => (1, uin),
    };
    let mut source = request.source;
    source.signature_md5.make_ascii_lowercase();
    let content = request.content;
    pb::ShareMusicRequest {
        app_id: Some(source.app_id),
        app_type: Some(1),
        message_style: Some(4),
        client_info: Some(pb::ShareClientInfo {
            platform: Some(1),
            sdk_version: Some(source.sdk_version.unwrap_or_else(|| "0.0.0".into())),
            android_package_name: nonempty(source.package_name),
            android_signature: nonempty(source.signature_md5),
            ..Default::default()
        }),
        ext_info: Some(pb::ShareExtInfo::default()),
        send_type: Some(send_type),
        receiver_uin: Some(receiver_uin),
        rich_message: Some(pb::MusicShareBody {
            title: nonempty(content.title),
            summary: content.summary.filter(|value| !value.is_empty()),
            url: nonempty(content.jump_url),
            picture_url: nonempty(content.picture_url),
            music_url: nonempty(content.music_url),
            ..Default::default()
        }),
        sign_timestamp: Some(0),
        sign_nonce: Some(0),
        sign_signature: Some(String::new()),
        json: Some(String::new()),
        ..Default::default()
    }
}

fn unconfirmed(cause: Error) -> Error {
    Error::UnconfirmedSdkShare {
        cause: Box::new(cause),
    }
}

fn decode_response(bytes: Bytes) -> Result<MusicShareReceipt> {
    let envelope: pb::LegacyOidbEnvelope =
        crate::diagnostics::decode_response(SHARE_MUSIC_COMMAND, bytes).map_err(unconfirmed)?;
    if envelope.command.is_some_and(|command| command != 0xb77)
        || envelope.service.is_some_and(|service| service != 9)
    {
        return Err(unconfirmed(Error::Malformed(
            "Mismatched B77 OIDB response".into(),
        )));
    }
    let result = envelope
        .result
        .ok_or_else(|| unconfirmed(Error::Malformed("B77 OIDB response has no result".into())))?;
    if result != 0 {
        return Err(Error::Server {
            code: result as i32,
            message: envelope.error_message.unwrap_or_default(),
        });
    }
    let body = envelope
        .body
        .ok_or_else(|| unconfirmed(Error::Malformed("B77 OIDB response has no body".into())))?;
    let receipt: pb::ShareMusicResponse =
        crate::diagnostics::decode_response(SHARE_MUSIC_COMMAND, body).map_err(unconfirmed)?;
    Ok(MusicShareReceipt {
        jump_result: receipt.jump_result.unwrap_or_default(),
        jump_url: receipt.jump_url,
        wording: receipt.wording,
        developer_message: receipt.developer_message,
        level: receipt.level,
        sub_level: receipt.sub_level,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_oidb_rejection_is_not_reported_as_an_unknown_delivery() {
        let response = pb::LegacyOidbEnvelope {
            command: Some(0xb77),
            service: Some(9),
            result: Some(1001),
            error_message: Some("sharing rejected".into()),
            ..Default::default()
        };
        assert!(matches!(
            decode_response(response.encode_to_vec().into()),
            Err(Error::Server { code: 1001, message }) if message == "sharing rejected"
        ));
    }

    #[test]
    fn missing_receipt_is_unknown_but_present_empty_receipt_is_valid() {
        let mut response = pb::LegacyOidbEnvelope {
            command: Some(0xb77),
            service: Some(9),
            result: Some(0),
            ..Default::default()
        };
        assert!(matches!(
            decode_response(response.encode_to_vec().into()),
            Err(Error::UnconfirmedSdkShare { .. })
        ));
        response.body = Some(Bytes::new());
        assert_eq!(
            decode_response(response.encode_to_vec().into())
                .unwrap()
                .jump_result,
            0
        );
        response.result = None;
        assert!(matches!(
            decode_response(response.encode_to_vec().into()),
            Err(Error::UnconfirmedSdkShare { .. })
        ));
    }

    #[test]
    fn malformed_or_mismatched_receipts_do_not_imply_safe_retry() {
        for response in [
            pb::LegacyOidbEnvelope {
                command: Some(0xb78),
                result: Some(0),
                body: Some(Bytes::new()),
                ..Default::default()
            },
            pb::LegacyOidbEnvelope {
                service: Some(10),
                result: Some(0),
                body: Some(Bytes::new()),
                ..Default::default()
            },
            pb::LegacyOidbEnvelope {
                result: Some(0),
                body: Some(Bytes::from_static(&[0x1a, 0x08])),
                ..Default::default()
            },
        ] {
            assert!(matches!(
                decode_response(response.encode_to_vec().into()),
                Err(Error::UnconfirmedSdkShare { .. })
            ));
        }
    }
}
