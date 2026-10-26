use crate::{
    Error, Result, ServiceClient,
    models::{Encryption, RequestType},
    proto::mini_app as pb,
};
use bytes::Bytes;
use ciborium::Value;
use prost::Message;
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};

pub const MINI_APP_METHODS: &[&str] = &["adapt_share_info"];
pub const ADAPT_SHARE_INFO_COMMAND: &str = "LightAppSvc.mini_app_share.AdaptShareInfo";

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct MiniAppShareTemplate {
    pub id: String,
    pub data: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct MiniAppShareRequest {
    pub app_id: String,
    pub is_wx_mini_app: bool,
    pub title: Option<String>,
    pub description: Option<String>,
    pub picture_url: Option<String>,
    pub jump_url: Option<String>,
    pub icon_url: Option<String>,
    pub template: Option<MiniAppShareTemplate>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdaptedShareInfo {
    pub raw_json: String,
    pub light_app_json: String,
}

pub struct MiniApp {
    client: Arc<dyn ServiceClient>,
}

impl MiniApp {
    pub fn new(client: Arc<dyn ServiceClient>) -> Self {
        Self { client }
    }

    pub async fn adapt_share_info(&self, request: MiniAppShareRequest) -> Result<AdaptedShareInfo> {
        let body = encode_request(request);
        let response = self
            .client
            .request(
                ADAPT_SHARE_INFO_COMMAND,
                body.encode_to_vec().into(),
                RequestType::D2,
                Encryption::D2,
                Duration::from_secs(60),
            )
            .await?;
        decode_response(response)
    }

    pub async fn call(&self, method: &str, args: Value) -> Result<Value> {
        match method {
            "adapt_share_info" => {
                let request = args
                    .deserialized()
                    .map_err(|error| Error::Malformed(error.to_string()))?;
                Value::serialized(&self.adapt_share_info(request).await?)
                    .map_err(|error| Error::Malformed(error.to_string()))
            }
            _ => Err(Error::Unsupported(format!(
                "Unknown mini-app method: {method}"
            ))),
        }
    }
}

fn encode_request(request: MiniAppShareRequest) -> pb::AdaptShareInfoRequest {
    pb::AdaptShareInfoRequest {
        sdk_id: Some("V1_PC_MINISDK_99.99.99_1_APP_A".into()),
        body: Some(pb::ShareInfo {
            app_id: Some(request.app_id),
            title: request.title,
            description: request.description,
            scene: Some(1),
            business_type: Some(u32::from(request.is_wx_mini_app) * 2),
            picture_url: request.picture_url,
            jump_url: request.jump_url,
            icon_url: request.icon_url,
            version_type: Some(3),
            share_type: Some(0),
            template: request.template.map(|template| pb::ShareTemplate {
                id: Some(template.id),
                data: Some(template.data),
            }),
        }),
    }
}

fn decode_response(bytes: Bytes) -> Result<AdaptedShareInfo> {
    let response: pb::AdaptShareInfoResponse =
        crate::diagnostics::decode_response(ADAPT_SHARE_INFO_COMMAND, bytes)?;
    if let Some(code) = response.code.filter(|code| *code != 0) {
        return Err(Error::Server {
            code,
            message: response.error_message.unwrap_or_default(),
        });
    }
    let raw_json = response
        .content
        .and_then(|content| content.json)
        .ok_or_else(|| Error::Malformed("Mini-app response lacks card JSON".into()))?;
    let light_app_json = light_app_json(&raw_json)?;
    Ok(AdaptedShareInfo {
        raw_json,
        light_app_json,
    })
}

fn light_app_json(raw: &str) -> Result<String> {
    let mut card: serde_json::Map<String, serde_json::Value> = serde_json::from_str(raw)
        .map_err(|error| Error::Malformed(format!("Invalid mini-app card JSON: {error}")))?;
    for (source, destination) in [
        ("appName", "app"),
        ("appView", "view"),
        ("metaData", "meta"),
    ] {
        if let Some(value) = card.remove(source) {
            if card
                .get(destination)
                .is_some_and(|existing| existing != &value)
            {
                return Err(Error::Malformed(format!(
                    "Conflicting mini-app card field: {destination}"
                )));
            }
            card.insert(destination.into(), value);
        }
    }
    if !card
        .get("app")
        .is_some_and(|value| value.as_str().is_some_and(|app| !app.is_empty()))
        || !card.get("view").is_some_and(serde_json::Value::is_string)
        || !card.get("meta").is_some_and(serde_json::Value::is_object)
        || !card.get("config").is_some_and(serde_json::Value::is_object)
    {
        return Err(Error::Malformed(
            "Mini-app card lacks app/view/meta/config".into(),
        ));
    }
    card.entry("miniappShareOrigin")
        .or_insert(serde_json::Value::from(3));
    card.entry("miniappOpenRefer")
        .or_insert(serde_json::Value::from("10002"));
    serde_json::to_string(&card).map_err(|error| Error::Malformed(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn card_conversion_preserves_authorization_and_unrecognized_data() {
        let raw = r#"{"appName":"com.tencent.miniapp_01","appView":"view_test","metaData":{"detail_1":{"title":"标题","url":"https://example.invalid/a?b=1"}},"config":{"token":"synthetic-token","ctime":1800000000,"future":{"n":7}},"futureRoot":[1,{"keep":true}]}"#;
        let card: serde_json::Value = serde_json::from_str(&light_app_json(raw).unwrap()).unwrap();
        let original: serde_json::Value = serde_json::from_str(raw).unwrap();
        assert_eq!(card["config"], original["config"]);
        assert_eq!(card["meta"], original["metaData"]);
        assert_eq!(card["futureRoot"], original["futureRoot"]);
        assert_eq!(card["app"], original["appName"]);
        assert!(card.get("appName").is_none());
    }

    #[test]
    fn negative_server_rejection_preserves_signed_code_and_error_without_card() {
        let bytes = hex::decode(
            "108b9ba4d0ffffffffff011a18e88eb7e58f96e5ba94e794a8e4bfa1e681afe5a4b1e8b4a5",
        )
        .unwrap();
        let response = pb::AdaptShareInfoResponse::decode(bytes.as_slice()).unwrap();
        assert_eq!(response.code, Some(-100070005));
        assert!(
            matches!(decode_response(bytes.into()), Err(Error::Server { code: -100070005, message }) if message == "获取应用信息失败")
        );
    }

    #[test]
    fn conflicting_authoritative_names_and_malformed_cards_are_rejected() {
        for raw in ["null", "[]", "{}", r#"{"appName":"one","app":"two"}"#] {
            assert!(matches!(light_app_json(raw), Err(Error::Malformed(_))));
        }
    }
}
