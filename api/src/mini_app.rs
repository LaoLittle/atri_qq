use atri_core::Operation;
use serde::{Deserialize, Serialize};

pub const MINI_APP_SERVICE: &str = "qq.mini_app";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MiniAppShareTemplate {
    pub id: String,
    pub data: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AdaptShareInfoRequest {
    pub app_id: String,
    pub is_wx_mini_app: bool,
    pub title: Option<String>,
    pub description: Option<String>,
    pub picture_url: Option<String>,
    pub jump_url: Option<String>,
    pub icon_url: Option<String>,
    pub template: Option<MiniAppShareTemplate>,
}

impl Operation for AdaptShareInfoRequest {
    type Response = AdaptShareInfoResponse;
    const SERVICE: &'static str = MINI_APP_SERVICE;
    const METHOD: &'static str = "adapt_share_info";
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdaptShareInfoResponse {
    pub raw_json: String,
    pub light_app_json: String,
}
