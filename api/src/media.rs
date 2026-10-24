use atri_core::{Operation, Value};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct LegacyVideoPlayUrl<'a> {
    pub reference: &'a Value,
    pub context: LegacyVideoPlayContext,
}

impl Operation for LegacyVideoPlayUrl<'_> {
    type Response = String;
    const SERVICE: &'static str = "qq.media";
    const METHOD: &'static str = "legacy_video_play_url";
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LegacyVideoPlayContext {
    pub from_uin: u64,
    /// Recipient for a private message; the group UIN for a group message.
    pub to_uin: u64,
    pub client_type: u32,
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
    pub device_codec_info: Option<LegacyVideoDeviceCodecInfo>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LegacyVideoDeviceCodecInfo {
    pub platform_chip_info: Option<String>,
    pub os_version: Option<String>,
    pub device_name: Option<String>,
}
