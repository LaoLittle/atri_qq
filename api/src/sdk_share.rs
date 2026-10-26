use atri_core::Operation;
use serde::{Deserialize, Serialize};

pub const SDK_SHARE_SERVICE: &str = "qq.sdk_share";

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

impl Operation for ShareMusicRequest {
    type Response = MusicShareReceipt;
    const SERVICE: &'static str = SDK_SHARE_SERVICE;
    const METHOD: &'static str = "share_music";
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
