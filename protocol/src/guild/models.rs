use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelInfo {
    pub id: u64,
    pub guild_id: u64,
    pub name: String,
    pub kind: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuildInfo {
    pub id: u64,
    pub number: Option<String>,
    pub name: String,
    pub channels: Vec<ChannelInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuildSnapshot {
    pub self_tiny_id: Option<u64>,
    pub push_result: Option<u32>,
    pub guilds: Vec<GuildInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemberInfo {
    pub tiny_id: u64,
    pub nickname: String,
    pub card: String,
    pub role: Option<i32>,
    pub role_ids: Vec<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GuildElement {
    Text {
        text: String,
    },
    Mention {
        tiny_id: Option<u64>,
        display: String,
        everyone: bool,
    },
    Opaque {
        field: u32,
        #[serde(with = "serde_bytes")]
        payload: Vec<u8>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuildMessage {
    pub guild_id: u64,
    pub channel_id: u64,
    pub sender_tiny_id: Option<u64>,
    pub sender_name: String,
    pub is_self: bool,
    pub sequence: Option<u64>,
    pub count_sequence: Option<u64>,
    pub random: Option<u64>,
    pub time: Option<u64>,
    pub elements: Vec<GuildElement>,
    #[serde(with = "serde_bytes")]
    pub raw: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GuildEvent {
    Message {
        message: GuildMessage,
    },
    Opaque {
        command: String,
        #[serde(with = "serde_bytes")]
        payload: Vec<u8>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SendReceipt {
    pub guild_id: u64,
    pub channel_id: u64,
    pub sequence: Option<u64>,
    pub time: Option<u64>,
    pub random: u64,
}
