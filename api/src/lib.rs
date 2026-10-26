pub mod guild;
pub mod media;
pub mod mini_app;
pub mod sdk_share;
pub mod signing;
pub use guild::GUILD_SERVICE;

use atri_core::Operation;
use serde::{Deserialize, Serialize};

pub const CONTACTS_SERVICE: &str = "qq.contacts";
pub const FRIENDS_METHOD: &str = "friends";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FriendInfo {
    pub uin: u64,
    pub uid: String,
    pub nickname: String,
    pub remark: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FriendsRequest {
    #[serde(default)]
    pub refresh: bool,
}

impl Operation for FriendsRequest {
    type Response = FriendsResponse;
    const SERVICE: &'static str = CONTACTS_SERVICE;
    const METHOD: &'static str = FRIENDS_METHOD;
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FriendsResponse {
    pub friends: Vec<FriendInfo>,
}
