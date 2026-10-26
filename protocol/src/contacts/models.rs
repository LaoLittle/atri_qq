use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Gender {
    Male,
    Female,
    Unknown(u64),
}
impl From<u64> for Gender {
    fn from(value: u64) -> Self {
        match value {
            1 => Self::Male,
            2 => Self::Female,
            other => Self::Unknown(other),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FriendCategory {
    pub id: i32,
    pub name: String,
    pub member_count: i32,
    pub sort_id: i32,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Friend {
    pub uin: u64,
    pub uid: String,
    pub nickname: String,
    pub remark: String,
    pub personal_sign: String,
    pub qid: String,
    pub age: i32,
    pub gender: Gender,
    pub category_id: i32,
    pub category: Option<FriendCategory>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FriendStatus {
    pub status: Option<u32>,
    pub reported_status: Option<u32>,
    pub extended_status: Option<u32>,
    pub battery_status: Option<u32>,
    pub terminal_type: Option<u32>,
    pub network_type: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FriendStatusSnapshot {
    pub statuses: std::collections::BTreeMap<String, FriendStatus>,
    pub interval_minutes: Option<u32>,
    pub received_unix_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Group {
    pub uin: u64,
    pub name: String,
    pub member_count: u32,
    pub max_member_count: u32,
    pub created_time: u32,
    pub description: Option<String>,
    pub question: Option<String>,
    pub announcement: Option<String>,
    pub remark: Option<String>,
    pub owner_uid: Option<String>,
    pub last_speak_time: u64,
    pub latest_sequence: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum GroupMemberPermission {
    Member,
    Owner,
    Admin,
    Unknown(u64),
}
impl From<u64> for GroupMemberPermission {
    fn from(value: u64) -> Self {
        match value {
            0 => Self::Member,
            1 => Self::Owner,
            2 => Self::Admin,
            other => Self::Unknown(other),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupMember {
    pub group_uin: u64,
    pub uin: u64,
    pub uid: String,
    pub nickname: String,
    pub permission: GroupMemberPermission,
    pub level: u32,
    pub card: Option<String>,
    pub special_title: Option<String>,
    pub join_time: u32,
    pub last_message_time: u32,
    pub mute_until: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Birthday {
    /// A zero year means the server did not disclose it.
    pub year: u16,
    pub month: u8,
    pub day: u8,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Stranger {
    pub uin: u64,
    /// Numeric lookup does not return a UID; never substitute a decimal UIN.
    pub uid: Option<String>,
    pub nickname: String,
    pub personal_sign: String,
    pub remark: String,
    pub level: u64,
    pub gender: Gender,
    pub registration_time: u64,
    pub birthday: Option<Birthday>,
    pub age: u64,
    pub qid: String,
    pub country: String,
    pub city: String,
    pub home_city: Option<String>,
    pub email: Option<String>,
    pub mobile_phone: Option<String>,
    pub district: Option<String>,
    pub school: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupExtra {
    pub latest_message_sequence: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StrangerGroupInfo {
    pub uin: u64,
    pub name: String,
    pub created_time: u32,
    pub member_count: u32,
    pub max_member_count: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperationUser {
    pub uin: u64,
    pub uid: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum GroupNotificationType {
    Join,
    SetAdmin,
    KickOther,
    KickSelf,
    Exit,
    UnsetAdmin,
    Invite,
    Unknown(u64),
}
impl From<u64> for GroupNotificationType {
    fn from(value: u64) -> Self {
        match value {
            1 => Self::Join,
            3 => Self::SetAdmin,
            6 => Self::KickOther,
            7 => Self::KickSelf,
            13 => Self::Exit,
            16 => Self::UnsetAdmin,
            22 => Self::Invite,
            other => Self::Unknown(other),
        }
    }
}
impl GroupNotificationType {
    pub fn wire_value(&self) -> u64 {
        match self {
            Self::Join => 1,
            Self::SetAdmin => 3,
            Self::KickOther => 6,
            Self::KickSelf => 7,
            Self::Exit => 13,
            Self::UnsetAdmin => 16,
            Self::Invite => 22,
            Self::Unknown(value) => *value,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum GroupNotificationState {
    Waiting,
    Accepted,
    Rejected,
    Ignored,
    Unknown(u64),
}
impl From<u64> for GroupNotificationState {
    fn from(value: u64) -> Self {
        match value {
            1 => Self::Waiting,
            2 => Self::Accepted,
            3 => Self::Rejected,
            4 => Self::Ignored,
            other => Self::Unknown(other),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupNotification {
    pub group_uin: u64,
    pub sequence: u64,
    pub r#type: GroupNotificationType,
    pub state: GroupNotificationState,
    pub target: OperationUser,
    pub inviter: Option<OperationUser>,
    pub operator_user: Option<OperationUser>,
    pub comment: String,
    pub is_filtered: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FriendRequest {
    pub target: OperationUser,
    pub source: OperationUser,
    pub state: u32,
    pub time: u32,
    pub comment: String,
    pub add_source: String,
    pub source_id: u32,
    pub source_sub_id: u32,
    pub is_initiator: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientKey {
    pub key: String,
    pub expiration: u32,
}
