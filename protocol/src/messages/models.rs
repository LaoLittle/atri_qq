use crate::media::{MediaConversation, MediaReference};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Conversation {
    Friend { uin: u64, uid: String },
    Group { uin: u64 },
    Temporary { uin: u64, uid: String, source: i64 },
}
impl Conversation {
    pub fn media_conversation(&self) -> Result<MediaConversation> {
        match self {
            Self::Friend { uid, .. } => Ok(MediaConversation::Friend { uid: uid.clone() }),
            Self::Group { uin } => Ok(MediaConversation::Group { uin: *uin }),
            Self::Temporary { .. } => Err(Error::Unsupported(
                "Desktop temporary-session sending is not supported".into(),
            )),
        }
    }
    pub(crate) fn received_media_conversation(&self) -> MediaConversation {
        match self {
            Self::Friend { uid, .. } | Self::Temporary { uid, .. } => {
                MediaConversation::Friend { uid: uid.clone() }
            }
            Self::Group { uin } => MediaConversation::Group { uin: *uin },
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mention {
    #[serde(default)]
    pub uin: u64,
    pub uid: Option<String>,
    pub display: String,
    #[serde(default)]
    pub is_everyone: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reply {
    pub sequences: Vec<u64>,
    /// Canonical private server sequence; `sequences` retains the wire client sequence.
    #[serde(default)]
    pub server_sequence: Option<u64>,
    pub message_id: u64,
    pub sender_uin: u64,
    pub sender_uid: String,
    pub time: u32,
    #[serde(default)]
    pub elements: Vec<Vec<u8>>,
}
impl Reply {
    pub fn reference_sequence(&self, conversation: &Conversation) -> Option<u64> {
        match conversation {
            Conversation::Group { .. } => self.sequences.first().copied(),
            _ => self.server_sequence,
        }
        .filter(|sequence| *sequence != 0)
    }

    pub fn with_preview(message: &Message) -> Result<Self> {
        let elements = message
            .elements
            .iter()
            .filter_map(|element| match element {
                MessageElement::Reply(_) | MessageElement::Opaque(_) => None,
                MessageElement::Voice(_) => Some(MessageElement::Text("[语音]".into())),
                MessageElement::File(file) => {
                    Some(MessageElement::Text(format!("[文件] {}", file.name)))
                }
                MessageElement::GroupFile(file) => {
                    Some(MessageElement::Text(format!("[群文件] {}", file.name)))
                }
                element => Some(element.clone()),
            })
            .collect::<Vec<_>>();
        let body = super::encode_elements(&elements, &[])?;
        let body: crate::proto::messages::MessageBody = crate::proto::decode(body.as_slice())?;
        let rich: crate::proto::messages::RichText = crate::proto::decode(body.rich_text)?;
        let mut reply = Self::from(message);
        reply.elements = rich
            .elems
            .into_iter()
            .map(|element| element.to_vec())
            .collect();
        Ok(reply)
    }

    pub fn preview(
        &self,
        conversation: &Conversation,
        own_uin: u64,
    ) -> Result<Vec<MessageElement>> {
        use prost::Message as _;
        let rich = crate::proto::messages::RichText {
            elems: self.elements.iter().cloned().map(Into::into).collect(),
            ..Default::default()
        };
        let body = crate::proto::messages::MessageBody {
            rich_text: rich.encode_to_vec().into(),
            ..Default::default()
        };
        Ok(super::decode_elements(&body.encode_to_vec(), conversation, own_uin)?.elements)
    }
}
impl From<&Message> for Reply {
    fn from(message: &Message) -> Self {
        Self {
            sequences: vec![message.reply_sequence()],
            server_sequence: (!matches!(message.conversation, Conversation::Group { .. }))
                .then_some(message.sequence)
                .filter(|sequence| *sequence != 0),
            message_id: message.message_id,
            sender_uin: message.sender_uin,
            sender_uid: message.sender_uid.clone(),
            time: message.time.clamp(0, u32::MAX as i64) as u32,
            elements: vec![],
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardReference {
    pub resource_id: String,
    pub light_app_json: Option<String>,
    #[serde(default)]
    pub count: usize,
    #[serde(default)]
    pub raw_element: Option<Vec<u8>>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupFileMessage {
    pub business_id: u32,
    pub file_id: String,
    pub name: String,
    pub size: u64,
    pub md5: String,
    #[serde(default)]
    pub raw_element: Vec<u8>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpaqueScope {
    Element,
    RichText,
    MessageBody,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpaqueElement {
    pub scope: OpaqueScope,
    pub field: u32,
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum MessageElement {
    Text(String),
    Mention(Mention),
    Reply(Reply),
    Image(MediaReference),
    Voice(MediaReference),
    Video(MediaReference),
    File(MediaReference),
    LightApp(String),
    Forward(ForwardReference),
    GroupFile(GroupFileMessage),
    Opaque(OpaqueElement),
}
/// Decoded semantic content and separately retained, non-rendering protocol fields.
#[derive(Debug, Clone, Default)]
pub struct DecodedElements {
    pub elements: Vec<MessageElement>,
    pub metadata: Vec<OpaqueElement>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub conversation: Conversation,
    pub sender_uin: u64,
    pub sender_uid: String,
    #[serde(default)]
    pub recipient_uin: u64,
    #[serde(default)]
    pub recipient_uid: String,
    #[serde(default)]
    pub sender_name: String,
    /// Server message sequence. Zero means unavailable in the send acknowledgement.
    pub sequence: u64,
    /// Local request sequence for sent messages, distinct from the server's field 14.
    pub client_sequence: u64,
    pub message_id: u64,
    pub random: u32,
    /// Unix seconds from the server. Zero means unavailable in the send acknowledgement.
    pub time: i64,
    #[serde(default)]
    pub is_self: bool,
    pub is_bot: Option<bool>,
    pub elements: Vec<MessageElement>,
    #[serde(default)]
    pub metadata: Vec<OpaqueElement>,
    #[serde(default)]
    pub raw: Vec<u8>,
}
impl Message {
    /// Restore canonical private-message sequences from retained wire data.
    pub fn normalize_identity(&mut self) {
        if matches!(self.conversation, Conversation::Group { .. }) || self.raw.is_empty() {
            return;
        }
        let Ok(message) =
            crate::proto::decode::<crate::proto::messages::CommonMessage>(self.raw.as_slice())
        else {
            return;
        };
        if let Some(head) = message.content_head
            && let Some(sequence) = head.client_sequence.filter(|sequence| *sequence != 0)
        {
            self.sequence = sequence;
            self.client_sequence = head.sequence.unwrap_or_default();
        }
    }
    pub fn reply_sequence(&self) -> u64 {
        if !matches!(self.conversation, Conversation::Group { .. }) && self.client_sequence != 0 {
            self.client_sequence
        } else {
            self.sequence
        }
    }
    /// A server tombstone retains its message identity but has no semantic body.
    pub fn is_recalled(&self) -> bool {
        use crate::proto::messages as pb;
        if self.sequence == 0
            || self.raw.is_empty()
            || self
                .elements
                .iter()
                .any(|element| !matches!(element, MessageElement::Text(text) if text.is_empty()))
        {
            return false;
        }
        let Ok(message) = crate::proto::decode::<pb::CommonMessage>(self.raw.as_slice()) else {
            return false;
        };
        let Some(head) = message.content_head else {
            return false;
        };
        if message.routing_head.is_none()
            || (if matches!(self.conversation, Conversation::Group { .. }) {
                head.sequence
            } else {
                head.client_sequence
                    .filter(|sequence| *sequence != 0)
                    .or(head.sequence)
            }) != Some(self.sequence)
            || !matches!(head.message_type, Some(82 | 166 | 141))
        {
            return false;
        }
        let Ok(body) = crate::proto::decode::<pb::MessageBody>(message.message_body) else {
            return false;
        };
        body.content.is_none() && body.encrypted_content.is_none()
    }
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RoamDirection {
    Upwards,
    #[default]
    Downwards,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoamPage {
    pub peer_uid: String,
    pub is_complete: bool,
    pub time: u32,
    pub random: u32,
    pub messages: Vec<Message>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PushEvent {
    Message {
        message: Message,
    },
    Recall {
        conversation: Conversation,
        sequence: u64,
        random: Option<u32>,
        time: Option<u32>,
        author_uid: String,
        operator_uid: Option<String>,
        tip: String,
    },
    Poke {
        group_uin: Option<u64>,
        actor_uin: Option<u64>,
        target_uin: Option<u64>,
        parameters: BTreeMap<String, String>,
        raw: Vec<u8>,
    },
    Reaction {
        group_uin: u64,
        sequence: u64,
        operator_uid: String,
        added: bool,
        code: String,
        count: u32,
    },
    Membership {
        group_uin: u64,
        member_uid: String,
        operator_uid: Option<String>,
        joined: bool,
        change_type: u32,
        is_self: bool,
    },
    Essence {
        group_uin: u64,
        sequence: u64,
        random: u32,
        enabled: bool,
        author_uin: u64,
        operator_uin: u64,
        time: u32,
    },
    FriendRequest {
        source_uid: String,
        source_uin: u64,
        target_uid: String,
        message: String,
        source: String,
        raw: Vec<u8>,
    },
    GroupJoinRequest {
        group_uin: u64,
        target_uid: String,
        request_type: u64,
        comment: String,
        raw: Vec<u8>,
    },
    GroupInvitation {
        group_uin: u64,
        target_uid: String,
        inviter_uid: String,
        raw: Vec<u8>,
    },
    Opaque {
        command: String,
        message_type: Option<u64>,
        sub_type: Option<u64>,
        payload: Vec<u8>,
    },
}
