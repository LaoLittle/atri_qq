use crate::{
    Error, Result,
    client::ServiceClient,
    contacts::{
        Args, GroupNotification, GroupNotificationType, Operations, check_code, required, value,
    },
    proto::admin,
};
use ciborium::Value;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

pub const ADMIN_METHODS: &[&str] = &[
    "group_rename",
    "remark_group",
    "mute_group_global",
    "mute_group_member",
    "group_set_special_title",
    "group_member_rename",
    "kick_group_member",
    "group_transfer",
    "group_remain_at_all",
    "group_quit",
    "set_group_reaction",
    "send_friend_nudge",
    "send_group_nudge",
    "group_recall_poke",
    "friend_recall_poke",
    "set_pin_friend",
    "set_pin_group",
    "set_group_todo",
    "get_group_todo",
    "finish_group_todo",
    "remove_group_todo",
    "group_clock_in",
    "set_group_notification",
];
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u64)]
pub enum GroupNotificationAction {
    Accept = 1,
    Reject = 2,
    Ignore = 3,
}
impl TryFrom<u64> for GroupNotificationAction {
    type Error = Error;
    fn try_from(value: u64) -> Result<Self> {
        match value {
            1 => Ok(Self::Accept),
            2 => Ok(Self::Reject),
            3 => Ok(Self::Ignore),
            _ => Err(Error::Malformed(
                "Notification action must be 1 (accept), 2 (reject), or 3 (ignore)".into(),
            )),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupAtAllQuota {
    pub can_at_all: bool,
    pub remaining_for_user: u32,
    pub remaining_for_group: u32,
    pub user_prompt: Vec<u8>,
    pub group_prompt: Vec<u8>,
    pub show_label: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupTodo {
    pub group_uin: u64,
    pub sequence: u64,
    pub random: u32,
    pub creator_uin: u64,
    pub creator_nickname: String,
    pub title: String,
    pub jump_url: String,
    pub icon_url: String,
    pub created_time: u32,
    pub app_name: String,
    pub app_id: u64,
    pub message_type: i32,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupTodoUser {
    pub group_uin: u64,
    pub sequence: u64,
    pub status: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupTodoResult {
    pub todo: GroupTodo,
    pub users: Vec<GroupTodoUser>,
    pub expiration_time: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupClockInResult {
    pub is_success: bool,
    pub title: String,
    pub keep_day_text: String,
    pub group_rank_text: String,
    pub clock_in_time: i64,
    pub detail_url: String,
}

pub struct Admin {
    operations: Arc<Operations>,
}
impl Admin {
    pub fn new(client: Arc<dyn ServiceClient>) -> Self {
        Self::from_operations(Arc::new(Operations::new(client)))
    }
    /// Shares the contact caches so mutations invalidate the same entries used by readers.
    pub fn from_operations(operations: Arc<Operations>) -> Self {
        Self { operations }
    }
    pub async fn group_rename(&self, group_uin: u64, name: &str) -> Result<()> {
        let request = admin::GroupInfoRequest {
            group_uin: Some(group_uin),
            info: Some(admin::GroupInfoUpdate {
                name: Some(name.into()),
                ..Default::default()
            }),
        };
        self.operations
            .oidb::<_, admin::Empty>(0x89a, 15, &request, 0)
            .await?;
        self.operations.invalidate(None, true).await;
        Ok(())
    }
    pub async fn remark_group(&self, group_uin: u64, remark: &str) -> Result<()> {
        let request = admin::GroupRemarkRequest {
            info: Some(admin::GroupRemark {
                group_uin: Some(group_uin),
                remark: Some(remark.into()),
            }),
        };
        let response: admin::GroupRemarkResponse =
            self.operations.oidb(0xf16, 1, &request, 0).await?;
        if let Some(result) = response.result {
            let code = result.code.unwrap_or_default() as i32;
            if code != 0 {
                return Err(Error::Server {
                    code,
                    message: "Group remark was rejected".into(),
                });
            }
        }
        self.operations.invalidate(None, true).await;
        Ok(())
    }
    pub async fn mute_group_global(&self, group_uin: u64, is_mute: bool) -> Result<bool> {
        let request = admin::GroupInfoRequest {
            group_uin: Some(group_uin),
            info: Some(admin::GroupInfoUpdate {
                mute_duration: Some(if is_mute { u32::MAX as u64 } else { 0 }),
                ..Default::default()
            }),
        };
        self.operations
            .oidb::<_, admin::Empty>(0x89a, 0, &request, 0)
            .await?;
        Ok(true)
    }
    pub async fn mute_group_member(
        &self,
        group_uin: u64,
        target_uin: u64,
        duration: u32,
    ) -> Result<bool> {
        let account = self.operations.identity().await;
        let uid = self
            .operations
            .resolve_uid(target_uin, Some(group_uin))
            .await?;
        let request = admin::MemberMuteRequest {
            group_uin: Some(group_uin),
            operation: Some(1),
            member: Some(admin::MemberMute {
                uid: Some(uid),
                duration: Some(duration as u64),
            }),
        };
        self.operations.check_identity(&account).await?;
        self.operations
            .oidb::<_, admin::Empty>(0x1253, 1, &request, 0)
            .await?;
        self.operations.invalidate(Some(group_uin), false).await;
        Ok(true)
    }
    pub async fn group_set_special_title(
        &self,
        group_uin: u64,
        target_uin: u64,
        title: &str,
    ) -> Result<()> {
        self.member_text(group_uin, target_uin, title, true).await
    }
    pub async fn group_member_rename(
        &self,
        group_uin: u64,
        target_uin: u64,
        name: &str,
    ) -> Result<()> {
        self.member_text(group_uin, target_uin, name, false).await
    }
    async fn member_text(
        &self,
        group_uin: u64,
        target_uin: u64,
        value: &str,
        special_title: bool,
    ) -> Result<()> {
        let account = self.operations.identity().await;
        let uid = self
            .operations
            .resolve_uid(target_uin, Some(group_uin))
            .await?;
        let request = admin::MemberTextRequest {
            group_uin: Some(group_uin),
            member: Some(admin::MemberText {
                uid: Some(uid),
                special_title: special_title.then(|| value.to_owned()),
                name: (!special_title).then(|| value.to_owned()),
            }),
        };
        self.operations.check_identity(&account).await?;
        self.operations
            .oidb::<_, admin::Empty>(0x8fc, if special_title { 2 } else { 3 }, &request, 0)
            .await?;
        self.operations.invalidate(Some(group_uin), false).await;
        Ok(())
    }
    pub async fn kick_group_member(
        &self,
        group_uin: u64,
        target_uin: u64,
        reject_add_request: bool,
        reason: &str,
    ) -> Result<bool> {
        let account = self.operations.identity().await;
        let uid = self
            .operations
            .resolve_uid(target_uin, Some(group_uin))
            .await?;
        let request = admin::KickMemberRequest {
            group_uin: Some(group_uin),
            uid: Some(uid),
            reject_add_request: Some(reject_add_request),
            reason: Some(reason.into()),
        };
        self.operations.check_identity(&account).await?;
        self.operations
            .oidb::<_, admin::Empty>(0x8a0, 1, &request, 0)
            .await?;
        self.operations.invalidate(Some(group_uin), true).await;
        Ok(true)
    }
    pub async fn group_transfer(&self, group_uin: u64, target_uin: u64) -> Result<bool> {
        let account = self.operations.identity().await;
        let response: admin::GroupTransferResponse = self
            .operations
            .oidb(
                0x89e,
                0,
                &admin::GroupTransferRequest {
                    group_uin: Some(group_uin),
                    owner_uin: Some(account.0),
                    target_uin: Some(target_uin),
                },
                0,
            )
            .await?;
        check_code(response.code, response.message)?;
        self.operations.invalidate(Some(group_uin), true).await;
        Ok(true)
    }
    pub async fn group_remain_at_all(&self, group_uin: u64) -> Result<GroupAtAllQuota> {
        let account = self.operations.identity().await;
        let response: admin::AtAllQuotaResponse = self
            .operations
            .oidb(
                0x8a7,
                0,
                &admin::AtAllQuotaRequest {
                    operation: Some(1),
                    version: Some(2),
                    query: Some(1),
                    user_uin: Some(account.0),
                    group_uin: Some(group_uin),
                },
                0,
            )
            .await?;
        Ok(GroupAtAllQuota {
            can_at_all: response.can_at_all.unwrap_or_default(),
            remaining_for_user: response.remaining_for_user.unwrap_or_default(),
            remaining_for_group: response.remaining_for_group.unwrap_or_default(),
            user_prompt: response.user_prompt.unwrap_or_default().to_vec(),
            group_prompt: response.group_prompt.unwrap_or_default().to_vec(),
            show_label: response.show_label.unwrap_or_default(),
        })
    }
    pub async fn group_quit(&self, group_uin: u64) -> Result<()> {
        self.operations
            .oidb::<_, admin::Empty>(
                0x1097,
                1,
                &admin::GroupQuitRequest {
                    group_uin: Some(group_uin),
                },
                0,
            )
            .await?;
        self.operations.invalidate(Some(group_uin), true).await;
        Ok(())
    }
    pub async fn set_group_reaction(
        &self,
        group_uin: u64,
        sequence: u64,
        code: &str,
        is_add: bool,
    ) -> Result<()> {
        let request = admin::GroupReactionRequest {
            group_uin: Some(group_uin),
            sequence: Some(sequence),
            code: Some(code.into()),
            reaction_type: Some(reaction_type(code)),
        };
        self.operations
            .oidb::<_, admin::Empty>(0x9082, if is_add { 1 } else { 2 }, &request, 0)
            .await?;
        Ok(())
    }
    pub async fn send_friend_nudge(&self, peer_uin: u64, target_uin: Option<u64>) -> Result<()> {
        let target = match target_uin {
            Some(target) => target,
            None => self.operations.identity().await.0,
        };
        self.operations
            .oidb::<_, admin::Empty>(
                0xed3,
                1,
                &admin::NudgeRequest {
                    target_uin: Some(target),
                    group_uin: Some(0),
                    peer_uin: Some(peer_uin),
                },
                0,
            )
            .await?;
        Ok(())
    }
    pub async fn send_group_nudge(&self, group_uin: u64, target_uin: u64) -> Result<()> {
        self.operations
            .oidb::<_, admin::Empty>(
                0xed3,
                1,
                &admin::NudgeRequest {
                    target_uin: Some(target_uin),
                    group_uin: Some(group_uin),
                    peer_uin: Some(0),
                },
                0,
            )
            .await?;
        Ok(())
    }
    pub async fn group_recall_poke(
        &self,
        group_uin: u64,
        message_sequence: u64,
        message_time: u64,
        tips_sequence_id: u64,
    ) -> Result<()> {
        self.recall_poke(
            true,
            group_uin,
            message_sequence,
            message_time,
            tips_sequence_id,
        )
        .await
    }
    pub async fn friend_recall_poke(
        &self,
        peer_uin: u64,
        message_sequence: u64,
        message_time: u64,
        tips_sequence_id: u64,
    ) -> Result<()> {
        self.recall_poke(
            false,
            peer_uin,
            message_sequence,
            message_time,
            tips_sequence_id,
        )
        .await
    }
    async fn recall_poke(
        &self,
        is_group: bool,
        peer_uin: u64,
        message_sequence: u64,
        message_time: u64,
        tips_sequence_id: u64,
    ) -> Result<()> {
        let uid = if is_group {
            rand::rng().random_range(7_580_000_000_000_000_000..7_580_099_999_999_999_999u64)
        } else {
            rand::rng().random_range(7_500_000_000_000_000_000..7_509_999_999_999_999_999u64)
        };
        let info = admin::RecallPokeInfo {
            peer_uin: Some(peer_uin),
            message_type: Some(5),
            sequence: Some(message_sequence),
            time: Some(message_time),
            uid: Some(uid),
            group_uid: is_group.then_some(uid),
        };
        let (friend, group) = if is_group {
            (None, Some(info))
        } else {
            (Some(info), None)
        };
        let request = admin::RecallPokeRequest {
            friend,
            group,
            tips: Some(admin::RecallPokeTips {
                message_type: Some(1061),
                sequence_id: Some(tips_sequence_id),
            }),
        };
        self.operations
            .oidb::<_, admin::Empty>(0xf51, 1, &request, 0)
            .await?;
        Ok(())
    }
    pub async fn set_pin_friend(&self, friend_uin: u64, is_pin: bool) -> Result<()> {
        let account = self.operations.identity().await;
        let mut friends = self.operations.fetch_friends(false).await?;
        if !friends.iter().any(|friend| friend.uin == friend_uin) {
            friends = self.operations.fetch_friends(true).await?;
        }
        let friend = friends
            .iter()
            .find(|friend| friend.uin == friend_uin)
            .ok_or_else(|| Error::Malformed("Cannot pin an unknown QQ friend".into()))?;
        self.operations.check_identity(&account).await?;
        self.set_pin(Some(&friend.uid), None, is_pin).await
    }
    pub async fn set_pin_group(&self, group_uin: u64, is_pin: bool) -> Result<()> {
        self.set_pin(None, Some(group_uin), is_pin).await
    }
    async fn set_pin(&self, uid: Option<&str>, group_uin: Option<u64>, is_pin: bool) -> Result<()> {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| Error::Malformed(error.to_string()))?
            .as_secs();
        let request = pin_request(uid, group_uin, is_pin, seconds);
        self.operations
            .oidb::<_, admin::Empty>(0x5d6, if group_uin.is_none() { 18 } else { 1 }, &request, 0)
            .await?;
        Ok(())
    }
    pub async fn set_group_notification(
        &self,
        group_uin: u64,
        sequence: u64,
        notification_type: GroupNotificationType,
        is_filtered: bool,
        action: GroupNotificationAction,
        message: &str,
    ) -> Result<()> {
        let request = admin::GroupNotificationRequest {
            action: Some(action as u64),
            info: Some(admin::GroupNotificationInfo {
                sequence: Some(sequence),
                notification_type: Some(notification_type.wire_value()),
                group_uin: Some(group_uin),
                message: Some(message.into()),
            }),
        };
        self.operations
            .oidb::<_, admin::Empty>(0x10c8, if is_filtered { 2 } else { 1 }, &request, 0)
            .await?;
        self.operations.invalidate(Some(group_uin), false).await;
        Ok(())
    }
    pub async fn respond_group_notification(
        &self,
        notification: &GroupNotification,
        action: GroupNotificationAction,
        message: &str,
    ) -> Result<()> {
        self.set_group_notification(
            notification.group_uin,
            notification.sequence,
            notification.r#type.clone(),
            notification.is_filtered,
            action,
            message,
        )
        .await
    }
    pub async fn set_group_todo(&self, group_uin: u64, sequence: u64) -> Result<()> {
        self.operations
            .oidb::<_, admin::Empty>(
                0xf90,
                1,
                &admin::SetGroupTodoRequest {
                    group_uin: Some(group_uin),
                    sequence: Some(sequence),
                },
                0,
            )
            .await?;
        Ok(())
    }
    pub async fn get_group_todo(&self, group_uin: u64) -> Result<GroupTodoResult> {
        let response: admin::GetGroupTodoResponse = self
            .operations
            .oidb(
                0xf8e,
                1,
                &admin::GetGroupTodoRequest {
                    group_uin: Some(group_uin),
                },
                0,
            )
            .await?;
        let info = required(response.info, "group todo information")?;
        let todo = GroupTodo {
            group_uin: info.group_uin.unwrap_or_default(),
            sequence: info.sequence.unwrap_or_default(),
            random: info.random.unwrap_or_default(),
            creator_uin: info.creator_uin.unwrap_or_default(),
            creator_nickname: info.creator_nickname.unwrap_or_default(),
            title: info.title.unwrap_or_default(),
            jump_url: info.jump_url.unwrap_or_default(),
            icon_url: info.icon_url.unwrap_or_default(),
            created_time: info.created_time.unwrap_or_default(),
            app_name: info.app_name.unwrap_or_default(),
            app_id: info.app_id.unwrap_or_default(),
            message_type: info.message_type.unwrap_or_default(),
        };
        let users = response
            .users
            .iter()
            .map(|row| GroupTodoUser {
                group_uin: row.group_uin.unwrap_or_default(),
                sequence: row.sequence.unwrap_or_default(),
                status: row.status.unwrap_or_default(),
            })
            .collect();
        Ok(GroupTodoResult {
            todo,
            users,
            expiration_time: response.expiration_time.unwrap_or_default(),
        })
    }
    pub async fn finish_group_todo(&self, group_uin: u64) -> Result<()> {
        self.operations
            .oidb::<_, admin::Empty>(
                0xf90,
                2,
                &admin::FinishGroupTodoRequest {
                    group_uin: Some(group_uin),
                },
                0,
            )
            .await?;
        Ok(())
    }
    pub async fn remove_group_todo(&self, group_uin: u64) -> Result<()> {
        self.operations
            .oidb::<_, admin::Empty>(
                0xf90,
                3,
                &admin::RemoveGroupTodoRequest {
                    group_uin: Some(group_uin),
                },
                0,
            )
            .await?;
        Ok(())
    }
    pub async fn group_clock_in(&self, group_uin: u64) -> Result<GroupClockInResult> {
        let state = self.operations.client.snapshot().await;
        // EB7 takes the decimal numeric UIN, not the opaque QQ UID.
        let request = admin::ClockInRequest {
            info: Some(admin::ClockInInfo {
                user_uin: Some(state.keystore.uin.to_string()),
                group_uin: Some(group_uin.to_string()),
                version: Some(state.profile.version.clone()),
            }),
        };
        let response: admin::ClockInResponse = self.operations.oidb(0xeb7, 1, &request, 0).await?;
        let write = required(response.write, "group clock-in response")?;
        if let Some(result) = write.result {
            check_code(result.code, result.message)?;
        }
        let done = required(write.details, "group clock-in details")?;
        let words = done.words;
        Ok(GroupClockInResult {
            is_success: true,
            title: done.title.unwrap_or_default(),
            keep_day_text: done.keep_day_text.unwrap_or_default(),
            group_rank_text: words.first().cloned().unwrap_or_default(),
            clock_in_time: words.get(1).and_then(|word| word.parse().ok()).unwrap_or(0),
            detail_url: done.detail_url.unwrap_or_default(),
        })
    }
    pub async fn call(&self, method: &str, args: Value) -> Result<Value> {
        let args = Args::new(&args)?;
        match method {
            "group_rename" => value(
                &self
                    .group_rename(args.u64("group_uin")?, args.string("name")?)
                    .await?,
            ),
            "remark_group" => value(
                &self
                    .remark_group(args.u64("group_uin")?, args.string("remark")?)
                    .await?,
            ),
            "mute_group_global" => value(
                &self
                    .mute_group_global(args.u64("group_uin")?, args.boolean("is_mute", true)?)
                    .await?,
            ),
            "mute_group_member" => value(
                &self
                    .mute_group_member(
                        args.u64("group_uin")?,
                        args.u64("target_uin")?,
                        args.u32("duration")?,
                    )
                    .await?,
            ),
            "group_set_special_title" => value(
                &self
                    .group_set_special_title(
                        args.u64("group_uin")?,
                        args.u64("target_uin")?,
                        args.string("title")?,
                    )
                    .await?,
            ),
            "group_member_rename" => value(
                &self
                    .group_member_rename(
                        args.u64("group_uin")?,
                        args.u64("target_uin")?,
                        args.string("name")?,
                    )
                    .await?,
            ),
            "kick_group_member" => value(
                &self
                    .kick_group_member(
                        args.u64("group_uin")?,
                        args.u64("target_uin")?,
                        args.boolean("reject_add_request", false)?,
                        args.optional_string("reason")?.unwrap_or(""),
                    )
                    .await?,
            ),
            "group_transfer" => value(
                &self
                    .group_transfer(args.u64("group_uin")?, args.u64("target_uin")?)
                    .await?,
            ),
            "group_remain_at_all" => {
                value(&self.group_remain_at_all(args.u64("group_uin")?).await?)
            }
            "group_quit" => value(&self.group_quit(args.u64("group_uin")?).await?),
            "set_group_reaction" => value(
                &self
                    .set_group_reaction(
                        args.u64("group_uin")?,
                        args.u64("sequence")?,
                        args.string("code")?,
                        args.boolean("is_add", true)?,
                    )
                    .await?,
            ),
            "send_friend_nudge" => value(
                &self
                    .send_friend_nudge(args.u64("peer_uin")?, args.optional_u64("target_uin")?)
                    .await?,
            ),
            "send_group_nudge" => value(
                &self
                    .send_group_nudge(args.u64("group_uin")?, args.u64("target_uin")?)
                    .await?,
            ),
            "group_recall_poke" => value(
                &self
                    .group_recall_poke(
                        args.u64("group_uin")?,
                        args.u64("message_sequence")?,
                        args.u64("message_time")?,
                        args.u64("tips_sequence_id")?,
                    )
                    .await?,
            ),
            "friend_recall_poke" => value(
                &self
                    .friend_recall_poke(
                        args.u64("peer_uin")?,
                        args.u64("message_sequence")?,
                        args.u64("message_time")?,
                        args.u64("tips_sequence_id")?,
                    )
                    .await?,
            ),
            "set_pin_friend" => value(
                &self
                    .set_pin_friend(args.u64("friend_uin")?, args.boolean("is_pin", true)?)
                    .await?,
            ),
            "set_pin_group" => value(
                &self
                    .set_pin_group(args.u64("group_uin")?, args.boolean("is_pin", true)?)
                    .await?,
            ),
            "set_group_notification" => value(
                &self
                    .set_group_notification(
                        args.u64("group_uin")?,
                        args.u64("sequence")?,
                        args.u64("type")?.into(),
                        args.boolean("is_filtered", false)?,
                        args.u64("action")?.try_into()?,
                        args.optional_string("message")?.unwrap_or(""),
                    )
                    .await?,
            ),
            "set_group_todo" => value(
                &self
                    .set_group_todo(args.u64("group_uin")?, args.u64("sequence")?)
                    .await?,
            ),
            "get_group_todo" => value(&self.get_group_todo(args.u64("group_uin")?).await?),
            "finish_group_todo" => value(&self.finish_group_todo(args.u64("group_uin")?).await?),
            "remove_group_todo" => value(&self.remove_group_todo(args.u64("group_uin")?).await?),
            "group_clock_in" => value(&self.group_clock_in(args.u64("group_uin")?).await?),
            _ => Err(Error::Unsupported(format!(
                "Unknown desktop administration operation: {method}"
            ))),
        }
    }
}
fn reaction_type(code: &str) -> u64 {
    if code.encode_utf16().count() <= 3 {
        1
    } else {
        2
    }
}
fn pin_request(
    uid: Option<&str>,
    group_uin: Option<u64>,
    is_pin: bool,
    seconds: u64,
) -> admin::PinRequest {
    admin::PinRequest {
        operation: Some(0),
        contact_type: Some(if group_uin.is_none() { 1 } else { 11 }),
        update: Some(admin::PinUpdate {
            uid: uid.map(str::to_owned),
            group_uin,
            item: Some(admin::PinItem {
                key: Some(if group_uin.is_none() { 13578 } else { 13569 }),
                timestamp: Some(if is_pin {
                    (seconds as u32).to_be_bytes().to_vec().into()
                } else {
                    Default::default()
                }),
            }),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        models::{Encryption, IncomingPacket, Keystore, Profile, RequestType, SessionState},
        proto::contacts::OidbEnvelope,
    };
    use bytes::Bytes;
    use prost::Message;
    use std::{collections::VecDeque, sync::Mutex, time::Duration};
    use tokio::sync::{RwLock, broadcast};

    struct ScriptedClient {
        state: RwLock<SessionState>,
        replies: Mutex<VecDeque<Bytes>>,
        requests: Mutex<Vec<(String, Bytes)>>,
        packets: broadcast::Sender<IncomingPacket>,
    }
    impl ScriptedClient {
        fn new(replies: Vec<Bytes>) -> Arc<Self> {
            let mut keystore = Keystore::default();
            keystore.uin = 42;
            keystore.uid = "u_self".into();
            Arc::new(Self {
                state: RwLock::new(SessionState {
                    profile: Profile::default(),
                    keystore,
                    platform: crate::models::PlatformState::Linux {
                        machine_id: "admin-test".into(),
                    },
                    online: true,
                }),
                replies: Mutex::new(
                    replies
                        .into_iter()
                        .map(|body| {
                            OidbEnvelope {
                                code: Some(0),
                                body: Some(body),
                                ..Default::default()
                            }
                            .encode_to_vec()
                            .into()
                        })
                        .collect(),
                ),
                requests: Mutex::new(Vec::new()),
                packets: broadcast::channel(4).0,
            })
        }
    }
    #[async_trait::async_trait]
    impl ServiceClient for ScriptedClient {
        async fn request(
            &self,
            command: &str,
            body: Bytes,
            request_type: RequestType,
            encryption: Encryption,
            timeout: Duration,
        ) -> Result<Bytes> {
            assert_eq!(request_type, RequestType::D2);
            assert_eq!(encryption, Encryption::D2);
            assert_eq!(timeout, Duration::from_secs(30));
            self.requests.lock().unwrap().push((command.into(), body));
            self.replies
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| Error::Malformed("Unexpected admin request".into()))
        }
        async fn snapshot(&self) -> SessionState {
            self.state.read().await.clone()
        }
        async fn replace_state(&self, state: SessionState) {
            *self.state.write().await = state;
        }
        fn subscribe(&self) -> broadcast::Receiver<IncomingPacket> {
            self.packets.subscribe()
        }
    }
    fn reply<M: Message>(body: M) -> Bytes {
        body.encode_to_vec().into()
    }
    fn captured<M: Message + Default>(request: &(String, Bytes), command: u32, service: u32) -> M {
        assert_eq!(request.0, format!("OidbSvcTrpcTcp.0x{command:x}_{service}"));
        let envelope = OidbEnvelope::decode(request.1.clone()).unwrap();
        assert_eq!(envelope.command, Some(command));
        assert_eq!(envelope.service, Some(service));
        M::decode(envelope.body.unwrap()).unwrap()
    }
    #[tokio::test]
    async fn mutation_requests_preserve_routes_and_explicit_defaults() {
        let client = ScriptedClient::new((0..6).map(|_| reply(admin::Empty {})).collect());
        let api = Admin::new(client.clone());
        api.group_rename(987, "").await.unwrap();
        api.mute_group_global(987, false).await.unwrap();
        api.set_group_reaction(987, 0, "😀😀", false).await.unwrap();
        api.send_friend_nudge(123, None).await.unwrap();
        api.send_group_nudge(987, 123).await.unwrap();
        api.set_group_notification(
            987,
            0,
            1u64.into(),
            true,
            GroupNotificationAction::Reject,
            "",
        )
        .await
        .unwrap();
        let requests = client.requests.lock().unwrap();
        assert_eq!(requests.len(), 6);
        let rename: admin::GroupInfoRequest = captured(&requests[0], 0x89a, 15);
        assert_eq!(rename.group_uin, Some(987));
        assert_eq!(rename.info.unwrap().name.as_deref(), Some(""));
        let mute: admin::GroupInfoRequest = captured(&requests[1], 0x89a, 0);
        let info = mute.info.unwrap();
        assert_eq!(info.mute_duration, Some(0));
        assert_eq!(info.name, None);
        let reaction: admin::GroupReactionRequest = captured(&requests[2], 0x9082, 2);
        assert_eq!(reaction.group_uin, Some(987));
        assert_eq!(reaction.sequence, Some(0));
        assert_eq!(reaction.code.as_deref(), Some("😀😀"));
        assert_eq!(reaction.reaction_type, Some(2));
        let friend: admin::NudgeRequest = captured(&requests[3], 0xed3, 1);
        assert_eq!(
            (friend.target_uin, friend.group_uin, friend.peer_uin),
            (Some(42), Some(0), Some(123))
        );
        let group: admin::NudgeRequest = captured(&requests[4], 0xed3, 1);
        assert_eq!(
            (group.target_uin, group.group_uin, group.peer_uin),
            (Some(123), Some(987), Some(0))
        );
        let notification: admin::GroupNotificationRequest = captured(&requests[5], 0x10c8, 2);
        assert_eq!(notification.action, Some(2));
        let info = notification.info.unwrap();
        assert_eq!(info.sequence, Some(0));
        assert_eq!(info.group_uin, Some(987));
        assert_eq!(info.message.as_deref(), Some(""));
    }
    #[tokio::test]
    async fn mutation_server_rejections_reach_admin_callers() {
        let client = ScriptedClient::new(vec![
            reply(admin::GroupRemarkResponse {
                result: Some(admin::GroupRemarkResult { code: Some(9) }),
            }),
            reply(admin::GroupTransferResponse {
                code: Some(12),
                message: Some("denied".into()),
            }),
        ]);
        let api = Admin::new(client.clone());
        assert!(matches!(
            api.remark_group(987, "remark").await,
            Err(Error::Server { code: 9, .. })
        ));
        assert!(matches!(api.group_transfer(987, 123).await,
            Err(Error::Server { code: 12, message }) if message == "denied"));
        let requests = client.requests.lock().unwrap();
        let remark: admin::GroupRemarkRequest = captured(&requests[0], 0xf16, 1);
        assert_eq!(remark.info.unwrap().remark.as_deref(), Some("remark"));
        let transfer: admin::GroupTransferRequest = captured(&requests[1], 0x89e, 0);
        assert_eq!(
            (transfer.group_uin, transfer.owner_uin, transfer.target_uin),
            (Some(987), Some(42), Some(123))
        );
    }
    #[tokio::test]
    async fn quota_todo_and_clock_results_cross_the_service_boundary() {
        let client = ScriptedClient::new(vec![
            reply(admin::AtAllQuotaResponse {
                can_at_all: Some(true),
                remaining_for_user: Some(2),
                remaining_for_group: Some(3),
                user_prompt: Some(Bytes::from_static(b"user")),
                group_prompt: Some(Bytes::from_static(b"group")),
                show_label: Some(false),
            }),
            reply(admin::GetGroupTodoResponse {
                info: Some(admin::GroupTodoInfo {
                    group_uin: Some(987),
                    sequence: Some(10),
                    title: Some("todo".into()),
                    message_type: Some(-1),
                    ..Default::default()
                }),
                users: vec![admin::GroupTodoUser {
                    group_uin: Some(987),
                    sequence: Some(10),
                    status: Some(0),
                }],
                expiration_time: Some(123),
            }),
            reply(admin::ClockInResponse {
                write: Some(admin::ClockInWrite {
                    result: Some(admin::ClockInStatus {
                        code: Some(0),
                        message: None,
                    }),
                    details: Some(admin::ClockInDetails {
                        title: Some("clock".into()),
                        keep_day_text: Some("day".into()),
                        words: vec!["rank".into(), "456".into()],
                        detail_url: Some("url".into()),
                    }),
                }),
            }),
        ]);
        let api = Admin::new(client.clone());
        assert_eq!(
            api.group_remain_at_all(987).await.unwrap(),
            GroupAtAllQuota {
                can_at_all: true,
                remaining_for_user: 2,
                remaining_for_group: 3,
                user_prompt: b"user".to_vec(),
                group_prompt: b"group".to_vec(),
                show_label: false,
            }
        );
        let todo = api.get_group_todo(987).await.unwrap();
        assert_eq!(
            (
                todo.todo.group_uin,
                todo.todo.sequence,
                todo.todo.message_type
            ),
            (987, 10, -1)
        );
        assert_eq!(todo.todo.title, "todo");
        assert_eq!(todo.todo.creator_nickname, "");
        assert_eq!(
            todo.users,
            vec![GroupTodoUser {
                group_uin: 987,
                sequence: 10,
                status: 0
            }]
        );
        assert_eq!(todo.expiration_time, 123);
        assert_eq!(
            api.group_clock_in(987).await.unwrap(),
            GroupClockInResult {
                is_success: true,
                title: "clock".into(),
                keep_day_text: "day".into(),
                group_rank_text: "rank".into(),
                clock_in_time: 456,
                detail_url: "url".into(),
            }
        );
        let requests = client.requests.lock().unwrap();
        let quota: admin::AtAllQuotaRequest = captured(&requests[0], 0x8a7, 0);
        assert_eq!(
            (
                quota.operation,
                quota.version,
                quota.query,
                quota.user_uin,
                quota.group_uin
            ),
            (Some(1), Some(2), Some(1), Some(42), Some(987))
        );
        let todo: admin::GetGroupTodoRequest = captured(&requests[1], 0xf8e, 1);
        assert_eq!(todo.group_uin, Some(987));
        let clock: admin::ClockInRequest = captured(&requests[2], 0xeb7, 1);
        let info = clock.info.unwrap();
        assert_eq!(info.user_uin.as_deref(), Some("42"));
        assert_eq!(info.group_uin.as_deref(), Some("987"));
        assert!(info.version.is_some());
    }
    #[tokio::test]
    async fn missing_nested_admin_responses_remain_malformed() {
        let client = ScriptedClient::new(vec![
            reply(admin::GetGroupTodoResponse::default()),
            reply(admin::ClockInResponse {
                write: Some(admin::ClockInWrite::default()),
            }),
        ]);
        let api = Admin::new(client);
        assert!(matches!(
            api.get_group_todo(987).await,
            Err(Error::Malformed(_))
        ));
        assert!(matches!(
            api.group_clock_in(987).await,
            Err(Error::Malformed(_))
        ));
    }
    #[test]
    fn reaction_type_counts_utf16_not_utf8_or_unicode_scalars() {
        assert_eq!(reaction_type("😀1"), 1);
        assert_eq!(reaction_type("😀😀"), 2);
        assert_eq!(reaction_type("123"), 1);
        assert_eq!(reaction_type("1234"), 2);
    }
    #[test]
    fn pin_uses_big_endian_wrapping_timestamp_and_distinct_friend_group_keys() {
        let request = pin_request(Some("u_friend"), None, true, 0x1_01020304);
        let request = admin::PinRequest::decode(request.encode_to_vec().as_slice()).unwrap();
        let update = request.update.as_ref().unwrap();
        let item = update.item.as_ref().unwrap();
        assert_eq!(update.uid.as_deref(), Some("u_friend"));
        assert_eq!(update.group_uin, None);
        assert_eq!(item.key, Some(13578));
        assert_eq!(item.timestamp.as_deref(), Some(&[1, 2, 3, 4][..]));
        assert_eq!(request.contact_type, Some(1));
        assert_eq!(request.operation, Some(0));
        let request = pin_request(None, Some(987), false, 123);
        let request = admin::PinRequest::decode(request.encode_to_vec().as_slice()).unwrap();
        let update = request.update.as_ref().unwrap();
        let item = update.item.as_ref().unwrap();
        assert_eq!(update.uid, None);
        assert_eq!(update.group_uin, Some(987));
        assert_eq!(item.key, Some(13569));
        assert_eq!(item.timestamp.as_deref(), Some(&[][..]));
        assert_eq!(request.contact_type, Some(11));
        assert_eq!(request.operation, Some(0));
    }
}
