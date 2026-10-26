mod announcements;
pub use announcements::{AnnouncementPicture, GroupAnnouncement};
mod models;
pub use models::*;
pub(crate) mod robot_ranges;
pub use robot_ranges::{RobotUinRange, RobotUinRangesCache, RobotUinRangesSnapshot};

use crate::{
    Error, Result,
    client::ServiceClient,
    models::{Encryption, RequestType},
    proto::{contacts as protocol, decode},
};
use ciborium::Value;
use prost::Message;
use serde::Serialize;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
    time::Duration,
};
use tokio::sync::Mutex;

pub const CONTACT_METHODS: &[&str] = &[
    "friends",
    "friend_statuses",
    "categories",
    "groups",
    "members",
    "stranger",
    "resolve_uid",
    "resolve_uin",
    "group_extra",
    "stranger_group_info",
    "group_notifications",
    "filtered_group_notifications",
    "friend_requests",
    "cookies",
    "client_key",
    "set_status",
    "set_custom_status",
];

#[derive(Default)]
struct Cache {
    account: Option<(u64, String)>,
    friends: Option<Vec<Friend>>,
    groups: Option<Vec<Group>>,
    members: HashMap<u64, Vec<GroupMember>>,
    categories: BTreeMap<i32, FriendCategory>,
    uid_by_uin: HashMap<u64, String>,
    uin_by_uid: HashMap<String, u64>,
}
impl Cache {
    fn account(&mut self, account: &(u64, String)) {
        if self.account.as_ref() != Some(account) {
            *self = Self {
                account: Some(account.clone()),
                ..Self::default()
            };
        }
    }
    fn remember(&mut self, uin: u64, uid: &str) {
        if uin == 0 || uid.is_empty() {
            return;
        }
        if let Some(old) = self.uid_by_uin.insert(uin, uid.to_owned()) {
            if old != uid {
                self.uin_by_uid.remove(&old);
            }
        }
        if let Some(old) = self.uin_by_uid.insert(uid.to_owned(), uin) {
            if old != uin {
                self.uid_by_uin.remove(&old);
            }
        }
    }
}

pub(crate) struct CookieBatch {
    pub(crate) values: BTreeMap<String, String>,
    pub(crate) expirations: BTreeMap<String, u64>,
}

/// Desktop NT operations. Requests are awaited by the caller; no detached work is spawned.
pub struct Operations {
    pub(crate) client: Arc<dyn ServiceClient>,
    cache: Mutex<Cache>,
}
impl Operations {
    pub fn new(client: Arc<dyn ServiceClient>) -> Self {
        Self {
            client,
            cache: Mutex::new(Cache::default()),
        }
    }
    pub(crate) async fn identity(&self) -> (u64, String) {
        let state = self.client.snapshot().await;
        (state.keystore.uin, state.keystore.uid)
    }
    pub(crate) async fn check_identity(&self, account: &(u64, String)) -> Result<()> {
        if self.identity().await != *account {
            return Err(Error::Authentication(
                "QQ account changed during an operation".into(),
            ));
        }
        Ok(())
    }
    pub(crate) async fn request<
        Q: Message,
        R: Message + Default + prost::Name + std::fmt::Debug,
    >(
        &self,
        command: &str,
        body: &Q,
    ) -> Result<R> {
        let account = self.identity().await;
        let bytes = self
            .client
            .request(
                command,
                body.encode_to_vec().into(),
                RequestType::D2,
                Encryption::D2,
                Duration::from_secs(30),
            )
            .await?;
        self.check_identity(&account).await?;
        crate::diagnostics::decode_response(command, bytes)
    }
    pub(crate) async fn oidb<Q: Message, R: Message + Default + prost::Name + std::fmt::Debug>(
        &self,
        command: u32,
        service: u32,
        body: &Q,
        reserved: u32,
    ) -> Result<R> {
        let envelope = protocol::OidbEnvelope {
            command: Some(command),
            service: Some(service),
            reserved: Some(reserved),
            body: Some(body.encode_to_vec().into()),
            ..Default::default()
        };
        let response: protocol::OidbEnvelope = self
            .request(
                &format!("OidbSvcTrpcTcp.0x{command:x}_{service}"),
                &envelope,
            )
            .await?;
        check_code(response.code, response.message)?;
        crate::diagnostics::decode_response(
            &format!("OidbSvcTrpcTcp.0x{command:x}_{service}"),
            response.body.unwrap_or_default(),
        )
    }
    pub(crate) async fn invalidate(&self, group_uin: Option<u64>, groups: bool) {
        let mut cache = self.cache.lock().await;
        let account = self.identity().await;
        cache.account(&account);
        if let Some(group) = group_uin {
            cache.members.remove(&group);
        }
        if groups {
            cache.groups = None;
        }
    }
    pub async fn resolve_uid(&self, uin: u64, group_uin: Option<u64>) -> Result<String> {
        let account = self.identity().await;
        if account.0 == uin && !account.1.is_empty() {
            return Ok(account.1);
        }
        {
            let mut cache = self.cache.lock().await;
            self.check_identity(&account).await?;
            cache.account(&account);
            if let Some(uid) = cache.uid_by_uin.get(&uin) {
                return Ok(uid.clone());
            }
        }
        if let Some(group) = group_uin {
            self.fetch_members(group, true).await?;
        } else {
            self.fetch_friends(false).await?;
        }
        let cache = self.cache.lock().await;
        self.check_identity(&account).await?;
        cache
            .uid_by_uin
            .get(&uin)
            .cloned()
            .ok_or_else(|| Error::Malformed(format!("No QQ UID resolved for UIN {uin}")))
    }
    pub async fn resolve_uin(&self, uid: &str) -> Result<u64> {
        if uid.is_empty() {
            return Err(Error::Malformed("Cannot resolve an empty QQ UID".into()));
        }
        let account = self.identity().await;
        if account.1 == uid {
            return Ok(account.0);
        }
        {
            let mut cache = self.cache.lock().await;
            self.check_identity(&account).await?;
            cache.account(&account);
            if let Some(uin) = cache.uin_by_uid.get(uid) {
                return Ok(*uin);
            }
        }
        let stranger = self.fetch_stranger_uid(uid).await?;
        self.check_identity(&account).await?;
        Ok(stranger.uin)
    }
    pub async fn fetch_friends(&self, refresh: bool) -> Result<Vec<Friend>> {
        let account = self.identity().await;
        let mut cache = self.cache.lock().await;
        self.check_identity(&account).await?;
        cache.account(&account);
        if !refresh {
            if let Some(friends) = &cache.friends {
                return Ok(friends.clone());
            }
        }
        let mut rows = Vec::new();
        let mut categories = BTreeMap::new();
        let mut cookie = None;
        let mut seen = HashSet::new();
        loop {
            self.check_identity(&account).await?;
            // This is a full pull: no persisted server sequence is available.
            let request = protocol::FriendListRequest {
                count: Some(300),
                time: None,
                local_sequence: Some(0),
                cookie: cookie.clone(),
                flags: Some(1),
                proxy_sequence: Some(0),
                selections: vec![
                    protocol::FriendPropertySelection {
                        kind: Some(1),
                        keys: Some(protocol::PropertyKeys {
                            keys: vec![103, 102, 20002, 27394, 20009, 20037],
                        }),
                    },
                    protocol::FriendPropertySelection {
                        kind: Some(4),
                        keys: Some(protocol::PropertyKeys {
                            keys: vec![100, 101, 102],
                        }),
                    },
                ],
                keys: vec![13578, 13579, 13573, 13572, 13568],
                extra_keys: vec![4051],
            };
            let response: protocol::FriendListResponse = self.oidb(0xfd4, 1, &request, 0).await?;
            rows.extend(response.friends);
            for row in response.categories {
                let category = FriendCategory {
                    id: row.id.unwrap_or_default() as i32,
                    name: row.name.unwrap_or_default(),
                    member_count: row.member_count.unwrap_or_default() as i32,
                    sort_id: row.sort_id.unwrap_or_default() as i32,
                };
                categories.insert(category.id, category);
            }
            if response.finished.unwrap_or_default() != 0 {
                break;
            }
            cookie = next_cookie(response.cookie, &mut seen, "Friend")?;
            if cookie.is_none() {
                break;
            }
        }
        let result = rows
            .iter()
            .map(|row| decode_friend(row, &categories))
            .collect::<Result<Vec<_>>>()?;
        self.check_identity(&account).await?;
        for friend in &result {
            cache.remember(friend.uin, &friend.uid);
        }
        cache.categories = categories;
        cache.friends = Some(result.clone());
        Ok(result)
    }
    pub async fn fetch_friend_categories(&self, refresh: bool) -> Result<Vec<FriendCategory>> {
        let account = self.identity().await;
        self.fetch_friends(refresh).await?;
        let cache = self.cache.lock().await;
        self.check_identity(&account).await?;
        let mut result: Vec<_> = cache.categories.values().cloned().collect();
        result.sort_by_key(|category| (category.sort_id, category.id));
        Ok(result)
    }
    pub async fn fetch_groups(&self, refresh: bool) -> Result<Vec<Group>> {
        let account = self.identity().await;
        let mut cache = self.cache.lock().await;
        self.check_identity(&account).await?;
        cache.account(&account);
        if !refresh {
            if let Some(groups) = &cache.groups {
                return Ok(groups.clone());
            }
        }
        let request = protocol::GroupListRequest {
            selection: Some(protocol::GroupListSelection {
                info: Some(protocol::GroupInfoMask {
                    owner: Some(1),
                    created_time: Some(1),
                    capacity: Some(1),
                    count: Some(1),
                    name: Some(1),
                    field8: Some(1),
                    field9: Some(1),
                    field10: Some(1),
                    field11: Some(1),
                    field12: Some(1),
                    field13: Some(1),
                    field14: Some(1),
                    field15: Some(1),
                    field16: Some(1),
                    field17: Some(1),
                    description: Some(1),
                    question: Some(1),
                    field20: Some(1),
                    field22: Some(1),
                    field23: Some(1),
                    field24: Some(1),
                    field25: Some(1),
                    field26: Some(1),
                    field27: Some(1),
                    field28: Some(1),
                    field29: Some(1),
                    announcement: Some(1),
                    field31: Some(1),
                    field32: Some(1),
                    field5001: Some(1),
                    field5002: Some(1),
                    field5003: Some(1),
                }),
                custom: Some(protocol::GroupCustomMask {
                    last_speak_time: Some(1),
                    field2: Some(1),
                    remark: Some(1),
                    field4: Some(1),
                    latest_sequence: Some(1),
                    field6: Some(1),
                    field7: Some(1),
                    field8: Some(1),
                }),
                extra: Some(protocol::GroupExtraMask {
                    field5: Some(1),
                    field6: Some(1),
                }),
            }),
        };
        let response: protocol::GroupListResponse = self.oidb(0xfe5, 2, &request, 0).await?;
        let result = response
            .groups
            .into_iter()
            .map(|row| {
                let info = required(row.info, "group information")?;
                let custom = row.custom.unwrap_or_default();
                Ok(Group {
                    uin: row.uin.unwrap_or_default(),
                    name: info.name.unwrap_or_default(),
                    member_count: info.member_count.unwrap_or_default() as u32,
                    max_member_count: info.max_member_count.unwrap_or_default() as u32,
                    created_time: info.created_time.unwrap_or_default() as u32,
                    description: info.description,
                    question: info.question,
                    announcement: info.announcement,
                    remark: custom.remark,
                    owner_uid: info.owner.and_then(|v| v.uid),
                    last_speak_time: custom.last_speak_time.unwrap_or_default(),
                    latest_sequence: custom.latest_sequence.unwrap_or_default() as u32,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        self.check_identity(&account).await?;
        cache.groups = Some(result.clone());
        Ok(result)
    }
    pub async fn fetch_members(&self, group_uin: u64, refresh: bool) -> Result<Vec<GroupMember>> {
        let account = self.identity().await;
        let mut cache = self.cache.lock().await;
        self.check_identity(&account).await?;
        cache.account(&account);
        if !refresh {
            if let Some(members) = cache.members.get(&group_uin) {
                return Ok(members.clone());
            }
        }
        let fields = protocol::MemberMask {
            nickname: Some(1),
            card: Some(1),
            level: Some(1),
            field13: Some(1),
            field16: Some(1),
            title: Some(1),
            field18: Some(1),
            field20: Some(1),
            field21: Some(1),
            join_time: Some(1),
            last_message_time: Some(1),
            mute_until: Some(1),
            field103: Some(1),
            field104: Some(1),
            field105: Some(1),
            field106: Some(1),
            permission: Some(1),
            field200: Some(1),
            field201: Some(1),
        };
        let mut result = Vec::new();
        let mut cookie = None;
        let mut seen = HashSet::new();
        loop {
            self.check_identity(&account).await?;
            let request = protocol::MemberListRequest {
                group_uin: Some(group_uin),
                count: Some(5),
                version: Some(2),
                fields: Some(fields.clone()),
                cookie: cookie.clone(),
            };
            let response: protocol::MemberListResponse = self.oidb(0xfe7, 3, &request, 0).await?;
            if response.group_uin.unwrap_or_default() != 0 && response.group_uin != Some(group_uin)
            {
                return Err(Error::Malformed(
                    "Member response belongs to a different group".into(),
                ));
            }
            for row in response.members {
                let identity = required(row.identity, "group member identity")?;
                let uid = nonempty(identity.uid, "Group member has no QQ UID")?;
                result.push(GroupMember {
                    group_uin,
                    uin: identity.uin.unwrap_or_default(),
                    uid,
                    nickname: row.nickname.unwrap_or_default(),
                    permission: row.permission.unwrap_or_default().into(),
                    level: row.level.and_then(|v| v.level).unwrap_or_default() as u32,
                    card: row.card.map(decode_member_card).transpose()?.flatten(),
                    special_title: row.special_title,
                    join_time: row.join_time.unwrap_or_default() as u32,
                    last_message_time: row.last_message_time.unwrap_or_default() as u32,
                    mute_until: row.mute_until.unwrap_or_default() as u32,
                });
            }
            cookie = next_cookie(response.cookie, &mut seen, "Member")?;
            if cookie.is_none() {
                break;
            }
        }
        self.check_identity(&account).await?;
        for member in &result {
            cache.remember(member.uin, &member.uid);
        }
        cache.members.insert(group_uin, result.clone());
        Ok(result)
    }
    pub async fn fetch_stranger_uin(&self, uin: u64) -> Result<Stranger> {
        let account = self.identity().await;
        let uid = {
            let mut cache = self.cache.lock().await;
            self.check_identity(&account).await?;
            cache.account(&account);
            cache.uid_by_uin.get(&uin).cloned()
        };
        self.fetch_stranger(
            protocol::StrangerUinRequest {
                uin: Some(uin),
                keys: Some(stranger_keys()),
            },
            uid,
            1,
            account,
        )
        .await
    }
    pub async fn fetch_stranger_uid(&self, uid: &str) -> Result<Stranger> {
        if uid.is_empty() {
            return Err(Error::Malformed("Cannot look up an empty QQ UID".into()));
        }
        let request = protocol::StrangerUidRequest {
            uid: Some(uid.into()),
            keys: Some(stranger_keys()),
        };
        self.fetch_stranger(request, Some(uid.to_owned()), 0, self.identity().await)
            .await
    }
    async fn fetch_stranger<Q: Message>(
        &self,
        request: Q,
        uid: Option<String>,
        reserved: u32,
        account: (u64, String),
    ) -> Result<Stranger> {
        let response: protocol::StrangerResponse = self.oidb(0xfe1, 2, &request, reserved).await?;
        let body = required(response.body, "stranger body")?;
        let properties = required(body.properties, "stranger properties")?;
        let mut numbers = HashMap::new();
        let mut bytes = HashMap::new();
        for property in properties.numbers {
            numbers.insert(
                property.key.unwrap_or_default(),
                property.value.unwrap_or_default(),
            );
        }
        for property in properties.bytes {
            bytes.insert(
                property.key.unwrap_or_default(),
                property.value.unwrap_or_default(),
            );
        }
        let string = |key| {
            bytes
                .get(&key)
                .and_then(|v| std::str::from_utf8(v).ok())
                .map(str::to_owned)
        };
        let number = |key| numbers.get(&key).copied().unwrap_or(0);
        let nickname = string(20002)
            .ok_or_else(|| Error::Malformed("Stranger nickname was not returned".into()))?;
        let birthday = bytes
            .get(&20031)
            .filter(|v| !v.is_empty())
            .map(|data| decode_birthday(data))
            .transpose()?
            .flatten();
        let uin = body.uin.unwrap_or_default();
        if uin == 0 {
            return Err(Error::Malformed(
                "Stranger response has no numeric QQ UIN".into(),
            ));
        }
        self.check_identity(&account).await?;
        if let Some(uid) = &uid {
            let mut cache = self.cache.lock().await;
            self.check_identity(&account).await?;
            cache.account(&account);
            cache.remember(uin, uid);
        }
        Ok(Stranger {
            uin,
            uid,
            nickname,
            personal_sign: string(102).unwrap_or_default(),
            remark: string(103).unwrap_or_default(),
            level: number(105),
            gender: number(20009).into(),
            registration_time: number(20026),
            birthday,
            age: number(20037),
            qid: string(27394).unwrap_or_default(),
            country: string(20003).unwrap_or_default(),
            city: string(20004).unwrap_or_default(),
            home_city: string(20006),
            email: string(20011),
            mobile_phone: string(20016),
            district: string(20020),
            school: string(20021).or_else(|| string(200021)),
        })
    }
    pub async fn fetch_group_extra(&self, group_uin: u64) -> Result<GroupExtra> {
        let request = protocol::GroupDetailRequest {
            random: Some(rand::random::<u64>() % i64::MAX as u64),
            query: Some(protocol::GroupDetailQuery {
                group_uin: Some(group_uin),
                fields: Some(protocol::GroupDetailMask {
                    latest_sequence: Some(1),
                    ..Default::default()
                }),
            }),
        };
        let response: protocol::GroupDetailResponse = self.oidb(0x88d, 0, &request, 0).await?;
        let info = required(
            response.results.into_iter().next(),
            "group extra information",
        )?;
        check_code(info.code, response.message)?;
        Ok(GroupExtra {
            latest_message_sequence: required(info.info, "group extra result")?
                .latest_sequence
                .unwrap_or_default(),
        })
    }
    pub async fn fetch_stranger_group_info(&self, group_uin: u64) -> Result<StrangerGroupInfo> {
        let request = protocol::GroupDetailRequest {
            random: Some(rand::random::<u32>() as u64 % i32::MAX as u64),
            query: Some(protocol::GroupDetailQuery {
                group_uin: Some(group_uin),
                fields: Some(protocol::GroupDetailMask {
                    created_time: Some(0),
                    max_member_count: Some(0),
                    member_count: Some(0),
                    uin: Some(0),
                    name: Some(bytes::Bytes::new()),
                    ..Default::default()
                }),
            }),
        };
        let response: protocol::GroupDetailResponse = self.oidb(0x88d, 110, &request, 0).await?;
        let result = response.results.into_iter().next().ok_or_else(|| {
            Error::Malformed(
                response
                    .message
                    .clone()
                    .unwrap_or_else(|| "Group information was not returned".into()),
            )
        })?;
        check_code(result.code, response.message)?;
        let info = required(result.info, "stranger group information")?;
        Ok(StrangerGroupInfo {
            uin: info
                .uin
                .unwrap_or_else(|| result.group_uin.unwrap_or_default()),
            name: info.name.unwrap_or_default(),
            created_time: info.created_time.unwrap_or_default() as u32,
            member_count: info.member_count.unwrap_or_default() as u32,
            max_member_count: info.max_member_count.unwrap_or_default() as u32,
        })
    }
    pub async fn fetch_group_notifications(
        &self,
        count: u64,
        start: u64,
    ) -> Result<Vec<GroupNotification>> {
        self.fetch_notifications(count, start, false).await
    }
    pub async fn fetch_filtered_group_notifications(
        &self,
        count: u64,
        start: u64,
    ) -> Result<Vec<GroupNotification>> {
        self.fetch_notifications(count, start, true).await
    }
    async fn notification_user(
        &self,
        message: protocol::NotificationUser,
    ) -> Result<OperationUser> {
        let uid = nonempty(message.uid, "Notification user has no QQ UID")?;
        Ok(OperationUser {
            uin: self.resolve_uin(&uid).await?,
            uid,
        })
    }
    async fn fetch_notifications(
        &self,
        count: u64,
        start: u64,
        filtered: bool,
    ) -> Result<Vec<GroupNotification>> {
        let account = self.identity().await;
        let response: protocol::NotificationListResponse = self
            .oidb(
                0x10c0,
                if filtered { 2 } else { 1 },
                &protocol::NotificationListRequest {
                    count: Some(count),
                    start: Some(start),
                },
                0,
            )
            .await?;
        let mut result = Vec::new();
        for row in response.notifications {
            let group = required(row.group, "notification group")?;
            let target = self
                .notification_user(required(row.target, "notification target")?)
                .await?;
            let inviter = match row.inviter {
                Some(user) => Some(self.notification_user(user).await?),
                None => None,
            };
            let operator_user = match row.operator {
                Some(user) => Some(self.notification_user(user).await?),
                None => None,
            };
            result.push(GroupNotification {
                group_uin: group.uin.unwrap_or_default(),
                sequence: row.sequence.unwrap_or_default(),
                r#type: row.r#type.unwrap_or_default().into(),
                state: row.state.unwrap_or_default().into(),
                target,
                inviter,
                operator_user,
                comment: row.comment.unwrap_or_default(),
                is_filtered: filtered,
            });
        }
        self.check_identity(&account).await?;
        Ok(result)
    }
    pub async fn fetch_friend_requests(&self) -> Result<Vec<FriendRequest>> {
        let account = self.identity().await;
        if account.1.is_empty() {
            return Err(Error::Authentication(
                "Friend requests require the account's QQ UID".into(),
            ));
        }
        let mut result = Vec::new();
        let mut index = 0u32;
        let mut sequence = 0u32;
        loop {
            self.check_identity(&account).await?;
            let request = protocol::FriendRequestsRequest {
                mode: Some(1),
                sequence: (sequence != 0).then_some(sequence),
                r#type: Some(6),
                uid: Some(account.1.clone()),
                index: Some(index as u64),
                count: Some(80),
                version: Some(2),
                flags: Some(0),
                field12: Some(1),
                field22: Some(1),
            };
            let response: protocol::FriendRequestsResponse =
                self.oidb(0x5cf, 11, &request, 0).await?;
            check_code(response.code, response.error.and_then(|v| v.message))?;
            let success = required(response.success, "friend request list")?;
            let rows = success.requests;
            for row in &rows {
                let target_uid = nonempty(row.target_uid.clone(), "Friend request has no QQ UID")?;
                let source_uid = nonempty(row.source_uid.clone(), "Friend request has no QQ UID")?;
                let target = OperationUser {
                    uin: self.resolve_uin(&target_uid).await?,
                    uid: target_uid,
                };
                let source = OperationUser {
                    uin: self.resolve_uin(&source_uid).await?,
                    uid: source_uid,
                };
                result.push(FriendRequest {
                    target,
                    source,
                    state: row.state.unwrap_or_default() as u32,
                    time: row.time.unwrap_or_default() as u32,
                    comment: row.comment.clone().unwrap_or_default(),
                    add_source: row.add_source.clone().unwrap_or_default(),
                    source_id: row.source_id.unwrap_or_default() as u32,
                    source_sub_id: row.source_sub_id.unwrap_or_default() as u32,
                    is_initiator: row.is_initiator.unwrap_or_default() != 0,
                });
            }
            let total = success.total.unwrap_or_default();
            if success.finished.unwrap_or_default() != 0
                || (total != 0 && result.len() as u64 >= total)
            {
                break;
            }
            if rows.is_empty() {
                if total > result.len() as u64 {
                    return Err(Error::Malformed(
                        "Friend request pagination ended before its total".into(),
                    ));
                }
                break;
            }
            index = next_page_index(index, rows.len())?;
            sequence = success.sequence.unwrap_or_default();
            self.check_identity(&account).await?;
        }
        self.check_identity(&account).await?;
        Ok(result)
    }
    /// Domain-to-PSKey mapping, not an invented HTTP Cookie header.
    pub async fn fetch_cookies(&self, domains: &[String]) -> Result<BTreeMap<String, String>> {
        Ok(self.fetch_cookie_batch(domains).await?.values)
    }
    pub(crate) async fn fetch_cookie_batch(&self, domains: &[String]) -> Result<CookieBatch> {
        let request = protocol::CookiesRequest {
            domains: domains.to_vec(),
        };
        let response: protocol::CookiesResponse = self.oidb(0x102a, 0, &request, 0).await?;
        let mut result = BTreeMap::new();
        let mut expirations = BTreeMap::new();
        for row in response.cookies {
            let domain = row
                .domain
                .ok_or_else(|| Error::Malformed("Malformed domain PSKey entry".into()))?;
            let value = row
                .value
                .ok_or_else(|| Error::Malformed("Malformed domain PSKey entry".into()))?;
            if let Some(expiration) = row.expires_at {
                expirations.insert(domain.clone(), expiration);
            }
            result.insert(domain, value);
        }
        Ok(CookieBatch {
            values: result,
            expirations,
        })
    }
    pub async fn fetch_client_key(&self) -> Result<ClientKey> {
        let response: protocol::ClientKeyResponse =
            self.oidb(0x102a, 1, &protocol::Empty {}, 0).await?;
        Ok(ClientKey {
            key: nonempty(response.key, "Client key was not returned")?,
            expiration: u32::try_from(response.expiration.unwrap_or_default()).map_err(|_| {
                Error::Malformed("Client key TTL exceeds the supported range".into())
            })?,
        })
    }
    pub async fn fetch_friend_statuses(&self) -> Result<Arc<FriendStatusSnapshot>> {
        self.client.fetch_friend_statuses().await
    }
    pub async fn set_status(&self, status: u32) -> Result<bool> {
        if status > i32::MAX as u32 {
            return Err(Error::Malformed(
                "Status exceeds the desktop signed 32-bit status range".into(),
            ));
        }
        self.send_status(&protocol::StatusRequest {
            status: Some(status as u64),
            extended_status: Some(0),
            battery: Some(0),
            custom: None,
        })
        .await
    }
    pub async fn set_custom_status(&self, face_id: u32, text: &str) -> Result<bool> {
        let request = protocol::StatusRequest {
            status: Some(10),
            extended_status: Some(2000),
            battery: Some(0),
            custom: Some(protocol::CustomStatus {
                face_id: Some(face_id as u64),
                text: Some(text.into()),
                enabled: Some(1),
            }),
        };
        self.send_status(&request).await
    }
    async fn send_status(&self, request: &protocol::StatusRequest) -> Result<bool> {
        let response: protocol::StatusResponse = self
            .request(
                "trpc.qq_new_tech.status_svc.StatusService.SetStatus",
                request,
            )
            .await?;
        check_code(response.code, response.message)?;
        Ok(true)
    }
    pub async fn call(&self, method: &str, args: Value) -> Result<Value> {
        let args = Args::new(&args)?;
        match method {
            "friends" => value(&self.fetch_friends(args.boolean("refresh", false)?).await?),
            "friend_statuses" => value(self.fetch_friend_statuses().await?.as_ref()),
            "categories" => value(
                &self
                    .fetch_friend_categories(args.boolean("refresh", false)?)
                    .await?,
            ),
            "groups" => value(&self.fetch_groups(args.boolean("refresh", false)?).await?),
            "members" => value(
                &self
                    .fetch_members(args.u64("group_uin")?, args.boolean("refresh", false)?)
                    .await?,
            ),
            "stranger" => match args.optional_string("uid")? {
                Some(uid) => value(&self.fetch_stranger_uid(uid).await?),
                None => value(&self.fetch_stranger_uin(args.u64("uin")?).await?),
            },
            "resolve_uid" => value(
                &self
                    .resolve_uid(args.u64("uin")?, args.optional_u64("group_uin")?)
                    .await?,
            ),
            "resolve_uin" => value(&self.resolve_uin(args.string("uid")?).await?),
            "group_extra" => value(&self.fetch_group_extra(args.u64("group_uin")?).await?),
            "stranger_group_info" => value(
                &self
                    .fetch_stranger_group_info(args.u64("group_uin")?)
                    .await?,
            ),
            "group_notifications" => value(
                &self
                    .fetch_group_notifications(
                        args.default_u64("count", 50)?,
                        args.default_u64("start", 0)?,
                    )
                    .await?,
            ),
            "filtered_group_notifications" => value(
                &self
                    .fetch_filtered_group_notifications(
                        args.default_u64("count", 50)?,
                        args.default_u64("start", 0)?,
                    )
                    .await?,
            ),
            "friend_requests" => value(&self.fetch_friend_requests().await?),
            "cookies" => value(
                &self
                    .fetch_cookies(&args.decode::<Vec<String>>("domains")?)
                    .await?,
            ),
            "client_key" => value(&self.fetch_client_key().await?),
            "set_status" => value(&self.set_status(args.u32("status")?).await?),
            "set_custom_status" => value(
                &self
                    .set_custom_status(args.u32("face_id")?, args.string("text")?)
                    .await?,
            ),
            _ => Err(Error::Unsupported(format!(
                "Unknown desktop contacts operation: {method}"
            ))),
        }
    }
}

fn decode_member_card(card: protocol::MemberCard) -> Result<Option<String>> {
    let Some(bytes) = card.card else {
        return Ok(None);
    };
    if !card.rich.unwrap_or_default() {
        return std::str::from_utf8(&bytes)
            .map(|text| Some(text.to_owned()))
            .map_err(|error| Error::Malformed(format!("Invalid group member card text: {error}")));
    }
    let rich: protocol::RichMemberCard = decode(bytes)?;
    let capacity: usize = rich
        .elements
        .iter()
        .filter_map(|element| element.text.as_ref())
        .map(String::len)
        .sum();
    let mut parts = rich.elements.into_iter().filter_map(|element| element.text);
    let mut text = parts.next().unwrap_or_default();
    text.reserve(capacity - text.len());
    for part in parts {
        text.push_str(&part);
    }
    Ok(Some(text))
}

fn stranger_keys() -> protocol::StrangerKeys {
    protocol::StrangerKeys {
        keys: vec![
            101, 102, 103, 104, 105, 107, 20002, 20003, 20004, 20006, 20009, 20011, 20016, 20020,
            20021, 20026, 20031, 20037, 27394,
        ],
    }
}
pub(crate) fn required<T>(value: Option<T>, context: &str) -> Result<T> {
    value.ok_or_else(|| Error::Malformed(format!("Missing {context}")))
}
fn nonempty(value: Option<String>, context: &str) -> Result<String> {
    value
        .filter(|v| !v.is_empty())
        .ok_or_else(|| Error::Malformed(context.into()))
}
pub(crate) fn check_code(code: Option<u64>, message: Option<String>) -> Result<()> {
    let code = code.unwrap_or_default() as i32;
    if code == 0 {
        Ok(())
    } else {
        Err(Error::Server {
            code,
            message: message.unwrap_or_default(),
        })
    }
}
fn next_cookie(
    cookie: Option<bytes::Bytes>,
    seen: &mut HashSet<bytes::Bytes>,
    context: &str,
) -> Result<Option<bytes::Bytes>> {
    let Some(cookie) = cookie.filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    if !seen.insert(cookie.clone()) {
        return Err(Error::Malformed(format!(
            "{context} pagination repeated its cookie"
        )));
    }
    Ok(Some(cookie))
}
fn next_page_index(index: u32, count: usize) -> Result<u32> {
    u32::try_from(count)
        .ok()
        .and_then(|count| index.checked_add(count))
        .ok_or_else(|| Error::Malformed("Friend request page index overflow".into()))
}
fn decode_friend(
    row: &protocol::FriendRecord,
    categories: &BTreeMap<i32, FriendCategory>,
) -> Result<Friend> {
    let mut numbers = HashMap::new();
    let mut strings = HashMap::new();
    for entry in &row.business {
        if entry.kind.unwrap_or_default() != 1 {
            continue;
        }
        let biz: protocol::FriendProfileProperties =
            decode(required(entry.properties.as_ref(), "friend business properties")?.as_ref())?;
        for property in &biz.numbers {
            numbers.insert(
                property.key.unwrap_or_default(),
                property.value.unwrap_or_default(),
            );
        }
        for property in &biz.bytes {
            let value = property
                .value
                .as_ref()
                .and_then(|v| std::str::from_utf8(v).ok())
                .unwrap_or_default()
                .to_owned();
            strings.insert(property.key.unwrap_or_default(), value);
        }
    }
    let category_id = row.category_id.unwrap_or_default() as i32;
    Ok(Friend {
        uin: row.uin.unwrap_or_default(),
        uid: nonempty(row.uid.clone(), "Friend has no QQ UID")?,
        nickname: strings.remove(&20002).unwrap_or_default(),
        remark: strings.remove(&103).unwrap_or_default(),
        personal_sign: strings.remove(&102).unwrap_or_default(),
        qid: strings.remove(&27394).unwrap_or_default(),
        age: numbers.get(&20037).copied().unwrap_or(0) as i32,
        gender: numbers.get(&20009).copied().unwrap_or(0).into(),
        category_id,
        category: categories.get(&category_id).cloned(),
    })
}
fn decode_birthday(data: &[u8]) -> Result<Option<Birthday>> {
    if data.len() < 4 {
        return Err(Error::Malformed("Truncated stranger birthday".into()));
    }
    Ok(if data[2] == 0 || data[3] == 0 {
        None
    } else {
        Some(Birthday {
            year: u16::from_be_bytes([data[0], data[1]]),
            month: data[2],
            day: data[3],
        })
    })
}
pub(crate) fn value<T: Serialize>(value: &T) -> Result<Value> {
    Value::serialized(value).map_err(|error| Error::Malformed(error.to_string()))
}
pub(crate) struct Args<'a>(&'a Value);
impl<'a> Args<'a> {
    pub(crate) fn new(value: &'a Value) -> Result<Self> {
        if !matches!(value, Value::Map(_) | Value::Null) {
            return Err(Error::Malformed("Operation arguments must be a map".into()));
        }
        Ok(Self(value))
    }
    fn get(&self, key: &str) -> Option<&'a Value> {
        match self.0 {
            Value::Map(entries) => entries.iter().find_map(|(k, v)| {
                if matches!(k, Value::Text(name) if name == key) {
                    Some(v)
                } else {
                    None
                }
            }),
            _ => None,
        }
    }
    pub(crate) fn u64(&self, key: &str) -> Result<u64> {
        self.optional_u64(key)?
            .ok_or_else(|| Error::Malformed(format!("Missing {key}")))
    }
    pub(crate) fn optional_u64(&self, key: &str) -> Result<Option<u64>> {
        match self.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Integer(v)) => u64::try_from(*v)
                .map(Some)
                .map_err(|_| Error::Malformed(format!("{key} must be an unsigned 64-bit integer"))),
            _ => Err(Error::Malformed(format!(
                "{key} must be an unsigned integer"
            ))),
        }
    }
    pub(crate) fn default_u64(&self, key: &str, default: u64) -> Result<u64> {
        Ok(self.optional_u64(key)?.unwrap_or(default))
    }
    pub(crate) fn u32(&self, key: &str) -> Result<u32> {
        u32::try_from(self.u64(key)?)
            .map_err(|_| Error::Malformed(format!("{key} exceeds 32 bits")))
    }
    pub(crate) fn string(&self, key: &str) -> Result<&'a str> {
        self.optional_string(key)?
            .ok_or_else(|| Error::Malformed(format!("Missing {key}")))
    }
    pub(crate) fn optional_string(&self, key: &str) -> Result<Option<&'a str>> {
        match self.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Text(v)) => Ok(Some(v)),
            _ => Err(Error::Malformed(format!("{key} must be text"))),
        }
    }
    pub(crate) fn boolean(&self, key: &str, default: bool) -> Result<bool> {
        match self.get(key) {
            None => Ok(default),
            Some(Value::Bool(v)) => Ok(*v),
            _ => Err(Error::Malformed(format!("{key} must be boolean"))),
        }
    }
    pub(crate) fn decode<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<T> {
        self.get(key)
            .ok_or_else(|| Error::Malformed(format!("Missing {key}")))?
            .deserialized()
            .map_err(|error| Error::Malformed(error.to_string()))
    }
}

#[cfg(test)]
mod tests;
