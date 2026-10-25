use super::{ChannelInfo, GuildInfo, MemberInfo};
use crate::{
    Error, Result,
    client::ServiceClient,
    models::{Encryption, RequestType},
    proto::{contacts::OidbEnvelope, guild as protocol},
};
use bytes::Bytes;
use prost::Message;
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    time::Duration,
};

pub(super) trait Transport: Send + Sync {
    fn request_d2(
        &self,
        command: &str,
        body: Bytes,
        timeout: Duration,
    ) -> impl Future<Output = Result<Bytes>> + Send;
}

impl<T: ServiceClient + ?Sized> Transport for T {
    async fn request_d2(&self, command: &str, body: Bytes, timeout: Duration) -> Result<Bytes> {
        ServiceClient::request(
            self,
            command,
            body,
            RequestType::D2,
            Encryption::D2,
            timeout,
        )
        .await
    }
}

async fn oidb<Q: Message, R: Message + Default + prost::Name + std::fmt::Debug>(
    client: &(impl Transport + ?Sized),
    command: u32,
    service: u32,
    request: &Q,
    timeout: Duration,
) -> Result<R> {
    let command_name = format!("OidbSvcTrpcTcp.0x{command:x}_{service}");
    let request = OidbEnvelope {
        command: Some(command),
        service: Some(service),
        body: Some(request.encode_to_vec().into()),
        ..Default::default()
    };
    let response = client
        .request_d2(&command_name, request.encode_to_vec().into(), timeout)
        .await?;
    let response: OidbEnvelope = crate::diagnostics::decode_response(&command_name, response)?;
    let code = response.code.unwrap_or_default();
    if code != 0 {
        return Err(Error::Server {
            code: code as i32,
            message: response.message.unwrap_or_default(),
        });
    }
    let body = response
        .body
        .ok_or_else(|| Error::Malformed(format!("Missing {command_name} response body")))?;
    crate::diagnostics::decode_response(&command_name, body)
}

pub(super) async fn guilds(
    client: &(impl Transport + ?Sized),
    self_tiny_id: u64,
    timeout: Duration,
) -> Result<Vec<GuildInfo>> {
    let mut cookie = Bytes::new();
    let mut seen = HashSet::new();
    seen.insert(cookie.clone());
    let mut guilds: Vec<GuildInfo> = Vec::new();
    let mut positions: HashMap<u64, usize> = HashMap::new();
    loop {
        let request = protocol::QueryGuildsRequest {
            cookie: (!cookie.is_empty()).then(|| cookie.clone()),
            tiny_id: Some(self_tiny_id),
            guild_id: Some(0),
            page_size: Some(100),
        };
        let response: protocol::QueryGuildsResponse =
            oidb(client, 0x129d, 1, &request, timeout).await?;
        let page = response
            .page
            .ok_or_else(|| Error::Malformed("Missing guild directory response page".into()))?;
        for guild in page.guilds {
            let id = guild
                .guild_id
                .filter(|id| *id != 0)
                .ok_or_else(|| Error::Malformed("Guild directory entry has no guild ID".into()))?;
            if let Some(&index) = positions.get(&id) {
                if let Some(name) = guild.name {
                    guilds[index].name = String::from_utf8_lossy(&name).into_owned();
                }
                if let Some(number) = guild.number {
                    guilds[index].number = Some(String::from_utf8_lossy(&number).into_owned());
                }
            } else {
                positions.insert(id, guilds.len());
                guilds.push(GuildInfo {
                    id,
                    number: guild
                        .number
                        .map(|number| String::from_utf8_lossy(&number).into_owned()),
                    name: String::from_utf8_lossy(guild.name.as_deref().unwrap_or_default())
                        .into_owned(),
                    channels: Vec::new(),
                });
            }
        }
        if page.is_end == Some(true) {
            return Ok(guilds);
        }
        cookie = page.cookie.unwrap_or_default();
        if !seen.insert(cookie.clone()) {
            return Err(Error::Malformed(
                "Guild directory pagination repeated its cookie without finishing".into(),
            ));
        }
    }
}

pub(super) async fn channels(
    client: &(impl Transport + ?Sized),
    guild_id: u64,
    timeout: Duration,
) -> Result<Vec<ChannelInfo>> {
    let request = protocol::QueryChannelsRequest {
        guild_ids: vec![guild_id],
        filter: Some(protocol::QueryChannelFilter {
            field1: Some(1),
            field2: Some(1),
            field3: Some(1),
            field4: Some(1),
            field5: Some(1),
        }),
        source_type: Some(2),
        field5: Some(0),
        ..Default::default()
    };
    let response: protocol::QueryChannelsResponse =
        oidb(client, 0xf5d, 4, &request, timeout).await?;
    let mut channels = Vec::new();
    for guild in response.guilds {
        if guild.guild_id != Some(guild_id) {
            return Err(Error::Malformed(
                "Guild channel response belongs to a different or missing guild".into(),
            ));
        }
        for channel in guild.channels {
            let id = channel.id.filter(|id| *id != 0).ok_or_else(|| {
                Error::Malformed("Guild channel response has no channel ID".into())
            })?;
            channels.push(ChannelInfo {
                id,
                guild_id,
                name: String::from_utf8_lossy(channel.name.as_deref().unwrap_or_default())
                    .into_owned(),
                kind: channel.kind.unwrap_or_default(),
            });
        }
    }
    Ok(channels)
}

pub(super) async fn members(
    client: &(impl Transport + ?Sized),
    guild_id: u64,
    timeout: Duration,
) -> Result<Vec<MemberInfo>> {
    let mut continuation = (0, 0, Bytes::new());
    let mut seen = HashSet::new();
    seen.insert(continuation.clone());
    let mut members = Vec::new();
    let mut positions = HashMap::new();
    loop {
        let request = protocol::QueryMembersRequest {
            guild_id: Some(guild_id),
            field2: Some(3),
            field3: Some(0),
            filter: Some(protocol::QueryMemberFilter {
                field1: Some(1),
                field3: Some(1),
                field4: Some(1),
                field5: Some(1),
                field6: Some(1),
                field7: Some(1),
                field8: Some(1),
                field9: Some(1),
                field10: Some(1),
                field20: Some(1),
                field27: Some(1),
                field35: Some(1),
                field38: Some(1),
                field40: Some(1),
                field41: Some(1),
                field42: Some(1),
                field48: Some(1),
            }),
            start_index: Some(continuation.0),
            count: Some(100),
            channel_id: Some(0),
            cookie: (!continuation.2.is_empty()).then(|| continuation.2.clone()),
            role_index: Some(continuation.1),
        };
        let response: protocol::QueryMembersResponse =
            oidb(client, 0xf5b, 1, &request, timeout).await?;
        if response.guild_id.is_some_and(|id| id != guild_id) {
            return Err(Error::Malformed(
                "Guild member response belongs to a different guild".into(),
            ));
        }
        for member in response
            .bots
            .into_iter()
            .chain(response.members)
            .chain(response.feed_robots)
            .chain(response.ai_members)
        {
            merge_member(&mut members, &mut positions, member, None);
        }
        for group in response.roles {
            for member in group.members {
                merge_member(&mut members, &mut positions, member, group.id);
            }
        }
        if response.finished.unwrap_or_default() != 0 {
            return Ok(members);
        }
        continuation = (
            response.next_index.unwrap_or_default(),
            response.next_role_index.unwrap_or_default(),
            response.next_cookie.unwrap_or_default(),
        );
        if !seen.insert(continuation.clone()) {
            return Err(Error::Malformed(
                "Guild member pagination repeated its continuation without finishing".into(),
            ));
        }
    }
}

fn merge_member(
    members: &mut Vec<MemberInfo>,
    positions: &mut HashMap<u64, usize>,
    member: protocol::QueryMemberItem,
    role_id: Option<u64>,
) {
    let Some(tiny_id) = member.tiny_id.filter(|id| *id != 0) else {
        return;
    };
    let index = *positions.entry(tiny_id).or_insert_with(|| {
        let index = members.len();
        members.push(MemberInfo {
            tiny_id,
            nickname: String::new(),
            card: String::new(),
            role: None,
            role_ids: Vec::new(),
        });
        index
    });
    let existing = &mut members[index];
    if let Some(nickname) = member.nickname {
        existing.nickname = String::from_utf8_lossy(&nickname).into_owned();
    }
    if let Some(card) = member.member_name {
        existing.card = String::from_utf8_lossy(&card).into_owned();
    }
    if let Some(role) = member.role {
        existing.role = Some(role);
    }
    if let Some(role_id) = role_id {
        if !existing.role_ids.contains(&role_id) {
            existing.role_ids.push(role_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{IncomingPacket, SessionState};
    use std::{collections::VecDeque, sync::Mutex};
    use tokio::sync::broadcast;

    const TIMEOUT: Duration = Duration::from_secs(7);

    struct ScriptedClient {
        replies: Mutex<VecDeque<Bytes>>,
        requests: Mutex<Vec<(String, Bytes)>>,
        packets: broadcast::Sender<IncomingPacket>,
    }

    impl ScriptedClient {
        fn new(replies: Vec<Bytes>) -> Self {
            Self {
                replies: Mutex::new(replies.into()),
                requests: Mutex::new(Vec::new()),
                packets: broadcast::channel(4).0,
            }
        }

        fn request_body<M: Message + Default>(
            &self,
            index: usize,
            command: u32,
            service: u32,
        ) -> M {
            let requests = self.requests.lock().unwrap();
            let (name, bytes) = &requests[index];
            assert_eq!(name, &format!("OidbSvcTrpcTcp.0x{command:x}_{service}"));
            let envelope = OidbEnvelope::decode(bytes.clone()).unwrap();
            assert_eq!(envelope.command, Some(command));
            assert_eq!(envelope.service, Some(service));
            M::decode(envelope.body.unwrap()).unwrap()
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
            assert_eq!(timeout, TIMEOUT);
            self.requests.lock().unwrap().push((command.into(), body));
            self.replies
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| Error::Malformed("Unexpected guild query request".into()))
        }

        async fn snapshot(&self) -> SessionState {
            SessionState {
                profile: Default::default(),
                keystore: Default::default(),
                machine_id: "guild-query-test".into(),
                online: true,
            }
        }

        async fn replace_state(&self, _: SessionState) {}

        fn subscribe(&self) -> broadcast::Receiver<IncomingPacket> {
            self.packets.subscribe()
        }
    }

    fn reply(body: impl Message) -> Bytes {
        OidbEnvelope {
            code: Some(0),
            body: Some(body.encode_to_vec().into()),
            ..Default::default()
        }
        .encode_to_vec()
        .into()
    }

    fn member(tiny_id: u64) -> protocol::QueryMemberItem {
        protocol::QueryMemberItem {
            tiny_id: Some(tiny_id),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn members_merge_pages_and_all_member_sources_without_conflating_roles() {
        let client = ScriptedClient::new(vec![
            reply(protocol::QueryMembersResponse {
                guild_id: Some(42),
                bots: vec![protocol::QueryMemberItem {
                    nickname: Some(Bytes::from_static(b"first")),
                    role: Some(-7),
                    ..member(11)
                }],
                members: vec![member(12), member(0), protocol::QueryMemberItem::default()],
                roles: vec![protocol::QueryRoleGroup {
                    id: Some(800),
                    members: vec![member(11)],
                    ..Default::default()
                }],
                next_index: Some(2),
                next_role_index: Some(3),
                next_cookie: Some(Bytes::from_static(&[0xff, 0, 0xfe])),
                ..Default::default()
            }),
            reply(protocol::QueryMembersResponse {
                members: vec![protocol::QueryMemberItem {
                    nickname: Some(Bytes::from_static(b"updated")),
                    member_name: Some(Bytes::from_static(&[b'c', 0xff])),
                    ..member(11)
                }],
                roles: vec![
                    protocol::QueryRoleGroup {
                        id: Some(800),
                        members: vec![member(11)],
                        ..Default::default()
                    },
                    protocol::QueryRoleGroup {
                        id: Some(900),
                        members: vec![member(11), member(13)],
                        ..Default::default()
                    },
                ],
                feed_robots: vec![member(14)],
                ai_members: vec![member(15)],
                finished: Some(9),
                ..Default::default()
            }),
        ]);
        let result = members(&client, 42, TIMEOUT).await.unwrap();
        assert_eq!(
            result
                .iter()
                .map(|member| member.tiny_id)
                .collect::<Vec<_>>(),
            vec![11, 12, 14, 15, 13]
        );
        assert_eq!(result[0].nickname, "updated");
        assert_eq!(result[0].card, "c\u{fffd}");
        assert_eq!(result[0].role, Some(-7));
        assert_eq!(result[0].role_ids, vec![800, 900]);
        assert_eq!(result[4].role, None);
        assert_eq!(result[4].role_ids, vec![900]);
        let first: protocol::QueryMembersRequest = client.request_body(0, 0xf5b, 1);
        assert_eq!(first.guild_id, Some(42));
        assert_eq!(
            (first.field2, first.field3, first.channel_id),
            (Some(3), Some(0), Some(0))
        );
        assert_eq!(first.count, Some(100));
        assert_eq!(
            (first.start_index, first.role_index, first.cookie),
            (Some(0), Some(0), None)
        );
        let filter = first.filter.unwrap();
        assert_eq!(
            [
                filter.field1,
                filter.field3,
                filter.field4,
                filter.field5,
                filter.field6,
                filter.field7,
                filter.field8,
                filter.field9,
                filter.field10,
                filter.field20,
                filter.field27,
                filter.field35,
                filter.field38,
                filter.field40,
                filter.field41,
                filter.field42,
                filter.field48,
            ],
            [Some(1); 17]
        );
        let second: protocol::QueryMembersRequest = client.request_body(1, 0xf5b, 1);
        assert_eq!(second.start_index, Some(2));
        assert_eq!(second.role_index, Some(3));
        assert_eq!(second.cookie.as_deref(), Some(&[0xff, 0, 0xfe][..]));
        assert_eq!(client.requests.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn empty_member_pages_continue_using_each_continuation_component() {
        let client = ScriptedClient::new(vec![
            reply(protocol::QueryMembersResponse {
                next_role_index: Some(1),
                ..Default::default()
            }),
            reply(protocol::QueryMembersResponse {
                next_role_index: Some(1),
                next_cookie: Some(Bytes::from_static(&[0xff])),
                ..Default::default()
            }),
            reply(protocol::QueryMembersResponse {
                next_index: Some(1),
                next_role_index: Some(1),
                next_cookie: Some(Bytes::from_static(&[0xff])),
                ..Default::default()
            }),
            reply(protocol::QueryMembersResponse {
                finished: Some(2),
                members: vec![member(77)],
                ..Default::default()
            }),
        ]);
        let result = members(&client, 42, TIMEOUT).await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].tiny_id, 77);
        assert_eq!(client.requests.lock().unwrap().len(), 4);
        let second: protocol::QueryMembersRequest = client.request_body(1, 0xf5b, 1);
        assert_eq!(
            (second.start_index, second.role_index, second.cookie),
            (Some(0), Some(1), None)
        );
        let fourth: protocol::QueryMembersRequest = client.request_body(3, 0xf5b, 1);
        assert_eq!((fourth.start_index, fourth.role_index), (Some(1), Some(1)));
        assert_eq!(fourth.cookie.as_deref(), Some(&[0xff][..]));
    }

    #[tokio::test]
    async fn unfinished_member_pages_reject_stalls_and_longer_cycles() {
        let stalled = ScriptedClient::new(vec![reply(protocol::QueryMembersResponse {
            members: vec![member(11)],
            ..Default::default()
        })]);
        assert!(
            matches!(members(&stalled, 42, TIMEOUT).await, Err(Error::Malformed(message)) if message.contains("continuation"))
        );
        let cycling = ScriptedClient::new(vec![
            reply(protocol::QueryMembersResponse {
                next_index: Some(1),
                ..Default::default()
            }),
            reply(protocol::QueryMembersResponse {
                next_index: Some(2),
                ..Default::default()
            }),
            reply(protocol::QueryMembersResponse {
                next_index: Some(1),
                ..Default::default()
            }),
        ]);
        assert!(
            matches!(members(&cycling, 42, TIMEOUT).await, Err(Error::Malformed(message)) if message.contains("continuation"))
        );
        assert_eq!(cycling.requests.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn channels_decode_the_root_as_guild_entries_and_preserve_raw_kind() {
        let client = ScriptedClient::new(vec![reply(protocol::QueryChannelsResponse {
            guilds: vec![protocol::QueryGuildEntry {
                guild_id: Some(42),
                channels: vec![protocol::QueryChannelItem {
                    id: Some(123),
                    name: Some(Bytes::from_static(&[b'a', 0xff])),
                    kind: Some(u32::MAX),
                }],
            }],
        })]);
        assert_eq!(
            channels(&client, 42, TIMEOUT).await.unwrap(),
            vec![ChannelInfo {
                id: 123,
                guild_id: 42,
                name: "a\u{fffd}".into(),
                kind: u32::MAX,
            }]
        );
        let request: protocol::QueryChannelsRequest = client.request_body(0, 0xf5d, 4);
        assert_eq!(request.guild_ids, vec![42]);
        assert!(request.list.is_empty());
        assert_eq!((request.source_type, request.field5), (Some(2), Some(0)));
        let filter = request.filter.unwrap();
        assert_eq!(
            [
                filter.field1,
                filter.field2,
                filter.field3,
                filter.field4,
                filter.field5
            ],
            [Some(1); 5]
        );
        let empty = ScriptedClient::new(vec![reply(protocol::QueryChannelsResponse::default())]);
        assert!(channels(&empty, 42, TIMEOUT).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn foreign_guilds_never_return_mixed_results() {
        let channel_client = ScriptedClient::new(vec![reply(protocol::QueryChannelsResponse {
            guilds: vec![
                protocol::QueryGuildEntry {
                    guild_id: Some(42),
                    channels: vec![protocol::QueryChannelItem {
                        id: Some(123),
                        ..Default::default()
                    }],
                },
                protocol::QueryGuildEntry {
                    guild_id: Some(43),
                    channels: Vec::new(),
                },
            ],
        })]);
        assert!(matches!(
            channels(&channel_client, 42, TIMEOUT).await,
            Err(Error::Malformed(_))
        ));
        let member_client = ScriptedClient::new(vec![
            reply(protocol::QueryMembersResponse {
                guild_id: Some(42),
                members: vec![member(11)],
                next_index: Some(1),
                ..Default::default()
            }),
            reply(protocol::QueryMembersResponse {
                guild_id: Some(43),
                members: vec![member(12)],
                finished: Some(1),
                ..Default::default()
            }),
        ]);
        assert!(matches!(
            members(&member_client, 42, TIMEOUT).await,
            Err(Error::Malformed(_))
        ));
    }

    #[tokio::test]
    async fn outer_errors_and_missing_bodies_do_not_become_empty_success() {
        for code in [7, 1u64 << 32] {
            let envelope: Bytes = OidbEnvelope {
                code: Some(code),
                body: Some(Bytes::new()),
                message: Some("denied".into()),
                ..Default::default()
            }
            .encode_to_vec()
            .into();
            let channel_client = ScriptedClient::new(vec![envelope.clone()]);
            assert!(
                matches!(channels(&channel_client, 42, TIMEOUT).await, Err(Error::Server { message, .. }) if message == "denied")
            );
            let member_client = ScriptedClient::new(vec![envelope]);
            assert!(
                matches!(members(&member_client, 42, TIMEOUT).await, Err(Error::Server { message, .. }) if message == "denied")
            );
        }
        let envelope: Bytes = OidbEnvelope {
            code: Some(0),
            ..Default::default()
        }
        .encode_to_vec()
        .into();
        let channel_client = ScriptedClient::new(vec![envelope.clone()]);
        assert!(matches!(
            channels(&channel_client, 42, TIMEOUT).await,
            Err(Error::Malformed(_))
        ));
        let member_client = ScriptedClient::new(vec![envelope]);
        assert!(matches!(
            members(&member_client, 42, TIMEOUT).await,
            Err(Error::Malformed(_))
        ));
    }

    #[tokio::test]
    async fn missing_or_zero_channel_ids_are_not_fabricated() {
        for id in [None, Some(0)] {
            let client = ScriptedClient::new(vec![reply(protocol::QueryChannelsResponse {
                guilds: vec![protocol::QueryGuildEntry {
                    guild_id: Some(42),
                    channels: vec![protocol::QueryChannelItem {
                        id,
                        ..Default::default()
                    }],
                }],
            })]);
            assert!(matches!(
                channels(&client, 42, TIMEOUT).await,
                Err(Error::Malformed(_))
            ));
        }
    }

    #[tokio::test]
    async fn guild_directory_paginates_empty_pages_and_merges_ids_with_opaque_cookies() {
        let client = ScriptedClient::new(vec![
            reply(protocol::QueryGuildsResponse {
                page: Some(protocol::QueryGuildsPage {
                    guilds: vec![protocol::QueryGuildItem {
                        guild_id: Some(42),
                        name: Some(Bytes::from_static(b"first")),
                        ..Default::default()
                    }],
                    cookie: Some(Bytes::from_static(&[0xff])),
                    is_end: Some(false),
                }),
                joined_count_string: Some(Bytes::from_static(b"0")),
            }),
            reply(protocol::QueryGuildsResponse {
                page: Some(protocol::QueryGuildsPage {
                    guilds: Vec::new(),
                    cookie: Some(Bytes::from_static(&[0xff, 0])),
                    is_end: None,
                }),
                joined_count_string: Some(Bytes::from_static(b"1")),
            }),
            reply(protocol::QueryGuildsResponse {
                page: Some(protocol::QueryGuildsPage {
                    guilds: vec![
                        protocol::QueryGuildItem {
                            guild_id: Some(42),
                            name: Some(Bytes::from_static(&[b'g', 0xfe])),
                            ..Default::default()
                        },
                        protocol::QueryGuildItem {
                            guild_id: Some(43),
                            name: Some(Bytes::from_static(b"second")),
                            ..Default::default()
                        },
                    ],
                    cookie: Some(Bytes::from_static(&[0xff, 1])),
                    is_end: Some(false),
                }),
                joined_count_string: Some(Bytes::from_static(b"2")),
            }),
            reply(protocol::QueryGuildsResponse {
                page: Some(protocol::QueryGuildsPage {
                    guilds: Vec::new(),
                    cookie: Some(Bytes::from_static(&[0xff, 1])),
                    is_end: Some(true),
                }),
                ..Default::default()
            }),
        ]);
        let result = guilds(&client, 777, TIMEOUT).await.unwrap();
        assert_eq!(
            result,
            vec![
                GuildInfo {
                    id: 42,
                    number: None,
                    name: "g\u{fffd}".into(),
                    channels: Vec::new()
                },
                GuildInfo {
                    id: 43,
                    number: None,
                    name: "second".into(),
                    channels: Vec::new()
                },
            ]
        );
        assert_eq!(client.requests.lock().unwrap().len(), 4);
        for index in 0..4 {
            let request: protocol::QueryGuildsRequest = client.request_body(index, 0x129d, 1);
            assert_eq!(request.tiny_id, Some(777));
            assert_eq!(request.guild_id, Some(0));
            assert_eq!(request.page_size, Some(100));
            let expected_cookie = match index {
                0 => None,
                1 => Some(&[0xff][..]),
                2 => Some(&[0xff, 0][..]),
                _ => Some(&[0xff, 1][..]),
            };
            assert_eq!(request.cookie.as_deref(), expected_cookie);
        }
    }

    #[tokio::test]
    async fn guild_directory_requires_a_page_and_explicit_end_without_stalls_or_cycles() {
        let missing = ScriptedClient::new(vec![reply(protocol::QueryGuildsResponse::default())]);
        assert!(
            matches!(guilds(&missing, 777, TIMEOUT).await, Err(Error::Malformed(message)) if message.contains("page"))
        );
        for is_end in [None, Some(false)] {
            let stalled = ScriptedClient::new(vec![reply(protocol::QueryGuildsResponse {
                page: Some(protocol::QueryGuildsPage {
                    guilds: vec![protocol::QueryGuildItem {
                        guild_id: Some(42),
                        ..Default::default()
                    }],
                    is_end,
                    ..Default::default()
                }),
                ..Default::default()
            })]);
            assert!(
                matches!(guilds(&stalled, 777, TIMEOUT).await, Err(Error::Malformed(message)) if message.contains("cookie"))
            );
        }
        let cycling = ScriptedClient::new(
            [1u8, 2, 1]
                .into_iter()
                .map(|cookie| {
                    reply(protocol::QueryGuildsResponse {
                        page: Some(protocol::QueryGuildsPage {
                            cookie: Some(vec![cookie].into()),
                            is_end: Some(false),
                            ..Default::default()
                        }),
                        ..Default::default()
                    })
                })
                .collect(),
        );
        assert!(
            matches!(guilds(&cycling, 777, TIMEOUT).await, Err(Error::Malformed(message)) if message.contains("cookie"))
        );
        assert_eq!(cycling.requests.lock().unwrap().len(), 3);
        let partial = ScriptedClient::new(vec![
            reply(protocol::QueryGuildsResponse {
                page: Some(protocol::QueryGuildsPage {
                    guilds: vec![protocol::QueryGuildItem {
                        guild_id: Some(42),
                        ..Default::default()
                    }],
                    cookie: Some(Bytes::from_static(b"next")),
                    is_end: Some(false),
                }),
                ..Default::default()
            }),
            reply(protocol::QueryGuildsResponse::default()),
        ]);
        assert!(matches!(
            guilds(&partial, 777, TIMEOUT).await,
            Err(Error::Malformed(_))
        ));
        let finished = ScriptedClient::new(vec![reply(protocol::QueryGuildsResponse {
            page: Some(protocol::QueryGuildsPage {
                is_end: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        })]);
        assert!(guilds(&finished, 777, TIMEOUT).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn guild_directory_rejects_outer_errors_and_missing_bodies() {
        let error = ScriptedClient::new(vec![
            OidbEnvelope {
                code: Some(7),
                message: Some("denied".into()),
                body: Some(Bytes::new()),
                ..Default::default()
            }
            .encode_to_vec()
            .into(),
        ]);
        assert!(matches!(
            guilds(&error, 777, TIMEOUT).await,
            Err(Error::Server { code: 7, .. })
        ));
        let missing = ScriptedClient::new(vec![
            OidbEnvelope {
                code: Some(0),
                ..Default::default()
            }
            .encode_to_vec()
            .into(),
        ]);
        assert!(matches!(
            guilds(&missing, 777, TIMEOUT).await,
            Err(Error::Malformed(_))
        ));
    }

    #[tokio::test]
    async fn guild_directory_display_number_and_recommended_channel_are_not_full_metadata() {
        let body = Bytes::from_static(&[
            0x0a, 0x19, 0x0a, 0x15, 0x08, 0x2a, 0x12, 0x01, b'g', 0x58, 0x7b, 0x62, 0x01, b'x',
            0x68, 0x02, 0x8a, 0x01, 0x06, b'0', b'0', b'1', b'2', b'3', b'4', 0x18, 0x01,
        ]);
        let client = ScriptedClient::new(vec![
            OidbEnvelope {
                code: Some(0),
                body: Some(body),
                ..Default::default()
            }
            .encode_to_vec()
            .into(),
        ]);
        let result = guilds(&client, 777, TIMEOUT).await.unwrap();
        assert_eq!(
            result,
            vec![GuildInfo {
                id: 42,
                number: Some("001234".into()),
                name: "g".into(),
                channels: Vec::new(),
            }]
        );
    }
}
