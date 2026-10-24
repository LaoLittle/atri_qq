use super::*;
use crate::models::{IncomingPacket, Keystore, Profile, SessionState};
use bytes::Bytes;
use prost::Message;
use std::{collections::VecDeque, sync::Mutex as StdMutex};
use tokio::sync::{RwLock, broadcast};

struct ScriptedClient {
    state: RwLock<SessionState>,
    replies: StdMutex<VecDeque<Bytes>>,
    requests: StdMutex<Vec<(String, Bytes)>>,
    change_on_request: StdMutex<Option<(u64, String)>>,
    packets: broadcast::Sender<IncomingPacket>,
}
impl ScriptedClient {
    fn new<M: Message>(replies: Vec<M>) -> Arc<Self> {
        let mut keystore = Keystore::default();
        keystore.uin = 42;
        keystore.uid = "u_self".into();
        Arc::new(Self {
            state: RwLock::new(SessionState {
                profile: Profile::default(),
                keystore,
                machine_id: "test-machine".into(),
                online: true,
            }),
            replies: StdMutex::new(
                replies
                    .into_iter()
                    .map(|body| {
                        protocol::OidbEnvelope {
                            code: Some(0),
                            body: Some(body.encode_to_vec().into()),
                            ..Default::default()
                        }
                        .encode_to_vec()
                        .into()
                    })
                    .collect(),
            ),
            requests: StdMutex::new(Vec::new()),
            change_on_request: StdMutex::new(None),
            packets: broadcast::channel(4).0,
        })
    }
    async fn change_account(&self, uin: u64, uid: &str) {
        let mut state = self.state.write().await;
        state.keystore.uin = uin;
        state.keystore.uid = uid.into();
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
        let change = self.change_on_request.lock().unwrap().take();
        if let Some((uin, uid)) = change {
            self.change_account(uin, &uid).await;
        }
        self.replies
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| Error::Malformed("Unexpected test request".into()))
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
fn envelope(bytes: &Bytes) -> protocol::OidbEnvelope {
    protocol::OidbEnvelope::decode(bytes.clone()).unwrap()
}
fn request<M: Message + Default>(bytes: &Bytes) -> M {
    M::decode(envelope(bytes).body.unwrap()).unwrap()
}
fn friend(uin: u64, uid: &str, nickname: &str, category: i32) -> protocol::FriendRecord {
    protocol::FriendRecord {
        uid: Some(uid.into()),
        category_id: Some(category as u64),
        uin: Some(uin),
        business: vec![protocol::FriendBusiness {
            kind: Some(1),
            properties: Some(
                protocol::FriendProfileProperties {
                    numbers: vec![
                        protocol::NumberProperty {
                            key: Some(20009),
                            value: Some(2),
                        },
                        protocol::NumberProperty {
                            key: Some(20037),
                            value: Some(19),
                        },
                    ],
                    bytes: vec![protocol::BytesProperty {
                        key: Some(20002),
                        value: Some(Bytes::copy_from_slice(nickname.as_bytes())),
                    }],
                }
                .encode_to_vec()
                .into(),
            ),
        }],
    }
}
fn friend_page(
    rows: &[protocol::FriendRecord],
    cookie: Option<&[u8]>,
) -> protocol::FriendListResponse {
    protocol::FriendListResponse {
        friends: rows.to_vec(),
        cookie: cookie.map(Bytes::copy_from_slice),
        ..Default::default()
    }
}
#[test]
fn friend_business_payloads_are_decoded_only_for_the_profile_kind() {
    let mut row = friend(1001, "u_alice", "Alice", 0);
    let other_business = Bytes::from_static(b"\x0a\x04\x12\x02xx");
    row.business.push(protocol::FriendBusiness {
        kind: Some(6),
        properties: Some(other_business.clone()),
    });
    let page = friend_page(&[row], None);
    let decoded = protocol::FriendListResponse::decode(page.encode_to_vec().as_slice()).unwrap();
    let friend = decode_friend(&decoded.friends[0], &BTreeMap::new()).unwrap();
    assert_eq!(friend.nickname, "Alice");
    assert_eq!(friend.age, 19);
    assert_eq!(friend.gender, Gender::Female);
    assert_eq!(
        decoded.friends[0].business[1].properties.as_ref(),
        Some(&other_business)
    );
    let mut malformed_profile = decoded.friends[0].clone();
    malformed_profile.business[0].properties = Some(other_business);
    assert!(decode_friend(&malformed_profile, &BTreeMap::new()).is_err());
}
#[tokio::test]
async fn friend_pages_preserve_uid_uin_properties_categories_and_cache() {
    let mut first = friend_page(&[friend(1001, "u_alice", "Alice", 7)], Some(b"next"));
    first.categories.push(protocol::CategoryRecord {
        id: Some(7),
        name: Some("Colleagues".into()),
        member_count: Some(2),
        sort_id: Some(9),
    });
    let client = ScriptedClient::new(vec![
        first,
        friend_page(&[friend(2002, "u_bob", "Bob", 7)], None),
    ]);
    let operations = Operations::new(client.clone());
    let friends = operations.fetch_friends(false).await.unwrap();
    assert_eq!(friends.len(), 2);
    assert_eq!(
        (
            friends[0].uin,
            friends[0].uid.as_str(),
            friends[0].nickname.as_str()
        ),
        (1001, "u_alice", "Alice")
    );
    assert_eq!(friends[1].category.as_ref().unwrap().name, "Colleagues");
    assert_eq!(friends[1].age, 19);
    assert_eq!(friends[1].gender, Gender::Female);
    assert_eq!(operations.resolve_uid(2002, None).await.unwrap(), "u_bob");
    assert_eq!(operations.resolve_uin("u_alice").await.unwrap(), 1001);
    assert_eq!(operations.fetch_friends(false).await.unwrap(), friends);
    let requests = client.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    for (command, bytes) in requests.iter() {
        assert_eq!(command, "OidbSvcTrpcTcp.0xfd4_1");
        let envelope = envelope(bytes);
        assert_eq!(envelope.command, Some(0xfd4));
        assert_eq!(envelope.service, Some(1));
        let body: protocol::FriendListRequest = request(bytes);
        assert_eq!(body.count, Some(300));
        assert_eq!(body.time, None);
        assert_eq!(body.local_sequence, Some(0));
        assert_eq!(body.proxy_sequence, Some(0));
        assert_eq!(body.selections.len(), 2);
        assert_eq!(body.keys.len(), 5);
        assert_eq!(body.extra_keys, [4051]);
    }
    assert_eq!(
        request::<protocol::FriendListRequest>(&requests[0].1).cookie,
        None
    );
    assert_eq!(
        request::<protocol::FriendListRequest>(&requests[1].1)
            .cookie
            .as_deref(),
        Some(b"next".as_slice())
    );
}
#[tokio::test]
async fn repeated_friend_cookie_fails_without_publishing_partial_contacts() {
    let client = ScriptedClient::new(vec![
        friend_page(&[friend(1001, "u_alice", "Alice", 0)], Some(b"same")),
        friend_page(&[], Some(b"same")),
    ]);
    let operations = Operations::new(client);
    assert!(
        matches!(operations.fetch_friends(false).await,Err(Error::Malformed(message)) if message.contains("repeated"))
    );
    let cache = operations.cache.lock().await;
    assert!(cache.friends.is_none());
    assert!(cache.uid_by_uin.is_empty());
}
#[tokio::test]
async fn account_change_invalidates_contacts_and_identity_mappings() {
    let client = ScriptedClient::new(vec![
        friend_page(&[friend(1001, "u_old", "Old", 0)], None),
        friend_page(&[friend(1001, "u_new", "New", 0)], None),
    ]);
    let operations = Operations::new(client.clone());
    assert_eq!(
        operations.fetch_friends(false).await.unwrap()[0].uid,
        "u_old"
    );
    client.change_account(84, "u_second").await;
    assert_eq!(
        operations.fetch_friends(false).await.unwrap()[0].uid,
        "u_new"
    );
    let cache = operations.cache.lock().await;
    assert!(!cache.uin_by_uid.contains_key("u_old"));
    assert_eq!(
        cache.uid_by_uin.get(&1001).map(String::as_str),
        Some("u_new")
    );
}
#[tokio::test]
async fn in_flight_account_change_rejects_result_and_does_not_cache_it() {
    let client = ScriptedClient::new(vec![friend_page(&[friend(1001, "u_old", "Old", 0)], None)]);
    *client.change_on_request.lock().unwrap() = Some((84, "u_second".into()));
    let operations = Operations::new(client);
    assert!(matches!(
        operations.fetch_friends(false).await,
        Err(Error::Authentication(_))
    ));
    assert!(operations.cache.lock().await.friends.is_none());
}
#[tokio::test]
async fn member_response_for_another_group_is_rejected() {
    let client = ScriptedClient::new(vec![protocol::MemberListResponse {
        group_uin: Some(999),
        ..Default::default()
    }]);
    let operations = Operations::new(client);
    assert!(
        matches!(operations.fetch_members(123,false).await,Err(Error::Malformed(message)) if message.contains("different group"))
    );
    assert!(operations.cache.lock().await.members.is_empty());
}
#[tokio::test]
async fn friend_request_pages_use_fixed32_sequence_and_monotonic_index() {
    let row = protocol::FriendRequestRecord {
        target_uid: Some("u_self".into()),
        source_uid: Some("u_self".into()),
        state: Some(1),
        time: Some(123),
        source_id: Some(8),
        source_sub_id: Some(9),
        is_initiator: Some(1),
        ..Default::default()
    };
    let first_response = protocol::FriendRequestsResponse {
        success: Some(protocol::FriendRequestsSuccess {
            sequence: Some(0x10203040),
            total: Some(2),
            requests: vec![row.clone()],
            ..Default::default()
        }),
        ..Default::default()
    };
    let second_response = protocol::FriendRequestsResponse {
        success: Some(protocol::FriendRequestsSuccess {
            finished: Some(1),
            total: Some(2),
            requests: vec![row],
            ..Default::default()
        }),
        ..Default::default()
    };
    let client = ScriptedClient::new(vec![first_response, second_response]);
    let operations = Operations::new(client.clone());
    let requests = operations.fetch_friend_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].target.uin, 42);
    assert_eq!(requests[0].source.uid, "u_self");
    assert_eq!(requests[0].source_id, 8);
    assert!(requests[0].is_initiator);
    let requests = client.requests.lock().unwrap();
    let first: protocol::FriendRequestsRequest = request(&requests[0].1);
    let second: protocol::FriendRequestsRequest = request(&requests[1].1);
    assert_eq!(requests[0].0, "OidbSvcTrpcTcp.0x5cf_11");
    assert_eq!(first.sequence, None);
    assert_eq!(first.index, Some(0));
    assert_eq!(second.sequence, Some(0x10203040));
    assert_eq!(second.index, Some(1));
}
#[tokio::test]
async fn invalid_status_or_empty_uid_performs_no_network_operation() {
    let client = ScriptedClient::new(Vec::<protocol::Empty>::new());
    let operations = Operations::new(client.clone());
    assert!(operations.set_status(i32::MAX as u32 + 1).await.is_err());
    assert!(operations.resolve_uin("").await.is_err());
    assert!(operations.fetch_stranger_uid("").await.is_err());
    assert!(client.requests.lock().unwrap().is_empty());
}
#[tokio::test]
async fn stranger_identity_encoding_does_not_fabricate_uid_from_uin() {
    let response = protocol::StrangerResponse {
        body: Some(protocol::StrangerBody {
            uin: Some(9876),
            properties: Some(protocol::Properties {
                bytes: vec![protocol::BytesProperty {
                    key: Some(20002),
                    value: Some(Bytes::from_static(b"Stranger")),
                }],
                ..Default::default()
            }),
        }),
    };
    let client = ScriptedClient::new(vec![response.clone(), response]);
    let operations = Operations::new(client.clone());
    let numeric = operations.fetch_stranger_uin(9876).await.unwrap();
    assert_eq!(numeric.uin, 9876);
    assert_eq!(numeric.uid, None);
    assert_eq!(numeric.nickname, "Stranger");
    let opaque = operations.fetch_stranger_uid("u_opaque").await.unwrap();
    assert_eq!(opaque.uid.as_deref(), Some("u_opaque"));
    assert_eq!(
        operations.resolve_uid(9876, None).await.unwrap(),
        "u_opaque"
    );
    let requests = client.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(envelope(&requests[0].1).reserved, Some(1));
    assert_eq!(
        request::<protocol::StrangerUinRequest>(&requests[0].1).uin,
        Some(9876)
    );
    assert_eq!(envelope(&requests[1].1).reserved, Some(0));
    assert_eq!(
        request::<protocol::StrangerUidRequest>(&requests[1].1)
            .uid
            .as_deref(),
        Some("u_opaque")
    );
    assert_eq!(
        request::<protocol::StrangerUinRequest>(&requests[0].1)
            .keys
            .unwrap()
            .keys,
        stranger_keys().keys
    );
    assert_eq!(
        request::<protocol::StrangerUidRequest>(&requests[1].1)
            .keys
            .unwrap()
            .keys,
        stranger_keys().keys
    );
}
#[test]
fn stranger_keys_use_one_wrapper_with_repeated_unpacked_numbers() {
    let keys = protocol::StrangerKeys {
        keys: vec![101, 102],
    };
    let numeric = protocol::StrangerUinRequest {
        uin: Some(42),
        keys: Some(keys.clone()),
    };
    assert_eq!(
        numeric.encode_to_vec(),
        [0x08, 42, 0x1a, 4, 0x08, 101, 0x08, 102]
    );
    let opaque = protocol::StrangerUidRequest {
        uid: Some("u_test".into()),
        keys: Some(keys),
    };
    let expected = b"\x0a\x06u_test\x1a\x04\x08\x65\x08\x66";
    assert_eq!(opaque.encode_to_vec(), expected.as_slice());
    assert_eq!(
        protocol::StrangerUidRequest::decode(expected.as_slice())
            .unwrap()
            .keys
            .unwrap()
            .keys,
        [101, 102]
    );
}
#[test]
fn friend_private_id_selection_retains_all_repeated_keys() {
    let bytes = [0x98, 0xf1, 0x04, 1, 0x98, 0xf1, 0x04, 2];
    let body = protocol::FriendListRequest::decode(bytes.as_slice()).unwrap();
    assert_eq!(body.extra_keys, [1, 2]);
    assert_eq!(body.encode_to_vec(), bytes);
}
#[tokio::test]
async fn incomplete_friend_request_page_reports_the_server_total() {
    let response = protocol::FriendRequestsResponse {
        success: Some(protocol::FriendRequestsSuccess {
            total: Some(5),
            ..Default::default()
        }),
        ..Default::default()
    };
    let operations = Operations::new(ScriptedClient::new(vec![response]));
    assert!(
        matches!(operations.fetch_friend_requests().await,Err(Error::Malformed(message)) if message.contains("before its total"))
    );
}
#[tokio::test]
async fn oidb_error_preserves_signed_code_and_server_message() {
    let client = ScriptedClient::new(Vec::<protocol::Empty>::new());
    let response = protocol::OidbEnvelope {
        code: Some((-12i32) as u64),
        message: Some("Denied".into()),
        ..Default::default()
    };
    client
        .replies
        .lock()
        .unwrap()
        .push_back(response.encode_to_vec().into());
    let operations = Operations::new(client);
    assert!(
        matches!(operations.fetch_client_key().await,Err(Error::Server { code:-12, message }) if message == "Denied")
    );
}
#[test]
fn birthday_and_page_index_boundaries_are_checked() {
    assert!(decode_birthday(&[0, 1, 2]).is_err());
    assert_eq!(
        decode_birthday(&[0x07, 0xe8, 2, 29]).unwrap(),
        Some(Birthday {
            year: 2024,
            month: 2,
            day: 29
        })
    );
    assert_eq!(decode_birthday(&[0, 0, 0, 1]).unwrap(), None);
    assert_eq!(next_page_index(u32::MAX - 1, 1).unwrap(), u32::MAX);
    assert!(next_page_index(u32::MAX, 1).is_err());
}
#[test]
fn remapping_a_uid_or_uin_removes_the_old_reverse_mapping() {
    let mut cache = Cache::default();
    cache.remember(1, "u_old");
    cache.remember(1, "u_new");
    assert!(!cache.uin_by_uid.contains_key("u_old"));
    cache.remember(2, "u_new");
    assert!(!cache.uid_by_uin.contains_key(&1));
    assert_eq!(cache.uin_by_uid.get("u_new"), Some(&2));
    cache.remember(0, "u_zero");
    cache.remember(9, "");
    assert!(!cache.uin_by_uid.contains_key("u_zero"));
    assert!(!cache.uid_by_uin.contains_key(&9));
}
#[test]
fn malformed_friend_and_out_of_range_dynamic_arguments_are_rejected() {
    assert!(
        decode_friend(
            &protocol::FriendRecord {
                uin: Some(123),
                ..Default::default()
            },
            &BTreeMap::new()
        )
        .is_err()
    );
    let input = Value::Map(vec![(
        Value::Text("status".into()),
        Value::Integer((u32::MAX as u64 + 1).into()),
    )]);
    assert!(Args::new(&input).unwrap().u32("status").is_err());
    let input = Value::Map(vec![(
        Value::Text("uin".into()),
        Value::Integer((-1).into()),
    )]);
    assert!(Args::new(&input).unwrap().u64("uin").is_err());
}

#[tokio::test]
async fn groups_decode_optional_details_and_request_selection_masks() {
    let client = ScriptedClient::new(vec![protocol::GroupListResponse {
        groups: vec![protocol::GroupRecord {
            uin: Some(123),
            info: Some(protocol::GroupInfo {
                owner: Some(protocol::GroupOwner {
                    uid: Some("u_owner".into()),
                }),
                name: Some("Team".into()),
                member_count: Some(8),
                max_member_count: Some(50),
                created_time: Some(100),
                description: Some("Description".into()),
                question: Some(String::new()),
                announcement: None,
            }),
            custom: Some(protocol::GroupCustom {
                last_speak_time: Some(200),
                remark: Some("Work".into()),
                latest_sequence: Some(30),
            }),
        }],
    }]);
    let operations = Operations::new(client.clone());
    let groups = operations.fetch_groups(false).await.unwrap();
    assert_eq!(groups[0].uin, 123);
    assert_eq!(groups[0].name, "Team");
    assert_eq!(groups[0].owner_uid.as_deref(), Some("u_owner"));
    assert_eq!(
        (groups[0].member_count, groups[0].max_member_count),
        (8, 50)
    );
    assert_eq!(groups[0].created_time, 100);
    assert_eq!(groups[0].description.as_deref(), Some("Description"));
    assert_eq!(groups[0].question.as_deref(), Some(""));
    assert_eq!(groups[0].announcement, None);
    assert_eq!(groups[0].remark.as_deref(), Some("Work"));
    assert_eq!(
        (groups[0].last_speak_time, groups[0].latest_sequence),
        (200, 30)
    );
    assert_eq!(operations.fetch_groups(false).await.unwrap(), groups);
    let requests = client.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].0, "OidbSvcTrpcTcp.0xfe5_2");
    let selection = request::<protocol::GroupListRequest>(&requests[0].1)
        .selection
        .unwrap();
    let info = selection.info.unwrap();
    assert_eq!(
        (info.owner, info.name, info.description, info.announcement),
        (Some(1), Some(1), Some(1), Some(1))
    );
    assert_eq!(selection.custom.unwrap().latest_sequence, Some(1));
    assert_eq!(selection.extra.unwrap().field6, Some(1));
}

#[tokio::test]
async fn member_pages_decode_details_and_publish_identity_only_after_completion() {
    let row = protocol::MemberRecord {
        identity: Some(protocol::UserIdentity {
            uid: Some("u_member".into()),
            uin: Some(456),
        }),
        nickname: Some("Member".into()),
        card: Some(protocol::MemberCard {
            rich: None,
            card: Some(Bytes::new()),
        }),
        level: Some(protocol::MemberLevel { level: Some(12) }),
        special_title: Some("Expert".into()),
        join_time: Some(100),
        last_message_time: Some(200),
        mute_until: Some(300),
        permission: Some(1),
    };
    let client = ScriptedClient::new(vec![
        protocol::MemberListResponse {
            group_uin: Some(123),
            members: vec![row],
            cookie: Some(Bytes::from_static(b"members-next")),
        },
        protocol::MemberListResponse {
            group_uin: Some(123),
            ..Default::default()
        },
    ]);
    let operations = Operations::new(client.clone());
    let members = operations.fetch_members(123, false).await.unwrap();
    assert_eq!(members.len(), 1);
    let member = &members[0];
    assert_eq!(
        (member.group_uin, member.uin, member.uid.as_str()),
        (123, 456, "u_member")
    );
    assert_eq!(member.nickname, "Member");
    assert_eq!(member.card.as_deref(), Some(""));
    assert_eq!(member.special_title.as_deref(), Some("Expert"));
    assert_eq!(
        (
            member.level,
            member.join_time,
            member.last_message_time,
            member.mute_until
        ),
        (12, 100, 200, 300)
    );
    assert_eq!(operations.resolve_uid(456, None).await.unwrap(), "u_member");
    assert_eq!(operations.fetch_members(123, false).await.unwrap(), members);
    let requests = client.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].0, "OidbSvcTrpcTcp.0xfe7_3");
    let first: protocol::MemberListRequest = request(&requests[0].1);
    assert_eq!(
        (first.group_uin, first.count, first.version),
        (Some(123), Some(5), Some(2))
    );
    assert_eq!(first.cookie, None);
    let fields = first.fields.unwrap();
    assert_eq!(
        (
            fields.nickname,
            fields.card,
            fields.level,
            fields.permission
        ),
        (Some(1), Some(1), Some(1), Some(1))
    );
    assert_eq!(
        (
            fields.join_time,
            fields.last_message_time,
            fields.mute_until
        ),
        (Some(1), Some(1), Some(1))
    );
    assert_eq!(
        request::<protocol::MemberListRequest>(&requests[1].1)
            .cookie
            .as_deref(),
        Some(b"members-next".as_slice())
    );
}

#[tokio::test]
async fn group_extra_rejects_inner_error_even_when_sequence_is_present() {
    for info in [
        None,
        Some(protocol::GroupDetailInfo {
            latest_sequence: Some(99),
            ..Default::default()
        }),
    ] {
        let client = ScriptedClient::new(vec![protocol::GroupDetailResponse {
            results: vec![protocol::GroupDetailResult {
                group_uin: Some(123),
                code: Some(17),
                info,
            }],
            message: Some("Group access denied".into()),
            ..Default::default()
        }]);
        let error = Operations::new(client)
            .fetch_group_extra(123)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            Error::Server { code: 17, message } if message == "Group access denied"
        ));
    }
}

#[tokio::test]
async fn group_detail_preserves_present_zero_uin_and_explicit_zero_masks() {
    let response = |uin| protocol::GroupDetailResponse {
        results: vec![protocol::GroupDetailResult {
            group_uin: Some(123),
            code: Some(0),
            info: Some(protocol::GroupDetailInfo {
                uin,
                name: Some("External".into()),
                created_time: Some(10),
                member_count: Some(20),
                max_member_count: Some(30),
                latest_sequence: Some(99),
            }),
        }],
        ..Default::default()
    };
    let client = ScriptedClient::new(vec![response(Some(0)), response(None), response(None)]);
    let operations = Operations::new(client.clone());
    let group = operations.fetch_stranger_group_info(123).await.unwrap();
    assert_eq!(group.uin, 0);
    assert_eq!(group.name, "External");
    assert_eq!(
        (
            group.created_time,
            group.member_count,
            group.max_member_count
        ),
        (10, 20, 30)
    );
    assert_eq!(
        operations.fetch_stranger_group_info(123).await.unwrap().uin,
        123
    );
    assert_eq!(
        operations
            .fetch_group_extra(123)
            .await
            .unwrap()
            .latest_message_sequence,
        99
    );
    let requests = client.requests.lock().unwrap();
    assert_eq!(requests[0].0, "OidbSvcTrpcTcp.0x88d_110");
    let query = request::<protocol::GroupDetailRequest>(&requests[0].1)
        .query
        .unwrap();
    assert_eq!(query.group_uin, Some(123));
    let fields = query.fields.unwrap();
    assert_eq!(
        (
            fields.created_time,
            fields.member_count,
            fields.max_member_count,
            fields.uin
        ),
        (Some(0), Some(0), Some(0), Some(0))
    );
    assert_eq!(fields.name, Some(Bytes::new()));
    assert_eq!(fields.latest_sequence, None);
    assert_eq!(requests[2].0, "OidbSvcTrpcTcp.0x88d_0");
    let extra = request::<protocol::GroupDetailRequest>(&requests[2].1)
        .query
        .unwrap()
        .fields
        .unwrap();
    assert_eq!(extra.latest_sequence, Some(1));
    assert_eq!(extra.uin, None);
}

#[tokio::test]
async fn cookies_and_client_key_keep_server_values_and_require_presence() {
    let client = ScriptedClient::new(vec![protocol::CookiesResponse {
        cookies: vec![
            protocol::CookieRecord {
                domain: Some("qq.com".into()),
                value: Some("pskey".into()),
                expires_at: Some(1_900_000_000),
            },
            protocol::CookieRecord {
                domain: Some("empty.qq.com".into()),
                value: Some(String::new()),
                expires_at: None,
            },
        ],
    }]);
    let operations = Operations::new(client.clone());
    let domains = vec!["qq.com".into(), "empty.qq.com".into()];
    let cookies = operations.fetch_cookies(&domains).await.unwrap();
    assert_eq!(cookies.get("qq.com").map(String::as_str), Some("pskey"));
    assert_eq!(cookies.get("empty.qq.com").map(String::as_str), Some(""));
    let requests = client.requests.lock().unwrap();
    assert_eq!(requests[0].0, "OidbSvcTrpcTcp.0x102a_0");
    assert_eq!(
        request::<protocol::CookiesRequest>(&requests[0].1).domains,
        domains
    );
    drop(requests);
    let malformed = Operations::new(ScriptedClient::new(vec![protocol::CookiesResponse {
        cookies: vec![protocol::CookieRecord {
            domain: Some("qq.com".into()),
            value: None,
            expires_at: None,
        }],
    }]));
    assert!(matches!(
        malformed.fetch_cookies(&domains).await,
        Err(Error::Malformed(_))
    ));
    let client = ScriptedClient::new(vec![
        protocol::ClientKeyResponse {
            key: Some("client-secret".into()),
            expiration: Some(1234),
        },
        protocol::ClientKeyResponse {
            key: Some(String::new()),
            expiration: None,
        },
    ]);
    let operations = Operations::new(client.clone());
    let key = operations.fetch_client_key().await.unwrap();
    assert_eq!(key.key, "client-secret");
    assert_eq!(key.expiration, 1234);
    assert!(matches!(
        operations.fetch_client_key().await,
        Err(Error::Malformed(_))
    ));
    let requests = client.requests.lock().unwrap();
    assert_eq!(requests[0].0, "OidbSvcTrpcTcp.0x102a_1");
    assert_eq!(envelope(&requests[0].1).body, Some(Bytes::new()));
}

#[tokio::test]
async fn status_requests_preserve_zero_fields_and_custom_status() {
    let client = ScriptedClient::new(Vec::<protocol::Empty>::new());
    for _ in 0..2 {
        client.replies.lock().unwrap().push_back(
            protocol::StatusResponse {
                code: Some(0),
                message: None,
            }
            .encode_to_vec()
            .into(),
        );
    }
    let operations = Operations::new(client.clone());
    assert!(operations.set_status(0).await.unwrap());
    assert!(operations.set_custom_status(0, "").await.unwrap());
    let requests = client.requests.lock().unwrap();
    for (command, _) in requests.iter() {
        assert_eq!(
            command,
            "trpc.qq_new_tech.status_svc.StatusService.SetStatus"
        );
    }
    let status = protocol::StatusRequest::decode(requests[0].1.clone()).unwrap();
    assert_eq!(
        (status.status, status.extended_status, status.battery),
        (Some(0), Some(0), Some(0))
    );
    assert!(status.custom.is_none());
    let status = protocol::StatusRequest::decode(requests[1].1.clone()).unwrap();
    assert_eq!(
        (status.status, status.extended_status, status.battery),
        (Some(10), Some(2000), Some(0))
    );
    let custom = status.custom.unwrap();
    assert_eq!(custom.face_id, Some(0));
    assert_eq!(custom.text.as_deref(), Some(""));
    assert_eq!(custom.enabled, Some(1));
}

#[tokio::test]
async fn filtered_notifications_decode_users_and_preserve_pagination_defaults() {
    let client = ScriptedClient::new(vec![protocol::NotificationListResponse {
        notifications: vec![protocol::NotificationRecord {
            sequence: Some(55),
            r#type: Some(1),
            state: Some(1),
            group: Some(protocol::NotificationGroup { uin: Some(123) }),
            target: Some(protocol::NotificationUser {
                uid: Some("u_self".into()),
            }),
            inviter: Some(protocol::NotificationUser {
                uid: Some("u_self".into()),
            }),
            operator: None,
            comment: Some("Join".into()),
        }],
    }]);
    let operations = Operations::new(client.clone());
    let notifications = operations
        .fetch_filtered_group_notifications(0, 0)
        .await
        .unwrap();
    assert_eq!(notifications.len(), 1);
    let notification = &notifications[0];
    assert_eq!((notification.group_uin, notification.sequence), (123, 55));
    assert_eq!(
        (notification.target.uin, notification.target.uid.as_str()),
        (42, "u_self")
    );
    assert_eq!(notification.inviter.as_ref().unwrap().uin, 42);
    assert!(notification.operator_user.is_none());
    assert_eq!(notification.comment, "Join");
    assert!(notification.is_filtered);
    let requests = client.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].0, "OidbSvcTrpcTcp.0x10c0_2");
    let body: protocol::NotificationListRequest = request(&requests[0].1);
    assert_eq!((body.count, body.start), (Some(0), Some(0)));
}

#[tokio::test]
async fn member_list_decodes_binary_rich_cards_without_losing_other_members() {
    let bytes = hex::decode("087b12240a0b1207755f706c61696e207b5205506c61696e5a0e120ce699aee9809ae5908de7898712350a0b1206755f7269636820c8035204526963685a200801121c0a030a01ff0a081206e5bda9e889b20a081206e5908de78987109b27").unwrap();
    let response = protocol::MemberListResponse::decode(bytes.as_slice()).unwrap();
    let client = ScriptedClient::new(vec![response]);
    let operations = Operations::new(client);
    let members = operations.fetch_members(123, false).await.unwrap();
    assert_eq!(
        members.iter().map(|member| member.card.as_deref()).collect::<Vec<_>>(),
        vec![Some("普通名片"), Some("彩色名片")]
    );
    assert_eq!(operations.resolve_uid(123, None).await.unwrap(), "u_plain");
    assert_eq!(operations.resolve_uid(456, None).await.unwrap(), "u_rich");
}

#[test]
fn member_card_format_and_presence_are_not_guessed_from_bytes() {
    let plain = protocol::MemberCard {
        rich: Some(false),
        card: Some(Bytes::from_static(b"\x0a\x03abc")),
    };
    assert_eq!(decode_member_card(plain).unwrap().as_deref(), Some("\n\u{3}abc"));
    assert_eq!(
        decode_member_card(protocol::MemberCard {
            rich: Some(true),
            card: None,
        }).unwrap(),
        None
    );
    assert_eq!(
        decode_member_card(protocol::MemberCard {
            rich: Some(true),
            card: Some(Bytes::new()),
        }).unwrap().as_deref(),
        Some("")
    );
}

#[test]
fn malformed_rich_member_card_does_not_become_display_text() {
    let card = protocol::MemberCard {
        rich: Some(true),
        card: Some(Bytes::from_static(b"\x0a\xff")),
    };
    assert!(matches!(decode_member_card(card), Err(Error::Malformed(_))));
}
