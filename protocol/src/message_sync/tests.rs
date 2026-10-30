use super::*;
use crate::{
    Keystore, Profile,
    messages::{MessageElement, encode_elements},
    proto::messages as wire,
};
use prost::Message as _;

fn session() -> SessionState {
    SessionState {
        profile: Profile::linux(),
        platform: crate::models::PlatformState::Linux {
            machine_id: "synthetic-sync-device".into(),
        },
        keystore: Keystore {
            uin: 42,
            uid: "u_synthetic_self".into(),
            ..Default::default()
        },
        online: false,
    }
}
fn begin(
    coordinator: &Coordinator,
    session: &SessionState,
    generation: u64,
) -> (Arc<Binding>, Request, u32) {
    let (binding, action) = coordinator.begin(
        generation,
        session,
        &CancellationToken::new(),
        crate::login::info_sync(session, false),
    );
    let request = coordinator.prepare(&binding, action).unwrap();
    let Request::Info { body, .. } = &request else {
        panic!("expected InfoSync");
    };
    let random = body.request_random.unwrap();
    (binding, request, random)
}
fn message(group: Option<u64>, sequence: u64, time: u64) -> Bytes {
    wire::CommonMessage {
        routing_head: Some(wire::RoutingHead {
            sender_uin: Some(123),
            sender_uid: "u_synthetic_peer".into(),
            recipient_uin: Some(42),
            recipient_uid: "u_synthetic_self".into(),
            group: group.map(|uin| wire::CommonGroup {
                uin: Some(uin),
                ..Default::default()
            }),
            ..Default::default()
        }),
        content_head: Some(wire::ContentHead {
            message_type: Some(if group.is_some() { 82 } else { 166 }),
            sequence: Some(sequence),
            client_sequence: Some(sequence + 1000),
            time: Some(time),
            ..Default::default()
        }),
        message_body: encode_elements(&[MessageElement::Text("ping".into())], &[])
            .unwrap()
            .into(),
    }
    .encode_to_vec()
    .into()
}
fn ingest(
    coordinator: &Coordinator,
    session: &SessionState,
    generation: u64,
    push: pb::InfoSyncPush,
) -> Vec<Action> {
    coordinator
        .ingest(generation, session, INFO_PUSH, push.encode_to_vec().into())
        .unwrap()
        .2
}
fn c2c(random: u32, stage: u32, cookie: &'static [u8], messages: Vec<Bytes>) -> pb::InfoSyncPush {
    pb::InfoSyncPush {
        request_random: Some(random),
        stage: Some(stage),
        c2c_messages: Some(pb::C2cMessages {
            current_cookie: Some(Bytes::from_static(cookie)),
            previous_cookie: Some(Bytes::from_static(b"independent-previous")),
            conversations: vec![pb::C2cConversation {
                last_message_time: Some(99999),
                messages,
                ..Default::default()
            }],
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[test]
fn first_view_consumes_history_before_committing_opaque_cookies_and_actual_max_time() {
    let coordinator = Coordinator::default();
    let session = session();
    let (binding, request, random) = begin(&coordinator, &session, 7);
    let response = auth::InfoSyncResponse {
        register: Some(auth::InfoSyncRegisterResponse {
            message: Some("register success".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(
        coordinator
            .direct(&binding, &request, Ok(response.encode_to_vec().into()))
            .is_empty()
    );
    assert!(!coordinator.snapshot().first_view_complete);
    ingest(
        &coordinator,
        &session,
        7,
        c2c(random + 1, 2, b"wrong", vec![message(None, 1, 800)]),
    );
    assert!(coordinator.snapshot().batches.is_empty());
    ingest(
        &coordinator,
        &session,
        7,
        c2c(
            random,
            1,
            b"\x08\x96\x01\x42\x03raw",
            vec![message(None, 2, 300), message(None, 1, 200)],
        ),
    );
    let snapshot = coordinator.snapshot();
    assert!(snapshot.checkpoint.current_cookie.is_empty());
    assert_eq!(snapshot.batches[0].source, Source::FirstView);
    assert_eq!(snapshot.batches[0].messages[0].sequence, 1001);
    assert!(
        matches!(&snapshot.batches[0].messages[0].elements[0], MessageElement::Text(text) if text == "ping")
    );
    ingest(
        &coordinator,
        &session,
        7,
        pb::InfoSyncPush {
            request_random: Some(random),
            stage: Some(2),
            ..Default::default()
        },
    );
    let snapshot = coordinator.snapshot();
    assert_eq!(
        snapshot.checkpoint.current_cookie.as_ref(),
        b"\x08\x96\x01\x42\x03raw"
    );
    assert_eq!(
        snapshot.checkpoint.previous_cookie.as_ref(),
        b"independent-previous"
    );
    assert_eq!(snapshot.checkpoint.c2c_last_message_time, 300);
    assert!(snapshot.first_view_complete && snapshot.additional_complete);
    assert!(!snapshot.protocol_complete);
    assert!(
        ingest(
            &coordinator,
            &session,
            7,
            pb::InfoSyncPush {
                request_random: Some(random),
                stage: Some(4),
                ..Default::default()
            }
        )
        .is_empty()
    );
    assert_eq!(coordinator.snapshot().sent_flag, 1759);
    assert!(coordinator.snapshot().protocol_complete);
}

#[test]
fn malformed_message_rolls_back_the_whole_packet_and_its_cookie_candidate() {
    let coordinator = Coordinator::default();
    let session = session();
    let (_, _, random) = begin(&coordinator, &session, 7);
    ingest(
        &coordinator,
        &session,
        7,
        c2c(random, 1, b"accepted", vec![message(None, 1, 100)]),
    );
    let failed = c2c(
        random,
        2,
        b"unconsumed",
        vec![message(None, 2, 900), Bytes::from_static(b"\x80")],
    );
    assert!(
        coordinator
            .ingest(7, &session, INFO_PUSH, failed.encode_to_vec().into())
            .is_err()
    );
    ingest(
        &coordinator,
        &session,
        7,
        pb::InfoSyncPush {
            request_random: Some(random),
            stage: Some(2),
            ..Default::default()
        },
    );
    let snapshot = coordinator.snapshot();
    assert_eq!(snapshot.batches.len(), 1);
    assert_eq!(snapshot.batches[0].messages.len(), 1);
    assert_eq!(snapshot.checkpoint.current_cookie.as_ref(), b"accepted");
    assert_eq!(snapshot.checkpoint.c2c_last_message_time, 100);
}

#[test]
fn partial_mask_waits_for_stage_four_then_retries_only_the_failed_flag_once() {
    let coordinator = Coordinator::default();
    let session = session();
    let (binding, old_request, random) = begin(&coordinator, &session, 7);
    let actions = ingest(
        &coordinator,
        &session,
        7,
        pb::InfoSyncPush {
            result: Some(0x05f5e3c0),
            ..c2c(random, 2, b"consumed", vec![message(None, 1, 100)])
        },
    );
    assert!(actions.is_empty());
    assert!(coordinator.snapshot().first_view_complete);
    assert_eq!(coordinator.snapshot().retry_mask, 1);
    let mut actions = ingest(
        &coordinator,
        &session,
        7,
        pb::InfoSyncPush {
            request_random: Some(random),
            stage: Some(4),
            ..Default::default()
        },
    );
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].delay, Duration::from_secs(3));
    ingest(
        &coordinator,
        &session,
        7,
        c2c(random, 2, b"stale", vec![message(None, 2, 900)]),
    );
    let request = coordinator.prepare(&binding, actions.remove(0)).unwrap();
    let Request::Info { body, .. } = &request else {
        panic!("expected InfoSync retry");
    };
    assert_eq!(body.sync_flag, Some(1));
    assert!(body.register.is_none());
    assert_eq!(
        body.sync.as_ref().unwrap().current_cookie.as_deref(),
        Some(b"consumed".as_slice())
    );
    assert_ne!(body.request_random, Some(random));
    assert_eq!(coordinator.snapshot().initial_flag, 1759);
    assert_eq!(coordinator.snapshot().retry_mask, 0);
    let old_response = auth::InfoSyncResponse {
        request_random: Some(random),
        register: Some(auth::InfoSyncRegisterResponse {
            message: Some("register success".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(
        coordinator
            .direct(
                &binding,
                &old_request,
                Ok(old_response.encode_to_vec().into())
            )
            .is_empty()
    );
    assert!(coordinator.registration(&binding).unwrap().unwrap().is_ok());
    let actions = ingest(
        &coordinator,
        &session,
        7,
        pb::InfoSyncPush {
            request_random: body.request_random,
            result: Some(0x05f5e3c0),
            stage: Some(4),
            ..Default::default()
        },
    );
    assert!(actions.is_empty());
    let snapshot = coordinator.snapshot();
    assert!(snapshot.protocol_complete);
    assert_eq!(snapshot.checkpoint.c2c_last_message_time, 100);
    assert_eq!(snapshot.batches.len(), 1);
}

#[test]
fn every_observed_root_result_accumulates_its_mask_without_clearing_successful_pushes() {
    for (code, expected) in [
        (0x05f5e3bd, 1759),
        (0x05f5e3be, 1759),
        (0x05f5e3bf, 1759),
        (0x05f5e3c0, 1),
        (0x05f5e3c1, 2),
        (0x05f5e3c2, 0),
        (0x05f5e3c3, 4),
        (0x05f5e3c4, 4),
        (0x05f5e3c5, 4),
        (0x05f5e3c6, 4),
        (0x05f5e3c7, 4),
        (0x05f5e3c8, 0),
        (0x05f5e3c9, 4),
        (0x05f5e3ca, 0x12),
        (0x05f5e3cb, 0),
        (0x05f5e3cc, 1759),
        (0x05f5e3cd, 1759),
        (0x05f5e3ce, 0),
        (0x05f5e3cf, 0x200),
        (17, 0),
    ] {
        let coordinator = Coordinator::default();
        let session = session();
        let (_, _, random) = begin(&coordinator, &session, 7);
        ingest(
            &coordinator,
            &session,
            7,
            pb::InfoSyncPush {
                result: Some(code),
                request_random: Some(random),
                stage: Some(1),
                ..Default::default()
            },
        );
        ingest(
            &coordinator,
            &session,
            7,
            pb::InfoSyncPush {
                request_random: Some(random),
                stage: Some(1),
                ..Default::default()
            },
        );
        assert_eq!(coordinator.snapshot().retry_mask, expected, "{code:x}");
    }
}

#[test]
fn group_additional_uses_two_sequences_server_budget_and_explicit_batch_completion() {
    let coordinator = Coordinator::default();
    let session = session();
    let (binding, request, random) = begin(&coordinator, &session, 7);
    coordinator.direct(
        &binding,
        &request,
        Ok(auth::InfoSyncResponse {
            group_replenishment: Some(1),
            register: Some(auth::InfoSyncRegisterResponse {
                message: Some("register success".into()),
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode_to_vec()
        .into()),
    );
    let mut actions = ingest(
        &coordinator,
        &session,
        7,
        pb::InfoSyncPush {
            request_random: Some(random),
            stage: Some(2),
            groups: (1..=101)
                .map(|id| pb::GroupNode {
                    group_uin: Some(id),
                    message_seq: Some(120),
                    total_seq: Some(140),
                    message_time: Some(id),
                    mask: Some(2),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        },
    );
    assert_eq!(actions.len(), 1);
    let first = coordinator.prepare(&binding, actions.remove(0)).unwrap();
    let Request::Group { body, .. } = &first else {
        panic!("expected group additional");
    };
    assert_eq!(body.groups.len(), 100);
    assert_eq!(body.groups[0].group_uin, Some(101));
    assert_eq!(
        (body.groups[0].begin_seq, body.groups[0].end_seq),
        (Some(106), Some(120))
    );
    assert_eq!(body.groups[0].pull_system_message_count, Some(15));
    assert_eq!(body.groups[0].aio_message_count, Some(1));
    assert_eq!(body.groups[1].begin_seq, Some(120));
    assert_eq!(body.groups[1].pull_system_message_count, Some(1));
    assert_eq!(body.groups[1].aio_message_count, None);
    let group_random = body.request_random.unwrap();
    let response = pb::GroupSyncResponse {
        request_random: Some(group_random),
        ..Default::default()
    };
    assert!(
        coordinator
            .direct(&binding, &first, Ok(response.encode_to_vec().into()))
            .is_empty()
    );
    assert!(!coordinator.snapshot().additional_complete);
    let push = pb::GroupMsgPush {
        request_random: Some(group_random + 1),
        flag: Some(2),
        groups: vec![pb::GroupMessageResult {
            group_uin: Some(101),
            messages: vec![message(Some(101), 119, 222)],
            ..Default::default()
        }],
    };
    coordinator
        .ingest(7, &session, GROUP_PUSH, push.encode_to_vec().into())
        .unwrap();
    assert!(coordinator.snapshot().batches.is_empty());
    let push = pb::GroupMsgPush {
        request_random: Some(group_random),
        flag: Some(1),
        groups: vec![
            pb::GroupMessageResult {
                group_uin: Some(101),
                messages: vec![message(Some(101), 119, 222)],
                server_end_seq: Some(120),
                ..Default::default()
            },
            pb::GroupMessageResult {
                result: Some(9),
                group_uin: Some(100),
                messages: vec![message(Some(100), 120, 333)],
                ..Default::default()
            },
        ],
    };
    coordinator
        .ingest(7, &session, GROUP_PUSH, push.encode_to_vec().into())
        .unwrap();
    let snapshot = coordinator.snapshot();
    assert_eq!(snapshot.batches[0].source, Source::GroupAdditional);
    assert_eq!(snapshot.batches[0].messages.len(), 1);
    assert_eq!(snapshot.checkpoint.groups[&101].received_message_seq, 119);
    assert_eq!(snapshot.checkpoint.groups[&101].total_seq, 0);
    assert!(!snapshot.checkpoint.groups.contains_key(&100));
    assert!(!snapshot.additional_complete);
    let mut actions = coordinator
        .ingest(
            7,
            &session,
            GROUP_PUSH,
            pb::GroupMsgPush {
                request_random: Some(group_random),
                flag: Some(2),
                groups: vec![],
            }
            .encode_to_vec()
            .into(),
        )
        .unwrap()
        .2;
    let second = coordinator.prepare(&binding, actions.remove(0)).unwrap();
    let Request::Group { body, .. } = &second else {
        panic!("expected second group batch");
    };
    assert_eq!(body.groups.len(), 1);
    assert_eq!(body.groups[0].group_uin, Some(1));
    assert_eq!(body.request_random, Some(group_random));
    let stale = pb::GroupSyncResponse {
        result: Some(TERMINAL_RESULT),
        request_random: Some(group_random),
        ..Default::default()
    };
    coordinator.direct(&binding, &first, Ok(stale.encode_to_vec().into()));
    assert!(!coordinator.snapshot().additional_complete);
    let stale = pb::GroupMsgPush {
        request_random: Some(group_random),
        flag: Some(2),
        groups: vec![pb::GroupMessageResult {
            group_uin: Some(101),
            ..Default::default()
        }],
    };
    coordinator
        .ingest(7, &session, GROUP_PUSH, stale.encode_to_vec().into())
        .unwrap();
    assert!(!coordinator.snapshot().additional_complete);
    let last = pb::GroupMsgPush {
        request_random: Some(group_random),
        flag: Some(2),
        groups: vec![pb::GroupMessageResult {
            result: Some(8),
            group_uin: Some(1),
            server_end_seq: Some(120),
            ..Default::default()
        }],
    };
    coordinator
        .ingest(7, &session, GROUP_PUSH, last.encode_to_vec().into())
        .unwrap();
    let snapshot = coordinator.snapshot();
    assert!(snapshot.additional_complete);
    assert_eq!(snapshot.checkpoint.group_last_message_time, 222);
    assert!(!snapshot.checkpoint.groups.contains_key(&1));
}

#[test]
fn expired_masked_and_total_only_nodes_produce_only_the_proven_ranges() {
    let coordinator = Coordinator::default();
    let session = session();
    let checkpoint = Checkpoint {
        account: 42,
        uid: session.keystore.uid.clone(),
        groups: BTreeMap::from([
            (
                1,
                GroupProgress {
                    received_message_seq: 120,
                    total_seq: 130,
                    ..Default::default()
                },
            ),
            (
                2,
                GroupProgress {
                    expired_message_seq: 120,
                    expired_total_seq: 140,
                    ..Default::default()
                },
            ),
            (
                3,
                GroupProgress {
                    clear_message_seq: Some(118),
                    clear_total_seq: Some(140),
                    ..Default::default()
                },
            ),
        ]),
        ..Default::default()
    };
    coordinator
        .restore(checkpoint, 42, &session.keystore.uid)
        .unwrap();
    let (binding, _, random) = begin(&coordinator, &session, 7);
    let mut nodes: Vec<_> = (1..=6)
        .map(|id| pb::GroupNode {
            group_uin: Some(id),
            message_seq: Some(120),
            total_seq: Some(140),
            ..Default::default()
        })
        .collect();
    nodes[3].mask = Some(3);
    nodes[4].all_message_expired = Some(true);
    nodes[5].no_further_messages = Some(true);
    let mut actions = ingest(
        &coordinator,
        &session,
        7,
        pb::InfoSyncPush {
            request_random: Some(random),
            stage: Some(2),
            groups: nodes,
            ..Default::default()
        },
    );
    let request = coordinator.prepare(&binding, actions.remove(0)).unwrap();
    let Request::Group { body, .. } = request else {
        panic!("expected group request");
    };
    assert_eq!(body.groups.len(), 2);
    let total = body
        .groups
        .iter()
        .find(|group| group.group_uin == Some(1))
        .unwrap();
    assert_eq!((total.begin_seq, total.end_seq), (None, None));
    assert_eq!(
        (total.end_total_seq, total.pull_system_message_count),
        (Some(140), Some(10))
    );
    let clear = body
        .groups
        .iter()
        .find(|group| group.group_uin == Some(3))
        .unwrap();
    assert_eq!((clear.begin_seq, clear.end_seq), (Some(120), Some(120)));
    assert_eq!(clear.end_total_seq, None);
}

#[test]
fn same_identity_reconnect_retains_checkpoint_but_cancelled_or_replaced_sessions_cannot_commit() {
    let coordinator = Coordinator::default();
    let mut session = session();
    let (old, _, random) = begin(&coordinator, &session, 7);
    ingest(
        &coordinator,
        &session,
        7,
        c2c(random, 2, b"retained", vec![message(None, 1, 100)]),
    );
    coordinator.close(7);
    assert!(old.cancel.is_cancelled());
    let (binding, request, random) = begin(&coordinator, &session, 8);
    let Request::Info { body, .. } = &request else {
        panic!("expected InfoSync");
    };
    assert_eq!(
        body.sync.as_ref().unwrap().current_cookie.as_deref(),
        Some(b"retained".as_slice())
    );
    assert_eq!(body.sync.as_ref().unwrap().last_message_time, Some(100));
    ingest(
        &coordinator,
        &session,
        7,
        c2c(random, 2, b"old-generation", vec![message(None, 2, 900)]),
    );
    binding.cancel.cancel();
    ingest(
        &coordinator,
        &session,
        8,
        c2c(random, 2, b"cancelled", vec![message(None, 2, 900)]),
    );
    assert_eq!(
        coordinator.snapshot().checkpoint.current_cookie.as_ref(),
        b"retained"
    );
    session.keystore.uid = "u_replacement_identity".into();
    coordinator.replace_identity(session.keystore.uin, &session.keystore.uid);
    let snapshot = coordinator.snapshot();
    assert!(snapshot.checkpoint.current_cookie.is_empty());
    assert!(snapshot.batches.is_empty());
    assert!(
        coordinator
            .direct(
                &binding,
                &request,
                Ok(auth::InfoSyncResponse {
                    result: Some(TERMINAL_RESULT),
                    ..Default::default()
                }
                .encode_to_vec()
                .into())
            )
            .is_empty()
    );
    assert!(
        coordinator
            .restore(
                Checkpoint {
                    account: 42,
                    uid: "u_other".into(),
                    ..Default::default()
                },
                42,
                &session.keystore.uid
            )
            .is_err()
    );
}

#[test]
fn server_delay_has_priority_and_registration_retries_use_three_then_capped_linear_backoff() {
    let coordinator = Coordinator::default();
    let session = session();
    let (binding, mut request, _) = begin(&coordinator, &session, 7);
    let Request::Info { body: original, .. } = &request else {
        panic!("expected InfoSync");
    };
    let original = original.clone();
    let mut actions = coordinator.direct(
        &binding,
        &request,
        Ok(auth::InfoSyncResponse {
            result: Some(TERMINAL_RESULT),
            delay: Some(auth::InfoSyncDelay {
                field_1: Some(1),
                field_2: Some(2),
            }),
            ..Default::default()
        }
        .encode_to_vec()
        .into()),
    );
    assert_eq!(actions[0].delay, Duration::from_secs(60));
    request = coordinator.prepare(&binding, actions.remove(0)).unwrap();
    let Request::Info { body, .. } = &request else {
        panic!("expected delayed InfoSync");
    };
    let mut replay = body.clone();
    replay.request_random = original.request_random;
    assert_eq!(replay, original);
    assert!(!coordinator.snapshot().first_view_complete);
    for seconds in [3, 30, 60, 90, 120, 150, 180, 210, 240, 270, 300, 300] {
        let mut actions = coordinator.direct(&binding, &request, Err(Error::Timeout));
        assert_eq!(actions[0].delay, Duration::from_secs(seconds));
        request = coordinator.prepare(&binding, actions.remove(0)).unwrap();
        let Request::Info { body, .. } = &request else {
            panic!("expected register retry");
        };
        assert_eq!(body.sync_flag, Some(1759));
        assert!(body.register.is_some());
    }
}

#[test]
fn unknown_system_records_remain_typed_history_without_advancing_chat_time() {
    let coordinator = Coordinator::default();
    let session = session();
    let (_, _, random) = begin(&coordinator, &session, 7);
    let raw: Bytes = wire::CommonMessage {
        routing_head: Some(wire::RoutingHead::default()),
        content_head: Some(wire::ContentHead {
            message_type: Some(528),
            time: Some(999),
            ..Default::default()
        }),
        message_body: Bytes::from_static(b"unknown-system-payload"),
    }
    .encode_to_vec()
    .into();
    ingest(
        &coordinator,
        &session,
        7,
        c2c(random, 2, b"opaque-consumed", vec![raw.clone()]),
    );
    let snapshot = coordinator.snapshot();
    assert_eq!(snapshot.batches[0].source, Source::FirstView);
    assert!(snapshot.batches[0].messages.is_empty());
    assert_eq!(snapshot.batches[0].opaque_messages, vec![raw]);
    assert_eq!(snapshot.checkpoint.c2c_last_message_time, 0);
    assert_eq!(
        snapshot.checkpoint.current_cookie.as_ref(),
        b"opaque-consumed"
    );
    assert!(snapshot.c2c_additional_complete && snapshot.group_additional_complete);
}

#[test]
fn ordinary_message_decode_failure_does_not_terminate_the_independent_guild_consumer() {
    let coordinator = Coordinator::default();
    let session = session();
    let (_, _, random) = begin(&coordinator, &session, 7);
    let guild = proto::guild::GuildFirstViewData {
        first_sync_result: Some(1),
        in_tab_nodes: vec![
            proto::guild::FirstViewGuildNode {
                guild_id: Some(99),
                ..Default::default()
            }
            .encode_to_vec()
            .into(),
        ],
        ..Default::default()
    };
    let push = pb::InfoSyncPush {
        result: Some(0x05f5e3c0),
        guild: Some(guild),
        ..c2c(random, 1, b"rejected", vec![Bytes::from_static(b"\x80")])
    };
    assert!(
        coordinator
            .ingest(7, &session, INFO_PUSH, push.encode_to_vec().into())
            .is_err()
    );
    ingest(
        &coordinator,
        &session,
        7,
        pb::InfoSyncPush {
            request_random: Some(random),
            stage: Some(4),
            guild: Some(Default::default()),
            ..Default::default()
        },
    );
    assert_eq!(coordinator.guild.snapshot(7).unwrap().guilds[0].id, 99);
    assert!(coordinator.snapshot().checkpoint.current_cookie.is_empty());
}

#[test]
fn group_progress_uses_received_tail_total_not_server_end_or_independent_max() {
    fn record(sequence: u64, total_sequence: u64, field_30: bool, message_id: u64) -> Bytes {
        let mut value = wire::CommonMessage::decode(message(Some(55), sequence, sequence)).unwrap();
        let head = value.content_head.as_mut().unwrap();
        head.total_sequence = Some(total_sequence);
        head.field_30 = Some(field_30);
        head.message_id = Some(message_id);
        value.encode_to_vec().into()
    }
    let coordinator = Coordinator::default();
    let session = session();
    let (_, _, random) = begin(&coordinator, &session, 7);
    let deliver = |messages| {
        ingest(
            &coordinator,
            &session,
            7,
            pb::InfoSyncPush {
                request_random: Some(random),
                stage: Some(2),
                group_messages: Some(pb::GroupMessages {
                    groups: vec![pb::GroupMessageResult {
                        group_uin: Some(55),
                        server_end_seq: Some(9999),
                        messages,
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let progress = coordinator.snapshot().checkpoint.groups[&55].clone();
        (progress.received_message_seq, progress.total_seq)
    };
    assert_eq!(
        deliver(vec![record(8, 99, true, 8), record(10, 3, true, 10)]),
        (10, 3)
    );
    assert_eq!(
        deliver(vec![record(11, 500, true, 11), record(12, 0, true, 12)]),
        (12, 3)
    );
    assert_eq!(
        deliver(vec![record(20, 5, true, 9), record(20, 7, true, 1)]),
        (20, 7)
    );
    assert_eq!(
        deliver(vec![record(21, 100, false, 1), record(21, 8, false, 9)]),
        (21, 8)
    );
}
