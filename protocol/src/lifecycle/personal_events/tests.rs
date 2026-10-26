use super::*;
use crate::personal_events::{Checkpoint, Coordinator, Source};

fn envelope(body: impl Into<Bytes>) -> Bytes {
    OidbEnvelope {
        command: Some(0x1092),
        service: Some(0),
        body: Some(body.into()),
        ..Default::default()
    }
    .encode_to_vec()
    .into()
}

fn event_response(cursor: &[u8], events: Vec<Bytes>) -> Bytes {
    let group = pb::PersonalEventGroup {
        group_uin: Some(42),
        events,
    }
    .encode_to_vec();
    envelope(
        pb::PersonalEventsResponse {
            result: Some(0),
            groups: vec![group.into()],
            cursor: Some(Bytes::copy_from_slice(cursor)),
            ..Default::default()
        }
        .encode_to_vec(),
    )
}

fn record(event_type: u64, sequence: u64, value: u64) -> Bytes {
    pb::PersonalEventRecord {
        event_type: Some(event_type),
        message_seq: Some(sequence),
        field_5: Some(value),
        ..Default::default()
    }
    .encode_to_vec()
    .into()
}

fn coordinator() -> Coordinator {
    let coordinator = Coordinator::default();
    coordinator.replace_identity(10001, "u_account");
    coordinator
}

#[test]
fn request_uses_the_restored_personal_cursor_including_initial_empty_presence() {
    let initial: OidbEnvelope = crate::proto::decode(build(None)).unwrap();
    assert_eq!((initial.command, initial.service), (Some(0x1092), Some(0)));
    let request: pb::PersonalEventsRequest = crate::proto::decode(initial.body.unwrap()).unwrap();
    assert_eq!(request.cursor, Some(Bytes::new()));
    let coordinator = coordinator();
    coordinator
        .restore(
            Checkpoint {
                account: 10001,
                uid: "u_account".into(),
                cursor: Some(Bytes::from_static(b"personal-cursor")),
                ..Default::default()
            },
            10001,
            "u_account",
        )
        .unwrap();
    let (_, cursor) = coordinator
        .begin(3, 10001, "u_account", &CancellationToken::new())
        .unwrap();
    let resumed: OidbEnvelope = crate::proto::decode(build(cursor)).unwrap();
    let request: pb::PersonalEventsRequest = crate::proto::decode(resumed.body.unwrap()).unwrap();
    assert_eq!(
        request.cursor.as_deref(),
        Some(b"personal-cursor".as_slice())
    );
}

#[test]
fn native_records_decode_without_inventing_event_semantics() {
    let body = Bytes::from_static(&[
        0x08, 0x00, 0x1a, 0x10, 0x08, 0x2a, 0x12, 0x0c, 0x08, 0x07, 0x10, 0x64, 0x18, 0x08, 0x20,
        0x09, 0x28, 0x0a, 0x48, 0x37, 0x22, 0x03, b'n', b'e', b'w',
    ]);
    let decoded = decode(envelope(body.clone())).unwrap();
    assert_eq!(decoded.cursor.as_deref(), Some(b"new".as_slice()));
    assert_eq!(decoded.raw_response, body);
    let group = &decoded.groups[0];
    assert_eq!(group.group_uin, 42);
    let event = &group.events[0];
    assert_eq!(event.event_type, Some(7));
    assert_eq!(event.message_seq, Some(100));
    assert_eq!(
        (event.field_3, event.field_4, event.field_5),
        (Some(8), Some(9), Some(10))
    );
    assert_eq!(
        event.raw.as_ref(),
        &[
            0x08, 0x07, 0x10, 0x64, 0x18, 0x08, 0x20, 0x09, 0x28, 0x0a, 0x48, 0x37
        ]
    );
}

#[test]
fn message_box_consumption_merges_by_type_and_sequence_atomically() {
    let coordinator = coordinator();
    let cancel = CancellationToken::new();
    let (first, _) = coordinator.begin(1, 10001, "u_account", &cancel).unwrap();
    coordinator
        .finish(
            &first,
            decode(event_response(
                b"old",
                vec![record(7, 100, 1), record(8, 100, 2)],
            )),
        )
        .unwrap();
    let (second, cursor) = coordinator.begin(2, 10001, "u_account", &cancel).unwrap();
    assert_eq!(cursor.as_deref(), Some(b"old".as_slice()));
    let mut changes = coordinator.subscribe();
    changes.borrow_and_update();
    coordinator
        .finish(
            &second,
            decode(event_response(
                b"new",
                vec![record(7, 100, 3), record(7, 99, 4), record(900001, 100, 5)],
            )),
        )
        .unwrap();
    assert!(changes.has_changed().unwrap());
    let snapshot = coordinator.snapshot();
    assert_eq!(
        snapshot.checkpoint.cursor.as_deref(),
        Some(b"new".as_slice())
    );
    let message_box = &snapshot.checkpoint.groups[&42];
    assert_eq!(
        message_box.events[&7].keys().copied().collect::<Vec<_>>(),
        vec![99, 100]
    );
    assert_eq!(message_box.events[&7][&100].field_5, Some(3));
    assert_eq!(message_box.events[&8][&100].field_5, Some(2));
    assert_eq!(message_box.events[&900001][&100].field_5, Some(5));
    assert!(!snapshot.fetching);
    assert!(snapshot.complete);
}

#[test]
fn malformed_later_group_and_business_errors_preserve_cursor_and_boxes() {
    let coordinator = coordinator();
    let cancel = CancellationToken::new();
    let (first, _) = coordinator.begin(1, 10001, "u_account", &cancel).unwrap();
    coordinator
        .finish(
            &first,
            decode(event_response(b"old", vec![record(7, 100, 1)])),
        )
        .unwrap();
    let valid_group = pb::PersonalEventGroup {
        group_uin: Some(42),
        events: vec![record(7, 101, 9)],
    }
    .encode_to_vec();
    let malformed = envelope(
        pb::PersonalEventsResponse {
            result: Some(0),
            cursor: Some(Bytes::from_static(b"must-not-commit")),
            groups: vec![valid_group.into(), Bytes::from_static(&[0x08])],
            ..Default::default()
        }
        .encode_to_vec(),
    );
    let (second, _) = coordinator.begin(2, 10001, "u_account", &cancel).unwrap();
    assert!(coordinator.finish(&second, decode(malformed)).is_err());
    let snapshot = coordinator.snapshot();
    assert_eq!(
        snapshot.checkpoint.cursor.as_deref(),
        Some(b"old".as_slice())
    );
    assert_eq!(
        snapshot.checkpoint.groups[&42].events[&7][&100].field_5,
        Some(1)
    );
    assert!(!snapshot.checkpoint.groups[&42].events[&7].contains_key(&101));
    assert!(!snapshot.fetching);
    assert!(!snapshot.complete);
    let (third, _) = coordinator.begin(3, 10001, "u_account", &cancel).unwrap();
    let rejected = envelope(
        pb::PersonalEventsResponse {
            result: Some(17),
            cursor: Some(Bytes::from_static(b"rejected")),
            ..Default::default()
        }
        .encode_to_vec(),
    );
    assert!(matches!(
        coordinator.finish(&third, decode(rejected)),
        Err(Error::Server { code: 17, .. })
    ));
    assert_eq!(
        coordinator.snapshot().checkpoint.cursor.as_deref(),
        Some(b"old".as_slice())
    );
}

#[test]
fn singleflight_and_late_generation_cannot_publish() {
    let coordinator = coordinator();
    let cancel = CancellationToken::new();
    let (old, _) = coordinator.begin(1, 10001, "u_account", &cancel).unwrap();
    assert!(coordinator.begin(1, 10001, "u_account", &cancel).is_none());
    let (current, _) = coordinator.begin(2, 10001, "u_account", &cancel).unwrap();
    assert!(old.cancel.is_cancelled());
    assert!(matches!(
        coordinator.finish(
            &old,
            decode(event_response(b"old", vec![record(7, 100, 1)]))
        ),
        Err(Error::Disconnected)
    ));
    assert!(coordinator.snapshot().fetching);
    coordinator
        .finish(
            &current,
            decode(event_response(b"current", vec![record(7, 101, 2)])),
        )
        .unwrap();
    assert!(coordinator.begin(2, 10001, "u_account", &cancel).is_none());
    assert_eq!(
        coordinator.snapshot().checkpoint.cursor.as_deref(),
        Some(b"current".as_slice())
    );
}

#[test]
fn cancellation_and_account_replacement_reject_late_results() {
    let coordinator = coordinator();
    let cancel = CancellationToken::new();
    let (binding, _) = coordinator.begin(1, 10001, "u_account", &cancel).unwrap();
    cancel.cancel();
    assert!(matches!(
        coordinator.finish(
            &binding,
            decode(event_response(b"late", vec![record(7, 100, 1)]))
        ),
        Err(Error::Disconnected)
    ));
    coordinator.abort(&binding);
    assert!(!coordinator.snapshot().fetching);
    assert!(coordinator.snapshot().checkpoint.cursor.is_none());
    let cancel = CancellationToken::new();
    let (binding, _) = coordinator.begin(2, 10001, "u_account", &cancel).unwrap();
    coordinator.replace_identity(10001, "u_replaced");
    assert!(matches!(
        coordinator.finish(
            &binding,
            decode(event_response(b"wrong-uid", vec![record(7, 100, 1)]))
        ),
        Err(Error::Disconnected)
    ));
    assert_eq!(coordinator.snapshot().checkpoint.uid, "u_replaced");
    assert!(coordinator.snapshot().checkpoint.groups.is_empty());
    let (binding, _) = coordinator.begin(3, 10001, "u_replaced", &cancel).unwrap();
    coordinator.replace_identity(10002, "u_replaced");
    assert!(matches!(
        coordinator.finish(&binding, decode(event_response(b"wrong-account", vec![]))),
        Err(Error::Disconnected)
    ));
}

#[test]
fn checkpoint_restore_is_scoped_and_never_replays_as_a_live_batch() {
    let coordinator = coordinator();
    let cancel = CancellationToken::new();
    let (binding, _) = coordinator.begin(1, 10001, "u_account", &cancel).unwrap();
    let batch = coordinator
        .finish(
            &binding,
            decode(event_response(b"saved", vec![record(900001, 100, 1)])),
        )
        .unwrap();
    assert_eq!(batch.source, Source::FirstViewPersonalEvents);
    assert_eq!(
        (batch.generation, batch.account, batch.uid.as_str()),
        (1, 10001, "u_account")
    );
    let saved = serde_json::to_vec(&coordinator.snapshot().checkpoint).unwrap();
    let restored: Checkpoint = serde_json::from_slice(&saved).unwrap();
    let replacement = Coordinator::default();
    assert!(
        replacement
            .restore(restored.clone(), 10001, "u_wrong")
            .is_err()
    );
    replacement.restore(restored, 10001, "u_account").unwrap();
    let snapshot = replacement.snapshot();
    assert_eq!(
        snapshot.checkpoint.cursor.as_deref(),
        Some(b"saved".as_slice())
    );
    assert_eq!(
        snapshot.checkpoint.groups[&42].events[&900001][&100].field_5,
        Some(1)
    );
    assert!(snapshot.last_batch.is_none());
    assert_eq!(snapshot.generation, None);
    assert!(!snapshot.complete);
}

#[test]
fn absent_cursor_and_empty_event_status_do_not_clear_persisted_state() {
    let coordinator = coordinator();
    let cancel = CancellationToken::new();
    let (binding, _) = coordinator.begin(1, 10001, "u_account", &cancel).unwrap();
    coordinator
        .finish(
            &binding,
            decode(event_response(b"saved", vec![record(7, 100, 1)])),
        )
        .unwrap();
    let (binding, _) = coordinator.begin(2, 10001, "u_account", &cancel).unwrap();
    let no_events = envelope(
        pb::PersonalEventsResponse {
            result: Some(NO_EVENTS),
            ..Default::default()
        }
        .encode_to_vec(),
    );
    coordinator.finish(&binding, decode(no_events)).unwrap();
    let snapshot = coordinator.snapshot();
    assert_eq!(
        snapshot.checkpoint.cursor.as_deref(),
        Some(b"saved".as_slice())
    );
    assert_eq!(
        snapshot.checkpoint.groups[&42].events[&7][&100].field_5,
        Some(1)
    );
    assert!(snapshot.complete);
    assert!(snapshot.last_batch.unwrap().groups.is_empty());
}

#[test]
fn records_without_classification_are_preserved_instead_of_acknowledged() {
    let coordinator = coordinator();
    let cancel = CancellationToken::new();
    let raw = Bytes::from_static(&[0x48, 0x37]);
    let (binding, _) = coordinator.begin(1, 10001, "u_account", &cancel).unwrap();
    coordinator
        .finish(
            &binding,
            decode(event_response(b"saved", vec![raw.clone()])),
        )
        .unwrap();
    let snapshot = coordinator.snapshot();
    let message_box = &snapshot.checkpoint.groups[&42];
    assert!(message_box.events.is_empty());
    assert_eq!(message_box.unclassified_events[0].raw, raw);
    assert_eq!(
        message_box.unclassified_events[0].source,
        Source::FirstViewPersonalEvents
    );
    assert_eq!(message_box.unclassified_events[0].event_type, None);
    assert_eq!(message_box.unclassified_events[0].message_seq, None);
}
