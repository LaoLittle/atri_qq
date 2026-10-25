use super::*;

fn message(text: &str, sequence: u64) -> Bytes {
    proto::guild::ChannelMessage {
        head: Some(proto::guild::MessageHead {
            routing: Some(proto::guild::RoutingHead {
                guild_id: Some(11),
                channel_id: Some(22),
                sender_tiny_id: Some(33),
                ..Default::default()
            }),
            content: Some(proto::guild::ContentHead {
                message_type: Some(3840),
                sequence: Some(sequence),
                ..Default::default()
            }),
        }),
        body: Some(codec::encode_text(text)),
        ..Default::default()
    }
    .encode_to_vec()
    .into()
}

#[test]
fn compressed_batches_use_raw_lz4_for_every_nonzero_flag_and_preserve_unknown_notifications() {
    let large = "a".repeat(16384);
    let batch = proto::guild::CompressedMessages {
        messages: vec![
            message(&large, 1),
            Bytes::from_static(b"\x80"),
            message("tail", 2),
        ],
    }
    .encode_to_vec();
    let raw: Bytes = proto::guild::OnlinePush {
        messages: vec![message("not the compressed batch", 3)],
        compression_flag: Some(7),
        compressed_messages: Some(lz4_flex::block::compress(&batch).into()),
        ..Default::default()
    }
    .encode_to_vec()
    .into();
    let events = decode_events(raw.clone(), Some(33), 99).unwrap();
    let [
        GuildEvent::Message { message: first },
        GuildEvent::Message { message: last },
        GuildEvent::Opaque { command, payload },
    ] = events.as_slice()
    else {
        panic!("Known messages on both sides of an invalid record must survive");
    };
    assert_eq!(first.elements, [GuildElement::Text { text: large }]);
    assert!(first.is_self);
    assert_eq!(
        last.elements,
        [GuildElement::Text {
            text: "tail".into()
        }]
    );
    assert_eq!(last.sequence, Some(2));
    assert_eq!(command, PUSH_COMMAND);
    assert_eq!(payload.as_slice(), raw.as_ref());
}

#[test]
fn corrupt_or_oversized_lz4_is_not_a_successful_empty_batch() {
    let compressed = lz4_flex::block::compress(&[b'x'; 8192]);
    assert!(matches!(
        decompress_messages(&compressed, 1024),
        Err(Error::Malformed(_))
    ));
    assert!(matches!(
        decompress_messages(b"\xf0\x00", 1024),
        Err(Error::Malformed(_))
    ));
    assert!(matches!(
        decompress_messages(b"\x00", 1024),
        Err(Error::Malformed(_))
    ));
    let raw = proto::guild::OnlinePush {
        compression_flag: Some(1),
        ..Default::default()
    }
    .encode_to_vec()
    .into();
    assert!(matches!(
        decode_events(raw, None, 0),
        Err(Error::Malformed(_))
    ));
}

#[test]
fn direct_messages_are_notifications_instead_of_public_channel_messages() {
    let mut direct: proto::guild::ChannelMessage = proto::decode(message("private", 1)).unwrap();
    direct
        .head
        .as_mut()
        .unwrap()
        .routing
        .as_mut()
        .unwrap()
        .direct_message_flag = Some(1);
    let raw: Bytes = proto::guild::OnlinePush {
        messages: vec![direct.encode_to_vec().into(), message("public", 2)],
        ..Default::default()
    }
    .encode_to_vec()
    .into();
    let events = decode_events(raw.clone(), None, 0).unwrap();
    assert!(
        matches!(&events[0], GuildEvent::Message { message } if message.elements == [GuildElement::Text { text: "public".into() }])
    );
    assert!(
        matches!(&events[1], GuildEvent::Opaque { payload, .. } if payload.as_slice() == raw.as_ref())
    );
}

#[test]
fn send_transport_success_does_not_mask_business_or_transfer_refusal() {
    let response = proto::guild::SendResponse {
        result: Some(4001),
        error: Some(Bytes::from_static(b"refused")),
        transfer: Some(proto::guild::TransferResult {
            code: Some(4002),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(matches!(
        decode_send_response(11, 22, 7, response.encode_to_vec().into()),
        Err(Error::Server { code: 4001, .. })
    ));
    let response = proto::guild::SendResponse {
        result: Some(0),
        transfer: Some(proto::guild::TransferResult {
            code: Some(4002),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(matches!(
        decode_send_response(11, 22, 7, response.encode_to_vec().into()),
        Err(Error::Server { code: 4002, .. })
    ));
}

#[test]
fn accepted_send_with_zero_server_sequence_and_time_keeps_a_client_reference() {
    let response = proto::guild::SendResponse {
        result: Some(0),
        send_time: Some(0),
        head: Some(proto::guild::MessageHead {
            content: Some(proto::guild::ContentHead {
                sequence: Some(0),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    let receipt = decode_send_response(11, 22, 7, response.encode_to_vec().into()).unwrap();
    assert_eq!(receipt.sequence, Some(0));
    assert_eq!(receipt.time, Some(0));
    assert!(receipt.sequence.filter(|value| *value > 0).is_some() || receipt.random > 0);
}
