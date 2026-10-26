use super::*;
use crate::proto::o3 as pb;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    ecdsa::EcdsaSig,
    md::Md,
    nid::Nid,
    pkey::{Id, Private},
    pkey_ctx::PkeyCtx,
};

fn peer() -> ([u8; 33], EcKey<Private>) {
    peer_with_scalar(1)
}

fn peer_with_scalar(scalar: u32) -> ([u8; 33], EcKey<Private>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let private = BigNum::from_u32(scalar).unwrap();
    let mut context = BigNumContext::new().unwrap();
    let mut public = EcPoint::new(&group).unwrap();
    public
        .mul_generator2(&group, &private, &mut context)
        .unwrap();
    let encoded = public
        .to_bytes(&group, PointConversionForm::COMPRESSED, &mut context)
        .unwrap()
        .try_into()
        .unwrap();
    (
        encoded,
        EcKey::from_private_components(&group, &private, &public).unwrap(),
    )
}

fn establish_reply(body: Bytes, peer: &EcKey<Private>, token: &[u8]) -> Bytes {
    establish_reply_with_config(
        body,
        peer,
        token,
        Some(pb::ChannelConfig {
            option1: 1,
            option2: 1,
            option3: 1,
            option4: 1,
            option5: 1,
            option6: 1,
            option7: 0,
        }),
        crate::o3::unix_seconds().unwrap() + 3600,
    )
    .0
}

fn establish_reply_with_config(
    body: Bytes,
    peer: &EcKey<Private>,
    token: &[u8],
    config: Option<pb::ChannelConfig>,
    token_expires_at: u64,
) -> (Bytes, [u8; 32], Bytes) {
    let request = pb::EstablishShareKeyRequest::decode(body).unwrap();
    assert_eq!(request.method.as_ref(), b"getToken");
    let scalar = peer.private_key().to_vec_padded(32).unwrap();
    let private = crate::crypto::Ecdh::from_private(crate::crypto::Curve::P256, &scalar).unwrap();
    let shared = private
        .shared_secret(&request.client_public_key, false)
        .unwrap();
    let mut hkdf = PkeyCtx::new_id(Id::HKDF).unwrap();
    hkdf.derive_init().unwrap();
    hkdf.set_hkdf_md(Md::sha256()).unwrap();
    hkdf.set_hkdf_key(&shared).unwrap();
    hkdf.set_hkdf_salt(&[]).unwrap();
    hkdf.add_hkdf_info(&[]).unwrap();
    let mut key = [0u8; 32];
    assert_eq!(hkdf.derive(Some(&mut key)).unwrap(), 32);
    let plaintext = crate::crypto::aes_gcm_decrypt(&request.encrypted_body, &key).unwrap();
    let inner = pb::ChannelPlaintext::decode(plaintext.as_slice()).unwrap();
    assert_eq!(inner.uuid, request.channel_uuid);
    signing_engine::proto::TokenReport::decode(inner.body).unwrap();
    let mut context = BigNumContext::new().unwrap();
    let encoded = peer
        .public_key()
        .to_bytes(peer.group(), PointConversionForm::COMPRESSED, &mut context)
        .unwrap();
    let mut transcript = [0u8; 49];
    transcript[..33].copy_from_slice(&encoded);
    transcript[33..41].copy_from_slice(&inner.parameter.to_be_bytes());
    transcript[41..].copy_from_slice(&7u64.to_be_bytes());
    let signature = EcdsaSig::sign(&crate::crypto::sha256(&transcript), peer).unwrap();
    let mut raw = signature.r().to_vec_padded(32).unwrap();
    raw.extend(signature.s().to_vec_padded(32).unwrap());
    let expires_at = crate::o3::unix_seconds().unwrap() + 3600;
    let business = signing_engine::proto::IssuedTokenReply {
        token: token.to_vec(),
        expires_at: token_expires_at,
    }
    .encode_to_vec();
    let result = pb::EstablishInnerResponse {
        material: vec![raw.into()],
        parameter: 7,
        channel_time: expires_at,
        business_response: vec![business.into()],
        config,
    }
    .encode_to_vec();
    let reply = pb::EstablishShareKeyResponse {
        encrypted_body: vec![
            crate::crypto::aes_gcm_encrypt(&result, &key)
                .unwrap()
                .into(),
        ],
        status: Some(0),
    }
    .encode_to_vec()
    .into();
    (reply, key, request.channel_uuid)
}

async fn next_establish(client: &Client, queue: &mut mpsc::Receiver<Outgoing>) -> (i32, Bytes) {
    loop {
        let request = tokio::time::timeout(Duration::from_secs(5), queue.recv())
            .await
            .unwrap()
            .unwrap();
        let (sequence, command, body, _) = outgoing_d2(request.frame, &[0; 16]);
        if command == crate::o3::ESTABLISH_COMMAND {
            return (sequence, body);
        }
        assert_eq!(command, crate::o3::REPORT_COMMAND);
        client
            .receive(incoming(sequence, &command, &[], Some(&[0; 16])), 0)
            .unwrap();
    }
}

fn bind(client: &Client) {
    client.begin_signing_login().unwrap();
    client.inner.lock().unwrap().state.keystore.uin = 1234;
    client.mark_signing_ticket_complete().unwrap();
}

fn token(client: &Client) -> Vec<u8> {
    let mut inner = client.inner.lock().unwrap();
    let Inner { signer, state, .. } = &mut *inner;
    signer
        .sign("MessageSvc.PbSendMsg", 1, b"test-message", state, false)
        .unwrap()
        .unwrap()
        .token
}

async fn published(events: &mut broadcast::Receiver<LoginEvent>, selector: u32) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let LoginEvent::KeystoreChanged(keystore) = events.recv().await.unwrap() {
                if keystore.o3_xwid_switch == Some(selector) {
                    return;
                }
            }
        }
    })
    .await
    .unwrap();
}

fn assert_wire_token(
    reserved: crate::proto::sso::Reserved,
    expected_token: &[u8],
    sign_enabled: bool,
) {
    let secure = reserved.secure_info.unwrap();
    assert_eq!(secure.token.unwrap().as_ref(), expected_token);
    assert_eq!(!secure.sign.unwrap().is_empty(), sign_enabled);
}

async fn signed_message(
    client: &Client,
    queue: &mut mpsc::Receiver<Outgoing>,
    expected_token: &[u8],
    sign_enabled: bool,
) {
    client
        .send_only(
            "MessageSvc.PbSendMsg",
            Bytes::from_static(b"synthetic business message"),
            0,
        )
        .await
        .unwrap();
    loop {
        let request = tokio::time::timeout(Duration::from_secs(5), queue.recv())
            .await
            .unwrap()
            .unwrap();
        let (sequence, command, body, reserved) = outgoing_d2(request.frame, &[0; 16]);
        if command == "MessageSvc.PbSendMsg" {
            assert_eq!(body.as_ref(), b"synthetic business message");
            assert_wire_token(reserved, expected_token, sign_enabled);
            return;
        }
        assert_eq!(command, crate::o3::REPORT_COMMAND);
        client
            .receive(incoming(sequence, &command, &[], Some(&[0; 16])), 0)
            .unwrap();
    }
}

#[tokio::test]
async fn automatic_bootstrap_authenticates_before_publication_and_keeps_ack_live() {
    let (client, mut queue) = queued_client();
    let (public, peer) = peer();
    let mut events = client.login_events();
    client.start_background_work(0);
    client.start_signing_work(0, crate::o3::Channel::with_peer(public));
    bind(&client);
    let (sequence, body) = next_establish(&client, &mut queue).await;
    assert!(token(&client).is_empty());
    let descriptor = Bytes::from_static(b"required-descriptor");
    let push = auth::PushAckSource {
        required: Some(1),
        descriptors: vec![descriptor.clone()],
    }
    .encode_to_vec();
    client
        .receive(
            incoming(
                -123,
                "trpc.msg.olpush.OlPushService.MsgPush",
                &push,
                Some(&[0; 16]),
            ),
            0,
        )
        .unwrap();
    loop {
        let outgoing = tokio::time::timeout(Duration::from_secs(5), queue.recv())
            .await
            .unwrap()
            .unwrap();
        let (seq, command, body, _) = outgoing_d2(outgoing.frame, &[0; 16]);
        if command == "trpc.msg.olpush.OlPushService.SsoPushAck" {
            assert_eq!(
                auth::PushAckRequest::decode(body).unwrap().descriptors,
                vec![descriptor]
            );
            break;
        }
        assert_eq!(command, crate::o3::REPORT_COMMAND);
        client
            .receive(incoming(seq, &command, &[], Some(&[0; 16])), 0)
            .unwrap();
    }
    let reply = establish_reply(body, &peer, b"authenticated-token");
    client
        .receive(
            incoming(
                sequence,
                crate::o3::ESTABLISH_COMMAND,
                &reply,
                Some(&[0; 16]),
            ),
            0,
        )
        .unwrap();
    published(&mut events, 1).await;
    assert_eq!(token(&client), b"authenticated-token");
    let encoded = {
        let inner = client.inner.lock().unwrap();
        let mut bytes = Vec::new();
        ciborium::into_writer(&inner.state.keystore, &mut bytes).unwrap();
        bytes
    };
    let stored: Keystore = ciborium::from_reader(encoded.as_slice()).unwrap();
    assert_eq!(stored.o3_xwid_switch, Some(1));
    client.terminate("O3 bootstrap complete".into());
}

#[tokio::test]
async fn new_login_cancels_old_channel_request_and_rejects_late_token() {
    let (client, mut queue) = queued_client();
    let (public, peer) = peer();
    let mut events = client.login_events();
    client.start_background_work(0);
    client.start_signing_work(0, crate::o3::Channel::with_peer(public));
    bind(&client);
    let (old_sequence, old_body) = next_establish(&client, &mut queue).await;
    bind(&client);
    let (new_sequence, new_body) = next_establish(&client, &mut queue).await;
    assert!(
        !client
            .inner
            .lock()
            .unwrap()
            .pending
            .contains_key(&old_sequence)
    );
    let old_reply = establish_reply(old_body, &peer, b"old-token");
    client
        .receive(
            incoming(
                old_sequence,
                crate::o3::ESTABLISH_COMMAND,
                &old_reply,
                Some(&[0; 16]),
            ),
            0,
        )
        .unwrap();
    assert!(token(&client).is_empty());
    let new_reply = establish_reply(new_body, &peer, b"current-token");
    client
        .receive(
            incoming(
                new_sequence,
                crate::o3::ESTABLISH_COMMAND,
                &new_reply,
                Some(&[0; 16]),
            ),
            0,
        )
        .unwrap();
    published(&mut events, 1).await;
    assert_eq!(token(&client), b"current-token");
    client.terminate("O3 generation complete".into());
}

#[tokio::test]
async fn authenticated_config_zero_option1_and_missing_config_preserve_wire_tokens() {
    for (config, issued_token, selector, sign_enabled) in [
        (
            Some(pb::ChannelConfig {
                option1: 0,
                option2: 1,
                option6: 1,
                ..Default::default()
            }),
            &b"synthetic-option1-zero-token"[..],
            1,
            true,
        ),
        (None, &b"synthetic-missing-config-token"[..], 0, false),
    ] {
        let (client, mut queue) = queued_client();
        let (public, peer) = peer();
        let mut events = client.login_events();
        client.start_background_work(0);
        client.start_signing_work(0, crate::o3::Channel::with_peer(public));
        bind(&client);
        let (sequence, body) = next_establish(&client, &mut queue).await;
        signed_message(&client, &mut queue, b"", true).await;
        let (reply, _, _) = establish_reply_with_config(
            body,
            &peer,
            issued_token,
            config,
            crate::o3::unix_seconds().unwrap() + 3600,
        );
        client
            .receive(
                incoming(
                    sequence,
                    crate::o3::ESTABLISH_COMMAND,
                    &reply,
                    Some(&[0; 16]),
                ),
                0,
            )
            .unwrap();
        published(&mut events, selector).await;
        assert_eq!(token(&client), issued_token);
        signed_message(&client, &mut queue, issued_token, sign_enabled).await;
        assert_eq!(
            client.inner.lock().unwrap().state.keystore.o3_xwid_switch,
            Some(selector)
        );
        client.terminate("synthetic configuration regression complete".into());
    }
}

fn access_reply(key: &[u8; 32], body: &[u8]) -> Bytes {
    pb::SecureAccessResponse {
        encrypted_body: vec![crate::crypto::aes_gcm_encrypt(body, key).unwrap().into()],
        status: Some(0),
    }
    .encode_to_vec()
    .into()
}

async fn next_access(
    client: &Client,
    queue: &mut mpsc::Receiver<Outgoing>,
) -> (i32, pb::SecureAccessRequest) {
    loop {
        let outgoing = tokio::time::timeout(Duration::from_secs(5), queue.recv())
            .await
            .unwrap()
            .unwrap();
        let (sequence, command, body, _) = outgoing_d2(outgoing.frame, &[0; 16]);
        if command == crate::o3::ACCESS_COMMAND {
            return (sequence, pb::SecureAccessRequest::decode(body).unwrap());
        }
        assert_eq!(command, crate::o3::REPORT_COMMAND);
        client
            .receive(incoming(sequence, &command, &[], Some(&[0; 16])), 0)
            .unwrap();
    }
}

fn answer_access(client: &Client, sequence: i32, key: &[u8; 32], body: &[u8]) {
    let reply = access_reply(key, body);
    client
        .receive(
            incoming(sequence, crate::o3::ACCESS_COMMAND, &reply, Some(&[0; 16])),
            0,
        )
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn heartbeat_tasks_refresh_live_tokens_without_waiting_for_ack_and_reuse_channel() {
    let (client, mut queue) = queued_client();
    let (public, peer) = peer();
    client.start_background_work(0);
    client.start_signing_work(0, crate::o3::Channel::with_peer(public));
    bind(&client);
    let (sequence, body) = next_establish(&client, &mut queue).await;
    let (reply, key, uuid) = establish_reply_with_config(
        body,
        &peer,
        b"live-token",
        Some(pb::ChannelConfig {
            option2: 1,
            option4: 1,
            option6: 1,
            ..Default::default()
        }),
        crate::o3::unix_seconds().unwrap() + 7200,
    );
    client
        .receive(
            incoming(
                sequence,
                crate::o3::ESTABLISH_COMMAND,
                &reply,
                Some(&[0; 16]),
            ),
            0,
        )
        .unwrap();
    let (sequence, first) = next_access(&client, &mut queue).await;
    assert_eq!(first.method.as_ref(), b"heartbeat");
    assert_eq!(first.channel_uuid, uuid);
    let plain = crate::crypto::aes_gcm_decrypt(&first.encrypted_body, &key).unwrap();
    let first = pb::HeartbeatRequest::decode(plain.as_slice()).unwrap();
    assert_eq!(first.sequence, 0);
    let identifier = first.header.unwrap().identifier;
    let tasks = pb::HeartbeatResponse {
        identifier: Bytes::from_static(b"server-batch"),
        tasks: vec![
            pb::HeartbeatTask {
                kind: 7,
                identifier: Bytes::from_static(b"refresh"),
                ..Default::default()
            },
            pb::HeartbeatTask {
                kind: 8,
                identifier: Bytes::from_static(b"properties"),
                payload: Bytes::from_static(&[0, 16]),
            },
        ],
    };
    answer_access(&client, sequence, &key, &tasks.encode_to_vec());
    let mut ack_sequence = None;
    let mut refresh_sequence = None;
    let mut report_sequence = None;
    for _ in 0..3 {
        let (sequence, access) = next_access(&client, &mut queue).await;
        assert_eq!(access.channel_uuid, uuid);
        let plain = crate::crypto::aes_gcm_decrypt(&access.encrypted_body, &key).unwrap();
        match access.method.as_ref() {
            b"taskAck" => {
                let ack = pb::TaskAckRequest::decode(plain.as_slice()).unwrap();
                assert_eq!(ack.identifier.as_ref(), b"server-batch");
                assert_eq!(ack.header.unwrap().identifier, identifier);
                ack_sequence = Some(sequence);
            }
            b"getToken" => {
                let report = signing_engine::proto::TokenReport::decode(plain.as_slice()).unwrap();
                assert_eq!(report.previous_token, b"live-token");
                refresh_sequence = Some(sequence);
            }
            b"taskReport" => {
                let report = pb::TaskReportRequest::decode(plain.as_slice()).unwrap();
                assert_eq!(report.identifier.as_ref(), b"server-batch");
                assert_eq!(report.results[0].identifier.as_ref(), b"refresh");
                assert!(report.results[0].body.is_empty());
                assert_eq!(report.results[1].identifier.as_ref(), b"properties");
                let properties =
                    signing_engine::proto::TokenReport::decode(report.results[1].body.clone())
                        .unwrap();
                assert_eq!(properties.previous_token, b"live-token");
                assert_eq!(
                    properties
                        .properties
                        .iter()
                        .map(|property| property.id)
                        .collect::<Vec<_>>(),
                    [16]
                );
                report_sequence = Some(sequence);
            }
            method => panic!("unexpected method: {}", String::from_utf8_lossy(method)),
        }
    }
    assert!(ack_sequence.is_some());
    assert!(report_sequence.is_some());
    assert_eq!(token(&client), b"live-token");
    let issued = signing_engine::proto::IssuedTokenReply {
        token: b"refreshed-token".to_vec(),
        expires_at: crate::o3::unix_seconds().unwrap() + 7200,
    };
    answer_access(
        &client,
        refresh_sequence.unwrap(),
        &key,
        &issued.encode_to_vec(),
    );
    let empty = pb::HeartbeatResponse {
        identifier: Bytes::from_static(b"completed"),
        ..Default::default()
    }
    .encode_to_vec();
    answer_access(&client, ack_sequence.unwrap(), &key, &empty);
    answer_access(&client, report_sequence.unwrap(), &key, &empty);
    tokio::time::timeout(Duration::from_secs(1), async {
        while token(&client) != b"refreshed-token" {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::advance(Duration::from_secs(179)).await;
    assert!(queue.try_recv().is_err());
    tokio::time::advance(Duration::from_secs(1)).await;
    let (sequence, second) = next_access(&client, &mut queue).await;
    assert_eq!(second.method.as_ref(), b"heartbeat");
    assert_eq!(second.channel_uuid, uuid);
    let plain = crate::crypto::aes_gcm_decrypt(&second.encrypted_body, &key).unwrap();
    let second = pb::HeartbeatRequest::decode(plain.as_slice()).unwrap();
    assert_eq!(second.sequence, 1);
    assert_eq!(second.header.unwrap().identifier, identifier);
    answer_access(&client, sequence, &key, &empty);
    assert_eq!(token(&client), b"refreshed-token");
    client.terminate("O3 heartbeat and server tasks verified".into());
}

#[tokio::test]
async fn transport_reconnect_keeps_authenticated_channel_for_the_same_signer_scope() {
    let (client, mut queue) = queued_client();
    let (public, peer) = peer();
    let mut events = client.login_events();
    client.start_background_work(0);
    client.start_signing_work(0, crate::o3::Channel::with_peer(public));
    bind(&client);
    let (sequence, body) = next_establish(&client, &mut queue).await;
    let (reply, key, uuid) = establish_reply_with_config(
        body,
        &peer,
        b"cached-token",
        Some(pb::ChannelConfig {
            option2: 1,
            option6: 1,
            ..Default::default()
        }),
        crate::o3::unix_seconds().unwrap() + 7200,
    );
    client
        .receive(
            incoming(
                sequence,
                crate::o3::ESTABLISH_COMMAND,
                &reply,
                Some(&[0; 16]),
            ),
            0,
        )
        .unwrap();
    published(&mut events, 1).await;
    client.terminate("transport closed".into());
    let (sender, mut reconnected) = mpsc::channel(16);
    {
        let mut inner = client.inner.lock().unwrap();
        inner.generation = 1;
        inner.cancel = CancellationToken::new();
        inner.connection = Some(Connection {
            generation: 1,
            sender,
        });
        inner.signing_ready = false;
    }
    client.start_signing_work(1, crate::o3::Channel::with_peer(public));
    client.mark_signing_ticket_complete().unwrap();
    client
        .inner
        .lock()
        .unwrap()
        .signer
        .refresh_token_task()
        .unwrap();
    client.signing_work.notify_one();
    let outgoing = tokio::time::timeout(Duration::from_secs(5), reconnected.recv())
        .await
        .unwrap()
        .unwrap();
    let (_, command, body, _) = outgoing_d2(outgoing.frame, &[0; 16]);
    assert_eq!(command, crate::o3::ACCESS_COMMAND);
    let request = pb::SecureAccessRequest::decode(body).unwrap();
    assert_eq!(request.method.as_ref(), b"getToken");
    assert_eq!(request.channel_uuid, uuid);
    let plain = crate::crypto::aes_gcm_decrypt(&request.encrypted_body, &key).unwrap();
    let report = signing_engine::proto::TokenReport::decode(plain.as_slice()).unwrap();
    assert_eq!(report.previous_token, b"cached-token");
    client.terminate("O3 transport reuse verified".into());
}

#[tokio::test]
async fn reconnect_cancels_unfinished_bootstrap_without_stalling_token_work() {
    let (client, mut queue) = queued_client();
    let (public, _) = peer();
    client.start_background_work(0);
    client.start_signing_work(0, crate::o3::Channel::with_peer(public));
    bind(&client);
    let (_, old) = next_establish(&client, &mut queue).await;
    let old = pb::EstablishShareKeyRequest::decode(old).unwrap();
    client.terminate("bootstrap transport closed".into());
    let (sender, mut reconnected) = mpsc::channel(16);
    {
        let mut inner = client.inner.lock().unwrap();
        inner.generation = 1;
        inner.cancel = CancellationToken::new();
        inner.connection = Some(Connection {
            generation: 1,
            sender,
        });
        inner.signing_ready = false;
    }
    client.start_signing_work(1, crate::o3::Channel::with_peer(public));
    client.mark_signing_ticket_complete().unwrap();
    client
        .inner
        .lock()
        .unwrap()
        .signer
        .refresh_token_task()
        .unwrap();
    client.signing_work.notify_one();
    let outgoing = tokio::time::timeout(Duration::from_secs(5), reconnected.recv())
        .await
        .unwrap()
        .unwrap();
    let (_, command, body, _) = outgoing_d2(outgoing.frame, &[0; 16]);
    assert_eq!(command, crate::o3::ESTABLISH_COMMAND);
    let current = pb::EstablishShareKeyRequest::decode(body).unwrap();
    assert_ne!(current.channel_uuid, old.channel_uuid);
    assert_ne!(current.client_public_key, old.client_public_key);
    client.terminate("O3 interrupted bootstrap recovery verified".into());
}

#[tokio::test]
async fn background_peer_rotation_preserves_ack_and_applies_interval_at_next_work() {
    let (client, mut queue) = queued_client();
    let (public, first_peer) = peer();
    let (rotated_public, rotated_peer) = peer_with_scalar(2);
    let encoded: [u8; 33] = std::array::from_fn(|index| {
        let decoded = (index + 8) % 33;
        rotated_public[decoded] ^ b"3UEBOKPY"[decoded % 8]
    });
    client.start_background_work(0);
    client.start_signing_work(0, crate::o3::Channel::with_peer(public));
    bind(&client);
    let (sequence, body) = next_establish(&client, &mut queue).await;
    let (reply, first_key, first_uuid) = establish_reply_with_config(
        body,
        &first_peer,
        b"before-rotation",
        Some(pb::ChannelConfig { option2: 1, option4: 1, option6: 1, ..Default::default() }),
        crate::o3::unix_seconds().unwrap() + 7200,
    );
    client.receive(incoming(sequence, crate::o3::ESTABLISH_COMMAND, &reply, Some(&[0; 16])), 0).unwrap();
    let (sequence, heartbeat) = next_access(&client, &mut queue).await;
    assert_eq!(heartbeat.method.as_ref(), b"heartbeat");
    let tasks = pb::HeartbeatResponse {
        identifier: Bytes::from_static(b"rotation"),
        tasks: vec![
            pb::HeartbeatTask { kind: 6, identifier: Bytes::from_static(b"interval"), payload: Bytes::copy_from_slice(&61u32.to_be_bytes()) },
            pb::HeartbeatTask { kind: 9, identifier: Bytes::from_static(b"peer"), payload: Bytes::copy_from_slice(&encoded) },
            pb::HeartbeatTask { kind: 7, identifier: Bytes::from_static(b"refresh"), ..Default::default() },
            pb::HeartbeatTask { kind: 11, identifier: Bytes::from_static(b"calculation"), payload: Bytes::from_static(b"rotation payload") },
        ],
    };
    answer_access(&client, sequence, &first_key, &tasks.encode_to_vec());
    let (ack_sequence, ack) = next_access(&client, &mut queue).await;
    assert_eq!(ack.method.as_ref(), b"taskAck");
    assert_eq!(ack.channel_uuid, first_uuid);
    let plain = crate::crypto::aes_gcm_decrypt(&ack.encrypted_body, &first_key).unwrap();
    assert_eq!(pb::TaskAckRequest::decode(plain.as_slice()).unwrap().identifier.as_ref(), b"rotation");
    let (sequence, body) = next_establish(&client, &mut queue).await;
    let request = pb::EstablishShareKeyRequest::decode(body.clone()).unwrap();
    assert_eq!(request.key_identifier.as_ref(), hex::encode(encoded).as_bytes());
    let (reply, rotated_key, rotated_uuid) = establish_reply_with_config(
        body,
        &rotated_peer,
        b"after-rotation",
        Some(pb::ChannelConfig { option2: 1, option4: 1, option6: 1, ..Default::default() }),
        crate::o3::unix_seconds().unwrap() + 7200,
    );
    client.receive(incoming(sequence, crate::o3::ESTABLISH_COMMAND, &reply, Some(&[0; 16])), 0).unwrap();
    let (report_sequence, report) = next_access(&client, &mut queue).await;
    assert_eq!(report.method.as_ref(), b"taskReport");
    assert_eq!(report.channel_uuid, rotated_uuid);
    let plain = crate::crypto::aes_gcm_decrypt(&report.encrypted_body, &rotated_key).unwrap();
    let report = pb::TaskReportRequest::decode(plain.as_slice()).unwrap();
    assert_eq!(report.results.iter().map(|r| r.identifier.as_ref()).collect::<Vec<_>>(), [b"interval".as_slice(), b"peer".as_slice(), b"refresh".as_slice(), b"calculation".as_slice()]);
    assert!(report.results[..3].iter().all(|result| result.body.is_empty()));
    assert_eq!(report.results[3].body.len(), 215);
    let empty = pb::HeartbeatResponse { identifier: Bytes::from_static(b"done"), ..Default::default() }.encode_to_vec();
    answer_access(&client, ack_sequence, &first_key, &empty);
    answer_access(&client, report_sequence, &rotated_key, &empty);
    tokio::task::yield_now().await;
    assert_eq!(token(&client), b"after-rotation");
    let deadline = client.inner.lock().unwrap().o3.heartbeat.deadline().unwrap();
    tokio::time::pause();
    tokio::time::advance(deadline - Instant::now() - Duration::from_secs(1)).await;
    assert!(queue.try_recv().is_err());
    tokio::time::advance(Duration::from_secs(1)).await;
    let (sequence, heartbeat) = next_access(&client, &mut queue).await;
    assert_eq!(heartbeat.channel_uuid, rotated_uuid);
    let plain = crate::crypto::aes_gcm_decrypt(&heartbeat.encrypted_body, &rotated_key).unwrap();
    let heartbeat = pb::HeartbeatRequest::decode(plain.as_slice()).unwrap();
    assert_eq!(heartbeat.interval_seconds, 61);
    assert_eq!(heartbeat.sequence, 1);
    answer_access(&client, sequence, &rotated_key, &empty);
    client.terminate("synthetic rotation regression complete".into());
}

fn blocked_calculation_runtime() -> (
    tokio::runtime::Runtime,
    oneshot::Sender<()>,
    JoinHandle<()>,
) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    let (release, released) = oneshot::channel();
    let (started, running) = std::sync::mpsc::sync_channel(0);
    let blocker = runtime.spawn_blocking(move || {
        started.send(()).unwrap();
        let _ = released.blocking_recv();
    });
    running.recv_timeout(Duration::from_secs(5)).unwrap();
    (runtime, release, blocker)
}

async fn calculation_client() -> (
    Arc<Client>,
    mpsc::Receiver<Outgoing>,
    [u8; 32],
    i32,
) {
    let (client, mut queue) = queued_client();
    let (public, peer) = peer();
    client.start_signing_work(0, crate::o3::Channel::with_peer(public));
    bind(&client);
    let (sequence, body) = next_establish(&client, &mut queue).await;
    let (reply, key, _) = establish_reply_with_config(
        body,
        &peer,
        b"calculation-token",
        Some(pb::ChannelConfig {
            option2: 1,
            option4: 1,
            option6: 1,
            ..Default::default()
        }),
        crate::o3::unix_seconds().unwrap() + 7200,
    );
    client
        .receive(
            incoming(
                sequence,
                crate::o3::ESTABLISH_COMMAND,
                &reply,
                Some(&[0; 16]),
            ),
            0,
        )
        .unwrap();
    let (sequence, heartbeat) = next_access(&client, &mut queue).await;
    assert_eq!(heartbeat.method.as_ref(), b"heartbeat");
    (client, queue, key, sequence)
}

#[test]
fn blocked_task11_keeps_ack_signing_and_network_completion_live_until_ordered_report() {
    let (runtime, release, blocker) = blocked_calculation_runtime();
    runtime.block_on(async move {
        let (client, mut queue, key, sequence) = calculation_client().await;
        let tasks = pb::HeartbeatResponse {
            identifier: Bytes::from_static(b"calculation-batch"),
            tasks: vec![
                pb::HeartbeatTask {
                    kind: 11,
                    identifier: Bytes::from_static(b"calculation"),
                    payload: vec![0x5a; 1024 * 1024].into(),
                },
                pb::HeartbeatTask {
                    kind: 7,
                    identifier: Bytes::from_static(b"refresh"),
                    ..Default::default()
                },
                pb::HeartbeatTask {
                    kind: 6,
                    identifier: Bytes::from_static(b"interval"),
                    payload: Bytes::copy_from_slice(&90u32.to_be_bytes()),
                },
            ],
        };
        answer_access(&client, sequence, &key, &tasks.encode_to_vec());
        let (ack_sequence, ack) = next_access(&client, &mut queue).await;
        assert_eq!(ack.method.as_ref(), b"taskAck");
        let plain = crate::crypto::aes_gcm_decrypt(&ack.encrypted_body, &key).unwrap();
        assert_eq!(
            pb::TaskAckRequest::decode(plain.as_slice()).unwrap().identifier.as_ref(),
            b"calculation-batch"
        );
        let (refresh_sequence, refresh) = next_access(&client, &mut queue).await;
        assert_eq!(refresh.method.as_ref(), b"getToken");
        assert!(queue.try_recv().is_err());
        let issued = signing_engine::proto::IssuedTokenReply {
            token: b"during-calculation".to_vec(),
            expires_at: crate::o3::unix_seconds().unwrap() + 7200,
        };
        answer_access(&client, refresh_sequence, &key, &issued.encode_to_vec());
        answer_access(&client, ack_sequence, &key, &[]);
        tokio::time::timeout(Duration::from_secs(5), async {
            while token(&client) != b"during-calculation" {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        signed_message(&client, &mut queue, b"during-calculation", true).await;
        assert!(queue.try_recv().is_err());
        release.send(()).unwrap();
        blocker.await.unwrap();
        let (sequence, report) = next_access(&client, &mut queue).await;
        assert_eq!(report.method.as_ref(), b"taskReport");
        let plain = crate::crypto::aes_gcm_decrypt(&report.encrypted_body, &key).unwrap();
        let report = pb::TaskReportRequest::decode(plain.as_slice()).unwrap();
        assert_eq!(report.identifier.as_ref(), b"calculation-batch");
        assert_eq!(
            report.results.iter().map(|result| result.identifier.as_ref()).collect::<Vec<_>>(),
            [b"calculation".as_slice(), b"refresh".as_slice(), b"interval".as_slice()]
        );
        assert_eq!(report.results[0].body.len(), 215);
        assert!(report.results[1..].iter().all(|result| result.body.is_empty()));
        answer_access(&client, sequence, &key, &[]);
        client.terminate("synthetic calculation concurrency complete".into());
    });
}

#[test]
fn cancelled_or_stale_task11_cannot_publish_into_a_changed_session() {
    for replacement in 0..3 {
        let (runtime, release, blocker) = blocked_calculation_runtime();
        runtime.block_on(async move {
            let (client, mut queue, key, sequence) = calculation_client().await;
            let tasks = pb::HeartbeatResponse {
                identifier: Bytes::from_static(b"stale-calculation-batch"),
                tasks: vec![
                    pb::HeartbeatTask {
                        kind: 11,
                        identifier: Bytes::from_static(b"stale-calculation"),
                        payload: Bytes::from_static(b"synthetic stale payload"),
                    },
                    pb::HeartbeatTask {
                        kind: 10,
                        identifier: Bytes::from_static(b"ready-result-in-stale-batch"),
                        payload: Bytes::from_static(&[1, 0, 0, 0]),
                    },
                ],
            };
            answer_access(&client, sequence, &key, &tasks.encode_to_vec());
            let (_, ack) = next_access(&client, &mut queue).await;
            assert_eq!(ack.method.as_ref(), b"taskAck");
            assert!(queue.try_recv().is_err());
            match replacement {
                0 => {
                    bind(&client);
                    client.inner.lock().unwrap().signer.refresh_token_task().unwrap();
                    client.signing_work.notify_one();
                    let (_, body) = next_establish(&client, &mut queue).await;
                    assert_eq!(
                        pb::EstablishShareKeyRequest::decode(body).unwrap().method.as_ref(),
                        b"getToken"
                    );
                }
                1 => {
                    let mut state = client.snapshot().await;
                    state.keystore.uin = 5678;
                    client.replace_state(state).await;
                }
                2 => {
                    client.terminate("synthetic calculation reconnect".into());
                    let (sender, receiver) = mpsc::channel(8);
                    {
                        let mut inner = client.inner.lock().unwrap();
                        inner.generation = 1;
                        inner.cancel = CancellationToken::new();
                        inner.connection = Some(Connection { generation: 1, sender });
                    }
                    queue = receiver;
                    let (public, _) = peer();
                    client.start_signing_work(1, crate::o3::Channel::with_peer(public));
                    client.mark_signing_ticket_complete().unwrap();
                    client.inner.lock().unwrap().signer.refresh_token_task().unwrap();
                    client.signing_work.notify_one();
                    let (_, refresh) = next_access(&client, &mut queue).await;
                    assert_eq!(refresh.method.as_ref(), b"getToken");
                }
                _ => unreachable!(),
            }
            release.send(()).unwrap();
            blocker.await.unwrap();
            tokio::task::spawn_blocking(|| ()).await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(100), queue.recv()).await.is_err(),
                "stale task report escaped replacement {replacement}"
            );
            client.terminate("synthetic stale calculation complete".into());
        });
    }
}
