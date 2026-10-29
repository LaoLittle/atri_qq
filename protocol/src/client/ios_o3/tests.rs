use super::*;
use crate::{
    client::{ios_signing_tests, tests::incoming},
    proto::o3 as pb,
};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    ecdsa::EcdsaSig,
    nid::Nid,
    pkey::Private,
};
use signing_engine::ios::token::{DeviceTokenRequest, DeviceTokenResponse, NativePayloadResources};

fn client(
    profile: Profile,
    token: &'static [u8],
    uin: u64,
) -> (Arc<Client>, mpsc::Receiver<Outgoing>, EcKey<Private>) {
    let mut config = ios_signing_tests::config(profile);
    config.ios_signing.as_mut().unwrap().raw_device_token = Bytes::from_static(token);
    let client = Client::new(
        config,
        Keystore {
            uin,
            ..Default::default()
        },
    )
    .unwrap();
    let (key, peer) = server_material();
    let (sender, queue) = mpsc::channel(16);
    {
        let mut inner = client.inner.lock().unwrap();
        inner.connection = Some(Connection {
            generation: 0,
            sender,
        });
        inner.ios_o3 = Some(Channel::with_peer(CheckMode::Sdk, peer));
    }
    (client, queue, key)
}

fn server_material() -> (EcKey<Private>, [u8; 33]) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let scalar = BigNum::from_u32(1).unwrap();
    let mut context = BigNumContext::new().unwrap();
    let mut point = EcPoint::new(&group).unwrap();
    point.mul_generator2(&group, &scalar, &mut context).unwrap();
    let peer = point.to_bytes(&group, PointConversionForm::COMPRESSED, &mut context).unwrap();
    (EcKey::from_private_components(&group, &scalar, &point).unwrap(), peer.try_into().unwrap())
}

fn refresh(client: &Arc<Client>) -> JoinHandle<Result<Option<TokenPersistence>>> {
    let client = client.clone();
    tokio::spawn(async move {
        let properties = BTreeMap::from([(
            24,
            Bytes::from_static(b"synthetic actual-shaped test property"),
        )]);
        client
            .refresh_ios_token(
                &properties,
                NativePayload::Generate(NativePayloadResources {
                    material: [17; 16],
                    material_seed: 23,
                    fingerprint: *b"efcbf0da7fd8d81232fe2e7b912f3979",
                    unix_seconds: 1_700_000_000,
                    process_id: 4242,
                    allocation_low32: Some(432880),
                }),
            )
            .await
    })
}

async fn next(queue: &mut mpsc::Receiver<Outgoing>) -> Outgoing {
    tokio::time::timeout(Duration::from_secs(3), queue.recv())
        .await
        .unwrap()
        .unwrap()
}

fn body(outgoing: &Outgoing) -> Bytes {
    ios_signing_tests::request_parts(outgoing.frame.clone(), &[0; 16]).4
}

fn establish(server: &EcKey<Private>, body: Bytes, token: &[u8], valid: bool) -> (Bytes, [u8; 32]) {
    let request = pb::IosEstablishShareKeyRequest::decode(body).unwrap();
    let mut context = BigNumContext::new().unwrap();
    let point =
        EcPoint::from_bytes(server.group(), &request.client_public_key, &mut context).unwrap();
    let public =
        openssl::pkey::PKey::from_ec_key(EcKey::from_public_key(server.group(), &point).unwrap())
            .unwrap();
    let private = openssl::pkey::PKey::from_ec_key(server.clone()).unwrap();
    let mut derive = openssl::derive::Deriver::new(&private).unwrap();
    derive.set_peer(&public).unwrap();
    let shared = derive.derive_to_vec().unwrap();
    let mut hkdf = openssl::pkey_ctx::PkeyCtx::new_id(openssl::pkey::Id::HKDF).unwrap();
    hkdf.derive_init().unwrap();
    hkdf.set_hkdf_md(openssl::md::Md::sha256()).unwrap();
    hkdf.set_hkdf_key(&shared).unwrap();
    hkdf.set_hkdf_salt(&[]).unwrap();
    hkdf.add_hkdf_info(&[]).unwrap();
    let mut key = [0; 32];
    assert_eq!(hkdf.derive(Some(&mut key)).unwrap(), 32);
    let decoded = crate::crypto::aes_gcm_decrypt(&request.encrypted_body, &key).unwrap();
    let decoded = pb::ChannelPlaintext::decode(decoded.as_slice()).unwrap();
    let mut transcript = server
        .public_key()
        .to_bytes(
            server.group(),
            PointConversionForm::COMPRESSED,
            &mut context,
        )
        .unwrap();
    transcript.extend_from_slice(&decoded.parameter.to_be_bytes());
    transcript.extend_from_slice(&7u64.to_be_bytes());
    let signature = EcdsaSig::sign(&crate::crypto::sha256(&transcript), server).unwrap();
    let mut signature = [
        signature.r().to_vec_padded(32).unwrap(),
        signature.s().to_vec_padded(32).unwrap(),
    ]
    .concat();
    if !valid {
        signature[0] ^= 1;
    }
    let business = DeviceTokenResponse {
        token: Bytes::copy_from_slice(token),
        expires_at: crate::o3::unix_seconds().unwrap() + 3600,
    }
    .encode_to_vec();
    let inner = pb::IosEstablishInnerResponse {
        material: vec![signature.into()],
        parameter: 7,
        channel_time: crate::o3::unix_seconds().unwrap() + 3600,
        business_response: vec![business.into()],
        config: Some(pb::IosChannelConfig {
            option1: Some(1),
            option2: Some(1),
            ..Default::default()
        }),
    }
    .encode_to_vec();
    let encoded = pb::IosEstablishShareKeyResponse {
        encrypted_body: vec![crate::crypto::aes_gcm_encrypt(&inner, &key).unwrap().into()],
        ..Default::default()
    }
    .encode_to_vec()
    .into();
    (encoded, key)
}

fn deliver(client: &Client, outgoing: &Outgoing, response: &[u8]) {
    client
        .receive(
            incoming(
                outgoing.sequence,
                &outgoing.command,
                response,
                Some(&[0; 16]),
            ),
            0,
        )
        .unwrap();
}

#[tokio::test]
async fn cold_token_bootstrap_changes_live_sdk_output_and_next_refresh_uses_access() {
    for profile in [Profile::iphone(), Profile::ipad()] {
        let (client, mut queue, server) = client(profile, b"", 0);
        let task = refresh(&client);
        let outgoing = next(&mut queue).await;
        assert_eq!(outgoing.command, crate::o3::ESTABLISH_COMMAND);
        let (reply, key) = establish(
            &server,
            body(&outgoing),
            b"server-issued-mobile-token",
            true,
        );
        deliver(&client, &outgoing, &reply);
        let persisted = task.await.unwrap().unwrap().unwrap();
        assert_eq!(persisted.key, "dtck_20260129_0");
        let signed = {
            let client = client.clone();
            tokio::spawn(async move {
                client
                    .request(
                        "AvatarInfoSvr.QQHeadUrlReq",
                        Bytes::from_static(b"message"),
                        RequestType::D2,
                        Encryption::D2,
                        Duration::from_secs(3),
                    )
                    .await
            })
        };
        let outgoing = next(&mut queue).await;
        let secure = ios_signing_tests::reserved(outgoing.frame.clone())
            .secure_info
            .unwrap();
        assert_eq!(
            secure.token.unwrap().as_ref(),
            b"server-issued-mobile-token"
        );
        deliver(&client, &outgoing, b"ok");
        assert_eq!(signed.await.unwrap().unwrap().as_ref(), b"ok");
        let refreshed = refresh(&client);
        let outgoing = next(&mut queue).await;
        assert_eq!(outgoing.command, crate::o3::ACCESS_COMMAND);
        let request = pb::SecureAccessRequest::decode(body(&outgoing)).unwrap();
        let decoded = crate::crypto::aes_gcm_decrypt(&request.encrypted_body, &key).unwrap();
        let request = DeviceTokenRequest::decode(decoded.as_slice()).unwrap();
        assert_eq!(
            request.previous_token.as_ref(),
            b"server-issued-mobile-token"
        );
        let empty = DeviceTokenResponse {
            token: Bytes::new(),
            expires_at: 1,
        }
        .encode_to_vec();
        let response = pb::IosSecureAccessResponse {
            encrypted_body: vec![crate::crypto::aes_gcm_encrypt(&empty, &key).unwrap().into()],
            ..Default::default()
        }
        .encode_to_vec();
        deliver(&client, &outgoing, &response);
        assert!(refreshed.await.unwrap().unwrap().is_none());
        assert_eq!(
            client
                .ios_signing_resources_snapshot()
                .unwrap()
                .raw_device_token
                .as_ref(),
            b"server-issued-mobile-token"
        );
    }
}

#[tokio::test]
async fn failed_channel_authentication_cannot_publish_token_and_retry_keeps_material() {
    let (client, mut queue, server) = client(Profile::iphone(), b"trusted-old-snapshot", 0);
    let task = refresh(&client);
    let outgoing = next(&mut queue).await;
    let first = pb::IosEstablishShareKeyRequest::decode(body(&outgoing)).unwrap();
    let (reply, _) = establish(&server, body(&outgoing), b"must-not-install", false);
    deliver(&client, &outgoing, &reply);
    assert!(matches!(task.await.unwrap(), Err(Error::Crypto(_))));
    assert_eq!(
        client
            .ios_signing_resources_snapshot()
            .unwrap()
            .raw_device_token
            .as_ref(),
        b"trusted-old-snapshot"
    );
    let retry = refresh(&client);
    let outgoing = next(&mut queue).await;
    let second = pb::IosEstablishShareKeyRequest::decode(body(&outgoing)).unwrap();
    assert_eq!(first.channel_uuid, second.channel_uuid);
    let (reply, _) = establish(&server, body(&outgoing), b"authenticated-after-retry", true);
    deliver(&client, &outgoing, &reply);
    assert!(retry.await.unwrap().unwrap().is_some());
    assert_eq!(
        client
            .ios_signing_resources_snapshot()
            .unwrap()
            .raw_device_token
            .as_ref(),
        b"authenticated-after-retry"
    );
}

#[tokio::test]
async fn collection_gate_releases_before_network_and_old_scope_cannot_overwrite_new_resources() {
    for change in 0..3 {
        let (client, mut queue, server) = client(Profile::ipad(), b"trusted-old-snapshot", 0);
        let first = refresh(&client);
        let old = next(&mut queue).await;
        let second = refresh(&client);
        let queued = next(&mut queue).await;
        let expected = if change == 0 {
            let mut resources = client.ios_signing_resources_snapshot().unwrap();
            resources.raw_device_token = Bytes::from_static(b"external-new-snapshot");
            client.set_ios_signing_resources(resources).unwrap();
            b"external-new-snapshot".as_slice()
        } else {
            if change == 1 {
                client.begin_signing_login().unwrap();
            } else {
                let before = client.snapshot().await;
                let mut other = before.clone();
                other.keystore.uin = 12345;
                client.replace_state(other).await;
                client.replace_state(before).await;
            }
            b"trusted-old-snapshot".as_slice()
        };
        assert!(matches!(first.await.unwrap(), Err(Error::Disconnected)));
        assert!(matches!(second.await.unwrap(), Err(Error::Disconnected)));
        assert!(old.cancel.is_cancelled());
        assert!(queued.cancel.is_cancelled());
        let (late, _) = establish(&server, body(&old), b"late-must-not-install", true);
        deliver(&client, &old, &late);
        assert_eq!(
            client
                .ios_signing_resources_snapshot()
                .unwrap()
                .raw_device_token
                .as_ref(),
            expected
        );
        assert!(client.inner.lock().unwrap().pending.is_empty());
        let next_task = refresh(&client);
        let next = next(&mut queue).await;
        let (reply, _) = establish(&server, body(&next), b"new-scope-token", true);
        deliver(&client, &next, &reply);
        assert!(next_task.await.unwrap().unwrap().is_some());
    }
}

#[tokio::test(start_paused = true)]
async fn mobile_lifecycle_keeps_common_network_work_without_desktop_platform_polls() {
    for profile in [Profile::iphone(), Profile::ipad()] {
        let (client, mut queue, _) = client(profile, b"synthetic-test-token", 0);
        {
            let mut inner = client.inner.lock().unwrap();
            inner.state.online = true;
            inner.state.keystore.uin = 42;
            inner.state.keystore.uid = "synthetic-user".into();
            let connection_cancel = inner.cancel.clone();
            inner.credentials.activate(0, &connection_cancel);
            inner
                .ticket_refresh_schedule
                .send_replace(crate::ticket_refresh::Schedule {
                    generation: 0,
                    interval_seconds: None,
                    selected_time: true,
                });
        }
        let cancel = CancellationToken::new();
        let lifecycle = tokio::spawn(crate::lifecycle::run(
            Arc::downgrade(&client),
            0,
            cancel.clone(),
        ));
        let tickets = tokio::spawn(crate::ticket_refresh::run(
            Arc::downgrade(&client),
            0,
            cancel.clone(),
        ));
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        let mut commands = Vec::new();
        while let Ok(outgoing) = queue.try_recv() {
            commands.push(outgoing.command);
        }
        cancel.cancel();
        lifecycle.await.unwrap();
        tickets.await.unwrap();
        assert!(
            commands
                .iter()
                .any(|command| command == "ConfigPushSvc.GetIpDirect"),
            "common network work missing: {commands:?}"
        );
        assert!(
            !commands.iter().any(|command| matches!(
                command.as_str(),
                "QQClubComm.getNewFlag"
                    | "RedTouchSvc.ClientReport"
                    | "trpc.group_pro.configdistribution.ConfigDistributionSvr.SsoGetConfig"
            )),
            "mobile session emitted desktop platform polling: {commands:?}"
        );
        assert!(client.inner.lock().unwrap().pending.is_empty());
    }
}

#[tokio::test]
async fn selected_account_uses_a2_without_waiting_for_online_and_keeps_authenticated_channel() {
    let (client, mut queue, server) = client(Profile::iphone(), b"", 42);
    assert!(!client.snapshot().await.online);
    let task = refresh(&client);
    let outgoing = next(&mut queue).await;
    assert_eq!(
        outgoing.command,
        "trpc.o3.ecdh_access.EcdhAccess.SsoSecureA2Establish"
    );
    let (reply, key) = establish(&server, body(&outgoing), b"synthetic-issued-token", true);
    deliver(&client, &outgoing, &reply);
    task.await.unwrap().unwrap();
    let task = refresh(&client);
    let outgoing = next(&mut queue).await;
    assert_eq!(
        outgoing.command,
        "trpc.o3.ecdh_access.EcdhAccess.SsoSecureA2Access"
    );
    let request = pb::SecureAccessRequest::decode(body(&outgoing)).unwrap();
    let plaintext = crate::crypto::aes_gcm_decrypt(&request.encrypted_body, &key).unwrap();
    let request = DeviceTokenRequest::decode(plaintext.as_slice()).unwrap();
    assert_eq!(request.previous_token.as_ref(), b"synthetic-issued-token");
    let response = pb::IosSecureAccessResponse {
        encrypted_body: vec![
            crate::crypto::aes_gcm_encrypt(
                &DeviceTokenResponse {
                    token: Bytes::new(),
                    expires_at: 1,
                }
                .encode_to_vec(),
                &key,
            )
            .unwrap()
            .into(),
        ],
        ..Default::default()
    }
    .encode_to_vec();
    deliver(&client, &outgoing, &response);
    assert!(task.await.unwrap().unwrap().is_none());
    assert!(!client.snapshot().await.online);
}

#[tokio::test]
async fn system_payload_material_survives_resource_account_and_clock_changes() {
    for profile in [Profile::iphone(), Profile::ipad()] {
        let (client, _, _) = client(profile, b"", 0);
        let first = client.create_ios_native_payload([b'a'; 32]).unwrap();
        let mut resources = client.ios_signing_resources_snapshot().unwrap();
        resources.raw_device_token = Bytes::from_static(b"updated-synthetic-token");
        resources.raw_xwid = Bytes::from_static(b"updated-synthetic-xwid");
        client.set_ios_signing_resources(resources).unwrap();
        let second = {
            let mut inner = client.inner.lock().unwrap();
            let Inner { signer, state, .. } = &mut *inner;
            state.keystore.uin = 42;
            signer.begin_login(state).unwrap();
            signer.ticket_complete(state).unwrap();
            signer
                .create_ios_native_payload(state, [b'b'; 32], first.unix_seconds + 7200)
                .unwrap()
        };
        assert_eq!(first.material, second.material);
        assert_eq!(first.material_seed, second.material_seed);
        assert_eq!(second.fingerprint, [b'b'; 32]);
        assert_eq!(second.unix_seconds, first.unix_seconds + 7200);
        assert_eq!(second.process_id as u32, std::process::id());
        assert_eq!(second.allocation_low32, None);
        assert_eq!(
            client
                .ios_signing_resources_snapshot()
                .unwrap()
                .raw_device_token
                .as_ref(),
            b"updated-synthetic-token"
        );
    }
    let desktop = Client::new(ClientConfig::default(), Keystore::default()).unwrap();
    assert!(matches!(
        desktop.create_ios_native_payload([b'a'; 32]),
        Err(Error::Unsupported(_))
    ));
}

#[tokio::test]
async fn expired_issued_token_is_not_used_by_the_next_signed_request() {
    for profile in [Profile::iphone(), Profile::ipad()] {
        let (client, mut queue, _) = client(profile, b"", 0);
        client
            .inner
            .lock()
            .unwrap()
            .signer
            .complete_ios_token(
                &signing_engine::ios::token::TokenSubmission {
                    request_uin: "0".into(),
                },
                Ok(DeviceTokenResponse {
                    token: Bytes::from_static(b"expired-issued-token"),
                    expires_at: 1,
                }
                .encode_to_vec()
                .into()),
            )
            .unwrap();
        let task = {
            let client = client.clone();
            tokio::spawn(async move {
                client
                    .request(
                        "AvatarInfoSvr.QQHeadUrlReq",
                        Bytes::from_static(b"expiry-check"),
                        RequestType::D2,
                        Encryption::D2,
                        Duration::from_secs(3),
                    )
                    .await
            })
        };
        let outgoing = next(&mut queue).await;
        let security = ios_signing_tests::reserved(outgoing.frame.clone())
            .secure_info
            .unwrap();
        assert!(
            security.token.as_ref().is_none_or(|token| token.is_empty()),
            "{security:?}"
        );
        assert_eq!(
            client
                .ios_signing_resources_snapshot()
                .unwrap()
                .raw_device_token
                .as_ref(),
            b"expired-issued-token"
        );
        deliver(&client, &outgoing, b"ok");
        assert_eq!(task.await.unwrap().unwrap().as_ref(), b"ok");
    }
}

#[tokio::test]
async fn same_token_metadata_updates_and_token_switch_control_actual_wire_consumption() {
    for profile in [Profile::iphone(), Profile::ipad()] {
        let (client, mut queue, _) = client(profile, b"same-token-bytes", 0);
        let future = crate::o3::unix_seconds().unwrap() + 3600;
        for (expiry, enabled, expected) in [
            (future, 1, true),
            (1, 1, false),
            (future, 0, false),
            (future, 1, true),
        ] {
            let mut resources = client.ios_signing_resources_snapshot().unwrap();
            resources.raw_device_token_expires_at = expiry;
            resources.raw_device_token_uin = "42".into();
            resources.command_policy.set_switch(1, enabled);
            client.set_ios_signing_resources(resources).unwrap();
            let task = {
                let client = client.clone();
                tokio::spawn(async move {
                    client
                        .request(
                            "AvatarInfoSvr.QQHeadUrlReq",
                            Bytes::from_static(b"metadata-check"),
                            RequestType::D2,
                            Encryption::D2,
                            Duration::from_secs(3),
                        )
                        .await
                })
            };
            let outgoing = next(&mut queue).await;
            let security = ios_signing_tests::reserved(outgoing.frame.clone())
                .secure_info
                .unwrap();
            assert_eq!(
                security.token.unwrap_or_default().as_ref(),
                if expected {
                    b"same-token-bytes".as_slice()
                } else {
                    b""
                }
            );
            let snapshot = client.ios_signing_resources_snapshot().unwrap();
            assert_eq!(snapshot.raw_device_token.as_ref(), b"same-token-bytes");
            assert_eq!(snapshot.raw_device_token_expires_at, expiry);
            assert_eq!(snapshot.raw_device_token_uin, "42");
            deliver(&client, &outgoing, b"ok");
            assert_eq!(task.await.unwrap().unwrap().as_ref(), b"ok");
        }
    }
}

#[tokio::test]
async fn token_collector_uses_current_xwid_at_59_without_overwriting_r0_or_guid() {
    for profile in [Profile::iphone(), Profile::ipad()] {
        for (raw, expected) in [
            (
                &b"current-xwid\0unconsumed-suffix"[..],
                &b"current-xwid"[..],
            ),
            (&b"\xff\xfe"[..], &b""[..]),
            (
                &b"B1EF0400AA5AF7C1CCC4A6D75582112D78C00B6D21D76463A2A0269D267C11C28F71FA479221"[..],
                &b"B1EF0400AA5AF7C1CCC4A6D75582112D78C00B6D21D76463A2A0269D267C11C28F71FA479221"[..],
            ),
        ] {
            let (client, mut queue, server) = client(profile.clone(), b"", 0);
            let mut resources = client.ios_signing_resources_snapshot().unwrap();
            resources.raw_xwid = Bytes::from_static(raw);
            client.set_ios_signing_resources(resources).unwrap();
            let task = {
                let client = client.clone();
                tokio::spawn(async move {
                    let properties = BTreeMap::from([
                        (24, Bytes::from_static(b"synthetic-process-hash")),
                        (59, Bytes::from_static(b"stale-caller-xwid")),
                        (60, Bytes::from_static(b"observed-secure-r0")),
                        (61, Bytes::from_static(b"observed-sdk-guid")),
                    ]);
                    let payload = client.create_ios_native_payload([b'a'; 32]).unwrap();
                    client
                        .refresh_ios_token(&properties, NativePayload::Generate(payload))
                        .await
                })
            };
            let outgoing = next(&mut queue).await;
            let encoded = body(&outgoing);
            let envelope = pb::IosEstablishShareKeyRequest::decode(encoded.clone()).unwrap();
            let (response, key) = establish(&server, encoded, b"issued-token", true);
            let plaintext = crate::crypto::aes_gcm_decrypt(&envelope.encrypted_body, &key).unwrap();
            let plaintext = pb::ChannelPlaintext::decode(plaintext.as_slice()).unwrap();
            let request = DeviceTokenRequest::decode(plaintext.body).unwrap();
            let properties: BTreeMap<_, _> = request
                .items
                .iter()
                .map(|item| (item.id, item.data.as_ref()))
                .collect();
            assert_eq!(properties[&59], expected);
            assert_eq!(properties[&60], b"observed-secure-r0");
            assert_eq!(properties[&61], b"observed-sdk-guid");
            assert_eq!(
                request.items.iter().map(|item| item.id).collect::<Vec<_>>(),
                [24, 59, 60, 61]
            );
            deliver(&client, &outgoing, &response);
            task.await.unwrap().unwrap().unwrap();
            assert_eq!(
                client
                    .ios_signing_resources_snapshot()
                    .unwrap()
                    .raw_device_token
                    .as_ref(),
                b"issued-token"
            );
        }
    }
}

fn virtual_frame(frame: Bytes) -> (i32, String, Bytes, String, crate::proto::sso::Reserved) {
    let (_, _, _, mut head, body) = ios_signing_tests::request_parts(frame, &[0; 16]);
    let sequence = head.i32().unwrap();
    head.skip(20).unwrap();
    head.p32().unwrap();
    let command = String::from_utf8(head.p32().unwrap().to_vec()).unwrap();
    for _ in 0..3 {
        head.p32().unwrap();
    }
    let trailer = String::from_utf8(head.pref(2, true).unwrap().to_vec()).unwrap();
    let reserve = crate::proto::sso::Reserved::decode(head.p32().unwrap()).unwrap();
    assert!(head.rest().is_empty());
    (sequence, command, body, trailer, reserve)
}

fn virtual_request(client: &Arc<Client>, command: &'static str, wait: Duration) -> JoinHandle<Result<Bytes>> {
    let client = client.clone();
    tokio::spawn(async move {
        client.request(command, Bytes::from_static(b"business"), RequestType::D2, Encryption::D2, wait).await
    })
}

#[tokio::test]
async fn virtual_device_tcp_bootstrap_publishes_authenticated_token_and_consumes_real_statistics() {
    tokio::time::timeout(Duration::from_secs(20), async {
    for profile in [Profile::iphone(), Profile::ipad()] {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let config = ClientConfig {
            profile,
            host: "127.0.0.1".into(),
            port: listener.local_addr().unwrap().port(),
            ios_virtual: Some(Arc::new(crate::ios_device::IosVirtualConfig::default())),
            ..Default::default()
        };
        let client = Client::new(config.clone(), Keystore::default()).unwrap();
        let mut events = client.login_events();
        client.connect().await.unwrap();
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = Framed::new(socket, SsoFrameCodec);
        let (server, public) = server_material();
        client.inner.lock().unwrap().ios_o3 = Some(Channel::with_peer(CheckMode::Sdk, public));
        let first = virtual_request(&client, "AvatarInfoSvr.QQHeadUrlReq", Duration::from_secs(3));
        let mut sequence_marker = None;
        for _ in 0..2 {
            let frame = tokio::time::timeout(Duration::from_secs(3), socket.next()).await.unwrap().unwrap().unwrap();
            let (sequence, command, body, _, reserve) = virtual_frame(frame);
            let marker = reserve.trans_info.iter().find(|entry| entry.key.as_deref() == Some("client_conn_seq")).unwrap().value.clone().unwrap();
            if let Some(expected) = &sequence_marker {
                assert_eq!(&marker, expected);
            } else {
                sequence_marker = Some(marker);
            }
            assert_eq!(reserve.ip_stack_type, Some(1));
            assert_eq!(reserve.ip_origin, Some(1));
            let response = if command == crate::o3::ESTABLISH_COMMAND {
                assert_eq!(reserve.message_type, Some(0));
                let envelope = pb::IosEstablishShareKeyRequest::decode(body.clone()).unwrap();
                let (response, key) = establish(&server, body, b"authenticated-virtual-token", true);
                let plaintext = crate::crypto::aes_gcm_decrypt(&envelope.encrypted_body, &key).unwrap();
                let plaintext = pb::ChannelPlaintext::decode(plaintext.as_slice()).unwrap();
                let request = DeviceTokenRequest::decode(plaintext.body).unwrap();
                assert_eq!(request.previous_token.as_ref(), b"");
                response
            } else {
                assert_eq!(command, "AvatarInfoSvr.QQHeadUrlReq");
                assert_eq!(reserve.message_type, Some(32));
                assert_eq!(reserve.secure_info.unwrap().token.unwrap().as_ref(), b"");
                Bytes::from_static(b"first-business-response")
            };
            socket.send(incoming(sequence, &command, &response, Some(&[0; 16]))).await.unwrap();
        }
        assert_eq!(first.await.unwrap().unwrap().as_ref(), b"first-business-response");
        let saved = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let LoginEvent::KeystoreChanged(saved) = events.recv().await.unwrap() {
                    if saved.ios_virtual_state.as_ref().unwrap().token.token.as_ref() == b"authenticated-virtual-token" {
                        break saved;
                    }
                }
            }
        }).await.unwrap();
        let token = &saved.ios_virtual_state.as_ref().unwrap().token;
        assert_eq!(token.associated_uin, "0");
        assert!(token.expires_at > crate::o3::unix_seconds().unwrap());
        let signed = virtual_request(&client, "AvatarInfoSvr.QQHeadUrlReq", Duration::from_secs(3));
        let frame = socket.next().await.unwrap().unwrap();
        let (sequence, command, _, _, reserve) = virtual_frame(frame);
        assert_eq!(reserve.secure_info.unwrap().token.unwrap().as_ref(), b"authenticated-virtual-token");
        socket.send(incoming(sequence, &command, b"updated-token-response", Some(&[0; 16]))).await.unwrap();
        assert_eq!(signed.await.unwrap().unwrap().as_ref(), b"updated-token-response");
        let missing = virtual_request(&client, "virtual.unanswered.business", Duration::from_millis(200));
        let frame = socket.next().await.unwrap().unwrap();
        let (_, command, _, _, _) = virtual_frame(frame);
        assert_eq!(command, "virtual.unanswered.business");
        assert!(matches!(missing.await.unwrap(), Err(Error::Timeout)));
        for expected in [(3, 1), (1, 0)] {
            let push = virtual_request(&client, "PushService.get", Duration::from_secs(3));
            let frame = socket.next().await.unwrap().unwrap();
            let (sequence, command, _, trailer, _) = virtual_frame(frame);
            assert_eq!(command, "PushService.get");
            let statistics: Vec<&str> = trailer.split_once('|').unwrap().0.split(',').collect();
            assert_eq!(statistics.len(), 3);
            assert_eq!(statistics[0].parse::<i32>().unwrap(), expected.0);
            assert!(statistics[1].parse::<i64>().unwrap() >= 0);
            assert_eq!(statistics[2].parse::<i32>().unwrap(), expected.1);
            socket.send(incoming(sequence, &command, b"push-response", Some(&[0; 16]))).await.unwrap();
            assert_eq!(push.await.unwrap().unwrap().as_ref(), b"push-response");
        }
        let mut encoded = Vec::new();
        ciborium::into_writer(&saved, &mut encoded).unwrap();
        let restored: Keystore = ciborium::from_reader(encoded.as_slice()).unwrap();
        let original_identity = restored.ios_virtual_state.clone().unwrap();
        client.terminate_generation(1, "test completed".into());
        drop(socket);
        let recreated = Client::new(config, restored).unwrap();
        recreated.connect().await.unwrap();
        let (_socket, _) = listener.accept().await.unwrap();
        let next = recreated.snapshot().await.keystore.ios_virtual_state.unwrap();
        assert_eq!(next.collector_uuid, original_identity.collector_uuid);
        assert_eq!(next.xwid_candidate, original_identity.xwid_candidate);
        assert_eq!(next.token, original_identity.token);
        assert!(next.connection_sequence.unwrap() > original_identity.connection_sequence.unwrap());
        recreated.terminate_generation(1, "test completed".into());
    }
    }).await.unwrap();
}
