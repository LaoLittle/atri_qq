use super::*;
use crate::{signing::IosSigningResources, wire::Reader};
use ::signing::ios::{
    command_policy::{COMMAND_MODE_SWITCH, CommandPolicy, SIGN_SWITCH},
    proto::SecurityExtra,
};

pub(crate) fn config(profile: Profile) -> ClientConfig {
    ClientConfig {
        profile,
        platform: Some(PlatformConfig::Ios(IosConfig::Snapshot(
            IosSnapshotConfig {
                device: IosDevice {
                    system_version: "18.0".into(),
                    hardware_model: "synthetic-test-hardware".into(),
                    system_name: "iOS".into(),
                },
                signing: resources(),
                transport: transport_resources(),
                registration: IosRegistration {
                    initial: registration_template("native-guid-text", 1033, 1),
                    reconnect: registration_template("native-reconnect-guid-text", 1028, 2),
                },
            },
        ))),
        ..Default::default()
    }
}

fn registration_template(guid: &str, locale: u32, notify: u32) -> auth::InfoSyncRequest {
    auth::InfoSyncRequest {
        sync_flag: Some(1759),
        register: Some(auth::RegisterInfo {
            guid: Some(guid.into()),
            locale: Some(locale),
            mute: Some(1),
            business: Some(auth::RegisterBusiness {
                notify_switch: Some(notify),
                bound_uin_notify_switch: None,
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn resources() -> IosSigningResources {
    IosSigningResources {
        provenance: "synthetic-client-unit-test-only".into(),
        raw_device_token: Bytes::from_static(b"synthetic-client-token"),
        raw_device_token_expires_at: u64::MAX,
        raw_device_token_uin: "0".into(),
        raw_xwid: Bytes::from_static(b"synthetic-client-xwid"),
        channel_state: None,
        command_policy: CommandPolicy::new([(SIGN_SWITCH, 1), (COMMAND_MODE_SWITCH, 0)]),
    }
}

fn transport_resources() -> IosTransportResources {
    IosTransportResources {
        network_type: 2,
        effective_flags: [1, 2, 3, 4, 5, 6, 7, 8, 9, 2, 4],
        account_record_0x80: IosAccountRecord80(Bytes::from_static(b"synthetic\x80record")),
        carrier_mcc: "460".into(),
        carrier_mnc: "01".into(),
        cf_bundle_version: "12345".into(),
        account: IosTransportAccount::Uin { account_type: 0 },
        reserved: IosReservedTemplate::new(
            crate::proto::sso::Reserved {
                qimei: Some(Bytes::from_static(b"synthetic-qimei")),
                network_type: Some(2),
                trans_info: vec![crate::proto::sso::TransInfo {
                    key: Some("synthetic-key".into()),
                    value: Some(Bytes::from_static(b"synthetic-value")),
                }],
                ..Default::default()
            }
            .encode_to_vec()
            .into(),
        )
        .unwrap(),
        push_service_get_statistics: None,
    }
}

pub(super) fn reserved(frame: Bytes) -> crate::proto::sso::Reserved {
    let (protocol, _, _, mut header, _) = request_parts(frame, &[0; 16]);
    if protocol == RequestType::D2 as u32 {
        header.skip(24).unwrap();
        for _ in 0..5 {
            header.p32().unwrap();
        }
        header.pref(2, true).unwrap();
    } else {
        header.p32().unwrap();
        header.p32().unwrap();
    }
    crate::proto::decode(header.p32().unwrap()).unwrap()
}

#[test]
fn iphone_and_ipad_real_request_path_serializes_native_sdk_output() {
    for profile in [Profile::iphone(), Profile::ipad()] {
        let client = Client::new(config(profile), Keystore::default()).unwrap();
        let mut inner = client.inner.lock().unwrap();
        let (_, frame) = client
            .prepare_frame(
                &mut inner,
                "AvatarInfoSvr.QQHeadUrlReq",
                Bytes::from_static(b"synthetic-body"),
                RequestType::D2,
                Encryption::D2,
            )
            .unwrap();
        let security = reserved(frame).secure_info.unwrap();
        assert_eq!(security.sign.unwrap().as_ref(), b"QQQQ");
        assert_eq!(security.token.unwrap().as_ref(), b"synthetic-client-token");
        let extra = SecurityExtra::decode(security.extra.unwrap()).unwrap();
        assert_eq!(extra.qua.as_ref(), inner.state.profile.qua.as_bytes());
        assert_eq!(extra.raw_xwid.as_ref(), b"synthetic-client-xwid");
        assert!(inner.signer.drain_reports().is_empty());
        let (_, frame) = client
            .prepare_frame(
                &mut inner,
                "not.a.signed.command",
                Bytes::from_static(b"synthetic-body"),
                RequestType::D2,
                Encryption::D2,
            )
            .unwrap();
        assert!(reserved(frame).secure_info.is_none());
        drop(inner);
        let mut updated = resources();
        updated.raw_device_token = Bytes::from_static(b"updated-client-token");
        client.set_ios_signing_resources(updated).unwrap();
        let mut inner = client.inner.lock().unwrap();
        let (_, frame) = client
            .prepare_frame(
                &mut inner,
                "AvatarInfoSvr.QQHeadUrlReq",
                Bytes::from_static(b"synthetic-body"),
                RequestType::D2,
                Encryption::D2,
            )
            .unwrap();
        assert_eq!(
            reserved(frame).secure_info.unwrap().token.unwrap().as_ref(),
            b"updated-client-token"
        );
    }
}

#[test]
fn mobile_client_never_starts_desktop_o3_work() {
    let client = Client::new(config(Profile::iphone()), Keystore::default()).unwrap();
    client.start_signing_work(0, crate::o3::Channel::new());
    assert!(client.tasks.lock().unwrap().is_empty());
    assert!(client.inner.lock().unwrap().linux_o3().is_none());
    client.begin_signing_login().unwrap();
    client.inner.lock().unwrap().state.keystore.uin = 1234;
    client.mark_signing_ticket_complete().unwrap();
    let mut inner = client.inner.lock().unwrap();
    assert!(!inner.signing_ready);
    assert!(inner.signer.drain_reports().is_empty());
    assert!(inner.signer.telemetry_deadline().is_none());
    drop(inner);
    assert!(client.set_signing_footer_seed(&[0; 48]).is_err());
    assert!(client.set_signing_resources(None, None, None).is_err());
    assert!(client.answer_signing_property_challenge(&[]).is_err());
    let mut missing = config(Profile::iphone());
    missing.platform = None;
    assert!(Client::new(missing, Keystore::default()).is_err());
}

pub(crate) fn request_parts(frame: Bytes, key: &[u8]) -> (u32, u8, Bytes, Reader, Bytes) {
    let length = frame.len();
    let mut outer = Reader::new(frame);
    assert_eq!(outer.u32().unwrap() as usize, length);
    let protocol = outer.u32().unwrap();
    let encryption = outer.u8().unwrap();
    match protocol {
        12 => {
            outer.p32().unwrap();
        }
        13 => {
            outer.i32().unwrap();
        }
        _ => panic!("unexpected protocol"),
    }
    let account_type = outer.u8().unwrap();
    let account = outer.p32().unwrap();
    let bytes = outer.rest();
    let clear = match encryption {
        0 => bytes,
        1 => crate::crypto::tea_decrypt(&bytes, key).unwrap().into(),
        2 => crate::crypto::tea_decrypt(&bytes, &[0; 16]).unwrap().into(),
        _ => panic!("unexpected encryption"),
    };
    let mut payload = Reader::new(clear);
    let head = Reader::new(payload.p32().unwrap());
    let body = payload.p32().unwrap();
    assert!(payload.rest().is_empty());
    (protocol, account_type, account, head, body)
}

#[test]
fn mobile_complete_header_uses_explicit_native_resources_and_all_encryption_modes() {
    for (json, bid) in [
        (r#"{"platform":"IPhone"}"#, 537_396_808),
        (r#"{"platform":"IPad"}"#, 537_396_819),
    ] {
        let profile: Profile = serde_json::from_str(json).unwrap();
        let client = Client::new(
            config(profile),
            Keystore {
                ios_msf_imei: "synthetic-imei".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut inner = client.inner.lock().unwrap();
        inner.state.keystore.uin = 987654321;
        inner.state.keystore.uid = "synthetic-uid".into();
        inner.state.keystore.a2 = b"synthetic-a2".to_vec();
        inner.state.keystore.d2 = b"synthetic-d2".to_vec();
        inner.state.keystore.d2_key = vec![0x37; 16];
        inner.connection_cookie = Bytes::from_static(b"\xff\0cookie");
        for encryption in [Encryption::None, Encryption::D2, Encryption::Empty] {
            let (sequence, frame) = client
                .prepare_frame(
                    &mut inner,
                    "not.a.signed.command",
                    Bytes::from_static(b"\x01\x02\x03"),
                    RequestType::D2,
                    encryption,
                )
                .unwrap();
            let mut envelope = Reader::new(frame.clone());
            envelope.skip(9).unwrap();
            assert_eq!(
                envelope.p32().unwrap().as_ref(),
                if encryption == Encryption::D2 {
                    b"synthetic-d2".as_slice()
                } else {
                    &[]
                }
            );
            let (protocol, account_type, account, mut head, body) =
                request_parts(frame, &inner.state.keystore.d2_key);
            assert_eq!(protocol, 12);
            assert_eq!(account_type, 0);
            assert_eq!(account.as_ref(), b"987654321");
            assert_eq!(head.i32().unwrap(), sequence);
            assert_eq!(head.u32().unwrap(), bid);
            assert_eq!(head.u32().unwrap(), 0x20027635);
            assert_eq!(head.u8().unwrap(), 2);
            for byte in [1, 2, 3, 4, 5, 6, 7, 8, 9, 2, 4] {
                assert_eq!(head.u8().unwrap(), byte);
            }
            assert_eq!(head.p32().unwrap().as_ref(), b"synthetic-a2");
            assert_eq!(head.p32().unwrap().as_ref(), b"not.a.signed.command");
            assert_eq!(head.p32().unwrap().as_ref(), b"\xff\0cookie");
            assert_eq!(head.p32().unwrap().as_ref(), b"synthetic-imei");
            assert_eq!(head.p32().unwrap().as_ref(), b"synthetic\x80record");
            assert_eq!(head.pref(2, true).unwrap().as_ref(), b"|46001|I12345");
            let reserve: crate::proto::sso::Reserved =
                crate::proto::decode(head.p32().unwrap()).unwrap();
            assert_eq!(reserve.qimei.unwrap().as_ref(), b"synthetic-qimei");
            assert_eq!(reserve.network_type, Some(2));
            assert_eq!(
                reserve.trans_info[0].value.as_ref().unwrap().as_ref(),
                b"synthetic-value"
            );
            assert_eq!(reserve.uid.as_deref(), Some("synthetic-uid"));
            assert!(reserve.secure_info.is_none());
            assert!(head.rest().is_empty());
            assert_eq!(body.as_ref(), b"\x01\x02\x03");
        }
    }
}

#[test]
fn mobile_trim_and_account_updates_do_not_invent_an_account_conversion() {
    let client = Client::new(config(Profile::iphone()), Keystore::default()).unwrap();
    {
        let mut inner = client.inner.lock().unwrap();
        inner.connection_cookie = Bytes::from_static(b"connection-cookie");
        for uin in [0, 246813579] {
            inner.state.keystore.uin = uin;
            let frame = wire::encode_sso(
                "not.a.signed.command",
                inner.sequence,
                Bytes::new(),
                RequestType::Simple,
                Encryption::Empty,
                &inner.state,
                None,
                Some((&inner.ios().unwrap().transport, &inner.connection_cookie)),
                None,
                true,
                None,
                false,
            )
            .unwrap();
            let (protocol, account_type, account, mut head, body) = request_parts(frame, &[0; 16]);
            assert_eq!(protocol, 13);
            assert_eq!(account_type, 0);
            assert_eq!(account.as_ref(), uin.to_string().as_bytes());
            assert_eq!(head.p32().unwrap().as_ref(), b"not.a.signed.command");
            assert_eq!(head.p32().unwrap().as_ref(), b"connection-cookie");
            let _: crate::proto::sso::Reserved = crate::proto::decode(head.p32().unwrap()).unwrap();
            assert!(head.rest().is_empty());
            assert!(body.is_empty());
        }
    }
    let mut transport = transport_resources();
    transport.account = IosTransportAccount::Explicit {
        account_type: 3,
        text: Bytes::from_static(b"synthetic-phone-account"),
    };
    transport.network_type = 1;
    client.set_ios_transport_resources(transport).unwrap();
    let mut inner = client.inner.lock().unwrap();
    let (_, frame) = client
        .prepare_frame(
            &mut inner,
            "AvatarInfoSvr.QQHeadUrlReq",
            Bytes::new(),
            RequestType::D2,
            Encryption::D2,
        )
        .unwrap();
    let (_, account_type, account, _, _) = request_parts(frame.clone(), &[0; 16]);
    assert_eq!(account_type, 3);
    assert_eq!(account.as_ref(), b"synthetic-phone-account");
    assert_eq!(
        reserved(frame).secure_info.unwrap().token.unwrap().as_ref(),
        b"synthetic-client-token"
    );
    assert_eq!(inner.connection_cookie.as_ref(), b"connection-cookie");
}

#[test]
fn mobile_invalid_resources_and_missing_push_statistics_fail_explicitly() {
    let mut invalid = config(Profile::iphone());
    invalid.ios_snapshot_mut().unwrap().transport.account = IosTransportAccount::Explicit {
        account_type: 3,
        text: Bytes::new(),
    };
    assert!(Client::new(invalid, Keystore::default()).is_err());
    let client = Client::new(config(Profile::iphone()), Keystore::default()).unwrap();
    let mut inner = client.inner.lock().unwrap();
    assert!(matches!(
        client.prepare_frame(
            &mut inner,
            "PushService.get",
            Bytes::new(),
            RequestType::D2,
            Encryption::Empty,
        ),
        Err(Error::Authentication(_))
    ));
    inner
        .ios_mut()
        .unwrap()
        .transport
        .push_service_get_statistics = Some(IosPushStatistics {
        count: 7,
        elapsed: 123456789,
        value: -2,
    });
    for expected in [
        b"7,123456789,-2|46001|I12345".as_slice(),
        b"0,0,0|46001|I12345",
    ] {
        let (_, frame) = client
            .prepare_frame(
                &mut inner,
                "PushService.get",
                Bytes::new(),
                RequestType::D2,
                Encryption::Empty,
            )
            .unwrap();
        let (_, _, _, mut head, _) = request_parts(frame, &[0; 16]);
        head.skip(24).unwrap();
        for _ in 0..5 {
            head.p32().unwrap();
        }
        assert_eq!(head.pref(2, true).unwrap().as_ref(), expected);
    }
}

fn cookie_response(cookie: &[u8]) -> Bytes {
    let mut head = wire::Writer::new();
    head.i32(73);
    head.i32(0);
    head.p32([]).unwrap();
    head.p32("not.a.signed.command").unwrap();
    head.p32(cookie).unwrap();
    head.i32(0);
    head.p32([]).unwrap();
    let mut payload = wire::Writer::new();
    payload.p32(head.data).unwrap();
    payload.p32([]).unwrap();
    let mut envelope = wire::Writer::new();
    envelope.u32(12);
    envelope.u8(0);
    envelope.u8(0);
    envelope.p32("0").unwrap();
    envelope.bytes(payload.data);
    let mut frame = wire::Writer::new();
    frame.p32(envelope.data).unwrap();
    frame.data.into()
}

#[test]
fn connection_cookie_accepts_only_first_nonempty_current_generation_response_and_resets() {
    let client = Client::new(config(Profile::iphone()), Keystore::default()).unwrap();
    let (sender, _receiver) = mpsc::channel(8);
    {
        let mut inner = client.inner.lock().unwrap();
        inner.generation = 1;
        inner.connection = Some(Connection {
            generation: 1,
            sender: sender.clone(),
        });
    }
    client.receive(cookie_response(b"stale"), 0).unwrap();
    client.receive(cookie_response(b""), 1).unwrap();
    assert!(client.inner.lock().unwrap().connection_cookie.is_empty());
    client.receive(cookie_response(b"first"), 1).unwrap();
    client.receive(cookie_response(b"second"), 1).unwrap();
    assert_eq!(
        client.inner.lock().unwrap().connection_cookie.as_ref(),
        b"first"
    );
    client.terminate_generation(1, String::new());
    assert!(client.inner.lock().unwrap().connection_cookie.is_empty());
    {
        let mut inner = client.inner.lock().unwrap();
        inner.generation = 2;
        inner.connection = Some(Connection {
            generation: 2,
            sender,
        });
    }
    client.receive(cookie_response(b"stale"), 1).unwrap();
    assert!(client.inner.lock().unwrap().connection_cookie.is_empty());
    client.receive(cookie_response(b"new"), 2).unwrap();
    assert_eq!(
        client.inner.lock().unwrap().connection_cookie.as_ref(),
        b"new"
    );

    let linux = Client::new(ClientConfig::default(), Keystore::default()).unwrap();
    let (sender, _receiver) = mpsc::channel(8);
    {
        let mut inner = linux.inner.lock().unwrap();
        inner.generation = 1;
        inner.connection = Some(Connection {
            generation: 1,
            sender,
        });
    }
    linux.receive(cookie_response(b"mobile-only"), 1).unwrap();
    assert!(linux.inner.lock().unwrap().connection_cookie.is_empty());
}

#[test]
fn mobile_reserved_template_keeps_unknown_bytes_and_rejects_stale_dynamic_fields() {
    for template in [
        crate::proto::sso::Reserved {
            uid: Some("stale".into()),
            ..Default::default()
        },
        crate::proto::sso::Reserved {
            trace_parent: Some("stale".into()),
            ..Default::default()
        },
        crate::proto::sso::Reserved {
            secure_info: Some(crate::proto::sso::SecureInfo::default()),
            ..Default::default()
        },
    ] {
        assert!(IosReservedTemplate::new(template.encode_to_vec().into()).is_err());
    }
    assert!(IosReservedTemplate::new(Bytes::from_static(b"\xff")).is_err());
    let template = Bytes::from_static(b"\xf8\x07\x01\x48\x01");
    let mut transport = transport_resources();
    transport.reserved = IosReservedTemplate::new(template.clone()).unwrap();
    let client = Client::new(config(Profile::iphone()), Keystore::default()).unwrap();
    client.set_ios_transport_resources(transport).unwrap();
    let inner = client.inner.lock().unwrap();
    let frame = wire::encode_sso(
        "not.a.signed.command",
        inner.sequence,
        Bytes::new(),
        RequestType::Simple,
        Encryption::Empty,
        &inner.state,
        None,
        Some((&inner.ios().unwrap().transport, &inner.connection_cookie)),
        None,
        true,
        None,
        false,
    )
    .unwrap();
    let (_, _, _, mut head, _) = request_parts(frame, &[0; 16]);
    head.p32().unwrap();
    head.p32().unwrap();
    let bytes = head.p32().unwrap();
    assert!(bytes.starts_with(&template));
    let reserve: crate::proto::sso::Reserved = crate::proto::decode(bytes).unwrap();
    assert_eq!(reserve.flag, Some(1));
    assert_eq!(reserve.uid.as_deref(), Some(""));
    assert!(reserve.trace_parent.is_some());
    assert!(reserve.secure_info.is_none());
}

#[test]
fn linux_complete_wire_does_not_adopt_mobile_resources_or_cookies() {
    let client = Client::new(ClientConfig::default(), Keystore::default()).unwrap();
    assert!(
        client
            .set_ios_transport_resources(transport_resources())
            .is_err()
    );
    let mut inner = client.inner.lock().unwrap();
    assert!(inner.state.keystore.ios_msf_imei.is_empty());
    assert!(inner.ios().is_none());
    assert!(inner.linux_o3().is_some());
    inner.connection_cookie = Bytes::from_static(b"mobile-cookie");
    let (_, frame) = client
        .prepare_frame(
            &mut inner,
            "not.a.signed.command",
            Bytes::new(),
            RequestType::D2,
            Encryption::Empty,
        )
        .unwrap();
    let (_, account_type, account, mut head, _) = request_parts(frame, &[0; 16]);
    assert_eq!(account_type, 0);
    assert_eq!(account.as_ref(), b"0");
    head.i32().unwrap();
    assert_eq!(head.u32().unwrap(), inner.state.profile.sub_app_id);
    assert_eq!(head.u32().unwrap(), 2052);
    assert_eq!(head.u8().unwrap(), 2);
    for _ in 0..11 {
        assert_eq!(head.u8().unwrap(), 0);
    }
    head.p32().unwrap();
    head.p32().unwrap();
    assert!(head.p32().unwrap().is_empty());
    assert_eq!(
        head.p32().unwrap().as_ref(),
        hex::encode(&inner.state.keystore.guid).as_bytes()
    );
    assert!(head.p32().unwrap().is_empty());
    assert_eq!(
        head.pref(2, true).unwrap().as_ref(),
        inner.state.profile.version.as_bytes()
    );
}

#[test]
fn mobile_identity_is_persisted_independently_and_survives_client_recreation() {
    let guid = vec![0x31; 16];
    let legacy: Keystore =
        serde_json::from_str(r#"{"guid":[49,49,49,49,49,49,49,49,49,49,49,49,49,49,49,49]}"#)
            .unwrap();
    let client = Client::new(config(Profile::iphone()), legacy).unwrap();
    let mut saved = client.inner.lock().unwrap().state.keystore.clone();
    assert_eq!(saved.guid, guid);
    let identity = saved.ios_msf_imei.clone();
    assert_eq!(identity.len(), 36);
    for (index, byte) in identity.bytes().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            assert_eq!(byte, b'-');
        } else {
            assert!(byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte));
        }
    }
    assert_eq!(identity.as_bytes()[14], b'4');
    assert!(matches!(identity.as_bytes()[19], b'8' | b'9' | b'A' | b'B'));
    assert_ne!(identity.replace('-', ""), hex::encode_upper(&guid));
    assert!(!saved.ensure_ios_identity().unwrap());
    let persisted = serde_json::to_vec(&saved).unwrap();
    let restored: Keystore = serde_json::from_slice(&persisted).unwrap();
    let recreated = Client::new(config(Profile::ipad()), restored).unwrap();
    let mut inner = recreated.inner.lock().unwrap();
    let (_, frame) = recreated
        .prepare_frame(
            &mut inner,
            "not.a.signed.command",
            Bytes::new(),
            RequestType::D2,
            Encryption::Empty,
        )
        .unwrap();
    let (_, _, _, mut head, _) = request_parts(frame, &[0; 16]);
    head.i32().unwrap();
    assert_eq!(head.u32().unwrap(), 537_396_819);
    head.skip(16).unwrap();
    for _ in 0..3 {
        head.p32().unwrap();
    }
    assert_eq!(head.p32().unwrap().as_ref(), identity.as_bytes());
    drop(inner);
    let independent = Client::new(
        config(Profile::iphone()),
        Keystore {
            guid: guid.clone(),
            ..Default::default()
        },
    )
    .unwrap();
    assert_ne!(
        independent
            .inner
            .lock()
            .unwrap()
            .state
            .keystore
            .ios_msf_imei,
        identity
    );
    for retained in [
        "historical-opaque||not-keychain-metadata",
        "lowercase-identity",
    ] {
        let mut saved = Keystore {
            ios_msf_imei: retained.into(),
            ..Default::default()
        };
        assert!(!saved.ensure_ios_identity().unwrap());
        let client = Client::new(config(Profile::iphone()), saved).unwrap();
        let mut inner = client.inner.lock().unwrap();
        let (_, frame) = client
            .prepare_frame(
                &mut inner,
                "not.a.signed.command",
                Bytes::new(),
                RequestType::D2,
                Encryption::Empty,
            )
            .unwrap();
        let (_, _, _, mut head, _) = request_parts(frame, &[0; 16]);
        head.skip(24).unwrap();
        for _ in 0..3 {
            head.p32().unwrap();
        }
        assert_eq!(head.p32().unwrap().as_ref(), retained.as_bytes());
    }
}

#[test]
fn mobile_transport_rejects_invalid_effective_native_flags() {
    for (index, value) in [(9, 4), (9, 255), (10, 1), (10, 255)] {
        let mut transport = transport_resources();
        transport.effective_flags[index] = value;
        assert!(transport.validate().is_err());
    }
    let mut transport = transport_resources();
    transport.effective_flags[9] = 0;
    transport.effective_flags[10] = 0;
    transport.validate().unwrap();
}

#[tokio::test]
async fn successful_mobile_registration_does_not_become_first_registration_on_reauthentication() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let client = Client::new(
            ClientConfig {
                profile: Profile::ipad(),
                platform: Some(PlatformConfig::Ios(IosConfig::Virtual(Arc::new(
                    crate::ios_device::IosVirtualConfig::default(),
                )))),
                ..Default::default()
            },
            Keystore {
                uin: 42,
                ..Default::default()
            },
        )
        .unwrap();
        let (sender, mut queue) = mpsc::channel::<Outgoing>(16);
        client.inner.lock().unwrap().connection = Some(Connection {
            generation: 0,
            sender,
        });
        for (reconnect, first_register, scene) in [(false, 0, 7), (false, 1, 7), (true, 1, 4)] {
            let task = {
                let client = client.clone();
                tokio::spawn(async move { client.start_message_sync(reconnect).await })
            };
            let outgoing = queue.recv().await.unwrap();
            assert_eq!(outgoing.command, crate::message_sync::INFO_COMMAND);
            let request =
                auth::InfoSyncRequest::decode(request_parts(outgoing.frame, &[0; 16]).4).unwrap();
            let register = request.register.unwrap();
            assert_eq!(register.first_register, Some(first_register));
            assert_eq!(register.scene, Some(scene));
            let response = auth::InfoSyncResponse {
                request_random: request.request_random,
                register: Some(auth::InfoSyncRegisterResponse {
                    message: Some("register success".into()),
                    ..Default::default()
                }),
                ..Default::default()
            };
            client
                .receive(
                    tests::incoming(
                        outgoing.sequence,
                        &outgoing.command,
                        &response.encode_to_vec(),
                        Some(&[0; 16]),
                    ),
                    0,
                )
                .unwrap();
            task.await.unwrap().unwrap();
        }
        client.terminate("registration test completed".into());
    })
    .await
    .unwrap();
}
