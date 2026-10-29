use super::*;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    ecdsa::EcdsaSig,
    nid::Nid,
    pkey::Private,
};

fn setup() -> (Channel, EcKey<Private>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let private = BigNum::from_u32(1).unwrap();
    let mut context = BigNumContext::new().unwrap();
    let mut point = EcPoint::new(&group).unwrap();
    point
        .mul_generator2(&group, &private, &mut context)
        .unwrap();
    let peer = point
        .to_bytes(&group, PointConversionForm::COMPRESSED, &mut context)
        .unwrap();
    let key = EcKey::from_private_components(&group, &private, &point).unwrap();
    (
        Channel::with_peer(CheckMode::Sdk, peer.try_into().unwrap()),
        key,
    )
}

fn at(wall: u64, steady: u64) -> Clock {
    Clock {
        wall,
        steady: Duration::from_secs(steady),
    }
}

fn prepare(channel: &mut Channel, wall: u64, steady: u64) -> Request {
    channel
        .prepare_at(
            "getToken",
            Bytes::from_static(b"synthetic business request"),
            at(wall, steady),
        )
        .unwrap()
}

fn server_key(server: &EcKey<Private>, request: &Request) -> [u8; 32] {
    let public = if request.mode == Mode::Establish {
        pb::IosEstablishShareKeyRequest::decode(request.body.clone())
            .unwrap()
            .client_public_key
    } else {
        Bytes::copy_from_slice(&request.material.public)
    };
    let mut context = BigNumContext::new().unwrap();
    let point = EcPoint::from_bytes(server.group(), &public, &mut context).unwrap();
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
    key
}

fn inner(
    server: &EcKey<Private>,
    request: &Request,
    deadline: u64,
) -> pb::IosEstablishInnerResponse {
    let envelope = pb::IosEstablishShareKeyRequest::decode(request.body.clone()).unwrap();
    let plain = crypto::open(&server_key(server, request), &envelope.encrypted_body).unwrap();
    let plain = pb::ChannelPlaintext::decode(plain).unwrap();
    let mut context = BigNumContext::new().unwrap();
    let peer = server
        .public_key()
        .to_bytes(
            server.group(),
            PointConversionForm::COMPRESSED,
            &mut context,
        )
        .unwrap();
    let parameter = 0x1020_3040_5060_7080u64;
    let mut transcript = peer;
    transcript.extend_from_slice(&plain.parameter.to_be_bytes());
    transcript.extend_from_slice(&parameter.to_be_bytes());
    let signature = EcdsaSig::sign(&crate::crypto::sha256(&transcript), server).unwrap();
    let mut material = signature.r().to_vec_padded(32).unwrap();
    material.extend_from_slice(&signature.s().to_vec_padded(32).unwrap());
    pb::IosEstablishInnerResponse {
        material: vec![material.into()],
        parameter,
        channel_time: deadline,
        business_response: vec![Bytes::from_static(
            b"authenticated synthetic business reply",
        )],
        config: None,
    }
}

fn response(
    server: &EcKey<Private>,
    request: &Request,
    inner: pb::IosEstablishInnerResponse,
) -> Bytes {
    pb::IosEstablishShareKeyResponse {
        encrypted_body: vec![
            crypto::seal(&server_key(server, request), &inner.encode_to_vec()).unwrap(),
        ],
        ..Default::default()
    }
    .encode_to_vec()
    .into()
}

fn status(code: u32, duration: u64) -> Bytes {
    pb::IosEstablishShareKeyResponse {
        status: code,
        unavailable_duration_seconds: duration,
        ..Default::default()
    }
    .encode_to_vec()
    .into()
}

#[test]
fn incomplete_establish_reuses_material_and_authenticated_reply_enables_access() {
    let (mut channel, server) = setup();
    let first = prepare(&mut channel, 100, 100);
    let second = prepare(&mut channel, 101, 101);
    assert!(Arc::ptr_eq(&first.material, &second.material));
    drop(first);
    let encoded = response(&server, &second, inner(&server, &second, 500));
    let reply = channel.complete_at(second, encoded, at(102, 102)).unwrap();
    assert_eq!(
        reply.body.as_ref(),
        b"authenticated synthetic business reply"
    );
    let request = prepare(&mut channel, 103, 103);
    assert_eq!(request.command(false), ACCESS_COMMAND);
    let key = server_key(&server, &request);
    let encrypted = crypto::seal(&key, b"access response").unwrap();
    let encoded = pb::IosSecureAccessResponse {
        encrypted_body: vec![encrypted.slice(..10), encrypted.slice(10..)],
        extra: vec![
            Bytes::from_static(b"opaque\0"),
            Bytes::from_static(b"metadata"),
        ],
        ..Default::default()
    }
    .encode_to_vec()
    .into();
    let reply = channel.complete_at(request, encoded, at(104, 104)).unwrap();
    assert_eq!(reply.body.as_ref(), b"access response");
    assert_eq!(reply.extra.as_ref(), b"opaque\0metadata");
}

#[test]
fn expiry_requires_both_clocks_and_strict_whole_second_boundaries() {
    let (mut channel, server) = setup();
    let request = prepare(&mut channel, 100, 100);
    let uuid = request.material.uuid;
    let encoded = response(&server, &request, inner(&server, &request, 150));
    channel.complete_at(request, encoded, at(100, 100)).unwrap();
    for time in [
        at(151, 160),
        at(150, 200),
        at(149, 201),
        Clock {
            wall: 151,
            steady: Duration::new(160, 999_999_999),
        },
    ] {
        let request = channel
            .prepare_at("getToken", Bytes::from_static(b"next"), time)
            .unwrap();
        assert_eq!(request.command(false), ACCESS_COMMAND);
        assert_eq!(request.material.uuid, uuid);
    }
    let request = prepare(&mut channel, 151, 161);
    assert_eq!(request.command(false), ESTABLISH_COMMAND);
    assert_ne!(request.material.uuid, uuid);
}

#[test]
fn failed_authentication_keeps_material_but_applies_proven_deadline_and_config_effects() {
    let (mut channel, server) = setup();
    let request = prepare(&mut channel, 100, 100);
    let material = request.material.clone();
    let mut decoded = inner(&server, &request, 150);
    decoded.material = vec![Bytes::from_static(b"invalid signature")];
    decoded.config = Some(pb::IosChannelConfig {
        option1: Some(1),
        option9: Some(u32::MAX),
        ..Default::default()
    });
    let encoded = response(&server, &request, decoded);
    assert!(matches!(
        channel.complete_at(request, encoded, at(100, 100)),
        Err(Error::Crypto(_))
    ));
    let update = channel.take_switch_update().unwrap();
    assert_eq!(
        update.values,
        [
            Some(1),
            None,
            Some(0),
            Some(2),
            Some(0),
            Some(0),
            Some(0),
            Some(0),
            Some(2)
        ]
    );
    assert!(update.unresolved_native_defaults);
    let retry = prepare(&mut channel, 151, 160);
    assert!(Arc::ptr_eq(&material, &retry.material));
    assert_eq!(retry.command(false), ESTABLISH_COMMAND);
    let renewed = prepare(&mut channel, 151, 161);
    assert!(!Arc::ptr_eq(&material, &renewed.material));
}

#[test]
fn cooldown_precedes_status_and_only_blocks_the_named_business_until_exact_boundary() {
    let (mut channel, _) = setup();
    let request = prepare(&mut channel, 100, 100);
    let uuid = request.material.uuid;
    assert!(matches!(
        channel.complete_at(request, status(1002, 10), at(100, 100)),
        Err(Error::Server { code: 1999, .. })
    ));
    assert!(matches!(
        channel.prepare_at("getToken", Bytes::new(), at(200, 109)),
        Err(Error::Server { code: 1999, .. })
    ));
    let other = channel
        .prepare_at("other", Bytes::new(), at(200, 109))
        .unwrap();
    assert_eq!(other.material.uuid, uuid);
    let allowed = prepare(&mut channel, 200, 110);
    assert_eq!(allowed.material.uuid, uuid);
    assert!(matches!(
        channel.complete_at(allowed, status(1003, 0), at(200, 110)),
        Err(Error::Server { code: 1003, .. })
    ));
    let preserved = prepare(&mut channel, 201, 111);
    assert_eq!(preserved.material.uuid, uuid);
    assert!(matches!(
        channel.complete_at(preserved, status(77, 0), at(201, 111)),
        Err(Error::Server { code: 2000, .. })
    ));
    assert_ne!(prepare(&mut channel, 202, 112).material.uuid, uuid);
}

#[test]
fn newest_first_history_accepts_fifty_materials_and_rejects_evicted_requests() {
    let (mut channel, server) = setup();
    let mut outstanding = VecDeque::new();
    for i in 0..51 {
        let waiting = prepare(&mut channel, 100 + i, 100 + i);
        let rejected = prepare(&mut channel, 100 + i, 100 + i);
        outstanding.push_back(waiting);
        assert!(matches!(
            channel.complete_at(rejected, status(1001, 0), at(100 + i, 100 + i)),
            Err(Error::Server { code: 1001, .. })
        ));
    }
    let current = prepare(&mut channel, 200, 200);
    let uuid = current.material.uuid;
    let evicted = outstanding.pop_front().unwrap();
    let encoded = response(&server, &evicted, inner(&server, &evicted, 1));
    assert!(matches!(
        channel.complete_at(evicted, encoded, at(200, 200)),
        Err(Error::Authentication(_))
    ));
    for old in outstanding {
        let mut decoded = inner(&server, &old, 1);
        decoded.config = Some(pb::IosChannelConfig {
            option2: Some(0),
            ..Default::default()
        });
        let encoded = response(&server, &old, decoded);
        assert_eq!(
            channel
                .complete_at(old, encoded, at(200, 200))
                .unwrap()
                .body
                .as_ref(),
            b"authenticated synthetic business reply"
        );
    }
    assert!(channel.take_switch_update().is_none());
    let next = prepare(&mut channel, 10_000, 10_000);
    assert_eq!(next.command(false), ESTABLISH_COMMAND);
    assert_eq!(next.material.uuid, uuid);
}

#[test]
fn reset_rejects_late_authenticated_responses_and_clears_cooldowns() {
    let (mut channel, server) = setup();
    let request = prepare(&mut channel, 100, 100);
    let encoded = response(&server, &request, inner(&server, &request, 500));
    let unavailable_request = prepare(&mut channel, 100, 100);
    let _ = channel.complete_at(unavailable_request, status(0, 1000), at(100, 100));
    channel.reset();
    assert!(matches!(
        channel.complete_at(request, encoded, at(101, 101)),
        Err(Error::Authentication(_))
    ));
    assert_eq!(
        prepare(&mut channel, 101, 101).command(false),
        ESTABLISH_COMMAND
    );
}

#[test]
fn corrupt_gcm_and_empty_plaintext_do_not_discard_material_or_publish_business() {
    let (mut channel, server) = setup();
    let request = prepare(&mut channel, 100, 100);
    let uuid = request.material.uuid;
    let mut decoded = inner(&server, &request, 500);
    decoded.business_response = vec![Bytes::from_static(b"must not publish")];
    let mut outer =
        pb::IosEstablishShareKeyResponse::decode(response(&server, &request, decoded)).unwrap();
    let mut corrupt = outer.encrypted_body[0].to_vec();
    *corrupt.last_mut().unwrap() ^= 1;
    outer.encrypted_body = vec![corrupt.into()];
    assert!(matches!(
        channel.complete_at(request, outer.encode_to_vec().into(), at(100, 100)),
        Err(Error::Crypto(_))
    ));
    let request = prepare(&mut channel, 101, 101);
    assert_eq!(request.material.uuid, uuid);
    let outer = pb::IosEstablishShareKeyResponse {
        encrypted_body: vec![crypto::seal(&server_key(&server, &request), &[]).unwrap()],
        ..Default::default()
    };
    assert!(matches!(
        channel.complete_at(request, outer.encode_to_vec().into(), at(101, 101)),
        Err(Error::Crypto(_))
    ));
    assert_eq!(prepare(&mut channel, 102, 102).material.uuid, uuid);
}

#[test]
fn already_authenticated_establish_skips_repeat_signature_and_config_gate_preserves_switches() {
    let (mut channel, server) = setup();
    let first = prepare(&mut channel, 100, 100);
    let second = prepare(&mut channel, 100, 100);
    let encoded = response(&server, &first, inner(&server, &first, 500));
    channel.complete_at(first, encoded, at(100, 100)).unwrap();
    channel.take_switch_update();
    let mut decoded = inner(&server, &second, 600);
    decoded.material.clear();
    decoded.config = Some(pb::IosChannelConfig {
        option2: Some(0),
        skip_update: 1,
        ..Default::default()
    });
    let encoded = response(&server, &second, decoded);
    assert_eq!(
        channel
            .complete_at(second, encoded, at(101, 101))
            .unwrap()
            .body
            .as_ref(),
        b"authenticated synthetic business reply"
    );
    assert!(channel.take_switch_update().is_none());
    assert_eq!(
        prepare(&mut channel, 550, 200).command(false),
        ACCESS_COMMAND
    );
}
