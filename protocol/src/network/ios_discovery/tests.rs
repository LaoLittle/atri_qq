use super::*;

fn server(transport: i8) -> ServerInfo {
    ServerInfo {
        host: "127.0.0.1".into(),
        port: 8080,
        transport,
        probe_eligibility: 0,
        ..Default::default()
    }
}

#[test]
fn native_unsigned_words_and_real_tea_envelope_decode() {
    let request = HttpServerListReq {
        account_u32: NativeU32(0xffff_fffe),
        server_time: NativeU32(0x8000_0001),
        app_id: NativeU32(0x8000_0002),
        account: 0x1_ffff_fffe,
        carrier: "000000".into(),
        device_identifier: "stable-device".into(),
        network: 100,
        ..Default::default()
    };
    let cipher = encode_request(&request).unwrap();
    let plain = crypto::tea_decrypt(&cipher, &KEY).unwrap();
    assert_eq!(
        u32::from_be_bytes(plain[..4].try_into().unwrap()) as usize,
        plain.len()
    );
    #[derive(JceStruct)]
    struct PacketMetadata {
        #[jce(tag = "1", required)]
        version: i16,
        #[jce(tag = "4", required)]
        request_id: i32,
    }
    let metadata = PacketMetadata::decode(Bytes::copy_from_slice(&plain[4..])).unwrap();
    assert_eq!(metadata.version, 2);
    assert_eq!(metadata.request_id, 0);
    let payload = wire::config_push::payload(
        Bytes::copy_from_slice(&plain[4..]),
        "ConfigHttp",
        "HttpServerListReq",
        "HttpServerListReq",
        "ConfigHttp.HttpServerListReq",
    )
    .unwrap();
    assert_eq!(&payload[..9], &[0x13, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xfe]);
    let decoded = HttpServerListReq::decode(payload).unwrap();
    assert_eq!(decoded.account_u32.0, 0xffff_fffe);
    assert_eq!(decoded.server_time.0, 0x8000_0001);
    assert_eq!(decoded.app_id.0, 0x8000_0002);
    assert_eq!(decoded.field_3, 1);
    assert_eq!(decoded.field_12, 3);
}

#[test]
fn v2_and_native_flat_responses_feed_tcp_cache_not_probe_or_quic_lists() {
    let response = HttpServerListRes {
        result: 1,
        server_time: i32::MIN + 1,
        interval_seconds: 12,
        mobile: vec![server(1)],
        wifi: vec![server(4), server(0)],
        ipv6: vec![server(0)],
        list_13: vec![server(3)],
        list_32: vec![server(4)],
        ..Default::default()
    };
    let v2 = response_fixture(&response);
    let flat = encrypted_packet(wire::config_push::flat_payload_fixture(
        "ConfigHttp",
        "HttpServerListRes",
        "HttpServerListRes",
        wire::encode_jce_raw(&response),
    ))
    .unwrap();
    for cipher in [v2, flat] {
        let mut cache = ServerListCache::default();
        cache
            .accept(decode_response(&cipher).unwrap(), "000000", 5000)
            .unwrap();
        assert_eq!(cache.server_time, 0x8000_0001);
        assert_eq!(cache.interval_seconds, 600);
        assert_eq!(cache.tcp_servers(ServerSelection::Wifi).count(), 2);
        assert_eq!(cache.wifi[0].probe_eligibility, 0);
        let before = cache.clone();
        cache
            .accept(
                HttpServerListRes {
                    result: 0,
                    server_time: 17,
                    interval_seconds: i32::MAX,
                    wifi: vec![server(1)],
                    ..Default::default()
                },
                "different-carrier",
                9000,
            )
            .unwrap();
        assert_eq!(cache.interval_seconds, 604800);
        assert_eq!(cache.server_time, before.server_time);
        assert_eq!(cache.accepted_unix_seconds, before.accepted_unix_seconds);
        assert_eq!(cache.wifi, before.wifi);
        assert_eq!(cache.carrier, before.carrier);
        let unchanged = cache.clone();
        assert!(
            cache
                .accept(
                    HttpServerListRes {
                        result: -1,
                        ..Default::default()
                    },
                    "000000",
                    9999
                )
                .is_err()
        );
        assert_eq!(cache, unchanged);
        assert!(
            cache
                .accept(
                    HttpServerListRes {
                        result: 1,
                        interval_seconds: 601,
                        wifi: vec![ServerInfo {
                            host: "bad host".into(),
                            ..server(0)
                        }],
                        ..Default::default()
                    },
                    "000000",
                    9999
                )
                .is_err()
        );
        assert_eq!(cache, unchanged);
    }
    assert!(decode_response(b"not encrypted JCE").is_err());
}

#[test]
fn cache_carrier_freshness_bucket_identity_and_cbor_restore() {
    let mut store = crate::models::Keystore::default();
    let mut cache = ServerListCache::default();
    cache
        .accept(
            HttpServerListRes {
                result: 1,
                wifi: vec![server(0)],
                server_time: -1,
                ..Default::default()
            },
            "000000",
            1000,
        )
        .unwrap();
    assert!(cache.fresh(1001, "000000"));
    assert!(cache.fresh(999, "000000"));
    let wrapped = ServerListCache {
        accepted_unix_seconds: u64::from(u32::MAX) - 10,
        carrier: "000000".into(),
        ..Default::default()
    };
    assert!(wrapped.fresh(u64::from(u32::MAX) + 20, "000000"));
    assert!(!cache.fresh(1001, "46001"));
    assert!(!cache.fresh(1000 + 86400, "000000"));
    assert_eq!(bucket(true, None), "nossid_wifi");
    assert_eq!(bucket(false, None), "nossid_2g3g");
    assert_ne!(bucket(true, Some("a")), bucket(true, Some("b")));
    assert_ne!(bucket(true, Some("a")), bucket(false, Some("a")));
    store.ios_server_lists.insert(bucket(true, None), cache);
    let mut bytes = Vec::new();
    ciborium::into_writer(&store, &mut bytes).unwrap();
    let restored: crate::models::Keystore = ciborium::from_reader(bytes.as_slice()).unwrap();
    assert_eq!(restored.ios_server_lists, store.ios_server_lists);
    assert_eq!(
        restored.ios_server_lists["nossid_wifi"].server_time,
        u32::MAX
    );
}
