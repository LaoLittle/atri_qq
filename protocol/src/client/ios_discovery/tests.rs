use super::*;
use crate::network::ios_discovery::{HttpServerListRes, ServerInfo, ServerListCache};
use jce::JceStruct;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

fn client(profile: Profile, store: Keystore) -> Arc<Client> {
    let mut config = ios_signing_tests::config(profile);
    config.ios_snapshot_mut().unwrap().transport.network_type = 1;
    config.timeout = Duration::from_secs(2);
    Client::new(config, store).unwrap()
}

fn server(listener: &TcpListener, transport: i8) -> ServerInfo {
    ServerInfo {
        host: "127.0.0.1".into(),
        port: listener.local_addr().unwrap().port().into(),
        transport,
        probe_eligibility: 0,
        ..Default::default()
    }
}

fn seed(client: &Client, servers: Vec<ServerInfo>, fresh: bool) {
    let mut inner = client.inner.lock().unwrap();
    inner.state.keystore.ios_server_lists.insert(
        "nossid_wifi".into(),
        ServerListCache {
            server_time: 0x8000_0001,
            accepted_unix_seconds: if fresh { now_seconds() } else { 1 },
            carrier: "46001".into(),
            wifi: servers,
            ..Default::default()
        },
    );
}

async fn http(
    response: Bytes,
) -> (
    String,
    oneshot::Receiver<(String, Vec<u8>)>,
    Arc<Notify>,
    JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://{}/configsvr/serverlist.jsp",
        listener.local_addr().unwrap()
    );
    let release = Arc::new(Notify::new());
    let waiter = release.clone();
    let (sent, received) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        let (header_len, content_len) = loop {
            let mut chunk = [0; 2048];
            let read = stream.read(&mut chunk).await.unwrap();
            assert_ne!(read, 0);
            bytes.extend_from_slice(&chunk[..read]);
            if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                let header = String::from_utf8_lossy(&bytes[..end]);
                let length = header
                    .lines()
                    .find_map(|line| {
                        line.split_once(':')
                            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                            .map(|(_, value)| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap();
                break (end + 4, length);
            }
        };
        while bytes.len() < header_len + content_len {
            let mut chunk = [0; 2048];
            let read = stream.read(&mut chunk).await.unwrap();
            assert_ne!(read, 0);
            bytes.extend_from_slice(&chunk[..read]);
        }
        sent.send((
            String::from_utf8(bytes[..header_len].to_vec()).unwrap(),
            bytes[header_len..header_len + content_len].to_vec(),
        ))
        .unwrap();
        waiter.notified().await;
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response.len()
        );
        if stream.write_all(header.as_bytes()).await.is_ok() {
            let _ = stream.write_all(&response).await;
        }
    });
    (url, received, release, task)
}

async fn settled(client: &Client) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if client
                .inner
                .lock()
                .unwrap()
                .ios_mut()
                .unwrap()
                .discovery
                .pending
                .is_none()
            {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

fn request(bytes: Vec<u8>) -> HttpServerListReq {
    let key = hex::decode("f0441f5ff42da58fdcf7949aba62d411").unwrap();
    let plain = crate::crypto::tea_decrypt(&bytes, &key).unwrap();
    let payload = wire::config_push::payload(
        Bytes::copy_from_slice(&plain[4..]),
        "ConfigHttp",
        "HttpServerListReq",
        "HttpServerListReq",
        "ConfigHttp.HttpServerListReq",
    )
    .unwrap();
    HttpServerListReq::decode(payload).unwrap()
}

#[tokio::test]
async fn iphone_and_ipad_connect_without_waiting_http_and_discard_late_reason_zero() {
    for profile in [Profile::iphone(), Profile::ipad()] {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let quic = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = client(
            profile.clone(),
            Keystore {
                uin: 0x1_ffff_fffe,
                ..Default::default()
            },
        );
        seed(&client, vec![server(&quic, 4), server(&tcp, 0)], false);
        let old = client
            .inner
            .lock()
            .unwrap()
            .state
            .keystore
            .ios_server_lists
            .clone();
        let response = ios_discovery::response_fixture(&HttpServerListRes {
            result: 1,
            server_time: 77,
            wifi: vec![server(&quic, 0)],
            ..Default::default()
        });
        let (url, received, release, task) = http(response).await;
        client
            .inner
            .lock()
            .unwrap()
            .ios_mut()
            .unwrap()
            .discovery
            .url = Some(url);
        tokio::time::timeout(Duration::from_secs(1), client.connect())
            .await
            .unwrap()
            .unwrap();
        let (socket, _) = tokio::time::timeout(Duration::from_secs(1), tcp.accept())
            .await
            .unwrap()
            .unwrap();
        let (header, body) = tokio::time::timeout(Duration::from_secs(2), received)
            .await
            .unwrap()
            .unwrap();
        assert!(header.starts_with("POST /configsvr/serverlist.jsp HTTP/1.1"));
        assert!(
            header
                .to_ascii_lowercase()
                .contains("content-type: application/x-www-form-urlencoded")
        );
        let request = request(body);
        assert_eq!(request.account_u32.0, 0xffff_fffe);
        assert_eq!(request.server_time.0, 0x8000_0001);
        assert_eq!(request.app_id.0, profile.sub_app_id);
        assert_eq!(request.network, 100);
        assert_eq!(request.carrier, "46001");
        assert_eq!(
            request.device_identifier,
            client.inner.lock().unwrap().state.keystore.ios_msf_imei
        );
        assert!(
            client
                .inner
                .lock()
                .unwrap()
                .ios()
                .unwrap()
                .discovery
                .pending
                .is_some()
        );
        release.notify_one();
        task.await.unwrap();
        settled(&client).await;
        assert_eq!(
            client.inner.lock().unwrap().state.keystore.ios_server_lists,
            old
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), quic.accept())
                .await
                .is_err()
        );
        client.close_transport("fixture finished".into()).await;
        drop(socket);
    }
}

#[tokio::test]
async fn reason_three_accepts_after_tcp_connect_and_throttles_real_failure_refresh() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = client(Profile::iphone(), Keystore::default());
    let failed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed = server(&failed, 0);
    drop(failed);
    seed(&client, vec![closed, server(&tcp, 1)], true);
    let stale = client.snapshot().await;
    let response = ios_discovery::response_fixture(&HttpServerListRes {
        result: 1,
        server_time: -1,
        wifi: vec![server(&tcp, 0)],
        ..Default::default()
    });
    let (url, received, release, task) = http(response).await;
    client
        .inner
        .lock()
        .unwrap()
        .ios_mut()
        .unwrap()
        .discovery
        .url = Some(url);
    let mut events = client.events.subscribe();
    tokio::time::timeout(Duration::from_secs(1), client.connect())
        .await
        .unwrap()
        .unwrap();
    let (socket, _) = tcp.accept().await.unwrap();
    let generation = client.connection_generation();
    let _ = received.await.unwrap();
    client.start_ios_discovery(generation, true);
    release.notify_one();
    task.await.unwrap();
    settled(&client).await;
    assert!(matches!(
        events.recv().await.unwrap(),
        LoginEvent::KeystoreChanged(_)
    ));
    assert_eq!(
        client.inner.lock().unwrap().state.keystore.ios_server_lists["nossid_wifi"].server_time,
        u32::MAX
    );
    client.replace_state(stale).await;
    assert_eq!(
        client.inner.lock().unwrap().state.keystore.ios_server_lists["nossid_wifi"].server_time,
        u32::MAX
    );
    client.start_ios_discovery(generation, true);
    assert!(
        client
            .inner
            .lock()
            .unwrap()
            .ios()
            .unwrap()
            .discovery
            .pending
            .is_none()
    );
    client.close_transport("fixture finished".into()).await;
    drop(socket);
}

#[tokio::test]
async fn fresh_cache_suppresses_http_but_changed_carrier_and_generation_cancel_are_observable() {
    let fresh_client = client(Profile::ipad(), Keystore::default());
    seed(&fresh_client, Vec::new(), true);
    fresh_client.start_ios_discovery(0, false);
    assert!(
        fresh_client
            .inner
            .lock()
            .unwrap()
            .ios()
            .unwrap()
            .discovery
            .pending
            .is_none()
    );
    fresh_client
        .inner
        .lock()
        .unwrap()
        .ios_mut()
        .unwrap()
        .transport
        .carrier_mnc = "02".into();
    fresh_client.start_ios_discovery(0, false);
    assert!(
        fresh_client
            .inner
            .lock()
            .unwrap()
            .ios()
            .unwrap()
            .discovery
            .pending
            .is_none()
    );
    let client = client(Profile::ipad(), Keystore::default());
    seed(&client, Vec::new(), true);
    client
        .inner
        .lock()
        .unwrap()
        .ios_mut()
        .unwrap()
        .transport
        .carrier_mnc = "02".into();
    let response = ios_discovery::response_fixture(&HttpServerListRes {
        result: 1,
        server_time: 99,
        ..Default::default()
    });
    let (url, received, release, task) = http(response).await;
    client
        .inner
        .lock()
        .unwrap()
        .ios_mut()
        .unwrap()
        .discovery
        .url = Some(url);
    client.start_ios_discovery(0, false);
    let _ = received.await.unwrap();
    let pending_id = client
        .inner
        .lock()
        .unwrap()
        .ios_mut()
        .unwrap()
        .discovery
        .pending
        .as_ref()
        .unwrap()
        .id;
    client.start_ios_discovery(0, false);
    assert_eq!(
        client
            .inner
            .lock()
            .unwrap()
            .ios()
            .unwrap()
            .discovery
            .pending
            .as_ref()
            .unwrap()
            .id,
        pending_id
    );
    {
        let mut inner = client.inner.lock().unwrap();
        inner.generation = 1;
        inner.ios_mut().unwrap().discovery.cancel_pending();
    }
    release.notify_one();
    task.await.unwrap();
    settled(&client).await;
    assert_eq!(
        client.inner.lock().unwrap().state.keystore.ios_server_lists["nossid_wifi"].server_time,
        0x8000_0001
    );
    let response = ios_discovery::response_fixture(&HttpServerListRes {
        result: 1,
        server_time: 100,
        ..Default::default()
    });
    let (url, received, release, task) = http(response).await;
    client
        .inner
        .lock()
        .unwrap()
        .ios_mut()
        .unwrap()
        .discovery
        .url = Some(url);
    client
        .inner
        .lock()
        .unwrap()
        .ios_mut()
        .unwrap()
        .transport
        .network_type = 2;
    client.start_ios_discovery(1, false);
    let _ = received.await.unwrap();
    client.terminate("fixture cancel".into());
    release.notify_one();
    task.await.unwrap();
    settled(&client).await;
    assert_eq!(
        client.inner.lock().unwrap().state.keystore.ios_server_lists["nossid_wifi"].server_time,
        0x8000_0001
    );
}

#[tokio::test]
async fn explicit_ios_endpoint_remains_pinned_even_with_cache_and_http_override() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let other = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = ios_signing_tests::config(Profile::iphone());
    config.host = "127.0.0.1".into();
    config.port = tcp.local_addr().unwrap().port();
    config.ios_snapshot_mut().unwrap().transport.network_type = 1;
    let client = Client::new(config, Keystore::default()).unwrap();
    seed(&client, vec![server(&other, 0)], false);
    client
        .inner
        .lock()
        .unwrap()
        .ios_mut()
        .unwrap()
        .discovery
        .url = Some("http://127.0.0.1:1/should-not-send".into());
    client.connect().await.unwrap();
    let (socket, _) = tcp.accept().await.unwrap();
    assert!(
        client
            .inner
            .lock()
            .unwrap()
            .ios()
            .unwrap()
            .discovery
            .pending
            .is_none()
    );
    client.close_transport("fixture finished".into()).await;
    drop(socket);
}

#[tokio::test]
async fn restored_cellular_cache_drives_tcp_despite_default_wifi_selection() {
    let mobile = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let wifi = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut store = Keystore::default();
    store.ios_server_lists.insert(
        "nossid_2g3g".into(),
        ServerListCache {
            server_time: u32::MAX,
            accepted_unix_seconds: now_seconds(),
            carrier: "46001".into(),
            mobile: vec![server(&mobile, 0)],
            wifi: vec![server(&wifi, 0)],
            ..Default::default()
        },
    );
    let mut bytes = Vec::new();
    ciborium::into_writer(&store, &mut bytes).unwrap();
    let restored: Keystore = ciborium::from_reader(bytes.as_slice()).unwrap();
    let client = Client::new(ios_signing_tests::config(Profile::ipad()), restored).unwrap();
    assert_eq!(client.config.server_selection, ServerSelection::Wifi);
    client.connect().await.unwrap();
    let (socket, _) = tokio::time::timeout(Duration::from_secs(1), mobile.accept())
        .await
        .unwrap()
        .unwrap();
    assert!(
        client
            .inner
            .lock()
            .unwrap()
            .ios()
            .unwrap()
            .discovery
            .pending
            .is_none()
    );
    client.close_transport("fixture finished".into()).await;
    drop(socket);
}

#[tokio::test]
async fn http_interval_only_and_bad_cipher_preserve_accepted_list_identity() {
    for interval_only in [true, false] {
        let client = client(Profile::iphone(), Keystore::default());
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        seed(&client, vec![server(&tcp, 0)], false);
        let before =
            client.inner.lock().unwrap().state.keystore.ios_server_lists["nossid_wifi"].clone();
        let body = if interval_only {
            ios_discovery::response_fixture(&HttpServerListRes {
                result: 0,
                server_time: 77,
                interval_seconds: 601,
                ..Default::default()
            })
        } else {
            Bytes::from_static(b"not-a-valid-tea-response")
        };
        let (url, received, release, task) = http(body).await;
        client
            .inner
            .lock()
            .unwrap()
            .ios_mut()
            .unwrap()
            .discovery
            .url = Some(url);
        client.start_ios_discovery(0, false);
        let _ = received.await.unwrap();
        release.notify_one();
        task.await.unwrap();
        settled(&client).await;
        let after =
            client.inner.lock().unwrap().state.keystore.ios_server_lists["nossid_wifi"].clone();
        assert_eq!(after.wifi, before.wifi);
        assert_eq!(after.server_time, before.server_time);
        assert_eq!(after.accepted_unix_seconds, before.accepted_unix_seconds);
        assert_eq!(after.carrier, before.carrier);
        assert_eq!(
            after.interval_seconds,
            if interval_only {
                601
            } else {
                before.interval_seconds
            }
        );
    }
}

#[test]
fn declared_bssid_selects_separate_persistent_buckets_without_host_network_observation() {
    for bssid in [None, Some("declared-a"), Some("declared-b")] {
        let mut model = crate::ios_device::IosVirtualConfig::default();
        model.network.bssid = bssid.map(str::to_owned);
        let client = Client::new(
            ClientConfig {
                profile: Profile::ipad(),
                platform: Some(crate::models::PlatformConfig::Ios(
                    crate::models::IosConfig::Virtual(Arc::new(model)),
                )),
                ..Default::default()
            },
            Keystore::default(),
        )
        .unwrap();
        let inner = client.inner.lock().unwrap();
        let (key, carrier, wifi) = client.ios_discovery_context(&inner).unwrap();
        assert_eq!(key, ios_discovery::bucket(true, bssid));
        assert_eq!(carrier, "000000");
        assert!(wifi);
    }
}

#[tokio::test]
async fn ordinary_reconnect_does_not_repeat_reason_zero_after_http_failure_with_or_without_disk_cache()
 {
    for cached in [false, true] {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = client(Profile::iphone(), Keystore::default());
        if cached {
            seed(&client, vec![server(&tcp, 0)], false);
        } else {
            client.inner.lock().unwrap().sso_configuration =
                Some(Arc::new(crate::network::SsoConfiguration {
                    servers: crate::network::SsoServerLists {
                        list_3: vec![crate::network::SsoServerInfo {
                            host: "127.0.0.1".into(),
                            port: tcp.local_addr().unwrap().port().into(),
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                    raw: Bytes::new(),
                }));
        }
        let (url, received, release, task) =
            http(Bytes::from_static(b"invalid-discovery-cipher")).await;
        client
            .inner
            .lock()
            .unwrap()
            .ios_mut()
            .unwrap()
            .discovery
            .url = Some(url);
        client.connect().await.unwrap();
        let (first_socket, _) = tcp.accept().await.unwrap();
        let _ = received.await.unwrap();
        release.notify_one();
        task.await.unwrap();
        settled(&client).await;
        let discovery_id = client
            .inner
            .lock()
            .unwrap()
            .ios_mut()
            .unwrap()
            .discovery
            .next_id;
        assert_eq!(discovery_id, 1);
        client.close_transport("ordinary reconnect".into()).await;
        drop(first_socket);
        client.connect().await.unwrap();
        let (second_socket, _) = tcp.accept().await.unwrap();
        {
            let inner = client.inner.lock().unwrap();
            assert_eq!(inner.generation, 2);
            assert_eq!(
                inner.ios().unwrap().discovery.loaded_bucket.as_deref(),
                Some("nossid_wifi")
            );
            assert_eq!(inner.ios().unwrap().discovery.next_id, discovery_id);
            assert!(inner.ios().unwrap().discovery.pending.is_none());
            assert_eq!(inner.state.keystore.ios_server_lists.is_empty(), !cached);
        }
        client.close_transport("fixture finished".into()).await;
        drop(second_socket);
    }
}

#[tokio::test]
async fn direct_parent_cancellation_clears_pending_and_new_network_generation_can_refresh() {
    let client = client(Profile::ipad(), Keystore::default());
    let response = ios_discovery::response_fixture(&HttpServerListRes {
        result: 1,
        server_time: 19,
        ..Default::default()
    });
    let (url, received, release, task) = http(response.clone()).await;
    client
        .inner
        .lock()
        .unwrap()
        .ios_mut()
        .unwrap()
        .discovery
        .url = Some(url);
    client.start_ios_discovery(0, false);
    let _ = received.await.unwrap();
    client.cancellation().cancel();
    settled(&client).await;
    let (next_url, next_received, next_release, next_task) = http(response).await;
    {
        let mut inner = client.inner.lock().unwrap();
        inner.cancel = CancellationToken::new();
        inner.generation = 1;
        inner.ios_mut().unwrap().transport.network_type = 2;
        inner.ios_mut().unwrap().discovery.url = Some(next_url);
    }
    client.start_ios_discovery(1, false);
    let (_, body) = next_received.await.unwrap();
    assert_eq!(request(body).network, 1);
    let pending_id = client
        .inner
        .lock()
        .unwrap()
        .ios_mut()
        .unwrap()
        .discovery
        .pending
        .as_ref()
        .unwrap()
        .id;
    release.notify_one();
    task.await.unwrap();
    assert_eq!(
        client
            .inner
            .lock()
            .unwrap()
            .ios()
            .unwrap()
            .discovery
            .pending
            .as_ref()
            .unwrap()
            .id,
        pending_id
    );
    next_release.notify_one();
    next_task.await.unwrap();
    settled(&client).await;
    assert_eq!(
        client.inner.lock().unwrap().state.keystore.ios_server_lists["nossid_2g3g"].server_time,
        19
    );
}
