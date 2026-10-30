use super::*;
use crate::network::ios_discovery::ServerInfo;
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpSocket},
};

fn client(stack: Option<u32>) -> Arc<Client> {
    let mut configuration = super::super::ios_signing_tests::config(Profile::iphone());
    let transport = &mut configuration.ios_snapshot_mut().unwrap().transport;
    transport.network_type = 1;
    transport.reserved = IosReservedTemplate::new(
        crate::proto::sso::Reserved {
            ip_stack_type: stack,
            ..Default::default()
        }
        .encode_to_vec()
        .into(),
    )
    .unwrap();
    Client::new(configuration, Keystore::default()).unwrap()
}

fn server(port: u16) -> ServerInfo {
    ServerInfo {
        host: "127.0.0.1".into(),
        port: port.into(),
        transport: 0,
        probe_eligibility: 1,
        ..Default::default()
    }
}

async fn target() -> (ServerInfo, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = server(listener.local_addr().unwrap().port());
    let task = tokio::spawn(async move {
        let (mut socket, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), socket.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    });
    (endpoint, task)
}

#[tokio::test]
async fn rebuild_batches_append_and_probe_only_qualified_native_tcp_without_sso_or_cache_changes() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let client = client(Some(1));
        let mut reports = client.ios_probe_reports().unwrap();
        let (first, first_peer) = target().await;
        let (last, last_peer) = target().await;
        let rejected = TcpSocket::new_v4().unwrap();
        rejected.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut failure = server(rejected.local_addr().unwrap().port());
        failure.probe_eligibility = -1;
        let mut disabled = failure.clone();
        disabled.probe_eligibility = 0;
        let mut alternate_transport = failure.clone();
        alternate_transport.transport = 1;
        let mut quic = failure.clone();
        quic.transport = 4;
        let first_cache = ServerListCache {
            wifi: vec![disabled, alternate_transport, quic, first.clone()],
            mobile: vec![failure.clone()],
            ipv6: vec![failure.clone()],
            ..Default::default()
        };
        let second_cache = ServerListCache {
            wifi: vec![failure.clone(), last.clone()],
            ..Default::default()
        };
        {
            let mut inner = client.inner.lock().unwrap();
            inner
                .state
                .keystore
                .ios_server_lists
                .insert("first".into(), first_cache.clone());
            inner
                .state
                .keystore
                .ios_server_lists
                .insert("second".into(), second_cache.clone());
            client.enqueue_ios_http_probes(&mut inner, &first_cache, "first");
            client.enqueue_ios_http_probes(&mut inner, &second_cache, "second");
        }
        for (endpoint, bucket, connected) in [
            (&first, "first", true),
            (&failure, "second", false),
            (&last, "second", true),
        ] {
            let report = reports.recv().await.unwrap();
            assert_eq!(report.endpoint.host, endpoint.host);
            assert_eq!(i32::from(report.endpoint.port), endpoint.port);
            assert_eq!(
                report.source.as_ref(),
                &Source::HttpDiscovery {
                    bucket: bucket.into()
                }
            );
            assert_eq!(report.generation, 0);
            assert_eq!(report.network_type, 1);
            assert_eq!(report.ip_stack, 1);
            if connected {
                match report.outcome {
                    Outcome::Connected {
                        local_addr: Some(local),
                        peer_addr: Some(peer),
                    } => {
                        assert_eq!(local.ip(), "127.0.0.1".parse::<std::net::IpAddr>().unwrap());
                        assert_eq!(
                            peer,
                            format!("127.0.0.1:{}", endpoint.port).parse().unwrap()
                        );
                    }
                    ref other => panic!("expected TCP connection, got {other:?}"),
                }
            } else {
                assert!(matches!(report.outcome, Outcome::Failed { .. }));
            }
        }
        first_peer.await.unwrap();
        last_peer.await.unwrap();
        let state = client.snapshot().await;
        assert_eq!(state.keystore.ios_server_lists["first"], first_cache);
        assert_eq!(state.keystore.ios_server_lists["second"], second_cache);
        assert!(client.inner.lock().unwrap().pending.is_empty());
        client
            .close_transport("independent probe batches complete".into())
            .await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn unknown_stack_defers_connection_until_actual_transport_resources_supply_it() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let client = client(None);
        let mut reports = client.ios_probe_reports().unwrap();
        let (endpoint, peer) = target().await;
        let cache = ServerListCache {
            wifi: vec![endpoint],
            ..Default::default()
        };
        {
            let mut inner = client.inner.lock().unwrap();
            client.enqueue_ios_http_probes(&mut inner, &cache, "deferred");
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(20), reports.recv())
                .await
                .is_err()
        );
        let mut resources = client
            .inner
            .lock()
            .unwrap()
            .ios()
            .unwrap()
            .transport
            .clone();
        resources.reserved = IosReservedTemplate::new(
            crate::proto::sso::Reserved {
                ip_stack_type: Some(1),
                ..Default::default()
            }
            .encode_to_vec()
            .into(),
        )
        .unwrap();
        client.set_ios_transport_resources(resources).unwrap();
        let report = reports.recv().await.unwrap();
        assert!(matches!(report.outcome, Outcome::Connected { .. }));
        assert_eq!(
            report.source.as_ref(),
            &Source::HttpDiscovery {
                bucket: "deferred".into()
            }
        );
        peer.await.unwrap();
        client
            .close_transport("deferred probe complete".into())
            .await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn config_push_candidates_use_active_network_and_nonzero_eligibility() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let client = client(Some(1));
        let mut reports = client.ios_probe_reports().unwrap();
        let (endpoint, peer) = target().await;
        let rejected = TcpSocket::new_v4().unwrap();
        rejected.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let blocked = crate::network::SsoServerInfo {
            host: "127.0.0.1".into(),
            port: rejected.local_addr().unwrap().port().into(),
            field_11: 1,
            ..Default::default()
        };
        let mut disabled = blocked.clone();
        disabled.field_11 = 0;
        let mut alternate = blocked.clone();
        alternate.protocol = 1;
        let lists = SsoServerLists {
            list_1: vec![blocked.clone()],
            list_3: vec![
                disabled,
                alternate,
                crate::network::SsoServerInfo {
                    host: endpoint.host,
                    port: endpoint.port,
                    field_11: -1,
                    ..Default::default()
                },
            ],
            list_11: vec![blocked],
            ..Default::default()
        };
        client.enqueue_ios_config_probes(&mut client.inner.lock().unwrap(), &lists);
        let report = reports.recv().await.unwrap();
        assert_eq!(report.source.as_ref(), &Source::ConfigPush);
        assert_eq!(i32::from(report.endpoint.port), endpoint.port);
        assert!(matches!(report.outcome, Outcome::Connected { .. }));
        peer.await.unwrap();
        client
            .close_transport("configuration probe complete".into())
            .await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn shutdown_discards_unstarted_probe_without_reporting_a_fabricated_failure() {
    let client = client(Some(1));
    let mut reports = client.ios_probe_reports().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cache = ServerListCache {
        wifi: vec![server(listener.local_addr().unwrap().port())],
        ..Default::default()
    };
    client.enqueue_ios_http_probes(&mut client.inner.lock().unwrap(), &cache, "cancelled");
    client.terminate("cancel before independent connection".into());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err()
    );
    assert!(matches!(
        reports.try_recv(),
        Err(broadcast::error::TryRecvError::Empty)
    ));
    assert!(
        client
            .inner
            .lock()
            .unwrap()
            .ios()
            .unwrap()
            .probes
            .queue
            .is_empty()
    );
}
