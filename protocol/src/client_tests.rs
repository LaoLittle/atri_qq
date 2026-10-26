use super::*;
use crate::wire::{Reader, Writer};
use ::signing as signing_engine;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::time::timeout;

fn client() -> Arc<Client> {
    Client::new(ClientConfig::default(), Keystore::default()).unwrap()
}
fn queued_client() -> (Arc<Client>, mpsc::Receiver<Outgoing>) {
    let client = client();
    let (sender, receiver) = mpsc::channel(8);
    client.inner.lock().unwrap().connection = Some(Connection {
        generation: 0,
        sender,
    });
    (client, receiver)
}
fn outgoing_identity(frame: Bytes) -> (i32, String, String) {
    let mut r = Reader::new(frame);
    r.u32().unwrap();
    assert_eq!(r.u32().unwrap(), 13);
    assert_eq!(r.u8().unwrap(), 0);
    let sequence = r.i32().unwrap();
    r.u8().unwrap();
    let uin = String::from_utf8(r.p32().unwrap().to_vec()).unwrap();
    let mut payload = Reader::new(r.rest());
    let mut head = Reader::new(payload.p32().unwrap());
    let command = String::from_utf8(head.p32().unwrap().to_vec()).unwrap();
    (sequence, command, uin)
}
fn incoming(sequence: i32, command: &str, body: &[u8], key: Option<&[u8]>) -> Bytes {
    incoming_status(sequence, command, body, key, 0, "")
}
fn incoming_status(
    sequence: i32,
    command: &str,
    body: &[u8],
    key: Option<&[u8]>,
    return_code: i32,
    extra: &str,
) -> Bytes {
    let mut head = Writer::new();
    head.i32(sequence);
    head.i32(return_code);
    head.p32(extra).unwrap();
    head.p32(command).unwrap();
    head.p32([]).unwrap();
    head.i32(0);
    head.p32([]).unwrap();
    let mut payload = Writer::new();
    payload.p32(head.data).unwrap();
    payload.p32(body).unwrap();
    let mut envelope = Writer::new();
    envelope.u32(13);
    envelope.u8(if key.is_some() { 1 } else { 0 });
    envelope.u8(0);
    envelope.p32("0").unwrap();
    envelope.bytes(if let Some(key) = key {
        crate::crypto::tea_encrypt(&payload.data, key).unwrap()
    } else {
        payload.data
    });
    let mut frame = Writer::new();
    frame.p32(envelope.data).unwrap();
    frame.data.into()
}
fn send(
    client: Arc<Client>,
    command: &'static str,
    timeout: Duration,
) -> JoinHandle<Result<Bytes>> {
    tokio::spawn(async move {
        client
            .request(
                command,
                Bytes::from_static(b"request"),
                RequestType::Simple,
                Encryption::None,
                timeout,
            )
            .await
    })
}
#[tokio::test]
async fn matching_response_never_cancels_a_still_finishing_write() {
    let (client, mut queue) = queued_client();
    let request = send(client.clone(), "example.command", Duration::from_secs(5));
    let outgoing = queue.recv().await.unwrap();
    let (sequence, command, _) = outgoing_identity(outgoing.frame.clone());
    client
        .receive(incoming(sequence, &command, b"ok", None), 0)
        .unwrap();
    assert_eq!(request.await.unwrap().unwrap(), Bytes::from_static(b"ok"));
    assert!(!outgoing.cancel.is_cancelled());
    assert!(client.inner.lock().unwrap().pending.is_empty());
}
#[tokio::test]
async fn dropped_requests_remove_correlation_and_cancel_only_queued_frames() {
    let (client, mut queue) = queued_client();
    let request = send(client.clone(), "example.command", Duration::from_secs(5));
    let outgoing = queue.recv().await.unwrap();
    request.abort();
    let _ = request.await;
    assert!(outgoing.cancel.is_cancelled());
    assert!(client.inner.lock().unwrap().pending.is_empty());
}
#[tokio::test]
async fn timed_out_request_does_not_consume_the_next_response() {
    let (client, mut queue) = queued_client();
    let request = send(client.clone(), "example.command", Duration::from_millis(20));
    let first = queue.recv().await.unwrap();
    let (sequence, command, _) = outgoing_identity(first.frame);
    assert!(matches!(request.await.unwrap(), Err(Error::Timeout)));
    assert!(first.cancel.is_cancelled());
    let request = send(client.clone(), "example.command", Duration::from_secs(5));
    let second = queue.recv().await.unwrap();
    let (sequence2, _, _) = outgoing_identity(second.frame);
    assert_ne!(sequence, sequence2);
    client
        .receive(incoming(sequence, &command, b"late", None), 0)
        .unwrap();
    assert!(!request.is_finished());
    client
        .receive(incoming(sequence2, &command, b"current", None), 0)
        .unwrap();
    assert_eq!(
        request.await.unwrap().unwrap(),
        Bytes::from_static(b"current")
    );
}
#[tokio::test]
async fn renewal_keeps_request_identity_and_old_reply_key_coherent() {
    let (client, mut queue) = queued_client();
    let mut old = client.snapshot().await;
    old.keystore.uin = 123456;
    old.keystore.d2_key = vec![42; 16];
    client.replace_state(old.clone()).await;
    let request = send(client.clone(), "example.command", Duration::from_secs(5));
    let outgoing = queue.recv().await.unwrap();
    let (sequence, command, uin) = outgoing_identity(outgoing.frame);
    assert_eq!(uin, "123456");
    let mut new = old.clone();
    new.keystore.uin = 987654;
    new.keystore.d2_key = vec![17; 16];
    new.machine_id = "new-machine".into();
    client.replace_state(new).await;
    client
        .receive(
            incoming(
                sequence,
                &command,
                b"old-key-response",
                Some(&old.keystore.d2_key),
            ),
            0,
        )
        .unwrap();
    assert_eq!(
        request.await.unwrap().unwrap(),
        Bytes::from_static(b"old-key-response")
    );
}
#[tokio::test]
async fn framed_tcp_correlates_replies_after_malformed_envelopes_and_pushes() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut framed = Framed::new(socket, SsoFrameCodec);
        let request = framed.next().await.unwrap().unwrap();
        let (sequence, command, _) = outgoing_identity(request);
        let mut malformed = incoming(sequence, &command, b"not a reply", None).to_vec();
        malformed[8] = 0xff;
        framed.send(malformed.into()).await.unwrap();
        framed
            .send(incoming(
                -1,
                "trpc.msg.olpush.OlPushService.MsgPush",
                &[0xff],
                None,
            ))
            .await
            .unwrap();
        framed
            .send(incoming(sequence, "different.command", b"push", None))
            .await
            .unwrap();
        framed
            .send(incoming(sequence, &command, b"response", None))
            .await
            .unwrap();
        let _ = framed.next().await;
    });
    let client = Client::new(
        ClientConfig {
            host: "127.0.0.1".into(),
            port,
            ..Default::default()
        },
        Keystore::default(),
    )
    .unwrap();
    let mut pushes = client.subscribe();
    let mut events = client.login_events();
    client.connect().await.unwrap();
    client.inner.lock().unwrap().state.online = true;
    let result = client
        .request(
            "example.command",
            Bytes::new(),
            RequestType::Simple,
            Encryption::None,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(result, Bytes::from_static(b"response"));
    assert_eq!(pushes.recv().await.unwrap().command, "different.command");
    assert!(client.snapshot().await.online);
    assert!(!client.cancellation().is_cancelled());
    assert!(events.try_recv().is_err());
    client
        .close_transport("packet recovery regression finished".into())
        .await;
    server.await.unwrap();
}

#[tokio::test]
async fn stale_service_state_cannot_resurrect_a_closed_or_replaced_session() {
    let (client, _queue) = queued_client();
    let mut events = client.login_events();
    client.confirm_online(0).unwrap();
    let stale = client.snapshot().await;
    client.terminate("closed".into());
    client.replace_state(stale).await;
    assert!(!client.snapshot().await.online);
    assert!(matches!(client.confirm_online(0), Err(Error::Disconnected)));
    assert!(matches!(
        events.recv().await.unwrap(),
        LoginEvent::Online { .. }
    ));
    assert!(matches!(
        events.recv().await.unwrap(),
        LoginEvent::Offline { .. }
    ));
    let (sender, _receiver) = mpsc::channel(8);
    {
        let mut inner = client.inner.lock().unwrap();
        inner.generation = 1;
        inner.cancel = CancellationToken::new();
        inner.connection = Some(Connection {
            generation: 1,
            sender,
        });
    }
    assert!(matches!(client.confirm_online(0), Err(Error::Disconnected)));
    assert!(!client.snapshot().await.online);
}

#[tokio::test]
async fn normal_kick_unregisters_before_closing_and_rejects_business_requests() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = Client::new(
        ClientConfig {
            host: "127.0.0.1".into(),
            port: listener.local_addr().unwrap().port(),
            ..Default::default()
        },
        Keystore {
            d2_key: vec![0; 16],
            ..Default::default()
        },
    )
    .unwrap();
    let mut events = client.login_events();
    client.connect().await.unwrap();
    let (socket, _) = listener.accept().await.unwrap();
    let mut server = Framed::new(socket, SsoFrameCodec);
    client.confirm_online(client.connection_generation()).unwrap();
    assert!(matches!(events.recv().await.unwrap(), LoginEvent::Online { .. }));
    let pending = {
        let client = client.clone();
        tokio::spawn(async move {
            client.request("WaitingBeforeKick", Bytes::new(), RequestType::D2, Encryption::D2, Duration::from_secs(5)).await
        })
    };
    let frame = timeout(Duration::from_secs(2), server.next())
        .await.unwrap().unwrap().unwrap();
    assert_eq!(outgoing_d2(frame, &[0; 16]).1, "WaitingBeforeKick");
    let body = auth::Kick {
        title: Some("Session expired".into()),
        message: Some("Login is no longer valid".into()),
        app_id: Some(1001),
        instance_id: Some(537391664),
        kicked_type: Some(17),
        security_kicked_type: Some(3),
        ..Default::default()
    }.encode_to_vec();
    server.send(incoming(-71, "trpc.qq_new_tech.status_svc.StatusService.KickNT", &body, None))
        .await.unwrap();
    let frame = timeout(Duration::from_secs(2), server.next())
        .await.unwrap().unwrap().unwrap();
    let (_, command, body, _) = outgoing_d2(frame, &[0; 16]);
    assert_eq!(command, "trpc.qq_new_tech.status_svc.StatusService.UnRegister");
    let unregister: auth::UnregisterRequest = crate::proto::decode(body).unwrap();
    assert_eq!(unregister.reason, Some(1));
    assert!(matches!(pending.await.unwrap(), Err(Error::Disconnected)));
    assert!(matches!(
        client.request("AfterKick", Bytes::new(), RequestType::D2, Encryption::D2, Duration::from_secs(1)).await,
        Err(Error::Disconnected)
    ));
    assert!(matches!(
        timeout(Duration::from_secs(2), events.recv()).await.unwrap().unwrap(),
        LoginEvent::Offline { .. }
    ));
    assert!(!client.snapshot().await.online);
    assert!(timeout(Duration::from_secs(2), server.next()).await.unwrap().is_none());
}

#[tokio::test]
async fn error_kick_preserves_header_without_decoding_or_publishing_its_body() {
    let command = "trpc.qq_new_tech.status_svc.StatusService.KickNT";
    let extra = "身份验证失败，请你重新登录。(s26)";
    for body in [b"".as_slice(), b"\xff".as_slice()] {
        let (client, mut queue) = queued_client();
        let mut events = client.login_events();
        let mut pushes = client.subscribe();
        client.confirm_online(0).unwrap();
        events.recv().await.unwrap();
        let request = send(client.clone(), command, Duration::from_secs(5));
        let outgoing = queue.recv().await.unwrap();
        let (sequence, _, _) = outgoing_identity(outgoing.frame);
        client
            .receive(
                incoming_status(sequence, command, body, None, -10004, extra),
                0,
            )
            .unwrap();
        assert!(matches!(request.await.unwrap(), Err(Error::Disconnected)));
        match events.recv().await.unwrap() {
            LoginEvent::Offline { reason } => {
                assert_eq!(reason, format!("Kicked: Server error -10004: {extra}"));
            }
            _ => panic!("Expected offline event"),
        }
        assert!(!client.snapshot().await.online);
        assert!(pushes.try_recv().is_err());
        client
            .receive(
                incoming_status(sequence, command, body, None, -10004, extra),
                0,
            )
            .unwrap();
        assert!(events.try_recv().is_err());
    }
}

#[tokio::test]
async fn framed_tcp_error_kick_reports_header_and_disconnects_outstanding_requests() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut framed = Framed::new(socket, SsoFrameCodec);
        let request = framed.next().await.unwrap().unwrap();
        let (sequence, _, _) = outgoing_identity(request);
        framed
            .send(incoming_status(
                sequence,
                "trpc.qq_new_tech.status_svc.StatusService.KickNT",
                &[],
                None,
                -10004,
                "身份验证失败，请你重新登录。(s26)",
            ))
            .await
            .unwrap();
        assert!(framed.next().await.is_none());
    });
    let client = Client::new(
        ClientConfig {
            host: "127.0.0.1".into(),
            port,
            ..Default::default()
        },
        Keystore::default(),
    )
    .unwrap();
    let mut events = client.login_events();
    let mut pushes = client.subscribe();
    client.connect().await.unwrap();
    client
        .confirm_online(client.connection_generation())
        .unwrap();
    events.recv().await.unwrap();
    let result = client
        .request(
            "example.command",
            Bytes::new(),
            RequestType::Simple,
            Encryption::None,
            Duration::from_secs(5),
        )
        .await;
    assert!(matches!(result, Err(Error::Disconnected)));
    match events.recv().await.unwrap() {
        LoginEvent::Offline { reason } => assert_eq!(
            reason,
            "Kicked: Server error -10004: 身份验证失败，请你重新登录。(s26)"
        ),
        _ => panic!("Expected offline event"),
    }
    assert!(!client.snapshot().await.online);
    assert!(pushes.try_recv().is_err());
    timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn sso_request_errors_preserve_code_and_extra_without_ending_the_session() {
    let (client, mut queue) = queued_client();
    let mut events = client.login_events();
    let mut pushes = client.subscribe();
    client.confirm_online(0).unwrap();
    events.recv().await.unwrap();
    for code in [-10004, -1, 170013002] {
        let request = send(client.clone(), "example.command", Duration::from_secs(5));
        let outgoing = queue.recv().await.unwrap();
        let (sequence, command, _) = outgoing_identity(outgoing.frame);
        client
            .receive(
                incoming_status(sequence, &command, &[], None, code, "request rejected"),
                0,
            )
            .unwrap();
        assert!(matches!(
            request.await.unwrap(),
            Err(Error::Server { code: actual, message })
                if actual == code && message == "request rejected"
        ));
        assert!(client.snapshot().await.online);
        assert!(events.try_recv().is_err());
        assert!(pushes.try_recv().is_err());
    }
    let request = send(client.clone(), "example.command", Duration::from_secs(5));
    let outgoing = queue.recv().await.unwrap();
    let (sequence, command, _) = outgoing_identity(outgoing.frame);
    client
        .receive(incoming(sequence, &command, b"recovered", None), 0)
        .unwrap();
    assert_eq!(
        request.await.unwrap().unwrap(),
        Bytes::from_static(b"recovered")
    );
}

#[tokio::test]
async fn unsolicited_sso_errors_are_not_successful_pushes_or_control_requests() {
    let (client, mut queue) = queued_client();
    let mut events = client.login_events();
    let mut pushes = client.subscribe();
    client.confirm_online(0).unwrap();
    events.recv().await.unwrap();
    client.start_background_work(0);
    let body = auth::PushAckSource {
        required: Some(1),
        descriptors: vec![Bytes::from_static(b"opaque descriptor")],
    }
    .encode_to_vec();
    for (command, body) in [
        ("example.push", Bytes::new()),
        ("trpc.msg.olpush.OlPushService.MsgPush", Bytes::from(body)),
        (
            "ConfigPushSvc.PushReq",
            wire::config_push::request_fixture(1, 17),
        ),
    ] {
        assert!(matches!(
            client.receive(incoming_status(-1, command, &body, None, -10004, "rejected"), 0),
            Err(Error::Server { code: -10004, message }) if message == "rejected"
        ));
    }
    tokio::task::yield_now().await;
    assert!(queue.try_recv().is_err());
    assert!(pushes.try_recv().is_err());
    assert!(events.try_recv().is_err());
    assert!(client.snapshot().await.online);
    client
        .close_transport("error dispatch regression complete".into())
        .await;
}

#[tokio::test]
async fn stale_generation_kick_cannot_end_or_notify_the_current_session() {
    let (client, _queue) = queued_client();
    let mut events = client.login_events();
    let mut pushes = client.subscribe();
    client.confirm_online(0).unwrap();
    events.recv().await.unwrap();
    client
        .receive(
            incoming_status(
                -1,
                "trpc.qq_new_tech.status_svc.StatusService.KickNT",
                &[],
                None,
                -10004,
                "stale connection error",
            ),
            1,
        )
        .unwrap();
    assert!(client.snapshot().await.online);
    assert!(events.try_recv().is_err());
    assert!(pushes.try_recv().is_err());
}

#[tokio::test]
async fn control_reply_receipts_do_not_generate_an_acknowledgment_loop() {
    let (client, mut queue) = queued_client();
    client.start_background_work(0);
    let descriptor = Bytes::from_static(b"opaque control descriptor");
    let source = auth::PushAckSource {
        required: Some(1),
        descriptors: vec![descriptor.clone()],
    };
    client
        .receive(
            incoming(
                -1,
                "trpc.msg.olpush.OlPushService.MsgPush",
                &source.encode_to_vec(),
                None,
            ),
            0,
        )
        .unwrap();
    let outgoing = timeout(Duration::from_secs(5), queue.recv())
        .await
        .unwrap()
        .unwrap();
    let (sequence, command, body, _) = outgoing_d2(outgoing.frame, &[0; 16]);
    let ack: auth::PushAckRequest = crate::proto::decode(body.clone()).unwrap();
    assert_eq!(ack.descriptors, [descriptor]);
    client
        .receive(incoming(sequence, &command, &body, None), 0)
        .unwrap();
    let config = wire::config_push::request_fixture(1, 17);
    client
        .receive(incoming(-2, "ConfigPushSvc.PushReq", &config, None), 0)
        .unwrap();
    let outgoing = timeout(Duration::from_secs(5), queue.recv())
        .await
        .unwrap()
        .unwrap();
    let (sequence, command, body, _) = outgoing_d2(outgoing.frame, &[0; 16]);
    assert_eq!(command, "ConfigPushSvc.PushResp");
    client
        .receive(incoming(sequence, &command, &body, None), 0)
        .unwrap();
    tokio::task::yield_now().await;
    assert!(queue.try_recv().is_err());
    client
        .close_transport("control loop regression complete".into())
        .await;
}

fn outgoing_d2(frame: Bytes, key: &[u8]) -> (i32, String, Bytes, crate::proto::sso::Reserved) {
    let mut frame = Reader::new(frame);
    frame.u32().unwrap();
    assert_eq!(frame.u32().unwrap(), RequestType::D2 as u32);
    assert_eq!(frame.u8().unwrap(), Encryption::D2 as u8);
    frame.p32().unwrap();
    frame.u8().unwrap();
    frame.p32().unwrap();
    let mut payload = Reader::new(crate::crypto::tea_decrypt(&frame.rest(), key).unwrap());
    let mut header = Reader::new(payload.p32().unwrap());
    let body = payload.p32().unwrap();
    let sequence = header.i32().unwrap();
    header.skip(20).unwrap();
    header.p32().unwrap();
    let command = String::from_utf8(header.p32().unwrap().to_vec()).unwrap();
    header.p32().unwrap();
    header.p32().unwrap();
    header.p32().unwrap();
    header.pref(2, true).unwrap();
    let reserve = crate::proto::decode(header.p32().unwrap()).unwrap();
    (sequence, command, body, reserve)
}

#[tokio::test]
async fn group_history_business_error_preserves_session_for_a_subsequent_query() {
    use crate::{media::Media, messages::Messaging, proto::messages as rpc};
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut framed = Framed::new(socket, SsoFrameCodec);
        for code in [4, 0] {
            let request = framed.next().await.unwrap().unwrap();
            let (sequence, command, _, _) = outgoing_d2(request, &[0; 16]);
            let response = rpc::GroupHistoryResponse {
                body: Some(rpc::GroupHistoryBody {
                    code,
                    group_uin: Some(42),
                    ..Default::default()
                }),
                ..Default::default()
            };
            framed
                .send(incoming(
                    sequence,
                    &command,
                    &response.encode_to_vec(),
                    Some(&[0; 16]),
                ))
                .await
                .unwrap();
        }
        assert!(framed.next().await.is_none());
    });
    let client = Client::new(
        ClientConfig {
            host: "127.0.0.1".into(),
            port,
            ..Default::default()
        },
        Keystore::default(),
    )
    .unwrap();
    let mut events = client.login_events();
    client.connect().await.unwrap();
    client.inner.lock().unwrap().state.online = true;
    let messaging = Messaging::new(client.clone(), Arc::new(Media::new(client.clone())));
    let first = tokio::time::timeout(Duration::from_secs(3), messaging.history_group(42, 1, 2))
        .await
        .unwrap();
    assert!(matches!(first, Err(Error::Server { code: 4, .. })));
    let second = tokio::time::timeout(Duration::from_secs(3), messaging.history_group(42, 3, 4))
        .await
        .unwrap()
        .unwrap();
    assert!(second.is_empty());
    assert!(client.snapshot().await.online);
    assert!(!client.cancellation().is_cancelled());
    assert!(events.try_recv().is_err());
    client
        .close_transport("group history regression finished".into())
        .await;
    tokio::time::timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn alive_waits_for_idle_instead_of_interrupting_active_login_traffic() {
    let (client, mut queue) = queued_client();
    client.start_alive();
    let first = queue.recv().await.unwrap();
    let (sequence, command, _) = outgoing_identity(first.frame);
    client
        .receive(incoming(sequence, &command, &[0, 0, 0, 4], None), 0)
        .unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(9)).await;
    client
        .receive(incoming(-1, "example.push", b"active traffic", None), 0)
        .unwrap();
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert!(
        queue.try_recv().is_err(),
        "ordinary traffic postpones keepalive"
    );
    tokio::time::advance(Duration::from_secs(9)).await;
    let next = queue.recv().await.unwrap();
    let (_, command, _) = outgoing_identity(next.frame);
    assert_eq!(command, "Heartbeat.Alive");
    client.close_transport("idle test done".into()).await;
}

#[tokio::test(start_paused = true)]
async fn reregistration_replaces_heartbeat_timer_and_uses_completion_time() {
    let (client, mut queue) = queued_client();
    client.start_heartbeat(100, 5);
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(100)).await;
    assert!(queue.try_recv().is_err());
    client.start_heartbeat(200, 130);
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(20)).await;
    tokio::task::yield_now().await;
    assert!(
        queue.try_recv().is_err(),
        "the replaced timer must not send"
    );
    tokio::time::advance(Duration::from_secs(110)).await;
    let first = queue.recv().await.unwrap();
    let (sequence, command, body, reserve) = outgoing_d2(first.frame, &[0; 16]);
    assert!(reserve.secure_info.is_none());
    let body: auth::HeartbeatRequest = crate::proto::decode(body).unwrap();
    assert_eq!(body.server_time, Some(200));
    assert_eq!(body.r#type, Some(1));
    assert_eq!(body.state.as_ref().and_then(|state| state.status), Some(0));
    assert_eq!(body.state.as_ref().and_then(|state| state.field2), Some(0));
    assert_eq!(body.local_silence, Some(0));
    tokio::time::advance(Duration::from_secs(5)).await;
    let response = auth::HeartbeatResponse {
        interval_seconds: Some(3),
    }
    .encode_to_vec();
    client
        .receive(incoming(sequence, &command, &response, Some(&[0; 16])), 0)
        .unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(119)).await;
    tokio::task::yield_now().await;
    assert!(
        queue.try_recv().is_err(),
        "response interval is clamped to 120s"
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    let second = queue.recv().await.unwrap();
    let (sequence, command, body, _) = outgoing_d2(second.frame, &[0; 16]);
    let body: auth::HeartbeatRequest = crate::proto::decode(body).unwrap();
    assert_eq!(body.server_time, Some(335));
    assert!(queue.try_recv().is_err());
    let response = auth::HeartbeatResponse {
        interval_seconds: Some(900),
    }
    .encode_to_vec();
    client
        .receive(incoming(sequence, &command, &response, Some(&[0; 16])), 0)
        .unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(499)).await;
    tokio::task::yield_now().await;
    assert!(queue.try_recv().is_err());
    tokio::time::advance(Duration::from_secs(1)).await;
    let third = queue.recv().await.unwrap();
    let (_, _, body, _) = outgoing_d2(third.frame, &[0; 16]);
    let body: auth::HeartbeatRequest = crate::proto::decode(body).unwrap();
    assert_eq!(body.server_time, Some(455));
    client.close_transport("heartbeat test done".into()).await;
}

#[tokio::test(start_paused = true)]
async fn failed_sso_heartbeat_keeps_the_session_and_periodic_schedule() {
    let (client, mut queue) = queued_client();
    client.inner.lock().unwrap().state.online = true;
    client.start_heartbeat(100, 360);
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(360)).await;
    let first = queue.recv().await.unwrap();
    let (sequence, command, _, _) = outgoing_d2(first.frame, &[0; 16]);
    client
        .receive(incoming(sequence, &command, &[0xff], Some(&[0; 16])), 0)
        .unwrap();
    tokio::task::yield_now().await;
    assert!(client.snapshot().await.online);
    assert!(!client.cancellation().is_cancelled());
    tokio::time::advance(Duration::from_secs(359)).await;
    tokio::task::yield_now().await;
    assert!(
        queue.try_recv().is_err(),
        "no immediate retry on decode failure"
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    let second = queue.recv().await.unwrap();
    let (_, _, body, _) = outgoing_d2(second.frame, &[0; 16]);
    let body: auth::HeartbeatRequest = crate::proto::decode(body).unwrap();
    assert_eq!(body.server_time, Some(460));
    tokio::time::advance(client.config.timeout).await;
    tokio::task::yield_now().await;
    assert!(client.snapshot().await.online);
    assert!(!client.cancellation().is_cancelled());
    tokio::time::advance(Duration::from_secs(360)).await;
    let third = queue.recv().await.unwrap();
    let (_, command, _, _) = outgoing_d2(third.frame, &[0; 16]);
    assert_eq!(
        command,
        "trpc.qq_new_tech.status_svc.StatusService.SsoHeartBeat"
    );
    client
        .close_transport("heartbeat failure test done".into())
        .await;
    tokio::time::advance(Duration::from_secs(720)).await;
    assert!(
        queue.try_recv().is_err(),
        "transport close cancels the periodic schedule"
    );
}

#[tokio::test(start_paused = true)]
async fn logout_uses_native_user_triggered_fields_and_cancels_heartbeat() {
    let (client, mut queue) = queued_client();
    client.inner.lock().unwrap().state.online = true;
    client.start_heartbeat(100, 360);
    let closing = {
        let client = client.clone();
        tokio::spawn(async move { client.logout().await })
    };
    let outgoing = queue.recv().await.unwrap();
    let (sequence, command, body, reserve) = outgoing_d2(outgoing.frame, &[0; 16]);
    assert_eq!(
        command,
        "trpc.qq_new_tech.status_svc.StatusService.UnRegister"
    );
    assert!(reserve.secure_info.is_none());
    let request: auth::UnregisterRequest = crate::proto::decode(body).unwrap();
    assert_eq!(request.r#type, Some(0));
    assert_eq!(request.reason, Some(0));
    let device = request.device.unwrap();
    assert_eq!(device.name, Some(Bytes::new()));
    assert_eq!(device.kernel, Some(Bytes::new()));
    assert_eq!(device.vendor, Some(Bytes::new()));
    assert_eq!(device.model, Some(Bytes::new()));
    assert_eq!(device.os, Some(Bytes::new()));
    let response = auth::StatusResponse {
        message: Some("unregister success".into()),
    }
    .encode_to_vec();
    client
        .receive(incoming(sequence, &command, &response, Some(&[0; 16])), 0)
        .unwrap();
    closing.await.unwrap().unwrap();
    assert!(!client.snapshot().await.online);
    tokio::time::advance(Duration::from_secs(720)).await;
    assert!(queue.try_recv().is_err());
}

#[tokio::test]
async fn required_push_ack_echoes_descriptor_without_waiting_for_a_reply() {
    let (client, mut queue) = queued_client();
    client.start_background_work(0);
    let command = "trpc.msg.olpush.OlPushService.MsgPush";
    let descriptor = Bytes::from_static(&[0x0a, 2, 0xff, 0x80, 0xf8, 7, 1]);
    let mut source = auth::PushAckSource {
        required: Some(0),
        descriptors: vec![descriptor.clone()],
    };
    client
        .receive(incoming(-1, command, &source.encode_to_vec(), None), 0)
        .unwrap();
    tokio::task::yield_now().await;
    assert!(queue.try_recv().is_err());
    source.required = Some(1);
    client
        .receive(incoming(-2, command, &source.encode_to_vec(), None), 0)
        .unwrap();
    let outgoing = queue.recv().await.unwrap();
    let (_, command, body, reserve) = outgoing_d2(outgoing.frame, &[0; 16]);
    assert_eq!(command, "trpc.msg.olpush.OlPushService.SsoPushAck");
    assert!(reserve.secure_info.is_none());
    let ack: auth::PushAckRequest = crate::proto::decode(body).unwrap();
    assert_eq!(ack.descriptors, [descriptor]);
    assert!(
        client.inner.lock().unwrap().pending.is_empty(),
        "send-only ack must not await a nonexistent response"
    );
    client.close_transport("ack test done".into()).await;
}

#[tokio::test]
async fn push_ack_precedes_application_decoding_and_does_not_wait_for_subscribers() {
    let (client, mut queue) = queued_client();
    client.start_background_work(0);
    let descriptor = Bytes::from_static(b"synthetic opaque descriptor");
    let mut body = auth::PushAckSource {
        required: Some(1),
        descriptors: vec![descriptor.clone()],
    }
    .encode_to_vec();
    body.extend_from_slice(&[0x0a, 1, 0xff]);
    for sequence in [-1, -2] {
        client
            .receive(
                incoming(
                    sequence,
                    "trpc.msg.olpush.OlPushService.MsgPush",
                    &body,
                    None,
                ),
                0,
            )
            .unwrap();
    }
    for _ in 0..2 {
        let outgoing = queue.recv().await.unwrap();
        assert!(outgoing.required_control);
        let (_, command, body, _) = outgoing_d2(outgoing.frame, &[0; 16]);
        assert_eq!(command, "trpc.msg.olpush.OlPushService.SsoPushAck");
        let ack: auth::PushAckRequest = crate::proto::decode(body).unwrap();
        assert_eq!(ack.descriptors, [descriptor.clone()]);
    }
    assert!(client.inner.lock().unwrap().pending.is_empty());
    client
        .close_transport("independent ack regression complete".into())
        .await;
}

#[tokio::test]
async fn full_control_reply_backlog_terminates_instead_of_silently_losing_ack() {
    let (client, _queue) = queued_client();
    client
        .inner
        .lock()
        .unwrap()
        .control_replies
        .extend((0..4096).map(|_| ("trpc.msg.olpush.OlPushService.SsoPushAck", Bytes::new())));
    let body = auth::PushAckSource {
        required: Some(1),
        descriptors: vec![Bytes::from_static(b"synthetic descriptor")],
    }
    .encode_to_vec();
    assert!(
        client
            .receive(
                incoming(-1, "trpc.msg.olpush.OlPushService.MsgPush", &body, None),
                0,
            )
            .is_err()
    );
    assert!(client.inner.lock().unwrap().connection.is_none());
    assert!(client.inner.lock().unwrap().control_replies.is_empty());
}

#[tokio::test]
async fn framed_tcp_config_push_response_is_send_only_and_does_not_block_requests() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut framed = Framed::new(socket, SsoFrameCodec);
        let push = wire::config_push::request_fixture(1, 0x0102_0304_0506_0708);
        let expected = wire::config_push::decode(push.clone())
            .unwrap()
            .acknowledgment
            .unwrap();
        framed
            .send(incoming(-73, "ConfigPushSvc.PushReq", &push, None))
            .await
            .unwrap();
        let mut saw_ack = false;
        let mut requests = 0;
        while !saw_ack || requests != 2 {
            let frame = tokio::time::timeout(Duration::from_secs(5), framed.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            // Normal requests use Simple; control responses use D2.
            if frame[8] == Encryption::D2 as u8 {
                let (_, command, body, reserved) = outgoing_d2(frame, &[0; 16]);
                assert_eq!(command, "ConfigPushSvc.PushResp");
                assert_eq!(body, expected);
                assert!(reserved.secure_info.is_none());
                assert!(!saw_ack);
                saw_ack = true;
                // Deliberately do not send a service reply to PushResp.
            } else {
                let (sequence, command, _) = outgoing_identity(frame);
                assert_eq!(command, "example.control-parity");
                requests += 1;
                framed
                    .send(incoming(sequence, &command, b"response", None))
                    .await
                    .unwrap();
            }
        }
        let _ = framed.next().await;
    });
    let client = Client::new(
        ClientConfig {
            host: "127.0.0.1".into(),
            port,
            ..Default::default()
        },
        Keystore::default(),
    )
    .unwrap();
    let mut pushes = client.subscribe();
    client.connect().await.unwrap();
    assert_eq!(
        pushes.recv().await.unwrap().command,
        "ConfigPushSvc.PushReq"
    );
    for _ in 0..2 {
        assert_eq!(
            client
                .request(
                    "example.control-parity",
                    Bytes::new(),
                    RequestType::Simple,
                    Encryption::None,
                    Duration::from_secs(5),
                )
                .await
                .unwrap(),
            Bytes::from_static(b"response")
        );
    }
    assert!(client.inner.lock().unwrap().pending.is_empty());
    assert!(!client.cancellation().is_cancelled());
    client
        .close_transport("configuration TCP regression complete".into())
        .await;
    server.await.unwrap();
}

#[tokio::test]
async fn ticket_and_registration_telemetry_preserve_real_token_acquisition() {
    let (client, mut queue) = queued_client();
    client.start_background_work(0);
    client.begin_signing_login().unwrap();
    let mut state = client.snapshot().await;
    state.keystore.uin = 123456;
    client.replace_state(state).await;
    client.mark_signing_ticket_complete().unwrap();
    let outgoing = queue.recv().await.unwrap();
    let (sequence, command, body, reserve) = outgoing_d2(outgoing.frame, &[0; 16]);
    assert_eq!(command, crate::o3::REPORT_COMMAND);
    assert!(reserve.secure_info.is_some());
    let telemetry: crate::proto::o3::TelemetryReport = crate::proto::decode(body).unwrap();
    assert_eq!(
        telemetry.data[0].values.last().map(String::as_str),
        Some("emptyToken")
    );
    client
        .receive(incoming(sequence, &command, &[], Some(&[0; 16])), 0)
        .unwrap();
    tokio::task::yield_now().await;
    let report = client
        .drain_signing_reports()
        .into_iter()
        .find(|report| report.method == "getToken")
        .unwrap();
    let issued = signing_engine::proto::IssuedTokenReply {
        token: b"issued-test-token".to_vec(),
        expires_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600,
    };
    client
        .complete_signing_report(
            &report,
            signing_engine::token::ReportResponse {
                bytes: issued.encode_to_vec(),
                transport_succeeded: true,
                error_code: 0,
            },
        )
        .unwrap();
    let mut inner = client.inner.lock().unwrap();
    let Inner { state, signer, .. } = &mut *inner;
    let signature = signer
        .sign("MessageSvc.PbSendMsg", 1, b"message", state, false)
        .unwrap()
        .unwrap();
    assert_eq!(signature.token, b"issued-test-token");
    drop(inner);
    client.confirm_online(0).unwrap();
    let outgoing = queue.recv().await.unwrap();
    let (sequence, command, body, _) = outgoing_d2(outgoing.frame, &[0; 16]);
    assert_eq!(command, crate::o3::REPORT_COMMAND);
    let telemetry: crate::proto::o3::TelemetryReport = crate::proto::decode(body).unwrap();
    let values = telemetry.data.into_iter().next().unwrap().values;
    assert_eq!(values[2], "verify_file");
    assert_eq!(values[6], client.snapshot().await.machine_id);
    let inventory: serde_json::Value = serde_json::from_str(&values[3]).unwrap();
    assert_eq!(
        inventory,
        serde_json::json!({"/opt/QQ/resources/app/application.json": "0"})
    );
    let modules: Vec<String> = serde_json::from_str(&values[4]).unwrap();
    assert!(modules.iter().all(|path| path.starts_with("/opt/QQ/resources/app/")));
    assert!(!modules.iter().any(|path| path.ends_with("/875.background.js")));
    client
        .receive(incoming(sequence, &command, &[], Some(&[0; 16])), 0)
        .unwrap();
    client.close_transport("telemetry test done".into()).await;
}

#[test]
fn configured_property_challenges_work_before_connect_or_login() {
    let client = Client::new(
        ClientConfig {
            machine_id: "prelogin-device".into(),
            ..Default::default()
        },
        Keystore::default(),
    )
    .unwrap();
    let encoded = client
        .answer_signing_property_challenge(&[0, 16, 0, 99])
        .unwrap();
    let report = signing_engine::proto::TokenReport::decode(encoded.as_slice()).unwrap();
    let values: Vec<_> = report
        .properties
        .into_iter()
        .map(|property| (property.id, property.value))
        .collect();
    assert_eq!(
        values,
        [(16, b"prelogin-device".to_vec()), (99, b"-1".to_vec())]
    );
    assert!(client.drain_signing_reports().is_empty());
}

#[tokio::test]
async fn malformed_and_unknown_config_pushes_remain_observable_without_fabricated_replies() {
    let (client, mut queue) = queued_client();
    let mut pushes = client.subscribe();
    client.start_background_work(0);
    assert!(
        client
            .receive(incoming(-1, "ConfigPushSvc.PushReq", b"malformed", None), 0,)
            .is_err()
    );
    assert_eq!(
        pushes.recv().await.unwrap().body,
        Bytes::from_static(b"malformed")
    );
    let unknown = wire::config_push::request_fixture(2, 17);
    client
        .receive(incoming(-2, "ConfigPushSvc.PushReq", &unknown, None), 0)
        .unwrap();
    assert_eq!(pushes.recv().await.unwrap().body, unknown);
    tokio::task::yield_now().await;
    assert!(queue.try_recv().is_err());
    assert!(client.inner.lock().unwrap().connection.is_some());
    client
        .close_transport("unknown configuration regression complete".into())
        .await;
}

fn reply_credential<M: Message>(client: &Client, outgoing: Outgoing, body: M, generation: u64) {
    let (sequence, command, _, _) = outgoing_d2(outgoing.frame, &[0; 16]);
    let envelope = crate::proto::contacts::OidbEnvelope {
        code: Some(0),
        body: Some(body.encode_to_vec().into()),
        ..Default::default()
    };
    client
        .receive(
            incoming(
                sequence,
                &command,
                &envelope.encode_to_vec(),
                Some(&[0; 16]),
            ),
            generation,
        )
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn client_key_cache_expires_by_response_ttl_without_changing_fresh_fetch() {
    use crate::{contacts::Operations, proto::contacts as pb};
    let (client, mut queue) = queued_client();
    client.confirm_online(0).unwrap();
    let fetching = {
        let client = client.clone();
        tokio::spawn(async move { client.client_key().await })
    };
    let outgoing = queue.recv().await.unwrap();
    let (_, command, body, _) = outgoing_d2(outgoing.frame.clone(), &[0; 16]);
    assert_eq!(command, "OidbSvcTrpcTcp.0x102a_1");
    let envelope: pb::OidbEnvelope = crate::proto::decode(body).unwrap();
    assert_eq!(
        (envelope.command, envelope.service, envelope.body),
        (Some(0x102a), Some(1), Some(Bytes::new()))
    );
    reply_credential(
        &client,
        outgoing,
        pb::ClientKeyResponse {
            key: Some("first-session-key".into()),
            expiration: Some(2),
        },
        0,
    );
    assert_eq!(fetching.await.unwrap().unwrap().expiration, 2);
    assert_eq!(client.client_key().await.unwrap().key, "first-session-key");
    assert!(
        queue.try_recv().is_err(),
        "a valid cached key must not make another RPC"
    );

    let operations = Arc::new(Operations::new(client.clone()));
    for index in 0..2 {
        let operations = operations.clone();
        let fresh = tokio::spawn(async move { operations.fetch_client_key().await });
        let outgoing = queue.recv().await.unwrap();
        reply_credential(
            &client,
            outgoing,
            pb::ClientKeyResponse {
                key: Some(format!("explicit-fresh-{index}")),
                expiration: Some(50),
            },
            0,
        );
        assert_eq!(
            fresh.await.unwrap().unwrap().key,
            format!("explicit-fresh-{index}")
        );
    }
    assert_eq!(client.cached_client_key().unwrap().key, "first-session-key");
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(
        client.cached_client_key().is_none(),
        "expiry is exclusive, not a stale fallback"
    );
    let fetching = {
        let client = client.clone();
        tokio::spawn(async move { client.client_key().await })
    };
    reply_credential(
        &client,
        queue.recv().await.unwrap(),
        pb::ClientKeyResponse {
            key: Some("replacement-session-key".into()),
            expiration: Some(7),
        },
        0,
    );
    assert_eq!(
        fetching.await.unwrap().unwrap().key,
        "replacement-session-key"
    );
    tokio::time::advance(Duration::from_secs(6)).await;
    assert_eq!(
        client.cached_client_key().unwrap().expiration,
        1,
        "cached callers must receive remaining lifetime, not the original issuance TTL"
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(client.cached_client_key().is_none());
}

#[tokio::test(start_paused = true)]
async fn pskey_cache_uses_requested_domain_absolute_expiry_and_never_invents_one() {
    use crate::proto::contacts as pb;
    let (client, mut queue) = queued_client();
    client.confirm_online(0).unwrap();
    let domains = vec![
        "short.qq.com".into(),
        "long.qq.com".into(),
        "unknown.qq.com".into(),
    ];
    let fetching = {
        let client = client.clone();
        let domains = domains.clone();
        tokio::spawn(async move { client.cookies(&domains).await })
    };
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    reply_credential(
        &client,
        queue.recv().await.unwrap(),
        pb::CookiesResponse {
            cookies: vec![
                pb::CookieRecord {
                    domain: Some(domains[0].clone()),
                    value: Some("short-pskey".into()),
                    expires_at: Some(unix + 3),
                },
                pb::CookieRecord {
                    domain: Some(domains[1].clone()),
                    value: Some("long-pskey".into()),
                    expires_at: Some(unix + 20),
                },
                pb::CookieRecord {
                    domain: Some(domains[2].clone()),
                    value: Some("unknown-pskey".into()),
                    expires_at: None,
                },
                pb::CookieRecord {
                    domain: Some("unsolicited.qq.com".into()),
                    value: Some("other-scope".into()),
                    expires_at: Some(unix + 100),
                },
            ],
        },
        0,
    );
    assert_eq!(
        fetching
            .await
            .unwrap()
            .unwrap()
            .get(&domains[2])
            .map(String::as_str),
        Some("unknown-pskey")
    );
    assert!(client.cached_cookies(&domains).is_none());
    assert!(
        client
            .cached_cookies(&["unsolicited.qq.com".into()])
            .is_none()
    );
    assert!(client.cached_cookies(&domains[..2]).is_some());
    tokio::time::advance(Duration::from_secs(3)).await;
    assert!(client.cached_cookies(&domains[..1]).is_none());
    assert_eq!(
        client
            .cookies(&domains[1..2])
            .await
            .unwrap()
            .get(&domains[1])
            .map(String::as_str),
        Some("long-pskey")
    );
    assert!(queue.try_recv().is_err());

    let fetching = {
        let client = client.clone();
        let domain = domains[2].clone();
        tokio::spawn(async move { client.cookies(&[domain]).await })
    };
    reply_credential(
        &client,
        queue.recv().await.unwrap(),
        pb::CookiesResponse {
            cookies: vec![pb::CookieRecord {
                domain: Some(domains[2].clone()),
                value: Some("expired-pskey".into()),
                expires_at: Some(unix - 1),
            }],
        },
        0,
    );
    assert_eq!(
        fetching
            .await
            .unwrap()
            .unwrap()
            .get(&domains[2])
            .map(String::as_str),
        Some("expired-pskey")
    );
    assert!(
        client.cached_cookies(&domains[2..]).is_none(),
        "an already expired server value is fresh-only"
    );
}

#[tokio::test]
async fn completed_credential_reply_cannot_commit_after_ticket_or_account_replacement() {
    use crate::proto::contacts as pb;
    let (client, mut queue) = queued_client();
    client.confirm_online(0).unwrap();
    let fetching = {
        let client = client.clone();
        tokio::spawn(async move { client.client_key().await })
    };
    reply_credential(
        &client,
        queue.recv().await.unwrap(),
        pb::ClientKeyResponse {
            key: Some("old-ticket-key".into()),
            expiration: Some(1800),
        },
        0,
    );
    // The transport has completed the reply, but its consumer has not committed it.
    let mut state = client.snapshot().await;
    state.keystore.d2.push(1);
    client.replace_state(state).await;
    assert!(matches!(fetching.await.unwrap(), Err(Error::Disconnected)));
    assert!(client.cached_client_key().is_none());

    let fetching = {
        let client = client.clone();
        tokio::spawn(async move { client.cookies(&["qun.qq.com".into()]).await })
    };
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    reply_credential(
        &client,
        queue.recv().await.unwrap(),
        pb::CookiesResponse {
            cookies: vec![pb::CookieRecord {
                domain: Some("qun.qq.com".into()),
                value: Some("old-account-pskey".into()),
                expires_at: Some(unix + 172800),
            }],
        },
        0,
    );
    let original = client.snapshot().await;
    let mut other = original.clone();
    other.keystore.uid = "another-account".into();
    client.replace_state(other).await;
    client.replace_state(original).await;
    client.confirm_online(0).unwrap();
    assert!(matches!(fetching.await.unwrap(), Err(Error::Disconnected)));
    assert!(
        client.cached_cookies(&["qun.qq.com".into()]).is_none(),
        "switching back must not restore the old session scope"
    );
}

#[tokio::test]
async fn disconnect_cancels_credential_fetch_and_stale_generation_cannot_fill_new_cache() {
    use crate::proto::contacts as pb;
    let (client, mut queue) = queued_client();
    client.confirm_online(0).unwrap();
    let fetching = {
        let client = client.clone();
        tokio::spawn(async move { client.client_key().await })
    };
    let outgoing = queue.recv().await.unwrap();
    let cancelled = outgoing.cancel.clone();
    client.terminate("credential cancellation test".into());
    assert!(matches!(fetching.await.unwrap(), Err(Error::Disconnected)));
    assert!(cancelled.is_cancelled());
    let (sender, _receiver) = mpsc::channel(8);
    {
        let mut inner = client.inner.lock().unwrap();
        inner.generation = 1;
        inner.cancel = CancellationToken::new();
        inner.connection = Some(Connection {
            generation: 1,
            sender,
        });
    }
    client.confirm_online(1).unwrap();
    reply_credential(
        &client,
        outgoing,
        pb::ClientKeyResponse {
            key: Some("old-connection-key".into()),
            expiration: Some(1800),
        },
        0,
    );
    assert!(client.cached_client_key().is_none());
    assert!(client.is_current_online(1));
}

#[tokio::test(start_paused = true)]
async fn credential_maintenance_commits_keys_uses_server_cadence_and_stops_on_cancel() {
    use crate::proto::contacts as pb;
    let (client, mut queue) = queued_client();
    client.confirm_online(0).unwrap();
    client.inner.lock().unwrap().credentials.start();
    let maintenance = tokio::spawn(credentials::run(
        Arc::downgrade(&client),
        0,
        client.cancellation(),
        client.credential_work.clone(),
    ));
    reply_credential(
        &client,
        queue.recv().await.unwrap(),
        pb::ClientKeyResponse {
            key: Some("maintained-client-key".into()),
            expiration: Some(7),
        },
        0,
    );
    let outgoing = queue.recv().await.unwrap();
    let (_, command, body, _) = outgoing_d2(outgoing.frame.clone(), &[0; 16]);
    assert_eq!(command, "OidbSvcTrpcTcp.0x102a_0");
    let envelope: pb::OidbEnvelope = crate::proto::decode(body).unwrap();
    let requested: pb::CookiesRequest = crate::proto::decode(envelope.body.unwrap()).unwrap();
    assert_eq!(
        requested.domains,
        ["docs.qq.com", "mail.qq.com", "pd.qq.com"]
    );
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    reply_credential(
        &client,
        outgoing,
        pb::CookiesResponse {
            cookies: requested
                .domains
                .iter()
                .map(|domain| pb::CookieRecord {
                    domain: Some(domain.clone()),
                    value: Some(format!("pskey-for-{domain}")),
                    expires_at: Some(unix + 172800),
                })
                .collect(),
        },
        0,
    );
    tokio::task::yield_now().await;
    assert_eq!(
        client.client_key().await.unwrap().key,
        "maintained-client-key"
    );
    assert!(client.cached_cookies(&requested.domains).is_some());
    tokio::time::advance(Duration::from_secs(6)).await;
    tokio::task::yield_now().await;
    assert!(queue.try_recv().is_err());
    tokio::time::advance(Duration::from_secs(1)).await;
    let outgoing = queue.recv().await.unwrap();
    let (sequence, command, _, _) = outgoing_d2(outgoing.frame, &[0; 16]);
    let denied = pb::OidbEnvelope {
        code: Some((-12_i32) as u64),
        message: Some("Denied".into()),
        ..Default::default()
    };
    client
        .receive(
            incoming(sequence, &command, &denied.encode_to_vec(), Some(&[0; 16])),
            0,
        )
        .unwrap();
    tokio::task::yield_now().await;
    assert!(client.cached_client_key().is_none());
    assert!(
        client.is_current_online(0),
        "ordinary credential failure must not drop the session"
    );
    tokio::time::advance(Duration::from_secs(6)).await;
    tokio::task::yield_now().await;
    assert!(
        queue.try_recv().is_err(),
        "a failed refresh must not create an immediate retry"
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    let outgoing = queue.recv().await.unwrap();
    client.terminate("maintenance cancellation test".into());
    maintenance.await.unwrap();
    assert!(outgoing.cancel.is_cancelled());
    tokio::time::advance(Duration::from_secs(172800)).await;
    assert!(queue.try_recv().is_err());
    assert!(client.cached_cookies(&requested.domains).is_none());
}

#[tokio::test(start_paused = true)]
async fn initial_credential_failures_do_not_invent_ttl_or_background_retries() {
    use crate::proto::contacts as pb;
    let (client, mut queue) = queued_client();
    client.confirm_online(0).unwrap();
    client.inner.lock().unwrap().credentials.start();
    let maintenance = tokio::spawn(credentials::run(
        Arc::downgrade(&client),
        0,
        client.cancellation(),
        client.credential_work.clone(),
    ));
    for _ in 0..2 {
        let outgoing = queue.recv().await.unwrap();
        let (sequence, command, _, _) = outgoing_d2(outgoing.frame, &[0; 16]);
        let denied = pb::OidbEnvelope {
            code: Some((-12_i32) as u64),
            message: Some("Denied".into()),
            ..Default::default()
        };
        client
            .receive(
                incoming(sequence, &command, &denied.encode_to_vec(), Some(&[0; 16])),
                0,
            )
            .unwrap();
    }
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(172800)).await;
    tokio::task::yield_now().await;
    assert!(
        queue.try_recv().is_err(),
        "without a server lifetime there is no made-up periodic retry"
    );
    assert!(client.cached_client_key().is_none());
    assert!(client.is_current_online(0));
    let fetching = {
        let client = client.clone();
        tokio::spawn(async move { client.client_key().await })
    };
    reply_credential(
        &client,
        queue.recv().await.unwrap(),
        pb::ClientKeyResponse {
            key: Some("explicitly-recovered-key".into()),
            expiration: Some(13),
        },
        0,
    );
    assert_eq!(
        fetching.await.unwrap().unwrap().key,
        "explicitly-recovered-key"
    );
    client.terminate("initial failure recovery complete".into());
    maintenance.await.unwrap();
}

#[tokio::test]
async fn bound_business_requests_cannot_cross_connection_or_account_replacement() {
    let (client, mut first_queue) = queued_client();
    client.confirm_online(0).unwrap();
    client.terminate("synthetic connection replaced".into());
    let (sender, mut second_queue) = mpsc::channel(8);
    {
        let mut inner = client.inner.lock().unwrap();
        inner.generation = 1;
        inner.cancel = CancellationToken::new();
        inner.connection = Some(Connection {
            generation: 1,
            sender,
        });
    }
    client.confirm_online(1).unwrap();
    assert!(matches!(
        client
            .request_online(0, "example.business", Bytes::new(), Duration::from_secs(1))
            .await,
        Err(Error::Disconnected)
    ));
    let mut replacement = client.snapshot().await;
    replacement.keystore.uin = 42;
    client.replace_state(replacement).await;
    assert!(matches!(
        client
            .request_online(1, "example.business", Bytes::new(), Duration::from_secs(1))
            .await,
        Err(Error::Disconnected)
    ));
    assert!(first_queue.try_recv().is_err());
    assert!(second_queue.try_recv().is_err());
    client.terminate("synthetic replacement complete".into());
}

#[path = "client_o3_tests.rs"]
mod o3;

#[tokio::test]
async fn server_clock_accepts_exact_response_and_rejects_malformed_samples_without_losing_session() {
    let (client, mut queue) = queued_client();
    let expected = 2_000_000_000u32;
    let request = {
        let client = client.clone();
        tokio::spawn(async move { client.correct_time().await })
    };
    let outgoing = queue.recv().await.unwrap();
    let (sequence, command, _) = outgoing_identity(outgoing.frame);
    client
        .receive(incoming(sequence, &command, &expected.to_be_bytes(), None), 0)
        .unwrap();
    request.await.unwrap().unwrap();
    assert!((expected..=expected + 1).contains(&client.server_time_seconds().unwrap()));
    for length in [0, 1, 3, 5, 8] {
        let request = {
            let client = client.clone();
            tokio::spawn(async move { client.correct_time().await })
        };
        let outgoing = queue.recv().await.unwrap();
        let (sequence, command, _) = outgoing_identity(outgoing.frame);
        client
            .receive(incoming(sequence, &command, &vec![0xff; length], None), 0)
            .unwrap();
        assert!(matches!(request.await.unwrap(), Err(Error::Malformed(_))));
        assert!((expected..=expected + 1).contains(&client.server_time_seconds().unwrap()));
        assert!(client.inner.lock().unwrap().connection.is_some());
    }
}

#[tokio::test(start_paused = true)]
async fn server_clock_discards_timed_out_and_replaced_transport_samples() {
    let (client, mut queue) = queued_client();
    client.inner.lock().unwrap().clock.correction(2_000_000_000, SystemTime::now());
    let request = {
        let client = client.clone();
        tokio::spawn(async move { client.correct_time().await })
    };
    let outgoing = queue.recv().await.unwrap();
    tokio::time::advance(Duration::from_secs(8)).await;
    assert!(matches!(request.await.unwrap(), Err(Error::Timeout)));
    let (sequence, command, _) = outgoing_identity(outgoing.frame);
    client.receive(incoming(sequence, &command, &1u32.to_be_bytes(), None), 0).unwrap();
    assert!(client.server_time_seconds().unwrap() >= 2_000_000_000);
    let request = {
        let client = client.clone();
        tokio::spawn(async move { client.correct_time().await })
    };
    let outgoing = queue.recv().await.unwrap();
    client.terminate("synthetic clock transport replacement".into());
    assert!(matches!(request.await.unwrap(), Err(Error::Disconnected)));
    let (sequence, command, _) = outgoing_identity(outgoing.frame);
    client.receive(incoming(sequence, &command, &1u32.to_be_bytes(), None), 0).unwrap();
    assert!(client.server_time_seconds().unwrap() >= 2_000_000_000);
}

#[tokio::test(start_paused = true)]
async fn configuration_bootstrap_survives_update_failure_without_repeating_full_fetches() {
    use crate::proto::lifecycle as configuration;
    async fn next_configuration(
        client: &Client,
        queue: &mut mpsc::Receiver<Outgoing>,
    ) -> (i32, configuration::ConfigRequest) {
        loop {
            let outgoing = queue.recv().await.unwrap();
            let (sequence, command, body, _) = outgoing_d2(outgoing.frame, &[0; 16]);
            if command == "trpc.group_pro.configdistribution.ConfigDistributionSvr.SsoGetConfig" {
                return (sequence, configuration::ConfigRequest::decode(body).unwrap());
            }
            assert_eq!(command, "QQClubComm.getNewFlag");
            let reply = configuration::ClubFlagResponse {
                code: Some(0),
                poll_seconds: Some(300),
                ..Default::default()
            };
            client.receive(incoming(sequence, &command, &reply.encode_to_vec(), Some(&[0; 16])), 0).unwrap();
        }
    }
    let command = "trpc.group_pro.configdistribution.ConfigDistributionSvr.SsoGetConfig";
    let (client, mut queue) = queued_client();
    {
        let mut inner = client.inner.lock().unwrap();
        inner.state.online = true;
        inner.state.keystore.uin = 1234;
    }
    let cancel = CancellationToken::new();
    let driver = tokio::spawn(crate::lifecycle::run(Arc::downgrade(&client), 0, cancel.clone()));
    let (sequence, bootstrap) = next_configuration(&client, &mut queue).await;
    assert_eq!(bootstrap.fetch_type, Some(5));
    assert!(bootstrap.groups.is_empty());
    let reply = configuration::ConfigResponse {
        groups: vec![configuration::ConfigGroup {
            name: Some("100085".into()),
            old_version: Some("10055".into()),
            group_id: Some(100085),
            new_version: Some(8),
            records: vec![configuration::ConfigRecord {
                content: Some(Bytes::from_static(b"[]")),
                ..Default::default()
            }],
            ..Default::default()
        }],
        state: Some(configuration::ConfigServerState {
            config_sequence: Some(42),
            inc_cookies: Some(Bytes::from_static(b"global-cookie")),
            ..Default::default()
        }),
        ..Default::default()
    };
    client.receive(incoming(sequence, command, &reply.encode_to_vec(), Some(&[0; 16])), 0).unwrap();
    let (sequence, exact) = next_configuration(&client, &mut queue).await;
    assert_eq!(exact.fetch_type, Some(2));
    assert_eq!(exact.origin.unwrap().model_type, Some(2));
    assert_eq!(exact.groups[0].name.as_deref(), Some("100085"));
    assert_eq!(exact.groups[0].old_version.as_deref(), Some("1"));
    assert_eq!(exact.groups[0].new_version, Some(8));
    assert_eq!(exact.cache.unwrap().inc_cookies, Some(Bytes::new()));
    client.receive(incoming(sequence, command, b"\x22\xff", Some(&[0; 16])), 0).unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(3599)).await;
    tokio::task::yield_now().await;
    while let Ok(outgoing) = queue.try_recv() {
        let (sequence, command, _, _) = outgoing_d2(outgoing.frame, &[0; 16]);
        assert_eq!(command, "QQClubComm.getNewFlag");
        let reply = configuration::ClubFlagResponse {
            code: Some(0), poll_seconds: Some(300), ..Default::default()
        };
        client.receive(incoming(sequence, &command, &reply.encode_to_vec(), Some(&[0; 16])), 0).unwrap();
    }
    tokio::time::advance(Duration::from_secs(1)).await;
    let (sequence, exact) = next_configuration(&client, &mut queue).await;
    assert_eq!(exact.fetch_type, Some(2));
    assert_eq!(exact.groups[0].name.as_deref(), Some("100085"));
    assert_eq!(exact.groups[0].new_version, Some(8));
    let reply = configuration::ConfigResponse {
        state: Some(configuration::ConfigServerState::default()),
        ..Default::default()
    };
    client.receive(incoming(sequence, command, &reply.encode_to_vec(), Some(&[0; 16])), 0).unwrap();
    cancel.cancel();
    driver.await.unwrap();
    assert!(client.is_current_online(0));
    client.terminate("synthetic configuration lifecycle complete".into());
}

#[tokio::test]
async fn mobile_logoff_notice_is_observable_without_pc_logout_or_ack() {
    use jce::JceStruct;
    let (client, mut queue) = queued_client();
    client.confirm_online(0).unwrap();
    let mut notices = client.login_notifications();
    let mut events = client.login_events();
    let value = crate::network::LoginNotificationBody {
        raw_field0: 7,
        raw_field1: 2,
        raw_field3: 110,
        title: "Peer session".into(),
        message: "Another device changed status".into(),
        ..Default::default()
    };
    let mut body = bytes::BytesMut::with_capacity(value.encoded_len());
    value.encode_raw(&mut body);
    let body = wire::config_push::payload_fixture(
        "StatSvc",
        "SvcReqMSFLoginNotify",
        "SvcReqMSFLoginNotify",
        "QQService.SvcReqMSFLoginNotify",
        body.freeze(),
    );
    client.receive(incoming(-87, crate::network::LOGIN_NOTIFICATION_COMMAND, &body, None), 0).unwrap();
    assert_eq!(notices.recv().await.unwrap().body.raw_field3, 110);
    assert!(client.snapshot().await.online);
    assert!(events.try_recv().is_err());
    assert!(queue.try_recv().is_err());
}

#[tokio::test]
async fn canceled_file_transfer_acquisition_does_not_block_the_next_demand() {
    let (client, mut queue) = queued_client();
    {
        let mut inner = client.inner.lock().unwrap();
        inner.state.online = true;
        inner.state.keystore.uin = 7;
        inner.state.keystore.uid = "u_synthetic_file_self".into();
        inner.state.keystore.a2 = vec![2; 16];
    }
    let fetching = {
        let client = client.clone();
        tokio::spawn(async move { client.file_transfer_ticket().await })
    };
    let first = timeout(Duration::from_secs(2), queue.recv()).await.unwrap().unwrap();
    assert_eq!(first.command, "OidbSvcTrpcTcp.0x9a2_8");
    fetching.abort();
    assert!(fetching.await.unwrap_err().is_cancelled());
    let fetching = {
        let client = client.clone();
        tokio::spawn(async move { client.file_transfer_ticket().await })
    };
    let retry = timeout(Duration::from_secs(2), queue.recv()).await.unwrap().unwrap();
    let response = crate::proto::contacts::OidbEnvelope {
        command: Some(0x9a2),
        service: Some(8),
        code: Some(0),
        body: Some(crate::proto::file_transfer::FileTransSignResponse {
            ticket: Some(crate::proto::file_transfer::FileTransSignTicket {
                sign: Some(Bytes::from_static(b"synthetic-relay-ticket")),
                lifetime_seconds: Some(43200),
            }),
            ..Default::default()
        }.encode_to_vec().into()),
        ..Default::default()
    }.encode_to_vec();
    client.receive(incoming(retry.sequence, &retry.command, &response, None), 0).unwrap();
    fetching.await.unwrap().unwrap();
    assert!(client.cached_file_transfer_ticket().is_some());
    let replacement = SessionState {
        keystore: Keystore {
            uin: 8,
            uid: "u_synthetic_replacement".into(),
            ..Default::default()
        },
        ..client.snapshot().await
    };
    client.replace_state(replacement).await;
    assert!(client.cached_file_transfer_ticket().is_none());
    assert!(queue.try_recv().is_err());
    client.terminate("Synthetic file transfer scenario finished".into());
}

fn synchronized_message(group: Option<u64>, sequence: u64, time: u64) -> Bytes {
    use crate::{messages::{MessageElement, encode_elements}, proto::messages as pb};
    pb::CommonMessage {
        routing_head: Some(pb::RoutingHead {
            sender_uin: Some(7),
            sender_uid: "u_synthetic_peer".into(),
            group: group.map(|uin| pb::CommonGroup { uin: Some(uin), ..Default::default() }),
            ..Default::default()
        }),
        content_head: Some(pb::ContentHead {
            message_type: Some(if group.is_some() { 82 } else { 166 }),
            sequence: Some(sequence),
            client_sequence: Some(sequence + 1000),
            time: Some(time),
            ..Default::default()
        }),
        message_body: encode_elements(&[MessageElement::Text("ping".into())], &[]).unwrap().into(),
    }.encode_to_vec().into()
}

#[tokio::test]
async fn localhost_first_view_group_additional_and_partial_retry_consume_without_live_replay() {
    use crate::{message_sync::{self as sync, Source}, proto::message_sync as pb};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut framed = Framed::new(socket, SsoFrameCodec);
        let (sequence, command, body, _) = outgoing_d2(framed.next().await.unwrap().unwrap(), &[0; 16]);
        assert_eq!(command, sync::INFO_COMMAND);
        let request: auth::InfoSyncRequest = crate::proto::decode(body).unwrap();
        assert_eq!(request.sync_flag, Some(1759));
        assert!(request.register.is_some());
        let random = request.request_random.unwrap();
        let response = auth::InfoSyncResponse {
            request_random: Some(random),
            register: Some(auth::InfoSyncRegisterResponse { message: Some("register success".into()), ..Default::default() }),
            ..Default::default()
        };
        framed.send(incoming(sequence, &command, &response.encode_to_vec(), Some(&[0; 16]))).await.unwrap();
        let nodes = pb::InfoSyncPush {
            request_random: Some(random),
            stage: Some(5),
            groups: vec![pb::GroupNode { group_uin: Some(55), message_seq: Some(120), total_seq: Some(140), message_time: Some(222), ..Default::default() }],
            ..Default::default()
        };
        framed.send(incoming(-1, sync::INFO_PUSH, &nodes.encode_to_vec(), Some(&[0; 16]))).await.unwrap();
        let first = pb::InfoSyncPush {
            request_random: Some(random),
            result: Some(0x05f5e3c0),
            stage: Some(2),
            c2c_messages: Some(pb::C2cMessages {
                current_cookie: Some(Bytes::from_static(b"current\0opaque")),
                previous_cookie: Some(Bytes::from_static(b"independent-previous")),
                conversations: vec![pb::C2cConversation { last_message_time: Some(99999), messages: vec![synchronized_message(None, 1, 111)], ..Default::default() }],
                ..Default::default()
            }),
            ..Default::default()
        };
        framed.send(incoming(-2, sync::INFO_PUSH, &first.encode_to_vec(), Some(&[0; 16]))).await.unwrap();
        let end = pb::InfoSyncPush { request_random: Some(random), stage: Some(4), ..Default::default() };
        framed.send(incoming(-3, sync::INFO_PUSH, &end.encode_to_vec(), Some(&[0; 16]))).await.unwrap();
        let (sequence, command, body, _) = outgoing_d2(framed.next().await.unwrap().unwrap(), &[0; 16]);
        assert_eq!(command, sync::GROUP_COMMAND);
        let request: pb::GroupSyncRequest = crate::proto::decode(body).unwrap();
        assert_eq!(request.groups.len(), 1);
        assert_eq!((request.groups[0].begin_seq, request.groups[0].end_seq), (Some(106), Some(120)));
        let response = pb::GroupSyncResponse { request_random: request.request_random, ..Default::default() };
        framed.send(incoming(sequence, &command, &response.encode_to_vec(), Some(&[0; 16]))).await.unwrap();
        let group = pb::GroupMsgPush {
            request_random: request.request_random,
            flag: Some(2),
            groups: vec![pb::GroupMessageResult { group_uin: Some(55), server_end_seq: Some(120), messages: vec![synchronized_message(Some(55), 119, 222)], ..Default::default() }],
        };
        framed.send(incoming(-4, sync::GROUP_PUSH, &group.encode_to_vec(), Some(&[0; 16]))).await.unwrap();
        let (sequence, command, body, _) = outgoing_d2(framed.next().await.unwrap().unwrap(), &[0; 16]);
        assert_eq!(command, sync::INFO_COMMAND);
        let retry: auth::InfoSyncRequest = crate::proto::decode(body).unwrap();
        assert_eq!(retry.sync_flag, Some(1));
        assert!(retry.register.is_none());
        assert_ne!(retry.request_random, Some(random));
        assert_eq!(retry.group_last_message_time, Some(222));
        let state = retry.sync.unwrap();
        assert_eq!(state.current_cookie.as_deref(), Some(b"current\0opaque".as_slice()));
        assert_eq!(state.previous_cookie.as_deref(), Some(b"independent-previous".as_slice()));
        assert_eq!(state.last_message_time, Some(111));
        let response = auth::InfoSyncResponse { request_random: retry.request_random, ..Default::default() };
        framed.send(incoming(sequence, &command, &response.encode_to_vec(), Some(&[0; 16]))).await.unwrap();
        let stale = pb::InfoSyncPush {
            request_random: Some(random),
            stage: Some(2),
            c2c_messages: Some(pb::C2cMessages { current_cookie: Some(Bytes::from_static(b"stale")), conversations: vec![pb::C2cConversation { messages: vec![synchronized_message(None, 2, 999)], ..Default::default() }], ..Default::default() }),
            ..Default::default()
        };
        framed.send(incoming(-5, sync::INFO_PUSH, &stale.encode_to_vec(), Some(&[0; 16]))).await.unwrap();
        let complete = pb::InfoSyncPush { request_random: retry.request_random, stage: Some(4), ..Default::default() };
        framed.send(incoming(-6, sync::INFO_PUSH, &complete.encode_to_vec(), Some(&[0; 16]))).await.unwrap();
        assert!(framed.next().await.is_none());
    });
    let client = Client::new(ClientConfig { host: "127.0.0.1".into(), port, timeout: Duration::from_secs(5), ..Default::default() }, Keystore::default()).unwrap();
    let mut changed = client.message_sync_changes();
    client.connect().await.unwrap();
    let (_, registration) = timeout(Duration::from_secs(5), client.start_message_sync(false)).await.unwrap().unwrap();
    assert_eq!(registration.message.as_deref(), Some("register success"));
    timeout(Duration::from_secs(8), async {
        loop {
            let snapshot = client.message_sync_snapshot();
            if snapshot.protocol_complete && snapshot.additional_complete && snapshot.sent_flag == 1 { break; }
            changed.changed().await.unwrap();
        }
    }).await.unwrap();
    let snapshot = client.message_sync_snapshot();
    assert_eq!(snapshot.batches.len(), 2);
    assert_eq!(snapshot.batches[0].source, Source::FirstView);
    assert_eq!(snapshot.batches[1].source, Source::GroupAdditional);
    assert_eq!(snapshot.batches.iter().map(|batch| batch.messages.len()).sum::<usize>(), 2);
    assert_eq!(snapshot.checkpoint.c2c_last_message_time, 111);
    assert_eq!(snapshot.checkpoint.group_last_message_time, 222);
    assert_eq!(snapshot.checkpoint.groups[&55].received_message_seq, 119);
    assert_eq!(snapshot.checkpoint.groups[&55].total_seq, 0);
    let messaging = crate::messages::Messaging::new(client.clone(), Arc::new(crate::media::Media::new(client.clone())));
    let events = messaging.decode_push(IncomingPacket { command: sync::INFO_PUSH.into(), sequence: -7, return_code: 0, body: pb::InfoSyncPush::default().encode_to_vec().into(), header: Default::default() }).await;
    assert!(!events.iter().any(|event| matches!(event, crate::messages::PushEvent::Message { .. })));
    let value = messaging.call("sync_snapshot", ciborium::Value::Null).await.unwrap();
    let mut bytes = Vec::new();
    ciborium::into_writer(&value, &mut bytes).unwrap();
    let exposed: sync::Snapshot = ciborium::from_reader(bytes.as_slice()).unwrap();
    assert_eq!(exposed.batches[0].source, Source::FirstView);
    client.close_transport("Synthetic message synchronization finished".into()).await;
    timeout(Duration::from_secs(3), server).await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn message_sync_retry_waits_weakly_and_identity_replacement_cancels_queued_work() {
    let (client, mut queue) = queued_client();
    let session = client.snapshot().await;
    let (binding, action) = client.message_sync.begin(0, &session, &client.cancellation(), crate::login::info_sync(&session, false));
    let request = client.message_sync.prepare(&binding, action).unwrap();
    let actions = client.message_sync.direct(&binding, &request, Err(Error::Timeout));
    client.spawn_message_sync_actions(binding, actions);
    tokio::task::yield_now().await;
    let mut replacement = session.clone();
    replacement.keystore.uid = "u_synthetic_replacement".into();
    client.replace_state(replacement).await;
    tokio::time::advance(Duration::from_secs(4)).await;
    tokio::task::yield_now().await;
    assert!(queue.try_recv().is_err());
    let session = client.snapshot().await;
    let (binding, action) = client.message_sync.begin(0, &session, &client.cancellation(), crate::login::info_sync(&session, false));
    let request = client.message_sync.prepare(&binding, action).unwrap();
    let actions = client.message_sync.direct(&binding, &request, Err(Error::Timeout));
    client.spawn_message_sync_actions(binding, actions);
    tokio::task::yield_now().await;
    let weak = Arc::downgrade(&client);
    drop(client);
    assert!(weak.upgrade().is_none());
    assert!(queue.recv().await.is_none());
}

#[tokio::test(start_paused = true)]
async fn kick_cancels_message_sync_retry_before_any_late_send_or_cookie_commit() {
    let (client, mut queue) = queued_client();
    let session = client.snapshot().await;
    let (binding, action) = client.message_sync.begin(0, &session, &client.cancellation(), crate::login::info_sync(&session, false));
    let request = client.message_sync.prepare(&binding, action).unwrap();
    let actions = client.message_sync.direct(&binding, &request, Err(Error::Timeout));
    client.spawn_message_sync_actions(binding.clone(), actions);
    tokio::task::yield_now().await;
    let kick = auth::Kick { message: Some("synthetic synchronization cancellation".into()), ..Default::default() };
    client.receive(incoming(-1, "trpc.qq_new_tech.status_svc.StatusService.KickNT", &kick.encode_to_vec(), Some(&[0; 16])), 0).unwrap();
    assert!(binding.cancel.is_cancelled());
    let outgoing = queue.try_recv().unwrap();
    let (_, command, _, _) = outgoing_d2(outgoing.frame, &[0; 16]);
    assert_eq!(command, "trpc.qq_new_tech.status_svc.StatusService.UnRegister");
    let crate::message_sync::Request::Info { body } = request else { panic!("expected InfoSync"); };
    let late = crate::proto::message_sync::InfoSyncPush {
        request_random: body.request_random, stage: Some(2),
        c2c_messages: Some(crate::proto::message_sync::C2cMessages { current_cookie: Some(Bytes::from_static(b"late")), conversations: vec![crate::proto::message_sync::C2cConversation { messages: vec![synchronized_message(None, 1, 999)], ..Default::default() }], ..Default::default() }),
        ..Default::default()
    };
    client.receive(incoming(-2, crate::message_sync::INFO_PUSH, &late.encode_to_vec(), Some(&[0; 16])), 0).unwrap();
    tokio::time::advance(Duration::from_secs(4)).await;
    tokio::task::yield_now().await;
    assert!(queue.try_recv().is_err());
    assert!(client.message_sync_snapshot().checkpoint.current_cookie.is_empty());
    assert!(client.message_sync_snapshot().batches.is_empty());
    client.terminate("Synthetic kick synchronization scenario finished".into());
}
