use super::super::ios_signing_tests::{config, request_parts};
use super::*;
use crate::wire::{Reader, Writer};
use tokio::net::TcpListener;

const KEY: [u8; 16] = [0x37; 16];

fn store() -> Keystore {
    Keystore {
        uin: 123456,
        uid: "header-test-uid".into(),
        a2: b"header-test-a2".to_vec(),
        d2: b"header-test-d2".to_vec(),
        d2_key: KEY.to_vec(),
        ios_msf_imei: "header-test-imei".into(),
        ..Default::default()
    }
}

fn response(sequence: i32, command: &str, code: i32) -> Bytes {
    response_body(sequence, command, code, b"reply")
}

fn response_body(sequence: i32, command: &str, code: i32, body: &[u8]) -> Bytes {
    response_reserved(sequence, command, code, body, &[])
}

fn response_reserved(
    sequence: i32,
    command: &str,
    code: i32,
    body: &[u8],
    reserve: &[u8],
) -> Bytes {
    let mut head = Writer::new();
    head.i32(sequence);
    head.i32(code);
    head.p32([]).unwrap();
    head.p32(command).unwrap();
    head.p32([]).unwrap();
    head.i32(0);
    head.p32(reserve).unwrap();
    let mut payload = Writer::new();
    payload.p32(head.data).unwrap();
    payload.p32(body).unwrap();
    let mut outer = Writer::new();
    outer.u32(13);
    outer.u8(1);
    outer.u8(0);
    outer.p32("123456").unwrap();
    outer.bytes(crate::crypto::tea_encrypt(&payload.data, &KEY).unwrap());
    let mut frame = Writer::new();
    frame.p32(outer.data).unwrap();
    frame.data.into()
}

fn packet(frame: Bytes) -> (u32, i32, String, Bytes, crate::proto::sso::Reserved) {
    let mut outer = Reader::new(frame.clone());
    outer.u32().unwrap();
    let kind = outer.u32().unwrap();
    assert_eq!(outer.u8().unwrap(), Encryption::D2 as u8);
    let short_sequence = if kind == 13 {
        outer.i32().unwrap()
    } else {
        outer.p32().unwrap();
        0
    };
    let (_, _, _, mut head, body) = request_parts(frame, &KEY);
    let sequence = if kind == 12 {
        let sequence = head.i32().unwrap();
        head.skip(20).unwrap();
        assert_eq!(head.p32().unwrap().as_ref(), b"header-test-a2");
        sequence
    } else {
        short_sequence
    };
    let command = String::from_utf8(head.p32().unwrap().to_vec()).unwrap();
    head.p32().unwrap();
    if kind == 12 {
        head.p32().unwrap();
        head.p32().unwrap();
        head.pref(2, true).unwrap();
    }
    let reserve = crate::proto::decode(head.p32().unwrap()).unwrap();
    assert!(head.rest().is_empty());
    (kind, sequence, command, body, reserve)
}

fn request(
    client: &Arc<Client>,
    command: &'static str,
    duration: Duration,
) -> JoinHandle<Result<Bytes>> {
    let client = client.clone();
    tokio::spawn(async move {
        client
            .request(
                command,
                Bytes::from_static(b"original-body"),
                RequestType::D2,
                Encryption::D2,
                duration,
            )
            .await
    })
}

async fn connected(profile: Profile) -> (Arc<Client>, Framed<TcpStream, SsoFrameCodec>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = config(profile);
    config.host = "127.0.0.1".into();
    config.port = listener.local_addr().unwrap().port();
    let client = Client::new(config, store()).unwrap();
    client.connect().await.unwrap();
    let (socket, _) = listener.accept().await.unwrap();
    (client, Framed::new(socket, SsoFrameCodec))
}

#[tokio::test]
async fn encrypted_tcp_full_trim_policy_and_force_full_recovery_preserve_business_identity() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for profile in [Profile::iphone(), Profile::ipad()] {
            let (client, mut socket) = connected(profile).await;
            client
                .inner
                .lock()
                .unwrap()
                .ios_mut()
                .unwrap()
                .transport
                .account = IosTransportAccount::Uin { account_type: 6 };
            for command in ["header.type6", "Heartbeat.Ping"] {
                let task = request(&client, command, Duration::from_secs(3));
                let (kind, sequence, actual, _, _) = packet(socket.next().await.unwrap().unwrap());
                assert_eq!(kind, 12);
                assert_eq!(actual, command);
                socket.send(response(sequence, command, 0)).await.unwrap();
                task.await.unwrap().unwrap();
                let inner = client.inner.lock().unwrap();
                assert!(inner.ios().unwrap().header.qimei_materialized);
                assert!(!inner.ios().unwrap().header.full_selected);
                assert!(!inner.ios().unwrap().header.trim_enabled);
            }
            client
                .inner
                .lock()
                .unwrap()
                .ios_mut()
                .unwrap()
                .transport
                .account = IosTransportAccount::Uin { account_type: 0 };
            let first = request(&client, "header.business", Duration::from_secs(3));
            let (kind, sequence, command, _, reserve) =
                packet(socket.next().await.unwrap().unwrap());
            assert_eq!(kind, 12);
            assert!(reserve.qimei.is_some());
            socket
                .send(response(sequence + 99, "unmatched.push", 0))
                .await
                .unwrap();
            socket.send(response(sequence, &command, 7)).await.unwrap();
            assert!(matches!(
                first.await.unwrap(),
                Err(Error::Server { code: 7, .. })
            ));
            let second = request(
                &client,
                "AvatarInfoSvr.QQHeadUrlReq",
                Duration::from_secs(3),
            );
            let (kind, sequence, command, body, reserve) =
                packet(socket.next().await.unwrap().unwrap());
            assert_eq!(kind, 13);
            assert!(reserve.qimei.is_none());
            let original_security = reserve.secure_info.unwrap();
            let (id, deadline, cancel) = {
                let inner = client.inner.lock().unwrap();
                let pending = &inner.pending[&sequence];
                (
                    pending.id,
                    pending.replay.as_ref().unwrap().deadline,
                    pending.cancel.clone(),
                )
            };
            socket
                .send(response(sequence, &command, -10008))
                .await
                .unwrap();
            let (kind, retry_sequence, retry_command, retry_body, reserve) =
                packet(socket.next().await.unwrap().unwrap());
            assert_eq!(kind, 12);
            assert_eq!(retry_sequence, sequence);
            assert_eq!(retry_command, command);
            assert_eq!(retry_body, body);
            assert!(reserve.qimei.is_some());
            assert_eq!(reserve.secure_info.as_ref(), Some(&original_security));
            assert!(!second.is_finished());
            {
                let inner = client.inner.lock().unwrap();
                let pending = &inner.pending[&sequence];
                assert_eq!(pending.id, id);
                assert_eq!(pending.replay.as_ref().unwrap().deadline, deadline);
                assert!(pending.replay.as_ref().unwrap().force_full);
            }
            socket.send(response(sequence, &command, 0)).await.unwrap();
            assert_eq!(second.await.unwrap().unwrap().as_ref(), b"reply");
            assert!(!cancel.is_cancelled());
            assert!(client.inner.lock().unwrap().pending.is_empty());
            for command in [
                "header.after-recovery",
                "Heartbeat.Ping",
                crate::message_sync::INFO_COMMAND,
                "RegPrxySvc.info.synthetic",
                "wtlogin.exchange",
                "wtlogin.exchange.synthetic",
            ] {
                let task = request(&client, command, Duration::from_secs(3));
                let (kind, sequence, actual, _, _) = packet(socket.next().await.unwrap().unwrap());
                assert_eq!(actual, command);
                assert_eq!(
                    kind,
                    if command == "header.after-recovery" || command == "wtlogin.exchange.synthetic"
                    {
                        13
                    } else {
                        12
                    }
                );
                socket.send(response(sequence, command, 0)).await.unwrap();
                task.await.unwrap().unwrap();
            }
            {
                let mut inner = client.inner.lock().unwrap();
                inner.state.keystore.uid = "uid-only-change".into();
            }
            let changed = request(&client, "header.uid-change", Duration::from_secs(3));
            let (kind, sequence, command, _, reserve) =
                packet(socket.next().await.unwrap().unwrap());
            assert_eq!(kind, 12);
            assert_eq!(reserve.uid.as_deref(), Some("uid-only-change"));
            socket.send(response(sequence, &command, 0)).await.unwrap();
            changed.await.unwrap().unwrap();
            client.close_transport("header test complete".into()).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn encrypted_tcp_unmatched_ineligible_and_old_generation_do_not_enable_trim() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for profile in [Profile::iphone(), Profile::ipad()] {
            for missing_a2 in [true, false] {
                let (client, mut socket) = connected(profile.clone()).await;
                {
                    let mut inner = client.inner.lock().unwrap();
                    if missing_a2 {
                        inner.state.keystore.a2.clear();
                    } else {
                        inner.state.keystore.ios_msf_imei.clear();
                    }
                }
                let first = request(&client, "header.ineligible", Duration::from_secs(3));
                let frame = socket.next().await.unwrap().unwrap();
                let (kind, _, _, mut head, _) = request_parts(frame, &KEY);
                assert_eq!(kind, 12);
                let sequence = head.i32().unwrap();
                socket
                    .send(response(sequence, "header.ineligible", 0))
                    .await
                    .unwrap();
                first.await.unwrap().unwrap();
                assert!(
                    !client
                        .inner
                        .lock()
                        .unwrap()
                        .ios()
                        .unwrap()
                        .header
                        .trim_enabled
                );
                let second = request(&client, "header.ineligible-next", Duration::from_secs(3));
                let frame = socket.next().await.unwrap().unwrap();
                let (kind, _, _, mut head, _) = request_parts(frame, &KEY);
                assert_eq!(kind, 12);
                let sequence = head.i32().unwrap();
                client
                    .receive(
                        response(sequence, "header.ineligible-next", 0),
                        client.connection_generation() - 1,
                    )
                    .unwrap();
                assert!(!second.is_finished());
                assert!(
                    !client
                        .inner
                        .lock()
                        .unwrap()
                        .ios()
                        .unwrap()
                        .header
                        .trim_enabled
                );
                socket
                    .send(response(sequence, "header.ineligible-next", 0))
                    .await
                    .unwrap();
                second.await.unwrap().unwrap();
                client
                    .close_transport("ineligible test complete".into())
                    .await;
            }
            let (client, mut socket) = connected(profile).await;
            let first = request(&client, "header.unmatched", Duration::from_secs(3));
            let (kind, sequence, command, _, _) = packet(socket.next().await.unwrap().unwrap());
            assert_eq!(kind, 12);
            client
                .receive(
                    response(sequence + 1, "unmatched.push", 0),
                    client.connection_generation(),
                )
                .unwrap();
            let second = request(&client, "header.before-match", Duration::from_secs(3));
            let (kind, second_sequence, second_command, _, _) =
                packet(socket.next().await.unwrap().unwrap());
            assert_eq!(kind, 12);
            socket.send(response(sequence, &command, 0)).await.unwrap();
            socket
                .send(response(second_sequence, &second_command, 0))
                .await
                .unwrap();
            first.await.unwrap().unwrap();
            second.await.unwrap().unwrap();
            client
                .close_transport("unmatched test complete".into())
                .await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn encrypted_tcp_repeated_full_requests_end_at_original_deadline_and_cancellation_removes_pending()
 {
    tokio::time::timeout(Duration::from_secs(10), async {
        for profile in [Profile::iphone(), Profile::ipad()] {
            let (client, mut socket) = connected(profile).await;
            let duration = Duration::from_millis(120);
            let task = request(&client, "header.repeated-error", duration);
            let (kind, sequence, command, _, _) = packet(socket.next().await.unwrap().unwrap());
            assert_eq!(kind, 12);
            let deadline = client.inner.lock().unwrap().pending[&sequence]
                .replay
                .as_ref()
                .unwrap()
                .deadline;
            let mut attempts = 0;
            loop {
                socket
                    .send(response(sequence, &command, -10008))
                    .await
                    .unwrap();
                let frame =
                    tokio::time::timeout_at(deadline + Duration::from_millis(100), socket.next())
                        .await;
                match frame {
                    Ok(Some(Ok(frame))) => {
                        let (kind, retry_sequence, _, _, _) = packet(frame);
                        assert_eq!(kind, 12);
                        assert_eq!(retry_sequence, sequence);
                        assert!(
                            !client
                                .inner
                                .lock()
                                .unwrap()
                                .ios()
                                .unwrap()
                                .header
                                .trim_enabled
                        );
                        attempts += 1;
                        if task.is_finished() {
                            break;
                        }
                    }
                    _ => break,
                }
            }
            assert!(attempts > 0);
            assert!(matches!(task.await.unwrap(), Err(Error::Timeout)));
            assert!(client.inner.lock().unwrap().pending.is_empty());
            let task = request(&client, "header.cancel-retry", Duration::from_secs(3));
            let (_, sequence, command, _, _) = packet(socket.next().await.unwrap().unwrap());
            socket
                .send(response(sequence, &command, -10008))
                .await
                .unwrap();
            let (kind, retry_sequence, _, _, _) = packet(socket.next().await.unwrap().unwrap());
            assert_eq!(kind, 12);
            assert_eq!(retry_sequence, sequence);
            let cancel = client.inner.lock().unwrap().pending[&sequence]
                .cancel
                .clone();
            task.abort();
            let _ = task.await;
            assert!(cancel.is_cancelled());
            assert!(client.inner.lock().unwrap().pending.is_empty());
            client
                .close_transport("retry deadline test complete".into())
                .await;
        }
    })
    .await
    .unwrap();
}

#[test]
fn construction_consumes_qimei_even_on_encoding_failure_and_exempt_or_type6_never_select_full() {
    for profile in [Profile::iphone(), Profile::ipad()] {
        let client = Client::new(config(profile), store()).unwrap();
        let mut inner = client.inner.lock().unwrap();
        inner.state.keystore.d2_key.clear();
        assert!(
            client
                .prepare_frame(
                    &mut inner,
                    "Heartbeat.Ping",
                    Bytes::new(),
                    RequestType::D2,
                    Encryption::D2
                )
                .is_err()
        );
        assert!(inner.ios().unwrap().header.qimei_materialized);
        assert!(!inner.ios().unwrap().header.full_selected);
        inner.ios_mut().unwrap().header.response(true);
        assert!(!inner.ios().unwrap().header.trim_enabled);
        inner.ios_mut().unwrap().transport.account = IosTransportAccount::Uin { account_type: 6 };
        assert!(
            client
                .prepare_frame(
                    &mut inner,
                    "header.type6",
                    Bytes::new(),
                    RequestType::D2,
                    Encryption::D2
                )
                .is_err()
        );
        assert!(!inner.ios().unwrap().header.full_selected);
        inner.ios_mut().unwrap().header.response(true);
        assert!(!inner.ios().unwrap().header.trim_enabled);
        inner.ios_mut().unwrap().transport.account = IosTransportAccount::Uin { account_type: 0 };
        assert!(
            client
                .prepare_frame(
                    &mut inner,
                    "header.normal",
                    Bytes::new(),
                    RequestType::D2,
                    Encryption::D2
                )
                .is_err()
        );
        assert!(inner.ios().unwrap().header.full_selected);
        assert!(inner.ios().unwrap().header.qimei_materialized);
        inner.ios_mut().unwrap().header.response(true);
        assert!(inner.ios().unwrap().header.trim_enabled);
        assert!(
            client
                .prepare_frame(
                    &mut inner,
                    "wtlogin.login",
                    Bytes::new(),
                    RequestType::D2,
                    Encryption::D2
                )
                .is_err()
        );
        assert!(!inner.ios().unwrap().header.full_selected);
        assert!(!inner.ios().unwrap().header.trim_enabled);
    }
}

#[test]
fn account_type_text_uid_and_generation_changes_reset_only_at_eligible_selection() {
    let client = Client::new(config(Profile::iphone()), store()).unwrap();
    let mut inner = client.inner.lock().unwrap();
    for change in 0..6 {
        client
            .prepare_frame(
                &mut inner,
                "header.normal",
                Bytes::new(),
                RequestType::D2,
                Encryption::D2,
            )
            .unwrap();
        inner.ios_mut().unwrap().header.response(true);
        let (_, frame) = client
            .prepare_frame(
                &mut inner,
                "header.trim",
                Bytes::new(),
                RequestType::D2,
                Encryption::D2,
            )
            .unwrap();
        assert_eq!(request_parts(frame, &KEY).0, 13);
        match change {
            0 => inner.state.keystore.uid.push('x'),
            1 => inner.state.keystore.uin += 1,
            2 => {
                inner.ios_mut().unwrap().transport.account =
                    IosTransportAccount::Uin { account_type: 3 }
            }
            3 => {
                inner.ios_mut().unwrap().transport.account = IosTransportAccount::Explicit {
                    account_type: 3,
                    text: Bytes::from_static(b"explicit-account"),
                }
            }
            4 => {
                inner.ios_mut().unwrap().transport.account = IosTransportAccount::Explicit {
                    account_type: 3,
                    text: Bytes::from_static(b"changed-explicit-account"),
                }
            }
            _ => inner.generation += 1,
        }
        let (_, frame) = client
            .prepare_frame(
                &mut inner,
                "header.reset",
                Bytes::new(),
                RequestType::D2,
                Encryption::D2,
            )
            .unwrap();
        assert_eq!(request_parts(frame, &KEY).0, 12);
        assert!(!inner.ios().unwrap().header.trim_enabled);
    }
}

#[test]
fn newly_available_qimei_forces_one_full_construction_without_waiting_for_a_reply() {
    for profile in [Profile::iphone(), Profile::ipad()] {
        let mut config = config(profile);
        let qimei_template = config.ios_snapshot().unwrap().transport.reserved.clone();
        config.ios_snapshot_mut().unwrap().transport.reserved =
            IosReservedTemplate::new(Bytes::new()).unwrap();
        let client = Client::new(config, store()).unwrap();
        let mut inner = client.inner.lock().unwrap();
        client
            .prepare_frame(
                &mut inner,
                "header.first",
                Bytes::new(),
                RequestType::D2,
                Encryption::D2,
            )
            .unwrap();
        assert!(!inner.ios().unwrap().header.qimei_materialized);
        inner.ios_mut().unwrap().header.response(true);
        let (_, frame) = client
            .prepare_frame(
                &mut inner,
                "header.trim",
                Bytes::new(),
                RequestType::D2,
                Encryption::D2,
            )
            .unwrap();
        assert_eq!(request_parts(frame, &KEY).0, 13);
        inner.ios_mut().unwrap().transport.reserved = qimei_template;
        let (_, frame) = client
            .prepare_frame(
                &mut inner,
                "header.qimei",
                Bytes::new(),
                RequestType::D2,
                Encryption::D2,
            )
            .unwrap();
        assert_eq!(packet(frame).0, 12);
        assert!(inner.ios().unwrap().header.qimei_materialized);
        let (_, frame) = client
            .prepare_frame(
                &mut inner,
                "header.next",
                Bytes::new(),
                RequestType::D2,
                Encryption::D2,
            )
            .unwrap();
        assert_eq!(request_parts(frame, &KEY).0, 13);
    }
}

#[tokio::test]
async fn queued_full_recovery_keeps_original_deadline_and_cancellation() {
    for expire in [true, false] {
        let client = Client::new(config(Profile::iphone()), store()).unwrap();
        let (sender, mut queue) = mpsc::channel(1);
        client.inner.lock().unwrap().connection = Some(Connection {
            generation: 0,
            sender: sender.clone(),
        });
        let task = request(&client, "header.queued-recovery", Duration::from_millis(60));
        let original = queue.recv().await.unwrap();
        let (_, sequence, command, _, _) = packet(original.frame.clone());
        let deadline = original.deadline;
        let cancel = original.cancel.clone();
        sender
            .try_send(Outgoing {
                command: "queue.blocker".into(),
                sequence: 0,
                attempt: 0,
                frame: original.frame,
                deadline,
                cancel: CancellationToken::new(),
                required_control: false,
                terminal: false,
            })
            .unwrap_or_else(|_| panic!("queue should have room"));
        client
            .receive(response(sequence, &command, -10008), 0)
            .unwrap();
        {
            let inner = client.inner.lock().unwrap();
            assert_eq!(
                inner.pending[&sequence].replay.as_ref().unwrap().deadline,
                deadline
            );
        }
        if expire {
            assert!(matches!(task.await.unwrap(), Err(Error::Timeout)));
        } else {
            task.abort();
            let _ = task.await;
        }
        assert!(cancel.is_cancelled());
        assert!(client.inner.lock().unwrap().pending.is_empty());
        assert!(
            !client
                .inner
                .lock()
                .unwrap()
                .ios()
                .unwrap()
                .block_check
                .timed_out
        );
        tokio::task::yield_now().await;
        assert_eq!(queue.recv().await.unwrap().command, "queue.blocker");
        tokio::task::yield_now().await;
        assert!(queue.try_recv().is_err());
        client
            .close_transport("queued retry test complete".into())
            .await;
    }
}

#[tokio::test]
async fn encrypted_tcp_reconnection_clears_trim_and_rejects_old_generation_replies() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for profile in [Profile::iphone(), Profile::ipad()] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut config = config(profile);
            config.host = "127.0.0.1".into();
            config.port = listener.local_addr().unwrap().port();
            let client = Client::new(config, store()).unwrap();
            client.connect().await.unwrap();
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = Framed::new(socket, SsoFrameCodec);
            let task = request(
                &client,
                "header.previous-connection",
                Duration::from_secs(3),
            );
            let (kind, sequence, command, _, _) = packet(socket.next().await.unwrap().unwrap());
            assert_eq!(kind, 12);
            socket.send(response(sequence, &command, 0)).await.unwrap();
            task.await.unwrap().unwrap();
            assert!(
                client
                    .inner
                    .lock()
                    .unwrap()
                    .ios()
                    .unwrap()
                    .header
                    .trim_enabled
            );
            let old_generation = client.connection_generation();
            client.close_transport("reconnecting".into()).await;
            drop(socket);
            client.connect().await.unwrap();
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = Framed::new(socket, SsoFrameCodec);
            let task = request(&client, "header.new-connection", Duration::from_secs(3));
            let (kind, sequence, command, _, reserve) =
                packet(socket.next().await.unwrap().unwrap());
            assert_eq!(kind, 12);
            assert!(reserve.qimei.is_some());
            client
                .receive(response(sequence, &command, 0), old_generation)
                .unwrap();
            assert!(!task.is_finished());
            assert!(
                !client
                    .inner
                    .lock()
                    .unwrap()
                    .ios()
                    .unwrap()
                    .header
                    .trim_enabled
            );
            socket.send(response(sequence, &command, 0)).await.unwrap();
            task.await.unwrap().unwrap();
            client
                .close_transport("reconnection test complete".into())
                .await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn encrypted_business_identity_is_not_borrowed_by_native_internal_control_packets() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for profile in [Profile::iphone(), Profile::ipad()] {
            let (client, mut socket) = connected(profile).await;
            client
                .inner
                .lock()
                .unwrap()
                .ios_mut()
                .unwrap()
                .transport
                .account = IosTransportAccount::Explicit {
                account_type: 3,
                text: Bytes::from_static(b"user-account"),
            };
            let correction = {
                let client = client.clone();
                tokio::spawn(async move { client.correct_time().await })
            };
            let frame = socket.next().await.unwrap().unwrap();
            let mut outer = Reader::new(frame.clone());
            outer.u32().unwrap();
            assert_eq!(outer.u32().unwrap(), 12);
            assert_eq!(outer.u8().unwrap(), Encryption::None as u8);
            assert!(outer.p32().unwrap().is_empty());
            let (kind, account_type, account, mut header, body) = request_parts(frame, &KEY);
            assert_eq!(kind, 12);
            assert_eq!(account_type, 0);
            assert_eq!(account.as_ref(), b"0");
            let sequence = header.i32().unwrap();
            header.skip(20).unwrap();
            assert!(header.p32().unwrap().is_empty());
            assert_eq!(header.p32().unwrap().as_ref(), b"Client.CorrectTime");
            header.p32().unwrap();
            assert_eq!(header.p32().unwrap().as_ref(), b"header-test-imei");
            assert!(header.p32().unwrap().is_empty());
            header.pref(2, true).unwrap();
            let reserve: crate::proto::sso::Reserved =
                crate::proto::decode(header.p32().unwrap()).unwrap();
            assert!(reserve.qimei.is_some());
            assert!(reserve.uid.is_none());
            assert!(reserve.secure_info.is_none());
            assert_eq!(body.as_ref(), &[0, 0, 0, 4]);
            {
                let inner = client.inner.lock().unwrap();
                assert!(inner.ios().unwrap().header.qimei_materialized);
                assert!(!inner.ios().unwrap().header.full_selected);
                assert!(!inner.pending[&sequence].replay.as_ref().unwrap().eligible);
                assert!(
                    inner.pending[&sequence]
                        .replay
                        .as_ref()
                        .unwrap()
                        .internal_control
                );
                let remaining =
                    inner.pending[&sequence].replay.as_ref().unwrap().deadline - Instant::now();
                assert!(remaining > Duration::from_secs(50));
            }
            socket
                .send(response_body(
                    sequence,
                    "Client.CorrectTime",
                    0,
                    &1_800_000_000u32.to_be_bytes(),
                ))
                .await
                .unwrap();
            correction.await.unwrap().unwrap();
            let inner = client.inner.lock().unwrap();
            assert_eq!(inner.state.keystore.uin, 123456);
            assert_eq!(inner.state.keystore.uid, "header-test-uid");
            assert!(!inner.ios().unwrap().header.trim_enabled);
            drop(inner);
            client
                .close_transport("internal control test complete".into())
                .await;
        }
    })
    .await
    .unwrap();
}

#[test]
fn account_text_compares_actual_decimal_bytes_across_provider_representations() {
    for (text, uin, expected) in [
        (&b"0"[..], 0, true),
        (&b"123456"[..], 123456, true),
        (&b"0123456"[..], 123456, false),
        (&b""[..], 0, false),
        (&b"+1"[..], 1, false),
        (&b"18446744073709551615"[..], u64::MAX, true),
        (&b"18446744073709551616"[..], u64::MAX, false),
    ] {
        assert_eq!(text_is_uin(text, uin), expected);
    }
    let client = Client::new(config(Profile::iphone()), store()).unwrap();
    let mut inner = client.inner.lock().unwrap();
    client
        .prepare_frame(
            &mut inner,
            "header.first",
            Bytes::new(),
            RequestType::D2,
            Encryption::D2,
        )
        .unwrap();
    inner.ios_mut().unwrap().header.response(true);
    inner.ios_mut().unwrap().transport.account = IosTransportAccount::Explicit {
        account_type: 0,
        text: Bytes::from_static(b"123456"),
    };
    let (_, frame) = client
        .prepare_frame(
            &mut inner,
            "header.same-text",
            Bytes::new(),
            RequestType::D2,
            Encryption::D2,
        )
        .unwrap();
    assert_eq!(request_parts(frame, &KEY).0, 13);
    inner.ios_mut().unwrap().transport.account = IosTransportAccount::Explicit {
        account_type: 0,
        text: Bytes::from_static(b"0123456"),
    };
    let (_, frame) = client
        .prepare_frame(
            &mut inner,
            "header.changed-text",
            Bytes::new(),
            RequestType::D2,
            Encryption::D2,
        )
        .unwrap();
    assert_eq!(request_parts(frame, &KEY).0, 12);
}

fn control_packet(frame: Bytes, command: &str) -> (i32, crate::proto::sso::Reserved) {
    let mut outer = Reader::new(frame.clone());
    outer.u32().unwrap();
    assert_eq!(outer.u32().unwrap(), 12);
    assert_eq!(outer.u8().unwrap(), Encryption::None as u8);
    assert!(outer.p32().unwrap().is_empty());
    let (_, account_type, account, mut header, body) = request_parts(frame, &KEY);
    assert_eq!(account_type, 0);
    assert_eq!(account.as_ref(), b"0");
    let sequence = header.i32().unwrap();
    header.skip(20).unwrap();
    assert!(header.p32().unwrap().is_empty());
    assert_eq!(header.p32().unwrap().as_ref(), command.as_bytes());
    header.p32().unwrap();
    assert_eq!(header.p32().unwrap().as_ref(), b"header-test-imei");
    assert!(header.p32().unwrap().is_empty());
    header.pref(2, true).unwrap();
    let reserve: crate::proto::sso::Reserved = crate::proto::decode(header.p32().unwrap()).unwrap();
    assert!(reserve.uid.is_none());
    assert!(reserve.secure_info.is_none());
    assert!(reserve.qimei.is_some());
    assert_eq!(body.as_ref(), &[0, 0, 0, 4]);
    (sequence, reserve)
}

async fn await_written(client: &Client, count: usize) {
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let written = client
                .inner
                .lock()
                .unwrap()
                .pending
                .values()
                .filter(|pending| {
                    pending
                        .replay
                        .as_ref()
                        .is_some_and(|replay| matches!(replay.phase, Phase::Awaiting(_)))
                })
                .count();
            if written == count {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn native_alive_requires_distinct_aged_commands_and_only_resets_wait_accumulators() {
    for profile in [Profile::iphone(), Profile::ipad()] {
        tokio::time::timeout(Duration::from_secs(30), async {
            let (client, mut socket) = connected(profile).await;
            client.start_alive();
            assert!(
                tokio::time::timeout(Duration::from_millis(20), socket.next())
                    .await
                    .is_err()
            );
            let mut requests = Vec::new();
            for _ in 0..6 {
                requests.push(request(
                    &client,
                    "same.pending.command",
                    Duration::from_secs(25),
                ));
            }
            for _ in 0..6 {
                packet(socket.next().await.unwrap().unwrap());
            }
            await_written(&client, 6).await;
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(6)).await;
            tokio::time::resume();
            assert!(
                tokio::time::timeout(Duration::from_millis(20), socket.next())
                    .await
                    .is_err()
            );
            for command in [
                "aged.one",
                "aged.two",
                "aged.three",
                "aged.four",
                "aged.five",
                "aged.six",
            ] {
                requests.push(request(&client, command, Duration::from_secs(25)));
            }
            for _ in 0..6 {
                packet(socket.next().await.unwrap().unwrap());
            }
            await_written(&client, 12).await;
            let deadlines: HashMap<_, _> = client
                .inner
                .lock()
                .unwrap()
                .pending
                .iter()
                .map(|(sequence, pending)| (*sequence, pending.replay.as_ref().unwrap().deadline))
                .collect();
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(6)).await;
            tokio::time::resume();
            let (sequence, _) =
                control_packet(socket.next().await.unwrap().unwrap(), "Heartbeat.Alive");
            {
                let inner = client.inner.lock().unwrap();
                assert_eq!(
                    inner
                        .pending
                        .values()
                        .filter(|pending| pending.command == "Heartbeat.Alive")
                        .count(),
                    1
                );
                let replay = inner.pending[&sequence].replay.as_ref().unwrap();
                assert!(replay.internal_control);
                assert!(!replay.eligible);
                assert!(replay.deadline - Instant::now() <= Duration::from_secs(8));
            }
            requests.push(request(
                &client,
                "header.newer-than-probe",
                Duration::from_secs(25),
            ));
            let (_, newer_sequence, _, _, _) = packet(socket.next().await.unwrap().unwrap());
            await_written(&client, 14).await;
            client
                .inner
                .lock()
                .unwrap()
                .pending
                .get_mut(&newer_sequence)
                .unwrap()
                .replay
                .as_mut()
                .unwrap()
                .accumulated_wait = 4;
            socket
                .send(response(sequence, "Heartbeat.Alive", 0))
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    if !client.inner.lock().unwrap().pending.contains_key(&sequence) {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            {
                let inner = client.inner.lock().unwrap();
                assert_eq!(
                    inner.pending[&newer_sequence]
                        .replay
                        .as_ref()
                        .unwrap()
                        .accumulated_wait,
                    4
                );
                for (sequence, deadline) in deadlines {
                    let replay = inner.pending[&sequence].replay.as_ref().unwrap();
                    assert_eq!(replay.deadline, deadline);
                    assert_eq!(replay.accumulated_wait, 0);
                }
            }
            assert!(requests.iter().all(|request| !request.is_finished()));
            for request in requests {
                request.abort();
                let _ = request.await;
            }
            client
                .close_transport("distinct command probe complete".into())
                .await;
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn sent_business_timeout_triggers_one_native_probe_and_probe_timeout_invalidates_only_transport()
 {
    for profile in [Profile::iphone(), Profile::ipad()] {
        tokio::time::timeout(Duration::from_secs(15), async {
            let (client, mut socket) = connected(profile).await;
            let task = request(&client, "header.sent-timeout", Duration::from_millis(30));
            packet(socket.next().await.unwrap().unwrap());
            assert!(matches!(task.await.unwrap(), Err(Error::Timeout)));
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(1)).await;
            tokio::time::resume();
            let (sequence, _) =
                control_packet(socket.next().await.unwrap().unwrap(), "Heartbeat.Alive");
            assert!(client.inner.lock().unwrap().pending.contains_key(&sequence));
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(8)).await;
            tokio::time::resume();
            tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    if client.inner.lock().unwrap().connection.is_none() {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            let inner = client.inner.lock().unwrap();
            assert_eq!(inner.state.keystore.uin, 123456);
            assert_eq!(inner.state.keystore.a2, b"header-test-a2");
            assert_eq!(inner.state.keystore.d2, b"header-test-d2");
            assert!(inner.kick_reason.is_none());
            assert!(inner.pending.is_empty());
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn mobile_success_statuses_deliver_body_and_preserve_raw_status_without_verification_wait() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for profile in [Profile::iphone(), Profile::ipad()] {
            let (client, mut socket) = connected(profile).await;
            let mut packets = client.subscribe();
            for (code, command) in [
                (-10000, "header.__verify"),
                (-10000, "header.__refresh"),
                (-10007, "header.normal"),
            ] {
                let task = request(&client, command, Duration::from_secs(3));
                let (_, sequence, _, _, _) = packet(socket.next().await.unwrap().unwrap());
                socket
                    .send(response_body(
                        sequence,
                        command,
                        code,
                        b"actual-status-body",
                    ))
                    .await
                    .unwrap();
                assert_eq!(task.await.unwrap().unwrap().as_ref(), b"actual-status-body");
                let packet = packets.recv().await.unwrap();
                assert_eq!(packet.sequence, sequence);
                assert_eq!(packet.command, command);
                assert_eq!(packet.return_code, code);
                assert_eq!(packet.body.as_ref(), b"actual-status-body");
                assert!(client.captcha.lock().unwrap().is_none());
                assert!(client.device_verification.lock().unwrap().is_none());
                assert!(client.security.lock().unwrap().is_none());
            }
            client
                .close_transport("status delivery complete".into())
                .await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn desktop_does_not_adopt_mobile_success_statuses() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = Client::new(
        ClientConfig {
            host: "127.0.0.1".into(),
            port: listener.local_addr().unwrap().port(),
            platform: Some(PlatformConfig::Linux(LinuxConfig {
                machine_id: "status-fixture-machine".into(),
                application_uuid: "status-fixture-application".into(),
            })),
            ..Default::default()
        },
        store(),
    )
    .unwrap();
    client.connect().await.unwrap();
    let (socket, _) = listener.accept().await.unwrap();
    let mut socket = Framed::new(socket, SsoFrameCodec);
    for code in [-10000, -10007] {
        let task = request(&client, "header.desktop-status", Duration::from_secs(3));
        tokio::time::timeout(Duration::from_secs(3), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let sequence = *client.inner.lock().unwrap().pending.keys().next().unwrap();
        socket
            .send(response(sequence, "header.desktop-status", code))
            .await
            .unwrap();
        assert!(
            matches!(task.await.unwrap(), Err(Error::Server { code: actual, .. }) if actual == code)
        );
    }
    client
        .close_transport("desktop status boundary complete".into())
        .await;
}

#[tokio::test]
async fn ability_downgrade_reuses_full_or_trimmed_request_without_resigning_or_new_budget() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for profile in [Profile::iphone(), Profile::ipad()] {
            for primed in [false, true] {
                let (client, mut socket) = connected(profile.clone()).await;
                if primed {
                    let prime = request(&client, "header.prime", Duration::from_secs(3));
                    let (_, sequence, command, _, _) =
                        packet(socket.next().await.unwrap().unwrap());
                    socket.send(response(sequence, &command, 0)).await.unwrap();
                    prime.await.unwrap().unwrap();
                }
                let task = request(&client, "MessageSvc.PbSendMsg", Duration::from_secs(3));
                let original = packet(socket.next().await.unwrap().unwrap());
                assert!(original.4.secure_info.is_some());
                let (id, deadline) = {
                    let inner = client.inner.lock().unwrap();
                    let pending = &inner.pending[&original.1];
                    (pending.id, pending.replay.as_ref().unwrap().deadline)
                };
                socket
                    .send(response(original.1, &original.2, -10119))
                    .await
                    .unwrap();
                let replay = packet(socket.next().await.unwrap().unwrap());
                assert_eq!(replay.0, if primed { 13 } else { 12 });
                assert_eq!(replay.0, original.0);
                assert_eq!(replay.1, original.1);
                assert_eq!(replay.2, original.2);
                assert_eq!(replay.3, original.3);
                assert_eq!(replay.4.secure_info, original.4.secure_info);
                {
                    let inner = client.inner.lock().unwrap();
                    let pending = &inner.pending[&original.1];
                    assert_eq!(pending.id, id);
                    assert_eq!(pending.replay.as_ref().unwrap().deadline, deadline);
                    assert!(!pending.replay.as_ref().unwrap().force_full);
                    assert_eq!(inner.ios().unwrap().response.disabled_abilities & 1, 1);
                }
                socket.send(response(replay.1, &replay.2, 0)).await.unwrap();
                assert_eq!(task.await.unwrap().unwrap().as_ref(), b"reply");
                client
                    .close_transport("ability recovery complete".into())
                    .await;
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn unencrypted_header_failure_retires_transport_pending_until_original_caller_deadline() {
    for profile in [Profile::iphone(), Profile::ipad()] {
        let client = Client::new(config(profile), store()).unwrap();
        let (sender, mut queue) = mpsc::channel(8);
        client.inner.lock().unwrap().connection = Some(Connection {
            generation: 0,
            sender,
        });
        let task = request(&client, "header.consumed", Duration::from_secs(10));
        let outgoing = queue.recv().await.unwrap();
        client
            .receive(response(outgoing.sequence, "header.consumed", -10113), 0)
            .unwrap();
        assert!(client.inner.lock().unwrap().pending.is_empty());
        client
            .receive(response(outgoing.sequence, "header.consumed", 0), 0)
            .unwrap();
        tokio::time::advance(Duration::from_secs(9)).await;
        assert!(!task.is_finished());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(matches!(task.await.unwrap(), Err(Error::Timeout)));
        assert!(
            !client
                .inner
                .lock()
                .unwrap()
                .ios()
                .unwrap()
                .block_check
                .timed_out
        );
        assert!(queue.try_recv().is_err());
        client
            .close_transport("header failure retirement complete".into())
            .await;
    }
}

#[tokio::test]
async fn sideway_reconnect_preserves_request_and_session_but_rejects_old_socket_callbacks() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for profile in [Profile::iphone(), Profile::ipad()] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut configuration = config(profile);
            configuration.host = "127.0.0.1".into();
            configuration.port = listener.local_addr().unwrap().port();
            let client = Client::new(configuration, store()).unwrap();
            client.connect().await.unwrap();
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = Framed::new(socket, SsoFrameCodec);
            let task = request(&client, "MessageSvc.PbSendMsg", Duration::from_secs(3));
            let original = packet(socket.next().await.unwrap().unwrap());
            let (generation, source, id, deadline) = {
                let mut inner = client.inner.lock().unwrap();
                inner.state.online = true;
                let pending = &inner.pending[&original.1];
                (
                    inner.generation,
                    inner.transport_cancel.clone(),
                    pending.id,
                    pending.replay.as_ref().unwrap().deadline,
                )
            };
            let mut events = client.events.subscribe();
            socket
                .send(response(original.1, &original.2, -10114))
                .await
                .unwrap();
            let (new_socket, _) = listener.accept().await.unwrap();
            let mut new_socket = Framed::new(new_socket, SsoFrameCodec);
            let replay = packet(new_socket.next().await.unwrap().unwrap());
            assert_eq!(replay.1, original.1);
            assert_eq!(replay.2, original.2);
            assert_eq!(replay.3, original.3);
            assert_eq!(replay.4.secure_info, original.4.secure_info);
            assert!(source.is_cancelled());
            client
                .receive_from_transport(
                    response(original.1, &original.2, 0),
                    generation,
                    Some(&source),
                )
                .unwrap();
            client.terminate_transport(generation, &source, "old socket EOF".into());
            assert!(!task.is_finished());
            {
                let inner = client.inner.lock().unwrap();
                assert_eq!(inner.generation, generation);
                assert!(inner.state.online);
                assert_eq!(inner.state.keystore.a2, store().a2);
                assert_eq!(inner.state.keystore.d2, store().d2);
                assert!(!inner.cancel.is_cancelled());
                assert!(inner.ios().unwrap().response.sideway_disabled);
                assert!(!inner.ios().unwrap().response.reconnecting);
                let pending = &inner.pending[&original.1];
                assert_eq!(pending.id, id);
                assert_eq!(pending.replay.as_ref().unwrap().deadline, deadline);
                assert!(!pending.replay.as_ref().unwrap().force_full);
            }
            while let Ok(event) = events.try_recv() {
                assert!(!matches!(event, LoginEvent::Offline { .. }));
            }
            new_socket
                .send(response(replay.1, &replay.2, 0))
                .await
                .unwrap();
            assert_eq!(task.await.unwrap().unwrap().as_ref(), b"reply");
            client
                .close_transport("sideway recovery complete".into())
                .await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn identity_change_during_sideway_recovery_never_replays_or_terminates_new_identity() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (client, mut socket) = connected(Profile::iphone()).await;
        let gate = client.connect_gate.lock().await;
        let task = request(&client, "MessageSvc.PbSendMsg", Duration::from_secs(3));
        let (_, sequence, command, _, _) = packet(socket.next().await.unwrap().unwrap());
        socket
            .send(response(sequence, &command, -10114))
            .await
            .unwrap();
        loop {
            if client
                .inner
                .lock()
                .unwrap()
                .ios()
                .unwrap()
                .response
                .reconnecting
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        let mut replacement = client.snapshot().await;
        replacement.keystore.uin += 1;
        replacement.keystore.uid = "new-recovery-identity".into();
        client.replace_state(replacement).await;
        drop(gate);
        assert!(matches!(task.await.unwrap(), Err(Error::Disconnected)));
        let inner = client.inner.lock().unwrap();
        assert_eq!(inner.state.keystore.uid, "new-recovery-identity");
        assert!(!inner.cancel.is_cancelled());
        assert!(!inner.ios().unwrap().response.reconnecting);
        assert!(inner.connection.is_none());
        assert!(inner.pending.is_empty());
        drop(inner);
        client
            .close_transport("identity recovery boundary complete".into())
            .await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelled_physical_control_source_cannot_submit_on_same_logical_generation() {
    let client = Client::new(config(Profile::iphone()), store()).unwrap();
    let (sender, mut queue) = mpsc::channel(8);
    let source = {
        let mut inner = client.inner.lock().unwrap();
        inner.connection = Some(Connection {
            generation: 0,
            sender,
        });
        let old = inner.transport_cancel.clone();
        old.cancel();
        inner.transport_cancel = inner.cancel.child_token();
        old
    };
    assert!(matches!(
        client.correct_time_for_generation(0, true, &source).await,
        Err(Error::Disconnected)
    ));
    assert!(matches!(
        client
            .request_inner(
                "Heartbeat.Alive",
                Bytes::from_static(&[0, 0, 0, 4]),
                RequestType::D2,
                Encryption::None,
                Duration::from_secs(8),
                Some(RequestBinding::IosControl {
                    generation: 0,
                    source: &source
                }),
            )
            .await,
        Err(Error::Disconnected)
    ));
    assert!(queue.try_recv().is_err());
    assert!(!client.inner.lock().unwrap().cancel.is_cancelled());
    client
        .close_transport("physical clock fence complete".into())
        .await;
}

#[tokio::test]
async fn signature_attachment_switch_preserves_produced_security_across_replays() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for profile in [Profile::iphone(), Profile::ipad()] {
            let (client, mut socket) = connected(profile).await;
            let command = "MessageSvc.PbSendMsg";
            let initial = request(&client, command, Duration::from_secs(3));
            let first = packet(socket.next().await.unwrap().unwrap());
            assert!(first.4.secure_info.is_some());
            socket
                .send(response_reserved(first.1, command, 0, &[], &[0xc8, 1, 0]))
                .await
                .unwrap();
            initial.await.unwrap().unwrap();

            let pending = request(&client, command, Duration::from_secs(3));
            let disabled = packet(socket.next().await.unwrap().unwrap());
            assert!(disabled.4.secure_info.is_none());
            let produced = client.inner.lock().unwrap().pending[&disabled.1]
                .replay
                .as_ref()
                .unwrap()
                .signature
                .clone()
                .unwrap();
            socket
                .send(response_reserved(
                    disabled.1,
                    command,
                    -10008,
                    b"retry",
                    &[0xc8, 1, 2],
                ))
                .await
                .unwrap();
            let retry = packet(socket.next().await.unwrap().unwrap());
            assert_eq!(retry.1, disabled.1);
            assert!(retry.4.secure_info.is_none());
            socket
                .send(response_reserved(
                    -37,
                    "SSO.HelloPush",
                    0,
                    b"push",
                    &[0xc8, 1, 1],
                ))
                .await
                .unwrap();
            socket
                .send(response(disabled.1, command, -10008))
                .await
                .unwrap();
            let enabled = packet(socket.next().await.unwrap().unwrap());
            assert_eq!(enabled.1, disabled.1);
            assert_eq!(enabled.3, disabled.3);
            assert_eq!(enabled.4.secure_info.as_ref(), Some(&produced));
            socket.send(response(disabled.1, command, 0)).await.unwrap();
            pending.await.unwrap().unwrap();

            for (reserve, code, attached) in [
                (&[0xc8, 1, 3][..], -10000, false),
                (&[0xc8, 1, 0xff, 0xff, 0xff, 0xff, 0x0f][..], 0, false),
                (&[0x08, 1][..], 0, false),
                (&[0xc8, 1][..], 0, false),
                (&[0xc8, 1, 2][..], -12, false),
                (&[0xc8, 1, 2][..], -10007, true),
            ] {
                let operation = request(&client, command, Duration::from_secs(3));
                let current = packet(socket.next().await.unwrap().unwrap());
                socket
                    .send(response_reserved(
                        current.1, command, code, b"reply", reserve,
                    ))
                    .await
                    .unwrap();
                let result = operation.await.unwrap();
                assert_eq!(result.is_ok(), code != -12);
                let operation = request(&client, command, Duration::from_secs(3));
                let next = packet(socket.next().await.unwrap().unwrap());
                assert_eq!(next.4.secure_info.is_some(), attached);
                socket.send(response(next.1, command, 0)).await.unwrap();
                operation.await.unwrap().unwrap();
            }
            client
                .close_transport("signature switch test complete".into())
                .await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn host_signer_switch_and_packet_attachment_have_distinct_update_conditions() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for profile in [Profile::iphone(), Profile::ipad()] {
            let (client, mut socket) = connected(profile).await;
            let command = "MessageSvc.PbSendMsg";
            for (invokes, attached, body, reserve) in [
                (true, true, &b"reply"[..], &[0xc8, 1, 0][..]),
                (false, false, &b"reply"[..], &[0x08, 1][..]),
                (true, false, &b"reply"[..], &[0xc8, 1, 1][..]),
                (true, true, &b""[..], &[0xc8, 1, 0][..]),
                (
                    true,
                    false,
                    &b"reply"[..],
                    &[0xc8, 1, 0xff, 0xff, 0xff, 0xff, 0x0f][..],
                ),
                (true, false, &b"reply"[..], &[0xc8, 1, 2][..]),
                (true, true, &b"reply"[..], &[][..]),
            ] {
                let operation = request(&client, command, Duration::from_secs(3));
                let current = packet(socket.next().await.unwrap().unwrap());
                assert_eq!(current.4.secure_info.is_some(), attached);
                assert_eq!(
                    client.inner.lock().unwrap().pending[&current.1]
                        .replay
                        .as_ref()
                        .unwrap()
                        .signature
                        .is_some(),
                    invokes
                );
                socket
                    .send(response_reserved(current.1, command, 0, body, reserve))
                    .await
                    .unwrap();
                operation.await.unwrap().unwrap();
            }
            client
                .close_transport("Host switch test complete".into())
                .await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn sdk_consumed_dispatch_push_does_not_update_host_signer_switch() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for profile in [Profile::iphone(), Profile::ipad()] {
            let (client, mut socket) = connected(profile).await;
            let mut events = client.subscribe();
            let command = "MessageSvc.PbSendMsg";
            let dispatch = "trpc.qqaccess.dispatch.DispatchService.Push";
            for (push_command, body, flag, invokes, attached) in [
                (dispatch, Bytes::from_static(&[0x0f]), 0, false, false),
                (dispatch, Bytes::from_static(&[0x08, 1]), 2, false, false),
                (
                    "signature.generic.push",
                    Bytes::from_static(b"payload"),
                    2,
                    true,
                    true,
                ),
                (dispatch, Bytes::from_static(&[0x08, 1]), 0, true, false),
                (dispatch, Bytes::from_static(&[0x08, 3]), 1, true, true),
                (
                    dispatch,
                    Bytes::from_static(&[0x08, 3, 0x1a, 1, 0x0f]),
                    0,
                    false,
                    false,
                ),
                (
                    "Client.CorrectTime",
                    Bytes::from_static(b"payload"),
                    2,
                    true,
                    true,
                ),
                (
                    "SSO.HelloPush",
                    Bytes::from_static(b"payload"),
                    0,
                    true,
                    false,
                ),
            ] {
                socket
                    .send(response_reserved(
                        -37,
                        push_command,
                        -10007,
                        &body,
                        &[0xc8, 1, flag],
                    ))
                    .await
                    .unwrap();
                let event = events.recv().await.unwrap();
                assert_eq!(event.command, push_command);
                assert_eq!(event.return_code, -10007);
                let operation = request(&client, command, Duration::from_secs(3));
                let current = packet(socket.next().await.unwrap().unwrap());
                assert_eq!(current.4.secure_info.is_some(), attached);
                assert_eq!(
                    client.inner.lock().unwrap().pending[&current.1]
                        .replay
                        .as_ref()
                        .unwrap()
                        .signature
                        .is_some(),
                    invokes
                );
                socket.send(response(current.1, command, 0)).await.unwrap();
                operation.await.unwrap().unwrap();
            }
            let operation = request(&client, "Client.CorrectTime", Duration::from_secs(3));
            let current = packet(socket.next().await.unwrap().unwrap());
            socket
                .send(response_reserved(
                    current.1,
                    "Client.CorrectTime",
                    0,
                    b"reply",
                    &[0xc8, 1, 0],
                ))
                .await
                .unwrap();
            operation.await.unwrap().unwrap();
            let operation = request(&client, command, Duration::from_secs(3));
            let current = packet(socket.next().await.unwrap().unwrap());
            assert!(
                client.inner.lock().unwrap().pending[&current.1]
                    .replay
                    .as_ref()
                    .unwrap()
                    .signature
                    .is_some()
            );
            assert!(current.4.secure_info.is_none());
            socket.send(response(current.1, command, 0)).await.unwrap();
            operation.await.unwrap().unwrap();
            client
                .close_transport("dispatch switch test complete".into())
                .await;
        }
    })
    .await
    .unwrap();
}
