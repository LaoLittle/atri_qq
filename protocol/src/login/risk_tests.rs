use super::*;
use crate::{
    crypto::{Curve, Ecdh},
    wire::{SsoFrameCodec, Writer},
};
use futures_util::{SinkExt, StreamExt};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;

const STOP_CODE: u64 = 140022999;
const LOGIN_A1: &[u8] = b"synthetic-cached-login-a1";
const NT_KEY: [u8; 16] = [42; 16];
const ATTEMPT_COOKIE: &[u8] = b"synthetic-\xff\x00\xc0\x80-attempt-cookie";

#[derive(Clone, Copy)]
enum Scenario {
    ExpiredNormalQr,
    ExpiredPassword,
    UnusualDevice,
}

// All server replies below are explicitly synthetic, authenticated local TCP
// fixtures. They do not replay a live credential or establish server acceptance.
fn incoming(sequence: i32, command: &str, body: &[u8]) -> Bytes {
    incoming_with_key(sequence, command, body, None)
}

fn incoming_with_key(sequence: i32, command: &str, body: &[u8], key: Option<&[u8]>) -> Bytes {
    let mut header = Writer::new();
    header.i32(sequence);
    header.i32(0);
    header.p32([]).unwrap();
    header.p32(command).unwrap();
    header.p32([]).unwrap();
    header.i32(0);
    header.p32([]).unwrap();
    let mut payload = Writer::new();
    payload.p32(header.data).unwrap();
    payload.p32(body).unwrap();
    let mut envelope = Writer::new();
    envelope.u32(13);
    envelope.u8(u8::from(key.is_some()));
    envelope.u8(0);
    envelope.p32("0").unwrap();
    envelope.bytes(match key {
        Some(key) => crypto::tea_encrypt(&payload.data, key).unwrap(),
        None => payload.data,
    });
    let mut frame = Writer::new();
    frame.p32(envelope.data).unwrap();
    frame.data.into()
}

async fn request(socket: &mut Framed<TcpStream, SsoFrameCodec>) -> (i32, String, Bytes) {
    loop {
        let mut frame = Reader::new(socket.next().await.unwrap().unwrap());
        frame.u32().unwrap();
        let kind = frame.u32().unwrap();
        if kind == RequestType::Simple as u32 {
            assert_eq!(frame.u8().unwrap(), Encryption::None as u8);
            let sequence = frame.i32().unwrap();
            frame.u8().unwrap();
            frame.p32().unwrap();
            let mut header = Reader::new(frame.p32().unwrap());
            let command = String::from_utf8(header.p32().unwrap().to_vec()).unwrap();
            let body = match command.as_str() {
                "Heartbeat.Alive" => Bytes::new(),
                "Client.CorrectTime" => Bytes::copy_from_slice(&unix_seconds().to_be_bytes()),
                other => panic!("unexpected login control command {other}"),
            };
            socket
                .send(incoming(sequence, &command, &body))
                .await
                .unwrap();
            continue;
        }
        assert_eq!(kind, RequestType::D2 as u32);
        assert_eq!(frame.u8().unwrap(), Encryption::Empty as u8);
        frame.p32().unwrap();
        frame.u8().unwrap();
        frame.p32().unwrap();
        let mut payload = Reader::new(crypto::tea_decrypt(&frame.rest(), &[0; 16]).unwrap());
        let mut header = Reader::new(payload.p32().unwrap());
        let body = payload.p32().unwrap();
        let sequence = header.i32().unwrap();
        header.skip(20).unwrap();
        header.p32().unwrap();
        let command = String::from_utf8(header.p32().unwrap().to_vec()).unwrap();
        return (sequence, command, body);
    }
}

fn nt_request(body: Bytes) -> auth::NtRequest {
    let forward: auth::NtForward = proto::decode(body).unwrap();
    proto::decode(Bytes::from(
        crypto::aes_gcm_decrypt(&forward.encrypted.unwrap(), &NT_KEY).unwrap(),
    ))
    .unwrap()
}

fn nt_error(code: u64, signature: Option<Bytes>) -> Bytes {
    let body = auth::NtEasyLoginResponseBody {
        protection: signature.map(|signature| auth::NtUnusualDevice {
            signature: Some(signature),
        }),
        ..Default::default()
    };
    let common = auth::NtResponse {
        head: Some(auth::NtResponseHead {
            error: Some(auth::NtError {
                code: Some(code),
                title: Some("synthetic local rejection".into()),
                message: Some("synthetic server stopped the test".into()),
                jump_word: Some("synthetic continuation wording".into()),
                ..Default::default()
            }),
            cookie: Some(auth::NtCookie {
                cookie: Some(Bytes::from_static(ATTEMPT_COOKIE)),
            }),
            ..Default::default()
        }),
        body: Some(body.encode_to_vec().into()),
    };
    auth::NtForward {
        encrypted: Some(
            crypto::aes_gcm_encrypt(&common.encode_to_vec(), &NT_KEY)
                .unwrap()
                .into(),
        ),
        ..Default::default()
    }
    .encode_to_vec()
    .into()
}

fn wt_response(command: u16, clear: &[u8], random_key: &[u8]) -> Bytes {
    let mut packet = Writer::new();
    packet.u16(8001);
    packet.u16(command);
    packet.zeros(2 + 4 + 1);
    packet.u8(0);
    packet.u8(180); // Existing decoder's random-key response mode.
    packet.bytes(crypto::tea_encrypt(clear, random_key).unwrap());
    packet.u8(3);
    let mut framed = Writer::new();
    framed.u8(2);
    framed.u16((packet.data.len() + 3).try_into().unwrap());
    framed.bytes(packet.data);
    framed.data.into()
}

fn qr_response(command: u16, body: &[u8], random_key: &[u8]) -> Bytes {
    let mut inner = Writer::new();
    inner.u8(2);
    inner.u16(0);
    inner.u16(command);
    inner.zeros(21 + 1 + 2 + 2 + 4 + 8);
    inner.bytes(body);
    let mut clear = Writer::new();
    clear.u8(0);
    clear.u8(0);
    clear.u16(inner.data.len().try_into().unwrap());
    clear.u8(0);
    clear.bytes(inner.data);
    wt_response(0x812, &clear.data, random_key)
}

fn key_exchange_reply(body: Bytes, expire_seconds: i64) -> Bytes {
    let exchange: auth::KeyExchangeRequest = proto::decode(body).unwrap();
    let peer = Ecdh::new(Curve::P256).unwrap();
    let client_public = exchange.public_key.unwrap();
    let shared = peer.shared_secret(&client_public, false).unwrap();
    let session = auth::KeyExchangeSession {
        key: Some(Bytes::copy_from_slice(&NT_KEY)),
        ticket: Some(Bytes::from_static(b"synthetic-session-ticket")),
        expire_seconds: Some(expire_seconds),
    };
    let encrypted = crypto::aes_gcm_encrypt(&session.encode_to_vec(), &shared).unwrap();
    let digest = crypto::sha256(
        &[
            client_public.as_ref(),
            peer.public_key(),
            encrypted.as_slice(),
        ]
        .concat(),
    );
    let signing_key = SigningKey::from_slice(&[1; 32]).unwrap();
    let signature: Signature = signing_key.sign_prehash(&digest).unwrap();
    let reply = auth::KeyExchangeResponse {
        encrypted_secret: Some(encrypted.into()),
        signature: Some(Bytes::copy_from_slice(signature.to_der().as_bytes())),
        public_key: Some(Bytes::copy_from_slice(peer.public_key())),
    };
    reply.encode_to_vec().into()
}

async fn serve(scenario: Scenario, listener: TcpListener, store: Keystore, client: Arc<Client>) {
    let (stream, _) = listener.accept().await.unwrap();
    let mut socket = Framed::new(stream, SsoFrameCodec);
    let (sequence, command, body) = request(&mut socket).await;
    assert_eq!(command, "trpc.login.ecdh.EcdhService.SsoKeyExchange");
    let reply = key_exchange_reply(body, 3600);
    socket
        .send(incoming(sequence, &command, &reply))
        .await
        .unwrap();
    let (sequence, command, body) = request(&mut socket).await;
    assert_eq!(command, "trpc.login.ecdh.EcdhService.SsoNTLoginEasyLogin");
    let common = nt_request(body);
    assert!(common.head.unwrap().cookie.is_none());
    let body: auth::NtLoginBody = proto::decode(common.body.unwrap()).unwrap();
    assert_eq!(body.a1.unwrap().as_ref(), LOGIN_A1);
    let code = if matches!(scenario, Scenario::UnusualDevice) {
        140022011
    } else {
        140022015
    };
    let signature = matches!(scenario, Scenario::UnusualDevice)
        .then(|| Bytes::from_static(b"synthetic-unusual-device-signature"));
    socket
        .send(incoming(sequence, &command, &nt_error(code, signature)))
        .await
        .unwrap();

    let (sequence, command, body) = request(&mut socket).await;
    let saved = client.snapshot().await.keystore;
    if matches!(scenario, Scenario::UnusualDevice) {
        assert_eq!(saved.a1, LOGIN_A1);
    } else {
        assert!(
            saved.a1.is_empty(),
            "rejected cached A1 must not be retried after fallback failure"
        );
    }
    assert_eq!(saved.a2, store.a2);
    assert_eq!(saved.d2, store.d2);
    assert_eq!(saved.uid, store.uid);
    if matches!(scenario, Scenario::ExpiredPassword) {
        assert_eq!(
            command,
            "trpc.login.ecdh.EcdhService.SsoNTLoginPasswordLogin"
        );
        let common = nt_request(body);
        // A fresh password login deliberately starts without the EasyLogin cookie.
        assert!(common.head.unwrap().cookie.is_none());
        let body: auth::NtLoginBody = proto::decode(common.body.unwrap()).unwrap();
        assert!(!body.a1.as_ref().unwrap().is_empty());
        assert_ne!(body.a1.unwrap().as_ref(), LOGIN_A1);
        socket
            .send(incoming(sequence, &command, &nt_error(STOP_CODE, None)))
            .await
            .unwrap();
        return;
    }
    assert_eq!(command, "wtlogin.trans_emp");
    let mut acquired = Writer::new();
    acquired.zeros(6);
    acquired.u8(0);
    acquired.p16(b"synthetic-qr-signature").unwrap();
    let mut tlvs = Tlv::default();
    tlvs.add(0x17, b"synthetic-image");
    tlvs.add(
        0xd1,
        auth::QrResponseExtension {
            url: Some("https://example.invalid/local-test".into()),
        }
        .encode_to_vec(),
    );
    acquired.bytes(tlvs.encode(None).unwrap());
    socket
        .send(incoming(
            sequence,
            &command,
            &qr_response(0x31, &acquired.data, &store.random_key),
        ))
        .await
        .unwrap();

    let (sequence, command, _) = request(&mut socket).await;
    assert_eq!(command, "wtlogin.trans_emp");
    let mut confirmed = Writer::new();
    confirmed.zeros(6);
    confirmed.u8(0);
    confirmed.u64(store.uin);
    confirmed.u32(0);
    let mut tlvs = Tlv::default();
    if matches!(scenario, Scenario::UnusualDevice) {
        // No normal-WT tickets: only real verification mode can consume this.
        tlvs.add(0x3f, b"synthetic-fresh-one-click-proof");
    } else {
        tlvs.add(0x18, b"synthetic-normal-qr-a1");
        tlvs.add(0x19, b"synthetic-no-picture-signature");
        tlvs.add(0x1e, [11; 16]);
    }
    confirmed.bytes(tlvs.encode(None).unwrap());
    socket
        .send(incoming(
            sequence,
            &command,
            &qr_response(0x12, &confirmed.data, &store.random_key),
        ))
        .await
        .unwrap();

    let (sequence, command, body) = request(&mut socket).await;
    if matches!(scenario, Scenario::UnusualDevice) {
        assert_eq!(
            command,
            "trpc.login.ecdh.EcdhService.SsoNTLoginEasyLoginUnusualDevice"
        );
        let common = nt_request(body);
        assert_eq!(
            common.head.unwrap().cookie.unwrap().cookie.as_deref(),
            Some(ATTEMPT_COOKIE)
        );
        let body: auth::NtUnusualLoginBody = proto::decode(common.body.unwrap()).unwrap();
        assert_eq!(body.a1.unwrap().as_ref(), LOGIN_A1);
        assert_eq!(
            body.one_click_succeed_sig.unwrap().as_ref(),
            b"synthetic-fresh-one-click-proof"
        );
        socket
            .send(incoming(sequence, &command, &nt_error(STOP_CODE, None)))
            .await
            .unwrap();
    } else {
        assert_eq!(command, "wtlogin.login");
        let mut rejected = Writer::new();
        rejected.u16(0);
        rejected.u8(77);
        rejected.bytes(Tlv::default().encode(None).unwrap());
        socket
            .send(incoming(
                sequence,
                &command,
                &wt_response(0x810, &rejected.data, &store.random_key),
            ))
            .await
            .unwrap();
    }
}

async fn exercise(scenario: Scenario) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let store = Keystore {
        uin: 123456,
        uid: "synthetic-saved-identity".into(),
        a1: LOGIN_A1.to_vec(),
        a2: b"synthetic-cached-a2".to_vec(),
        d2: b"synthetic-cached-d2".to_vec(),
        ..Default::default()
    };
    let client = Client::new(
        ClientConfig {
            host: "127.0.0.1".into(),
            port,
            password: matches!(scenario, Scenario::ExpiredPassword)
                .then(|| "synthetic-password".into()),
            timeout: Duration::from_secs(3),
            ..Default::default()
        },
        store.clone(),
    )
    .unwrap();
    let signing_key = SigningKey::from_slice(&[1; 32]).unwrap();
    let mut codecs = LoginCodecs::new().unwrap();
    codecs.nt = NtLogin::with_verifier(
        crypto::P256Verifier::new(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        )
        .unwrap(),
    )
    .unwrap();
    *client.codecs.lock().await = Some(codecs);
    let server = tokio::spawn(serve(scenario, listener, store, client.clone()));
    let result = tokio::time::timeout(Duration::from_secs(10), client.login())
        .await
        .unwrap();
    let expected = if matches!(scenario, Scenario::ExpiredNormalQr) {
        77
    } else {
        STOP_CODE as i32
    };
    assert!(matches!(result, Err(Error::Server { code, .. }) if code == expected));
    assert!(!client.snapshot().await.online);
    server.await.unwrap();
}

#[tokio::test]
async fn client_tcp_expired_easy_login_starts_normal_qr_not_device_verification() {
    exercise(Scenario::ExpiredNormalQr).await;
}

#[tokio::test]
async fn client_tcp_expired_easy_login_uses_configured_password() {
    exercise(Scenario::ExpiredPassword).await;
}

#[tokio::test]
async fn client_tcp_unusual_device_preserves_a1_cookie_and_uses_fresh_phone_proof() {
    exercise(Scenario::UnusualDevice).await;
}

const MOBILE_PASSWORD: &str = "synthetic-mobile-password";
const MOBILE_SIGNATURE: &[u8] = b"\0\xffnative-device-signature";
const MOBILE_LONG_COOKIE: &[u8] = b"\xfe\0native-long-cookie";

fn mobile_client(profile: Profile, port: u16, cached_a1: bool, password: bool) -> Arc<Client> {
    let mut config = crate::client::ios_signing_tests::config(profile);
    config.host = "127.0.0.1".into();
    config.port = port;
    config.uin = 123456;
    config.password = password.then(|| MOBILE_PASSWORD.into());
    config.timeout = Duration::from_secs(3);
    let registration = auth::InfoSyncRequest {
        sync_flag: Some(1759),
        register: Some(auth::RegisterInfo {
            guid: Some("synthetic-native-registration-guid".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    config.ios_snapshot_mut().unwrap().registration = IosRegistration {
        initial: registration.clone(),
        reconnect: registration,
    };
    let client = Client::new(
        config,
        Keystore {
            uin: 123456,
            a1: if cached_a1 { LOGIN_A1.to_vec() } else { vec![] },
            ..Default::default()
        },
    )
    .unwrap();
    let signing_key = SigningKey::from_slice(&[1; 32]).unwrap();
    let mut codecs = LoginCodecs::for_config(&client.config).unwrap();
    codecs.nt.set_verifier(
        crypto::P256Verifier::new(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        )
        .unwrap(),
    );
    *client.codecs.try_lock().unwrap() = Some(codecs);
    client
}

async fn mobile_request(
    socket: &mut Framed<TcpStream, SsoFrameCodec>,
) -> Option<(i32, String, Bytes)> {
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(3), socket.next())
            .await
            .unwrap()?
            .unwrap();
        let mut outer = Reader::new(frame.clone());
        outer.u32().unwrap();
        let protocol = outer.u32().unwrap();
        let encryption = outer.u8().unwrap();
        let simple_sequence = (protocol == 13).then(|| outer.i32().unwrap());
        let (_, _, _, mut header, body) =
            crate::client::ios_signing_tests::request_parts(frame, &[0; 16]);
        let sequence = if let Some(sequence) = simple_sequence {
            sequence
        } else {
            let sequence = header.i32().unwrap();
            header.skip(20).unwrap();
            header.p32().unwrap();
            sequence
        };
        let command = String::from_utf8(header.p32().unwrap().to_vec()).unwrap();
        if matches!(command.as_str(), "Heartbeat.Alive" | "Client.CorrectTime") {
            let response = match command.as_str() {
                "Heartbeat.Alive" => Bytes::new(),
                "Client.CorrectTime" => Bytes::copy_from_slice(&unix_seconds().to_be_bytes()),
                other => panic!("unexpected native login control command {other}"),
            };
            socket
                .send(incoming_with_key(
                    sequence,
                    &command,
                    &response,
                    Some(&[0; 16]),
                ))
                .await
                .unwrap();
        } else {
            assert_eq!(protocol, RequestType::D2 as u32);
            assert_eq!(encryption, Encryption::Empty as u8);
            return Some((sequence, command, body));
        }
    }
}

async fn mobile_exchange(socket: &mut Framed<TcpStream, SsoFrameCodec>, expire_seconds: i64) {
    let (sequence, command, body) = mobile_request(socket).await.unwrap();
    assert_eq!(command, "trpc.login.ecdh.EcdhService.SsoKeyExchange");
    let reply = key_exchange_reply(body, expire_seconds);
    socket
        .send(incoming_with_key(
            sequence,
            &command,
            &reply,
            Some(&[0; 16]),
        ))
        .await
        .unwrap();
}

fn mobile_error(code: u64, url: &str, cookie: &'static [u8]) -> Bytes {
    let body = auth::NtPasswordResponseBody {
        captcha: (code == 140022008).then(|| auth::NtCaptchaChallenge {
            url: Some(url.into()),
        }),
        protection: (code == 140022011).then(|| auth::NtUnusualDevice {
            signature: Some(Bytes::from_static(b"must-not-escape-unusual-signature")),
        }),
        ..Default::default()
    };
    let response = auth::NtResponse {
        head: Some(auth::NtResponseHead {
            error: Some(auth::NtError {
                code: Some(code),
                jump_url: Some(url.into()),
                ..Default::default()
            }),
            cookie: Some(auth::NtCookie {
                cookie: Some(Bytes::from_static(cookie)),
            }),
            long_cookie: Some(auth::NtCookie {
                cookie: Some(Bytes::from_static(MOBILE_LONG_COOKIE)),
            }),
        }),
        body: Some(body.encode_to_vec().into()),
    };
    auth::NtForward {
        encrypted: Some(
            crypto::aes_gcm_encrypt(&response.encode_to_vec(), &NT_KEY)
                .unwrap()
                .into(),
        ),
        ..Default::default()
    }
    .encode_to_vec()
    .into()
}

async fn challenge(events: &mut tokio::sync::broadcast::Receiver<LoginEvent>) -> LoginChallenge {
    loop {
        match tokio::time::timeout(Duration::from_secs(3), events.recv())
            .await
            .unwrap()
            .unwrap()
        {
            LoginEvent::Challenge(challenge) => return challenge,
            LoginEvent::Offline { .. } => {
                panic!("native login closed before exposing its challenge")
            }
            _ => {}
        }
    }
}

fn assert_mobile_password_a1(a1: &Bytes, profile: &Profile) {
    let digest = crypto::md5(MOBILE_PASSWORD.as_bytes());
    let mut material = digest.to_vec();
    material.extend_from_slice(&123456_u64.to_be_bytes());
    let mut clear = Reader::new(crypto::tea_decrypt(a1, &crypto::md5(&material)).unwrap());
    assert_eq!(clear.u16().unwrap(), 4);
    clear.skip(8).unwrap();
    assert_eq!(clear.u32().unwrap(), profile.app_id);
    assert_eq!(clear.u32().unwrap(), 8001);
    assert_eq!(clear.u64().unwrap(), 123456);
    clear.skip(8).unwrap();
    assert_eq!(clear.u8().unwrap(), 1);
    assert_eq!(clear.bytes(16).unwrap().as_ref(), digest.as_slice());
}

fn mobile_verification(
    signature: &'static [u8],
    authentication_type: u32,
) -> IosDeviceVerificationResult {
    IosDeviceVerificationResult {
        signature: Bytes::from_static(signature),
        authentication_type,
    }
}

#[tokio::test]
async fn mobile_password_tcp_device_and_captcha_continuations_consume_real_signatures_once() {
    for (profile, expire_seconds, signature, authentication_type) in [
        (Profile::iphone(), 3600, MOBILE_SIGNATURE, 0),
        (Profile::ipad(), 3600, MOBILE_SIGNATURE, 0),
        (Profile::iphone(), 300, MOBILE_SIGNATURE, 0),
        (Profile::ipad(), 300, MOBILE_SIGNATURE, 7),
        (Profile::iphone(), 3600, b"".as_slice(), 7),
        (Profile::ipad(), 3600, b"".as_slice(), 7),
        (Profile::iphone(), 300, b"".as_slice(), 7),
        (Profile::ipad(), 300, b"".as_slice(), 7),
    ] {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let http = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let url = format!(
            "http://127.0.0.1:{}/native-device?sid=sid-%E9%AA%8C%E8%AF%81",
            http.local_addr().unwrap().port()
        );
        let client = mobile_client(
            profile.clone(),
            listener.local_addr().unwrap().port(),
            false,
            true,
        );
        assert!(matches!(
            client
                .submit_device_verification(mobile_verification(signature, authentication_type))
                .await,
            Err(Error::Authentication(_))
        ));
        let mut events = client.login_events();
        let server_url = url.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = Framed::new(stream, SsoFrameCodec);
            let cookies: [&'static [u8]; 4] = [b"first-\xff", b"second-\0", b"third-\xfe", b"stop"];
            for round in 0..4 {
                if round == 0 || expire_seconds < 301 {
                    mobile_exchange(&mut socket, expire_seconds).await;
                }
                let (sequence, command, encrypted) = mobile_request(&mut socket).await.unwrap();
                assert_eq!(
                    command,
                    "trpc.login.ecdh.EcdhService.SsoNTLoginPasswordLogin"
                );
                let common = nt_request(encrypted);
                let head = common.head.unwrap();
                assert!(head.security.is_none());
                assert!(head.long_cookie.is_none());
                if round == 0 {
                    assert!(head.cookie.is_none());
                } else {
                    assert_eq!(
                        head.cookie.unwrap().cookie.unwrap().as_ref(),
                        cookies[round - 1]
                    );
                }
                let body: auth::NtLoginBody = proto::decode(common.body.unwrap()).unwrap();
                assert_eq!(
                    body.login_process
                        .as_ref()
                        .unwrap()
                        .need_remind_cancellated_status,
                    Some(true)
                );
                if matches!(round, 1 | 3) {
                    assert!(body.a1.is_none());
                } else {
                    assert_mobile_password_a1(body.a1.as_ref().unwrap(), &profile);
                }
                match round {
                    0 => {
                        assert!(body.captcha.is_none());
                        assert!(body.device_check_succeed_sig.is_none());
                    }
                    1 | 3 => {
                        assert!(body.captcha.is_none());
                        if signature.is_empty() {
                            assert!(body.device_check_succeed_sig.is_none());
                        } else {
                            assert_eq!(body.device_check_succeed_sig.unwrap().as_ref(), signature);
                        }
                    }
                    2 => {
                        assert!(body.device_check_succeed_sig.is_none());
                        let iframe = body.captcha.unwrap();
                        assert_eq!(iframe.ticket.unwrap().as_ref(), "ticket-签名".as_bytes());
                        assert_eq!(iframe.random.unwrap().as_ref(), "random-随机".as_bytes());
                        assert_eq!(iframe.sid.unwrap().as_ref(), "sid-验证".as_bytes());
                    }
                    _ => unreachable!(),
                }
                let code = [140022010, 140022008, 140022010, STOP_CODE][round];
                socket
                    .send(incoming_with_key(
                        sequence,
                        &command,
                        &mobile_error(code, &server_url, cookies[round]),
                        Some(&[0; 16]),
                    ))
                    .await
                    .unwrap();
            }
            assert!(mobile_request(&mut socket).await.is_none());
        });
        let login = {
            let client = client.clone();
            tokio::spawn(async move { client.login().await })
        };
        for round in 0..3 {
            let next = challenge(&mut events).await;
            if round == 1 {
                assert!(
                    matches!(next, LoginChallenge::Captcha { url: challenge_url } if challenge_url == url)
                );
                assert!(matches!(
                    client
                        .submit_device_verification(mobile_verification(
                            signature,
                            authentication_type
                        ))
                        .await,
                    Err(Error::Authentication(_))
                ));
                client
                    .submit_captcha("ticket-签名".into(), "random-随机".into())
                    .await
                    .unwrap();
                assert!(matches!(
                    client
                        .submit_captcha("duplicate".into(), "duplicate".into())
                        .await,
                    Err(Error::Authentication(_))
                ));
            } else {
                assert!(
                    matches!(next, LoginChallenge::IosDeviceVerification { url: challenge_url } if challenge_url == url)
                );
                assert!(matches!(
                    client
                        .submit_device_verification(mobile_verification(b"", 0))
                        .await,
                    Err(Error::Authentication(_))
                ));
                assert!(matches!(
                    client
                        .submit_captcha("wrong".into(), "challenge".into())
                        .await,
                    Err(Error::Authentication(_))
                ));
                client
                    .submit_device_verification(mobile_verification(signature, authentication_type))
                    .await
                    .unwrap();
                assert!(matches!(
                    client
                        .submit_device_verification(mobile_verification(
                            signature,
                            authentication_type
                        ))
                        .await,
                    Err(Error::Authentication(_))
                ));
            }
        }
        let result = tokio::time::timeout(Duration::from_secs(3), login)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, Err(Error::Server { code, .. }) if code == STOP_CODE as i32));
        server.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(25), http.accept())
                .await
                .is_err()
        );
        assert!(client.device_verification.lock().unwrap().is_none());
        assert!(client.captcha.lock().unwrap().is_none());
    }
}

#[tokio::test]
async fn mobile_password_tcp_device_verification_close_abort_and_disconnect_release_waiter() {
    for profile in [Profile::iphone(), Profile::ipad()] {
        for action in 0..3 {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let client = mobile_client(
                profile.clone(),
                listener.local_addr().unwrap().port(),
                false,
                true,
            );
            let mut events = client.login_events();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = Framed::new(stream, SsoFrameCodec);
                mobile_exchange(&mut socket, 3600).await;
                let (sequence, command, _) = mobile_request(&mut socket).await.unwrap();
                assert_eq!(
                    command,
                    "trpc.login.ecdh.EcdhService.SsoNTLoginPasswordLogin"
                );
                socket
                    .send(incoming_with_key(
                        sequence,
                        &command,
                        &mobile_error(
                            140022010,
                            "https://qq.com/synthetic-native-verification",
                            ATTEMPT_COOKIE,
                        ),
                        Some(&[0; 16]),
                    ))
                    .await
                    .unwrap();
                socket
            });
            let login = {
                let client = client.clone();
                tokio::spawn(async move { client.login().await })
            };
            assert!(matches!(
                challenge(&mut events).await,
                LoginChallenge::IosDeviceVerification { .. }
            ));
            let mut socket = Some(server.await.unwrap());
            match action {
                0 => client.close().await,
                1 => login.abort(),
                2 => drop(socket.take()),
                _ => unreachable!(),
            }
            let result = tokio::time::timeout(Duration::from_secs(3), login)
                .await
                .unwrap();
            if action == 1 {
                assert!(result.unwrap_err().is_cancelled());
            } else {
                assert!(matches!(result.unwrap(), Err(Error::Disconnected)));
            }
            assert!(client.device_verification.lock().unwrap().is_none());
            assert!(client.captcha.lock().unwrap().is_none());
            assert!(matches!(
                client
                    .submit_device_verification(mobile_verification(MOBILE_SIGNATURE, 0))
                    .await,
                Err(Error::Authentication(_))
            ));
            client.close().await;
            if let Some(mut socket) = socket {
                assert!(mobile_request(&mut socket).await.is_none());
            }
        }
    }
}

#[tokio::test]
async fn mobile_easy_tcp_unsupported_native_risk_paths_never_send_desktop_qr() {
    for profile in [Profile::iphone(), Profile::ipad()] {
        for scenario in 0..2 {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let client = mobile_client(
                profile.clone(),
                listener.local_addr().unwrap().port(),
                true,
                scenario != 0,
            );
            let code = if scenario == 0 { 140022015 } else { 140022011 };
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = Framed::new(stream, SsoFrameCodec);
                mobile_exchange(&mut socket, 3600).await;
                let (sequence, command, body) = mobile_request(&mut socket).await.unwrap();
                assert_eq!(command, "trpc.login.ecdh.EcdhService.SsoNTLoginEasyLogin");
                let common = nt_request(body);
                let body: auth::NtLoginBody = proto::decode(common.body.unwrap()).unwrap();
                assert_eq!(body.a1.unwrap().as_ref(), LOGIN_A1);
                socket
                    .send(incoming_with_key(
                        sequence,
                        &command,
                        &mobile_error(
                            code,
                            "https://qq.com/must-not-escape-secret-url",
                            ATTEMPT_COOKIE,
                        ),
                        Some(&[0; 16]),
                    ))
                    .await
                    .unwrap();
                assert!(mobile_request(&mut socket).await.is_none());
            });
            let result = tokio::time::timeout(Duration::from_secs(3), client.login())
                .await
                .unwrap();
            let Err(Error::Unsupported(reason)) = result else {
                panic!("unclosed native risk route must be explicitly unsupported");
            };
            assert!(reason.contains(&format!("code={code}")));
            assert!(reason.contains("stage=easy"));
            assert!(!reason.contains("must-not-escape"));
            assert_eq!(
                client.snapshot().await.keystore.a1.is_empty(),
                scenario != 1
            );
            server.await.unwrap();
        }
    }
}

fn security_error(executable: bool) -> Bytes {
    let mut forward: auth::NtForward = proto::decode(mobile_error(
        140022011,
        "https://qq.com/security?token=synthetic-secret",
        ATTEMPT_COOKIE,
    ))
    .unwrap();
    let mut response: auth::NtResponse = proto::decode(Bytes::from(
        crypto::aes_gcm_decrypt(forward.encrypted.as_ref().unwrap(), &NT_KEY).unwrap(),
    ))
    .unwrap();
    response.head.as_mut().unwrap().error = Some(auth::NtError {
        code: Some(140022011),
        title: Some("安全提醒🔐".into()),
        message: Some("请完成安全验证，或继续登录。".into()),
        jump_word: Some("验证身份".into()),
        jump_url: executable.then(|| "https://qq.com/security?token=synthetic-secret".into()),
        detail: Some(auth::NtErrorDetail {
            need_new_device: Some(auth::NtErrorNewDevice { value: Some(false) }),
            unregistered: Some(auth::NtErrorText { value: None }),
            forbidden: Some(auth::NtErrorForbidden { area: Some(0) }),
            nice_account_expired: Some(auth::NtErrorText {
                value: Some("靓号到期".into()),
            }),
            sms_check: None,
        }),
        buttons: if executable {
            vec![
                auth::NtErrorButton {
                    wording: None,
                    url: None,
                },
                auth::NtErrorButton {
                    wording: Some(String::new()),
                    url: Some("native://continue_login".into()),
                },
                auth::NtErrorButton {
                    wording: Some("网页验证".into()),
                    url: Some("https://qq.com/button?token=synthetic-button".into()),
                },
                auth::NtErrorButton {
                    wording: Some("短信".into()),
                    url: Some("native://sms_login".into()),
                },
                auth::NtErrorButton {
                    wording: Some("手机".into()),
                    url: Some("native://phone_login".into()),
                },
                auth::NtErrorButton {
                    wording: None,
                    url: Some("native://continue_login?fake=1".into()),
                },
                auth::NtErrorButton {
                    wording: None,
                    url: Some("mqqapi://miniapp/open?forbid_token=synthetic".into()),
                },
                auth::NtErrorButton {
                    wording: None,
                    url: Some("itms-apps://itunes.apple.com".into()),
                },
            ]
        } else {
            vec![auth::NtErrorButton {
                wording: Some("短信".into()),
                url: Some("native://sms_login".into()),
            }]
        },
        unknown8: Some(false),
    });
    forward.encrypted = Some(
        crypto::aes_gcm_encrypt(&response.encode_to_vec(), &NT_KEY)
            .unwrap()
            .into(),
    );
    forward.encode_to_vec().into()
}

fn assert_security_notice(challenge: LoginChallenge) {
    let LoginChallenge::IosSecurity(challenge) = challenge else {
        panic!("missing iOS security challenge")
    };
    assert_eq!(challenge.code, Some(140022011));
    assert_eq!(challenge.title.as_deref(), Some("安全提醒🔐"));
    assert_eq!(
        challenge.message.as_deref(),
        Some("请完成安全验证，或继续登录。")
    );
    assert_eq!(challenge.jump_word.as_deref(), Some("验证身份"));
    assert_eq!(challenge.unknown8, Some(false));
    let detail = challenge.detail.unwrap();
    assert_eq!(detail.need_new_device.unwrap().value, Some(false));
    assert_eq!(detail.unregistered.unwrap().value, None);
    assert_eq!(detail.forbidden.unwrap().area, Some(0));
    assert_eq!(
        detail.nice_account_expired.unwrap().value.as_deref(),
        Some("靓号到期")
    );
    assert!(detail.sms_check.is_none());
    if challenge.buttons.len() > 1 {
        assert_eq!(challenge.buttons.len(), 8);
        assert_eq!(challenge.buttons[0].wording, None);
        assert_eq!(challenge.buttons[0].url, None);
        assert_eq!(challenge.buttons[1].wording.as_deref(), Some(""));
        assert_eq!(
            challenge.buttons[1].url.as_deref(),
            Some("native://continue_login")
        );
        assert_eq!(challenge.buttons[2].wording.as_deref(), Some("网页验证"));
        assert_eq!(
            challenge.jump_url.as_deref(),
            Some("https://qq.com/security?token=synthetic-secret")
        );
        assert_eq!(
            challenge.buttons[2].url.as_deref(),
            Some("https://qq.com/button?token=synthetic-button")
        );
    }
}

async fn reject_security_actions(client: &Client) {
    for action in [
        IosLoginSecurityAction::Continue { button_index: 99 },
        IosLoginSecurityAction::Continue { button_index: 0 },
        IosLoginSecurityAction::Continue { button_index: 2 },
        IosLoginSecurityAction::WebVerified {
            button_index: Some(99),
            authentication_type: 7,
        },
        IosLoginSecurityAction::WebVerified {
            button_index: None,
            authentication_type: 0,
        },
        IosLoginSecurityAction::WebVerified {
            button_index: Some(1),
            authentication_type: 7,
        },
        IosLoginSecurityAction::WebVerified {
            button_index: Some(5),
            authentication_type: 7,
        },
        IosLoginSecurityAction::WebVerified {
            button_index: Some(6),
            authentication_type: 7,
        },
        IosLoginSecurityAction::WebVerified {
            button_index: Some(7),
            authentication_type: 7,
        },
    ] {
        assert!(matches!(
            client.submit_security_action(action).await,
            Err(Error::Authentication(_))
        ));
        assert!(client.security.lock().unwrap().is_some());
    }
    for index in [3, 4] {
        assert!(matches!(
            client
                .submit_security_action(IosLoginSecurityAction::Continue {
                    button_index: index
                })
                .await,
            Err(Error::Unsupported(_))
        ));
        assert!(matches!(
            client
                .submit_security_action(IosLoginSecurityAction::WebVerified {
                    button_index: Some(index),
                    authentication_type: 7
                })
                .await,
            Err(Error::Unsupported(_))
        ));
        assert!(client.security.lock().unwrap().is_some());
    }
}

#[tokio::test]
async fn mobile_password_tcp_security_actions_retry_ordinary_password_with_fresh_a1_and_process_state()
 {
    for profile in [Profile::iphone(), Profile::ipad()] {
        for mode in 0..3 {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let client = mobile_client(
                profile.clone(),
                listener.local_addr().unwrap().port(),
                false,
                true,
            );
            assert!(matches!(
                client
                    .submit_security_action(IosLoginSecurityAction::Cancel)
                    .await,
                Err(Error::Authentication(_))
            ));
            let mut events = client.login_events();
            let server_profile = profile.clone();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = Framed::new(stream, SsoFrameCodec);
                mobile_exchange(&mut socket, 3600).await;
                let rounds = if mode == 0 {
                    4
                } else if mode == 1 {
                    2
                } else {
                    3
                };
                let mut last_a1 = None;
                for round in 0..rounds {
                    let (sequence, command, encrypted) = mobile_request(&mut socket).await.unwrap();
                    assert_eq!(
                        command,
                        "trpc.login.ecdh.EcdhService.SsoNTLoginPasswordLogin"
                    );
                    let common = nt_request(encrypted);
                    let head = common.head.unwrap();
                    if round == 0 {
                        assert!(head.cookie.is_none());
                    } else {
                        assert_eq!(
                            head.cookie.unwrap().cookie.unwrap().as_ref(),
                            ATTEMPT_COOKIE
                        );
                    }
                    let body: auth::NtLoginBody = proto::decode(common.body.unwrap()).unwrap();
                    let flag = mode == 1 || round < 2;
                    assert_eq!(
                        body.login_process.unwrap().need_remind_cancellated_status,
                        Some(flag)
                    );
                    if mode == 2 && round == 1 {
                        assert!(body.a1.is_none());
                        assert_eq!(
                            body.device_check_succeed_sig.unwrap().as_ref(),
                            MOBILE_SIGNATURE
                        );
                    } else {
                        let a1 = body.a1.as_ref().unwrap();
                        assert_mobile_password_a1(a1, &server_profile);
                        assert_ne!(last_a1.as_ref(), Some(a1));
                        last_a1 = Some(a1.clone());
                        assert!(body.device_check_succeed_sig.is_none());
                    }
                    if mode == 0 && round == 1 {
                        let iframe = body.captcha.unwrap();
                        assert_eq!(iframe.ticket.unwrap().as_ref(), b"security-captcha-ticket");
                    } else {
                        assert!(body.captcha.is_none());
                    }
                    let reply = if round + 1 == rounds {
                        mobile_error(STOP_CODE, "", ATTEMPT_COOKIE)
                    } else if round == 0 && mode != 1 {
                        mobile_error(
                            if mode == 0 { 140022008 } else { 140022010 },
                            "https://qq.com/verify?sid=security-sid",
                            ATTEMPT_COOKIE,
                        )
                    } else {
                        security_error(true)
                    };
                    socket
                        .send(incoming_with_key(
                            sequence,
                            &command,
                            &reply,
                            Some(&[0; 16]),
                        ))
                        .await
                        .unwrap();
                }
                assert!(mobile_request(&mut socket).await.is_none());
            });
            let login = {
                let client = client.clone();
                tokio::spawn(async move { client.login().await })
            };
            if mode != 1 {
                match challenge(&mut events).await {
                    LoginChallenge::Captcha { .. } if mode == 0 => client
                        .submit_captcha("security-captcha-ticket".into(), "security-random".into())
                        .await
                        .unwrap(),
                    LoginChallenge::IosDeviceVerification { .. } if mode == 2 => client
                        .submit_device_verification(mobile_verification(MOBILE_SIGNATURE, 0))
                        .await
                        .unwrap(),
                    _ => panic!("wrong initial verification challenge"),
                }
            }
            assert_security_notice(challenge(&mut events).await);
            assert!(client.captcha.lock().unwrap().is_none());
            assert!(client.device_verification.lock().unwrap().is_none());
            reject_security_actions(&client).await;
            client
                .submit_security_action(if mode == 1 {
                    IosLoginSecurityAction::WebVerified {
                        button_index: None,
                        authentication_type: 7,
                    }
                } else {
                    IosLoginSecurityAction::Continue { button_index: 1 }
                })
                .await
                .unwrap();
            assert!(matches!(
                client
                    .submit_security_action(IosLoginSecurityAction::Cancel)
                    .await,
                Err(Error::Authentication(_))
            ));
            if mode == 0 {
                assert_security_notice(challenge(&mut events).await);
                client
                    .submit_security_action(IosLoginSecurityAction::WebVerified {
                        button_index: Some(2),
                        authentication_type: 9,
                    })
                    .await
                    .unwrap();
            }
            assert!(
                matches!(login.await.unwrap(), Err(Error::Server { code, .. }) if code == STOP_CODE as i32)
            );
            assert!(client.security.lock().unwrap().is_none());
            server.await.unwrap();
        }
    }
}

#[tokio::test]
async fn mobile_security_tcp_cancel_unavailable_and_easy_notices_never_retry() {
    for profile in [Profile::iphone(), Profile::ipad()] {
        for mode in 0..3 {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let client = mobile_client(
                profile.clone(),
                listener.local_addr().unwrap().port(),
                mode == 2,
                true,
            );
            let mut events = client.login_events();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = Framed::new(stream, SsoFrameCodec);
                mobile_exchange(&mut socket, 3600).await;
                let (sequence, command, _) = mobile_request(&mut socket).await.unwrap();
                assert_eq!(
                    command,
                    if mode == 2 {
                        "trpc.login.ecdh.EcdhService.SsoNTLoginEasyLogin"
                    } else {
                        "trpc.login.ecdh.EcdhService.SsoNTLoginPasswordLogin"
                    }
                );
                socket
                    .send(incoming_with_key(
                        sequence,
                        &command,
                        &security_error(mode != 1),
                        Some(&[0; 16]),
                    ))
                    .await
                    .unwrap();
                assert!(mobile_request(&mut socket).await.is_none());
            });
            let login = {
                let client = client.clone();
                tokio::spawn(async move { client.login().await })
            };
            assert_security_notice(challenge(&mut events).await);
            if mode == 0 {
                reject_security_actions(&client).await;
                client
                    .submit_security_action(IosLoginSecurityAction::Cancel)
                    .await
                    .unwrap();
            }
            let result = login.await.unwrap();
            if mode == 2 {
                assert!(matches!(result, Err(Error::Unsupported(_))));
            } else {
                assert!(matches!(
                    result,
                    Err(Error::Server {
                        code: 140022011,
                        ..
                    })
                ));
            }
            assert!(matches!(
                client
                    .submit_security_action(IosLoginSecurityAction::Continue { button_index: 1 })
                    .await,
                Err(Error::Authentication(_))
            ));
            assert!(client.security.lock().unwrap().is_none());
            server.await.unwrap();
        }
    }
}

#[tokio::test]
async fn mobile_security_tcp_close_abort_and_disconnect_release_waiter() {
    for profile in [Profile::iphone(), Profile::ipad()] {
        for action in 0..3 {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let client = mobile_client(
                profile.clone(),
                listener.local_addr().unwrap().port(),
                false,
                true,
            );
            let mut events = client.login_events();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = Framed::new(stream, SsoFrameCodec);
                mobile_exchange(&mut socket, 3600).await;
                let (sequence, command, _) = mobile_request(&mut socket).await.unwrap();
                socket
                    .send(incoming_with_key(
                        sequence,
                        &command,
                        &security_error(true),
                        Some(&[0; 16]),
                    ))
                    .await
                    .unwrap();
                socket
            });
            let login = {
                let client = client.clone();
                tokio::spawn(async move { client.login().await })
            };
            assert_security_notice(challenge(&mut events).await);
            let mut socket = Some(server.await.unwrap());
            match action {
                0 => client.close().await,
                1 => login.abort(),
                2 => drop(socket.take()),
                _ => unreachable!(),
            }
            let result = login.await;
            if action == 1 {
                assert!(result.unwrap_err().is_cancelled());
            } else {
                assert!(matches!(result.unwrap(), Err(Error::Disconnected)));
            }
            assert!(client.security.lock().unwrap().is_none());
            assert!(matches!(
                client
                    .submit_security_action(IosLoginSecurityAction::Cancel)
                    .await,
                Err(Error::Authentication(_))
            ));
            client.close().await;
            if let Some(mut socket) = socket {
                assert!(mobile_request(&mut socket).await.is_none());
            }
        }
    }
}

#[tokio::test]
async fn mobile_authentication_does_not_wait_for_clock_response() {
    for profile in [Profile::iphone(), Profile::ipad()] {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let client = mobile_client(profile, listener.local_addr().unwrap().port(), false, true);
        let login = {
            let client = client.clone();
            tokio::spawn(async move { client.login().await })
        };
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = Framed::new(socket, SsoFrameCodec);
        let mut clock = false;
        let mut authentication = false;
        for _ in 0..2 {
            let frame = tokio::time::timeout(Duration::from_secs(1), socket.next())
                .await
                .expect("NT authentication was blocked by unanswered CorrectTime")
                .unwrap()
                .unwrap();
            let (protocol, _, _, mut header, body) =
                crate::client::ios_signing_tests::request_parts(frame, &[0; 16]);
            assert_eq!(protocol, RequestType::D2 as u32);
            header.skip(24).unwrap();
            header.p32().unwrap();
            match header.p32().unwrap().as_ref() {
                b"Client.CorrectTime" => {
                    assert_eq!(body.as_ref(), &[0, 0, 0, 4]);
                    clock = true;
                }
                b"trpc.login.ecdh.EcdhService.SsoKeyExchange" => authentication = true,
                command => panic!("unexpected login request {command:?}"),
            }
        }
        assert!(clock && authentication);
        login.abort();
        let _ = login.await;
        client.close().await;
    }
}
