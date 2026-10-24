use super::*;
use crate::{
    crypto::{Curve, Ecdh},
    wire::{SsoFrameCodec, Writer},
};
use futures_util::{SinkExt, StreamExt};
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
    envelope.u8(0);
    envelope.u8(0);
    envelope.p32("0").unwrap();
    envelope.bytes(payload.data);
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
            assert_eq!(command, "Heartbeat.Alive");
            socket
                .send(incoming(sequence, &command, &[]))
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

async fn serve(scenario: Scenario, listener: TcpListener, store: Keystore, client: Arc<Client>) {
    let (stream, _) = listener.accept().await.unwrap();
    let mut socket = Framed::new(stream, SsoFrameCodec);
    let (sequence, command, body) = request(&mut socket).await;
    assert_eq!(command, "trpc.login.ecdh.EcdhService.SsoKeyExchange");
    let exchange: auth::KeyExchangeRequest = proto::decode(body).unwrap();
    let peer = Ecdh::new(Curve::P256).unwrap();
    let shared = peer
        .shared_secret(&exchange.public_key.unwrap(), false)
        .unwrap();
    let session = auth::KeyExchangeSession {
        key: Some(Bytes::copy_from_slice(&NT_KEY)),
        ticket: Some(Bytes::from_static(b"synthetic-session-ticket")),
    };
    let reply = auth::KeyExchangeResponse {
        encrypted_secret: Some(
            crypto::aes_gcm_encrypt(&session.encode_to_vec(), &shared)
                .unwrap()
                .into(),
        ),
        public_key: Some(Bytes::copy_from_slice(peer.public_key())),
    };
    socket
        .send(incoming(sequence, &command, &reply.encode_to_vec()))
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
