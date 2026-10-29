use crate::{
    Error, Result,
    crypto::{self, Curve, Ecdh},
    models::*,
    proto::{self, auth},
    wire::malformed,
};
use bytes::Bytes;
use prost::Message;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::LazyLock};

const SERVER_PUBLIC: [u8; 65] = [
    0x04, 0x9d, 0x14, 0x23, 0x33, 0x27, 0x35, 0x98, 0x0e, 0xda, 0xbe, 0x7e, 0x9e, 0xa4, 0x51, 0xb3,
    0x39, 0x5b, 0x6f, 0x35, 0x25, 0x0d, 0xb8, 0xfc, 0x56, 0xf2, 0x58, 0x89, 0xf6, 0x28, 0xcb, 0xae,
    0x3e, 0x8e, 0x73, 0x07, 0x79, 0x14, 0x07, 0x1e, 0xee, 0xbc, 0x10, 0x8f, 0x4e, 0x01, 0x70, 0x05,
    0x77, 0x92, 0xbb, 0x17, 0xaa, 0x30, 0x3a, 0xf6, 0x52, 0x31, 0x3d, 0x17, 0xc1, 0xac, 0x81, 0x5e,
    0x79,
];
const VERIFIER_KEY: [u8; 32] = [
    0xe2, 0x73, 0x3b, 0xf4, 0x03, 0x14, 0x99, 0x13, 0xcb, 0xf8, 0x0c, 0x7a, 0x95, 0x16, 0x8b, 0xd4,
    0xca, 0x69, 0x35, 0xee, 0x53, 0xcd, 0x39, 0x76, 0x4b, 0xee, 0xbe, 0x2e, 0x00, 0x7e, 0x3a, 0xee,
];
const SERVER_SIGNING_PUBLIC: [u8; 65] = [
    0x04, 0x45, 0x39, 0x77, 0xb0, 0x48, 0xd0, 0xb7, 0x2c, 0x1a, 0x7d, 0x50, 0xc3, 0x6e, 0xbe, 0x88,
    0x1b, 0x69, 0xbb, 0xdd, 0x51, 0xa5, 0xc6, 0x62, 0xd0, 0x8a, 0x1b, 0xaf, 0x12, 0x36, 0xce, 0x92,
    0xcb, 0xb9, 0x54, 0x60, 0xf5, 0x73, 0xfe, 0x7a, 0x5b, 0x0e, 0xd9, 0xcc, 0xfe, 0xe0, 0x1e, 0xb4,
    0xdf, 0xb6, 0xe6, 0xec, 0xfa, 0x16, 0xa0, 0x90, 0xe3, 0xed, 0x8f, 0x58, 0x47, 0xa9, 0xda, 0xf9,
    0x84,
];
static SERVER_VERIFIER: LazyLock<crypto::P256Verifier> = LazyLock::new(|| {
    crypto::P256Verifier::new(&SERVER_SIGNING_PUBLIC).expect("embedded NT server verification key")
});

#[derive(Clone, Copy)]
pub(super) enum NtResponseKind {
    Easy,
    Refresh,
    Password,
    NewDevice,
    PasswordVerification,
}

pub(super) struct NtResult {
    pub code: u64,
    pub title: String,
    pub message: String,
    pub jump_word: String,
    pub jump_url: String,
    pub unusual_signature: Option<Bytes>,
    pub captcha_url: Option<String>,
    pub long_cookie: Option<Bytes>,
}
impl NtResult {
    pub fn require_success(&self) -> Result<()> {
        if self.code == 0 {
            Ok(())
        } else {
            Err(Error::Server {
                code: self.code as i32,
                message: format!("{}: {}", self.title, self.message),
            })
        }
    }
}
pub(super) struct NtLogin {
    ecdh: Ecdh,
    ios_device: Option<IosDevice>,
    device_name: Option<String>,
    exchange_prepared: bool,
    exchange_platform: ClientPlatform,
    long_cookies: BTreeMap<String, Bytes>,
    #[cfg(test)]
    verifier_override: Option<crypto::P256Verifier>,
}
impl NtLogin {
    pub fn new() -> Result<Self> {
        Ok(Self {
            ecdh: Ecdh::new(Curve::P256)?,
            ios_device: None,
            device_name: None,
            exchange_prepared: false,
            exchange_platform: ClientPlatform::Linux,
            long_cookies: BTreeMap::new(),
            #[cfg(test)]
            verifier_override: None,
        })
    }
    #[cfg(test)]
    pub(super) fn with_verifier(verifier: crypto::P256Verifier) -> Result<Self> {
        let mut codec = Self::new()?;
        codec.verifier_override = Some(verifier);
        Ok(codec)
    }
    pub fn with_device(device: Option<IosDevice>) -> Result<Self> {
        Self::with_device_name(device, None)
    }
    pub fn with_device_name(device: Option<IosDevice>, device_name: Option<String>) -> Result<Self> {
        let mut codec = Self::new()?;
        codec.ios_device = device;
        codec.device_name = device_name;
        Ok(codec)
    }
    pub fn key_exchange(&mut self, state: &SessionState, timestamp: u64) -> Result<Bytes> {
        if self.exchange_prepared {
            self.ecdh = Ecdh::new(Curve::P256)?;
        }
        self.exchange_prepared = true;
        self.exchange_platform = state.profile.platform;
        let shared = self.ecdh.shared_secret(&SERVER_PUBLIC, false)?;
        let secret = auth::KeyExchangeSecret {
            uin: Some(state.keystore.uin.to_string()),
            guid: Some(Bytes::copy_from_slice(&state.keystore.guid)),
        }
        .encode_to_vec();
        let encrypted = crypto::aes_gcm_encrypt(&secret, &shared)?;
        let mut verify = Sha256::new();
        verify.update(self.ecdh.public_key());
        verify.update(1u32.to_be_bytes());
        verify.update(&encrypted);
        verify.update(timestamp.to_be_bytes());
        let digest: [u8; 32] = verify.finalize().into();
        let hash = crypto::aes_gcm_encrypt(&digest, &VERIFIER_KEY)?;
        Ok(auth::KeyExchangeRequest {
            public_key: Some(Bytes::copy_from_slice(self.ecdh.public_key())),
            r#type: Some(1),
            encrypted_secret: Some(encrypted.into()),
            timestamp: Some(timestamp),
            encrypted_hash: Some(hash.into()),
        }
        .encode_to_vec()
        .into())
    }
    pub fn decode_key_exchange(
        &self,
        data: Bytes,
        previous: Option<&NtKeyExchangeSession>,
    ) -> Result<NtKeyExchangeSession> {
        if !self.exchange_prepared {
            return Err(malformed("NT exchange response arrived before a request"));
        }
        let p: auth::KeyExchangeResponse = proto::decode(data)?;
        let public = p
            .public_key
            .ok_or_else(|| malformed("Key exchange peer public key missing"))?;
        let encrypted = p
            .encrypted_secret
            .ok_or_else(|| malformed("Key exchange ciphertext missing"))?;
        let signature = p
            .signature
            .ok_or_else(|| malformed("Key exchange server signature missing"))?;
        let mut digest = Sha256::new();
        digest.update(self.ecdh.public_key());
        digest.update(&public);
        digest.update(&encrypted);
        let digest: [u8; 32] = digest.finalize().into();
        let verifier = &*SERVER_VERIFIER;
        #[cfg(test)]
        let verifier = self.verifier_override.as_ref().unwrap_or(verifier);
        verifier.verify_digest(&digest, &signature)?;
        let shared = self.ecdh.shared_secret(&public, false)?;
        let secret: auth::KeyExchangeSession =
            proto::decode(Bytes::from(crypto::aes_gcm_decrypt(&encrypted, &shared)?))?;
        let ticket = secret
            .ticket
            .filter(|v| !v.is_empty())
            .ok_or_else(|| malformed("Key exchange ticket missing"))?;
        let key = secret
            .key
            .filter(|v| matches!(v.len(), 16 | 24 | 32))
            .ok_or_else(|| malformed("Invalid key exchange session key"))?;
        let expire_seconds = secret.expire_seconds.unwrap_or(0);
        match previous {
            Some(previous) => previous.renew(key, ticket, expire_seconds),
            None => NtKeyExchangeSession::new(self.exchange_platform, key, ticket, expire_seconds),
        }
    }
    pub fn encode(
        &self,
        body: &impl Message,
        state: &SessionState,
        kind: NtResponseKind,
    ) -> Result<Bytes> {
        let head = self.request_head(state, kind)?;
        let k = &state.keystore;
        let session = k
            .key_exchange_session
            .as_ref()
            .ok_or_else(|| Error::Authentication("NT key exchange required".into()))?;
        let (key, ticket) = session.material()?;
        let common = auth::NtRequest {
            head: Some(head),
            body: Some(body.encode_to_vec().into()),
        }
        .encode_to_vec();
        let encrypted = crypto::aes_gcm_encrypt(&common, key)?;
        Ok(auth::NtForward {
            ticket: Some(ticket.clone()),
            encrypted: Some(encrypted.into()),
            r#type: Some(1),
        }
        .encode_to_vec()
        .into())
    }
    fn request_head(
        &self,
        state: &SessionState,
        kind: NtResponseKind,
    ) -> Result<auth::NtRequestHead> {
        let p = &state.profile;
        let k = &state.keystore;
        let ios = p.platform.is_ios();
        let os = if ios {
            let device = self.ios_device.as_ref().ok_or_else(|| {
                Error::Authentication("NT iOS login requires actual IosDevice resources".into())
            })?;
            device.validate()?;
            device.system_version.clone()
        } else {
            p.os.clone()
        };
        let platform = match p.platform {
            ClientPlatform::Linux => 7,
            ClientPlatform::Windows => 4,
            ClientPlatform::MacOS => 5,
            ClientPlatform::IPhone | ClientPlatform::IPad => 1,
        };
        Ok(auth::NtRequestHead {
            account: Some(auth::NtAccountRequest {
                uin: Some(k.uin.to_string()),
            }),
            client: Some(auth::NtClient {
                os: Some(os),
                device_name: Some(self.device_name.as_ref().unwrap_or(&k.device_name).clone()),
                platform: Some(platform),
                guid: Some(Bytes::copy_from_slice(&k.guid)),
            }),
            app: Some(auth::NtApp {
                kernel: Some(if ios {
                    p.version.clone()
                } else {
                    p.kernel.clone()
                }),
                app_id: Some(p.app_id),
                package_name: Some(p.package_name.clone()),
                qua: Some(p.qua.clone()),
            }),
            cookie: (!k.login_cookie.is_empty()).then(|| auth::NtCookie {
                cookie: Some(Bytes::copy_from_slice(&k.login_cookie)),
            }),
            security: (!ios).then_some(auth::NtSecurity { mode: Some(1) }),
            long_cookie: matches!(kind, NtResponseKind::Password)
                .then(|| {
                    let mut account = itoa::Buffer::new();
                    self.long_cookies
                        .get(account.format(k.uin))
                        .filter(|cookie| !cookie.is_empty())
                        .cloned()
                        .map(|cookie| auth::NtCookie {
                            cookie: Some(cookie),
                        })
                })
                .flatten(),
        })
    }
    pub fn decode(
        &self,
        data: Bytes,
        store: &mut Keystore,
        kind: NtResponseKind,
        generated_unix_seconds: u64,
    ) -> Result<NtResult> {
        let forward: auth::NtForward = proto::decode(data)?;
        let encrypted = forward
            .encrypted
            .ok_or_else(|| malformed("NT login forward ciphertext missing"))?;
        let (key, _) = store
            .key_exchange_session
            .as_ref()
            .ok_or_else(|| Error::Authentication("NT key exchange required".into()))?
            .material()?;
        let common: auth::NtResponse =
            proto::decode(Bytes::from(crypto::aes_gcm_decrypt(&encrypted, key)?))?;
        let head = common
            .head
            .ok_or_else(|| malformed("NT login response head missing"))?;
        let error = head.error.unwrap_or_default();
        let code = error.code.unwrap_or_default();
        let body = match common.body {
            Some(body) => body,
            None if code != 0
                && matches!(kind, NtResponseKind::Refresh | NtResponseKind::Password) =>
            {
                Bytes::new()
            }
            None => return Err(malformed("NT login response body missing")),
        };
        let (tickets, account, unusual_signature, captcha_url) = match kind {
            NtResponseKind::Easy => {
                let body: auth::NtEasyLoginResponseBody = proto::decode(body)?;
                (
                    body.tickets,
                    None,
                    body.protection.and_then(|p| p.signature),
                    None,
                )
            }
            NtResponseKind::Refresh => {
                let body: auth::NtRefreshTicketResponseBody = proto::decode(body)?;
                (body.tickets, body.account, None, None)
            }
            NtResponseKind::Password => {
                let body: auth::NtPasswordResponseBody = proto::decode(body)?;
                (
                    body.tickets,
                    body.account,
                    body.protection.and_then(|p| p.signature),
                    body.captcha.and_then(|p| p.url),
                )
            }
            NtResponseKind::NewDevice => {
                let body: auth::NtNewDeviceResponseBody = proto::decode(body)?;
                (body.tickets, body.account, None, None)
            }
            NtResponseKind::PasswordVerification => {
                let body: auth::NtPasswordVerificationResponseBody = proto::decode(body)?;
                (body.tickets, body.account, None, None)
            }
        };
        let mut candidate = store.clone();
        if !matches!(kind, NtResponseKind::Refresh) {
            if let Some(cookie) = head.cookie.and_then(|p| p.cookie) {
                candidate.login_cookie = cookie.to_vec()
            }
        }
        if code == 0 {
            let tickets =
                tickets.ok_or_else(|| malformed("Successful NT response lacks tickets"))?;
            if matches!(kind, NtResponseKind::Refresh) {
                if account.as_ref().is_some_and(|account| {
                    account
                        .uin
                        .is_some_and(|uin| uin != 0 && uin != candidate.uin)
                        || account.uid.as_ref().is_some_and(|uid| {
                            !uid.is_empty() && !candidate.uid.is_empty() && uid != &candidate.uid
                        })
                }) {
                    return Err(Error::Authentication(
                        "NT ticket refresh belongs to another account".into(),
                    ));
                }
                Self::save_refresh(&tickets, &mut candidate)?;
            } else {
                Self::save(&tickets, &mut candidate, generated_unix_seconds)?;
            }
            if let Some(account) = account.filter(|_| !matches!(kind, NtResponseKind::Refresh)) {
                if let Some(uin) = account.uin.filter(|&uin| uin != 0) {
                    candidate.uin = uin
                }
                if let Some(uid) = account.uid.filter(|s| !s.is_empty()) {
                    candidate.uid = uid
                }
                if let Some(nickname) = account.profile.and_then(|p| p.nickname) {
                    candidate.nickname = nickname
                }
            }
        }
        *store = candidate;
        Ok(NtResult {
            code,
            title: error.title.unwrap_or_default(),
            message: error.message.unwrap_or_default(),
            jump_word: error.jump_word.unwrap_or_default(),
            jump_url: error.jump_url.unwrap_or_default(),
            unusual_signature,
            captcha_url,
            long_cookie: head
                .long_cookie
                .and_then(|cookie| cookie.cookie)
                .filter(|cookie| !cookie.is_empty()),
        })
    }
    pub fn finish_response(&mut self, kind: NtResponseKind, account: &str, result: &NtResult) {
        if !matches!(kind, NtResponseKind::Password)
            || account.is_empty()
            || matches!(result.code, 0 | 140022008 | 140022010)
        {
            return;
        }
        match &result.long_cookie {
            Some(cookie) => {
                self.long_cookies.insert(account.to_owned(), cookie.clone());
            }
            None => {
                self.long_cookies.remove(account);
            }
        }
    }
    fn save(t: &auth::NtTickets, k: &mut Keystore, generated_unix_seconds: u64) -> Result<()> {
        let a1 =
            t.a1.as_ref()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| malformed("NT A1 ticket missing"))?;
        let a2 =
            t.a2.as_ref()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| malformed("NT A2 ticket missing"))?;
        let d2 =
            t.d2.as_ref()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| malformed("NT D2 ticket missing"))?;
        let d2_key = t
            .d2_key
            .as_ref()
            .filter(|v| v.len() == 16)
            .ok_or_else(|| malformed("NT D2 key is not sixteen bytes"))?;
        k.a1 = a1.to_vec();
        k.a2 = a2.to_vec();
        k.d2 = d2.to_vec();
        k.d2_key = d2_key.to_vec();
        if let Some(v) = &t.a1_key {
            k.a1_key = v.to_vec()
        }
        if let Some(v) = &t.a2_key {
            k.a2_key = v.to_vec()
        }
        if let Some(v) = &t.no_pic_sig {
            k.no_pic_sig = v.to_vec()
        }
        if let Some(tgt) = &t.tgt {
            if let Some(v) = &tgt.a2_key {
                k.a2_key = v.to_vec()
            }
            if let Some(v) = &tgt.session_ticket {
                k.wt_session_ticket = v.to_vec()
            }
            if let Some(v) = &tgt.session_ticket_key {
                k.wt_session_ticket_key = v.to_vec()
            }
            if let Some(c) = &tgt.profile {
                if let Some(n) = &c.nickname {
                    k.nickname = n.clone()
                }
                k.face_id = c.face_id.unwrap_or_default() as u16;
                k.gender = c.gender.unwrap_or_default() as u8;
                k.age = c.age.unwrap_or_default() as u8;
            }
        }
        if let Some(st) = &t.service_ticket {
            if let Some(v) = &st.ticket {
                k.st = v.to_vec()
            }
            if let Some(v) = &st.key {
                k.st_key = v.to_vec()
            }
        }
        if let Some(http) = &t.http_ticket {
            if let Some(v) = &http.ticket {
                k.st_web = v.to_vec()
            }
        }
        Self::save_times(t, k);
        k.ticket_generated_unix_seconds = k
            .nt_ticket_times
            .and_then(|times| times.selected())
            .map(|_| generated_unix_seconds);
        Ok(())
    }

    fn save_refresh(t: &auth::NtTickets, k: &mut Keystore) -> Result<()> {
        let a1 =
            t.a1.as_ref()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| malformed("NT refresh A1 ticket missing"))?;
        match (
            t.d2.as_ref().filter(|value| !value.is_empty()),
            t.d2_key.as_ref().filter(|value| !value.is_empty()),
        ) {
            (None, None) => {}
            (Some(ticket), Some(key)) if key.len() == 16 => {
                k.d2 = ticket.to_vec();
                k.d2_key = key.to_vec();
            }
            _ => return Err(malformed("NT refresh D2 ticket/key pair is invalid")),
        }
        k.a1 = a1.to_vec();
        if let Some(a2) = t.a2.as_ref().filter(|value| !value.is_empty()) {
            k.a2 = a2.to_vec();
        }
        Self::save_times(t, k);
        Ok(())
    }

    fn save_times(t: &auth::NtTickets, k: &mut Keystore) {
        let values = |v: &auth::NtTicketTimeValues| NtTicketTimeValues {
            raw_field1: v.raw_field1,
            raw_field2: v.raw_field2,
        };
        k.nt_ticket_times = Some(NtTicketTimeMetadata {
            field12: t.raw_time_field12.as_ref().map(values),
            field16: t.raw_time_field16.as_ref().map(values),
            received_unix_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| {
                    elapsed.as_millis().min(u64::MAX as u128) as u64
                }),
        });
        k.wt_ticket_times = None;
    }
    pub fn password_a1(password_digest: &[u8; 16], state: &SessionState) -> Result<Bytes> {
        let k = &state.keystore;
        if k.uin == 0 {
            return Err(Error::Authentication(
                "Password login requires a numeric UIN".into(),
            ));
        }
        let mut account = itoa::Buffer::new();
        crypto::NtClientA1 {
            app_id: state.profile.app_id,
            account: account.format(k.uin),
            salt: k.uin,
            guid: &k.guid,
            password_digest,
        }
        .encrypt(super::unix_seconds())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Writer;

    #[test]
    fn exchange_session_wire_preserves_signed_sixty_four_bit_lifetimes() {
        for lifetime in [i64::from(i32::MAX) + 1, i64::from(i32::MIN) - 1] {
            let session = auth::KeyExchangeSession {
                key: Some(Bytes::from_static(&[42; 16])),
                ticket: Some(Bytes::from_static(b"synthetic-ticket")),
                expire_seconds: Some(lifetime),
            };
            let decoded: auth::KeyExchangeSession =
                proto::decode(Bytes::from(session.encode_to_vec())).unwrap();
            assert_eq!(decoded.expire_seconds, Some(lifetime));
        }
    }

    #[test]
    fn ios_request_head_matches_native_serialization_without_desktop_security() {
        let codec = NtLogin::with_device(Some(IosDevice {
            system_version: "18.0".into(),
            hardware_model: "iPhone17,1".into(),
            system_name: "iOS".into(),
        }))
        .unwrap();
        let golden = "0a080a06313233343536122c0a0431382e30121073796e7468657469632d64657669636518012210313131313131313131313131313131311a350a06392e332e373510101a0f636f6d2e74656e63656e742e6d71712a1856315f4950485f53515f392e332e37355f315f4150505f41";
        for (json, bid) in [
            (r#"{"platform":"IPhone"}"#, 537_396_808),
            (r#"{"platform":"IPad"}"#, 537_396_819),
        ] {
            let profile: Profile = serde_json::from_str(json).unwrap();
            assert_eq!(profile.sub_app_id, bid);
            let mut state = SessionState {
                profile,
                keystore: Keystore {
                    uin: 123456,
                    guid: vec![0x31; 16],
                    device_name: "synthetic-device".into(),
                    key_exchange_session: Some(test_session()),
                    ..Default::default()
                },
                machine_id: "synthetic-machine".into(),
                online: false,
            };
            assert_eq!(
                hex::encode(
                    codec
                        .request_head(&state, NtResponseKind::Password)
                        .unwrap()
                        .encode_to_vec()
                ),
                golden
            );
            let body = auth::NtRefreshTicketBody {
                a1: Some(Bytes::from_static(b"synthetic-a1")),
            };
            let forward: auth::NtForward = proto::decode(
                codec
                    .encode(&body, &state, NtResponseKind::Refresh)
                    .unwrap(),
            )
            .unwrap();
            let common: auth::NtRequest = proto::decode(
                crypto::aes_gcm_decrypt(&forward.encrypted.unwrap(), session_key(&state.keystore))
                    .unwrap()
                    .as_slice(),
            )
            .unwrap();
            assert_eq!(hex::encode(common.head.unwrap().encode_to_vec()), golden);
            assert_eq!(common.body.unwrap(), body.encode_to_vec());
            state.keystore.login_cookie = b"synthetic-cookie".to_vec();
            assert_eq!(
                hex::encode(
                    codec
                        .request_head(&state, NtResponseKind::Password)
                        .unwrap()
                        .encode_to_vec()
                ),
                format!("{golden}2a120a1073796e7468657469632d636f6f6b6965"),
            );
            assert!(
                NtLogin::new()
                    .unwrap()
                    .encode(&body, &state, NtResponseKind::Refresh)
                    .is_err()
            );
        }
    }


    #[test]
    fn desktop_request_head_retains_linux_fields_and_security() {
        let state = SessionState {
            profile: serde_json::from_str("{}").unwrap(),
            keystore: Keystore::default(),
            machine_id: "synthetic-machine".into(),
            online: false,
        };
        let head = NtLogin::new()
            .unwrap()
            .request_head(&state, NtResponseKind::Password)
            .unwrap();
        assert_eq!(head.client.as_ref().unwrap().platform, Some(7));
        assert_eq!(head.client.unwrap().os.as_deref(), Some("Linux"));
        assert_eq!(head.app.unwrap().kernel.as_deref(), Some("Linux"));
        assert_eq!(head.security.unwrap().mode, Some(1));
    }

    #[test]
    fn profile_overrides_reach_nt_headers_and_uncatalogued_platforms_require_complete_input() {
        let codec = NtLogin::with_device(Some(IosDevice {
            system_version: "18.0".into(),
            hardware_model: "synthetic-hardware".into(),
            system_name: "iOS".into(),
        }))
        .unwrap();
        let state = SessionState {
            profile: serde_json::from_str(
                r#"{"platform":"IPad","qua":"explicit-qua","app_id":42,"version":"explicit-version","package_name":"explicit-package"}"#,
            )
            .unwrap(),
            keystore: Keystore::default(),
            machine_id: "synthetic-machine".into(),
            online: false,
        };
        let head = codec
            .request_head(&state, NtResponseKind::Password)
            .unwrap();
        assert_eq!(head.client.unwrap().platform, Some(1));
        let app = head.app.unwrap();
        assert_eq!(app.qua.as_deref(), Some("explicit-qua"));
        assert_eq!(app.app_id, Some(42));
        assert_eq!(app.kernel.as_deref(), Some("explicit-version"));
        assert_eq!(app.package_name.as_deref(), Some("explicit-package"));
        assert!(head.security.is_none());
        for (platform, code) in [("Windows", 4), ("MacOS", 5)] {
            let error = serde_json::from_str::<Profile>(&format!(r#"{{"platform":"{platform}"}}"#))
                .unwrap_err();
            assert!(error.to_string().contains("missing field `os`"));
            let input = format!(
                r#"{{"platform":"{platform}","os":"explicit-os","kernel":"explicit-kernel","qua":"explicit-qua","version":"explicit-version","package_name":"explicit-package","pt_version":"","sdk_version":"explicit-sdk","apk_signature_md5":null,"app_id":42,"sub_app_id":43,"sso_version":44,"client_version":45,"misc_bitmap":null,"main_sig_map":null,"sub_sig_map":null}}"#,
            );
            let explicit = SessionState {
                profile: serde_json::from_str(&input).unwrap(),
                ..state.clone()
            };
            let head = codec
                .request_head(&explicit, NtResponseKind::Password)
                .unwrap();
            let client = head.client.unwrap();
            assert_eq!(client.platform, Some(code));
            assert_eq!(client.os.as_deref(), Some("explicit-os"));
            let app = head.app.unwrap();
            assert_eq!(app.kernel.as_deref(), Some("explicit-kernel"));
            assert_eq!(app.qua.as_deref(), Some("explicit-qua"));
            assert_eq!(app.app_id, Some(42));
            assert_eq!(head.security.unwrap().mode, Some(1));
            let missing_optional = input.replace(r#","sub_sig_map":null"#, "");
            let error = serde_json::from_str::<Profile>(&missing_optional).unwrap_err();
            assert!(error.to_string().contains("missing field `sub_sig_map`"));
        }
    }

    #[test]
    fn explicit_null_profile_resources_fail_at_wt_consumers_instead_of_restoring_defaults() {
        let state = SessionState {
            profile: serde_json::from_str("{}").unwrap(),
            keystore: Keystore {
                tgtgt_key: vec![0x31; 16],
                ..Default::default()
            },
            machine_id: "synthetic-machine".into(),
            online: false,
        };
        let mut codec = super::super::wt::WtLogin::new().unwrap();
        assert!(codec.login(&state).is_ok());
        for (field, message) in [
            ("apk_signature_md5", "WT APK signature resource missing"),
            ("misc_bitmap", "WT misc bitmap resource missing"),
            ("main_sig_map", "WT main signature map resource missing"),
            ("sub_sig_map", "WT sub signature map resource missing"),
        ] {
            let explicit = SessionState {
                profile: serde_json::from_str(&format!(r#"{{"{field}":null}}"#)).unwrap(),
                ..state.clone()
            };
            match codec.login(&explicit) {
                Err(Error::Malformed(error)) => assert_eq!(error, message),
                _ => panic!("explicitly absent {field} was not rejected by WT login"),
            }
        }
    }

    fn test_session() -> NtKeyExchangeSession {
        NtKeyExchangeSession::new(
            ClientPlatform::Linux,
            Bytes::from_static(&[42; 16]),
            Bytes::from_static(b"synthetic-exchange-ticket"),
            3600,
        )
        .unwrap()
    }

    fn session_key(store: &Keystore) -> &[u8] {
        store
            .key_exchange_session
            .as_ref()
            .unwrap()
            .material()
            .unwrap()
            .0
    }

    #[test]
    fn key_exchange_rejects_unauthenticated_but_decryptable_session() {
        let mut codec = NtLogin::new().unwrap();
        let state = SessionState {
            profile: Profile::linux(),
            keystore: Keystore::default(),
            machine_id: "synthetic-machine".into(),
            online: false,
        };
        codec.key_exchange(&state, 1_700_000_000).unwrap();
        let mut scalar = [0; 32];
        scalar[31] = 1;
        let peer = Ecdh::from_private(Curve::P256, &scalar).unwrap();
        let shared = peer.shared_secret(codec.ecdh.public_key(), false).unwrap();
        let session = auth::KeyExchangeSession {
            key: Some(Bytes::from_static(&[7; 32])),
            ticket: Some(Bytes::from_static(b"synthetic-session-ticket")),
            expire_seconds: Some(3600),
        };
        let response = auth::KeyExchangeResponse {
            signature: None,
            public_key: Some(Bytes::copy_from_slice(peer.public_key())),
            encrypted_secret: Some(
                crypto::aes_gcm_encrypt(&session.encode_to_vec(), &shared)
                    .unwrap()
                    .into(),
            ),
        }
        .encode_to_vec();
        assert!(codec.decode_key_exchange(response.into(), None).is_err());
    }

    fn refresh_response(
        store: &Keystore,
        tickets: Option<auth::NtTickets>,
        account: Option<auth::NtAccount>,
        code: u64,
    ) -> Bytes {
        let common = auth::NtResponse {
            head: Some(auth::NtResponseHead {
                error: Some(auth::NtError {
                    code: Some(code),
                    ..Default::default()
                }),
                cookie: Some(auth::NtCookie {
                    cookie: Some(Bytes::from_static(b"refresh-must-not-replace-login-cookie")),
                }),
                ..Default::default()
            }),
            body: (code == 0).then(|| {
                auth::NtRefreshTicketResponseBody { tickets, account }
                    .encode_to_vec()
                    .into()
            }),
        };
        auth::NtForward {
            encrypted: Some(
                crypto::aes_gcm_encrypt(&common.encode_to_vec(), session_key(store))
                    .unwrap()
                    .into(),
            ),
            ..Default::default()
        }
        .encode_to_vec()
        .into()
    }

    fn refresh_store() -> Keystore {
        Keystore {
            uin: 1234,
            uid: "synthetic-refresh-identity".into(),
            a1: b"previous-a1".to_vec(),
            a2: b"retained-a2".to_vec(),
            d2: b"retained-d2".to_vec(),
            d2_key: vec![3; 16],
            key_exchange_session: Some(test_session()),
            login_cookie: b"retained-login-cookie".to_vec(),
            wt_ticket_times: Some(WtTicketTimeMetadata {
                next_refresh_unix_seconds: 604_900,
                expire_unix_seconds: 2_592_100,
            }),
            ticket_generated_unix_seconds: Some(100),
            ..Default::default()
        }
    }

    #[test]
    fn refresh_rotates_a1_and_time_without_dropping_omitted_transport_tickets() {
        let codec = NtLogin::new().unwrap();
        let mut store = refresh_store();
        let retained = store.clone();
        let response = refresh_response(
            &store,
            Some(auth::NtTickets {
                a1: Some(Bytes::from_static(b"refreshed-a1")),
                raw_time_field12: Some(auth::NtTicketTimeValues::default()),
                raw_time_field16: Some(auth::NtTicketTimeValues {
                    raw_field1: Some(2000),
                    raw_field2: Some(3000),
                }),
                ..Default::default()
            }),
            None,
            0,
        );
        codec
            .decode(response, &mut store, NtResponseKind::Refresh, 1_000)
            .unwrap()
            .require_success()
            .unwrap();
        assert_eq!(store.a1, b"refreshed-a1");
        assert_eq!(store.a2, retained.a2);
        assert_eq!(store.d2, retained.d2);
        assert_eq!(store.d2_key, retained.d2_key);
        assert_eq!(store.login_cookie, retained.login_cookie);
        assert_eq!(store.wt_ticket_times, None);
        assert_eq!(store.ticket_generated_unix_seconds, Some(100));
        assert_eq!(store.next_ticket_refresh_unix_seconds(), Some(0));
        assert_eq!(
            store.nt_ticket_times.unwrap().next_refresh_unix_seconds(),
            Some(0)
        );
    }

    #[test]
    fn refresh_preserves_generation_without_inventing_missing_record_times() {
        let codec = NtLogin::new().unwrap();
        for generated in [None, Some(100)] {
            let mut store = refresh_store();
            store.ticket_generated_unix_seconds = generated;
            for next in [Some(2_000), Some(3_000), None] {
                let response = refresh_response(
                    &store,
                    Some(auth::NtTickets {
                        a1: Some(Bytes::from_static(b"refreshed-a1")),
                        raw_time_field16: next.map(|next| auth::NtTicketTimeValues {
                            raw_field1: Some(next),
                            raw_field2: Some(next + 1),
                        }),
                        ..Default::default()
                    }),
                    None,
                    0,
                );
                codec
                    .decode(response, &mut store, NtResponseKind::Refresh, 9_000)
                    .unwrap()
                    .require_success()
                    .unwrap();
                assert_eq!(store.ticket_generated_unix_seconds, generated);
                assert_eq!(store.wt_ticket_times, None);
                assert_eq!(store.next_ticket_refresh_unix_seconds(), next);
            }
        }
    }

    #[test]
    fn refresh_rejects_incomplete_transport_keys_or_another_account_atomically() {
        let codec = NtLogin::new().unwrap();
        let mut store = refresh_store();
        let retained = store.clone();
        for (key_length, account) in [
            (15, None),
            (
                16,
                Some(auth::NtAccount {
                    uin: Some(5678),
                    ..Default::default()
                }),
            ),
            (
                16,
                Some(auth::NtAccount {
                    uid: Some("another-synthetic-identity".into()),
                    ..Default::default()
                }),
            ),
        ] {
            let response = refresh_response(
                &store,
                Some(auth::NtTickets {
                    a1: Some(Bytes::from_static(b"refreshed-a1")),
                    d2: Some(Bytes::from_static(b"refreshed-d2")),
                    d2_key: Some(vec![9; key_length].into()),
                    ..Default::default()
                }),
                account,
                0,
            );
            assert!(
                codec
                    .decode(response, &mut store, NtResponseKind::Refresh, 1_000)
                    .is_err()
            );
            assert!(store == retained);
        }
        let response = refresh_response(
            &store,
            Some(auth::NtTickets {
                a1: Some(Bytes::from_static(b"refreshed-a1")),
                a2: Some(Bytes::from_static(b"refreshed-a2")),
                d2: Some(Bytes::from_static(b"refreshed-d2")),
                d2_key: Some(vec![9; 16].into()),
                ..Default::default()
            }),
            Some(auth::NtAccount {
                uin: Some(retained.uin),
                uid: Some(retained.uid.clone()),
                ..Default::default()
            }),
            0,
        );
        codec
            .decode(response, &mut store, NtResponseKind::Refresh, 1_000)
            .unwrap()
            .require_success()
            .unwrap();
        assert_eq!(store.a1, b"refreshed-a1");
        assert_eq!(store.a2, b"refreshed-a2");
        assert_eq!(store.d2, b"refreshed-d2");
        assert_eq!(store.d2_key, [9; 16]);
        assert_eq!(store.login_cookie, retained.login_cookie);
    }

    #[test]
    fn rejected_refresh_without_body_does_not_change_live_tickets_or_challenge_cookie() {
        let codec = NtLogin::new().unwrap();
        let mut store = refresh_store();
        let retained = store.clone();
        let response = refresh_response(&store, None, None, 140022015);
        let result = codec
            .decode(response, &mut store, NtResponseKind::Refresh, 1_000)
            .unwrap();
        assert_eq!(result.code, 140022015);
        assert!(store == retained);
    }

    fn time_metadata_response(
        store: &Keystore,
        field12: Option<auth::NtTicketTimeValues>,
        field16: Option<auth::NtTicketTimeValues>,
        key_length: usize,
        code: u64,
    ) -> Bytes {
        let common = auth::NtResponse {
            head: Some(auth::NtResponseHead {
                error: Some(auth::NtError {
                    code: Some(code),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            body: Some(
                auth::NtEasyLoginResponseBody {
                    tickets: Some(auth::NtTickets {
                        a1: Some(Bytes::from_static(b"synthetic-a1")),
                        a2: Some(Bytes::from_static(b"synthetic-a2")),
                        d2: Some(Bytes::from_static(b"synthetic-d2")),
                        d2_key: Some(vec![7; key_length].into()),
                        raw_time_field12: field12,
                        raw_time_field16: field16,
                        ..Default::default()
                    }),
                    ..Default::default()
                }
                .encode_to_vec()
                .into(),
            ),
        };
        auth::NtForward {
            encrypted: Some(
                crypto::aes_gcm_encrypt(&common.encode_to_vec(), session_key(store))
                    .unwrap()
                    .into(),
            ),
            ..Default::default()
        }
        .encode_to_vec()
        .into()
    }

    #[test]
    fn authenticated_ticket_rotation_selects_present_field12_without_merging_field16() {
        let codec = NtLogin::new().unwrap();
        let mut store = Keystore {
            key_exchange_session: Some(test_session()),
            wt_ticket_times: Some(WtTicketTimeMetadata {
                next_refresh_unix_seconds: 604_900,
                expire_unix_seconds: 2_592_100,
            }),
            ticket_generated_unix_seconds: Some(100),
            ..Default::default()
        };
        let field16 = auth::NtTicketTimeValues {
            raw_field1: Some(1601),
            raw_field2: Some(1602),
        };
        for field12 in [
            None,
            Some(auth::NtTicketTimeValues::default()),
            Some(auth::NtTicketTimeValues {
                raw_field1: Some(0),
                raw_field2: None,
            }),
        ] {
            let response =
                time_metadata_response(&store, field12.clone(), Some(field16.clone()), 16, 0);
            codec
                .decode(response, &mut store, NtResponseKind::Easy, 1_000)
                .unwrap()
                .require_success()
                .unwrap();
            let times = store.nt_ticket_times.unwrap();
            assert_eq!(store.wt_ticket_times, None);
            assert_eq!(store.ticket_generated_unix_seconds, Some(1_000));
            assert_eq!(
                store.next_ticket_refresh_unix_seconds(),
                times.next_refresh_unix_seconds(),
            );
            assert_eq!(times.field12.is_some(), field12.is_some());
            assert_eq!(
                times.next_refresh_unix_seconds(),
                Some(if field12.is_some() { 0 } else { 1601 })
            );
            assert_eq!(
                times.selected(),
                Some(match field12 {
                    Some(v) => NtTicketTimeValues {
                        raw_field1: v.raw_field1,
                        raw_field2: v.raw_field2,
                    },
                    None => NtTicketTimeValues {
                        raw_field1: Some(1601),
                        raw_field2: Some(1602),
                    },
                })
            );
            assert!(times.received_unix_ms > 0);
            let restored: Keystore =
                serde_json::from_slice(&serde_json::to_vec(&store).unwrap()).unwrap();
            assert_eq!(restored.nt_ticket_times, Some(times));
        }
        let response = time_metadata_response(&store, None, None, 16, 0);
        codec
            .decode(response, &mut store, NtResponseKind::Easy, 1_000)
            .unwrap();
        assert_eq!(store.ticket_generated_unix_seconds, None);
        assert_eq!(store.wt_ticket_times, None);
        assert_eq!(store.next_ticket_refresh_unix_seconds(), None);
        assert_eq!(store.nt_ticket_times.unwrap().selected(), None);
        assert_eq!(
            store.nt_ticket_times.unwrap().next_refresh_unix_seconds(),
            None
        );
    }

    #[test]
    fn rejected_or_invalid_ticket_rotation_never_publishes_new_time_metadata() {
        let codec = NtLogin::new().unwrap();
        let mut store = Keystore {
            key_exchange_session: Some(test_session()),
            nt_ticket_times: Some(NtTicketTimeMetadata {
                field12: None,
                field16: Some(NtTicketTimeValues {
                    raw_field1: Some(16),
                    raw_field2: None,
                }),
                received_unix_ms: 1,
            }),
            ticket_generated_unix_seconds: Some(100),
            ..Default::default()
        };
        let retained = store.clone();
        for (key_length, code) in [(15, 0), (16, 140022008)] {
            let response = time_metadata_response(
                &store,
                Some(auth::NtTicketTimeValues::default()),
                None,
                key_length,
                code,
            );
            let result = codec.decode(response, &mut store, NtResponseKind::Easy, 1_000);
            if code == 0 {
                assert!(result.is_err());
            } else {
                assert_eq!(result.unwrap().code, code);
            }
            assert!(store == retained);
        }
    }

    #[test]
    fn nt_ticket_decryption_is_authenticated_and_transactional() {
        let codec = NtLogin::new().unwrap();
        let mut k = Keystore {
            key_exchange_session: Some(test_session()),
            ..Default::default()
        };
        let old = k.clone();
        let invalid_tickets = auth::NtTickets {
            a1: Some(Bytes::from_static(b"a1")),
            a2: Some(Bytes::from_static(b"a2")),
            d2: Some(Bytes::from_static(b"d2")),
            d2_key: Some(Bytes::from_static(&[0; 15])),
            ..Default::default()
        };
        let body = auth::NtEasyLoginResponseBody {
            tickets: Some(invalid_tickets),
            ..Default::default()
        };
        let common = auth::NtResponse {
            head: Some(auth::NtResponseHead {
                cookie: Some(auth::NtCookie {
                    cookie: Some(Bytes::from_static(b"uncommitted-\xff-cookie")),
                }),
                ..Default::default()
            }),
            body: Some(body.encode_to_vec().into()),
        }
        .encode_to_vec();
        let encrypted = crypto::aes_gcm_encrypt(&common, session_key(&k)).unwrap();
        let forward = auth::NtForward {
            encrypted: Some(encrypted.into()),
            ..Default::default()
        }
        .encode_to_vec()
        .into();
        assert!(
            codec
                .decode(forward, &mut k, NtResponseKind::Easy, 1_000)
                .is_err()
        );
        assert!(k == old);
        let forward = auth::NtForward {
            encrypted: Some(Bytes::from_static(&[0; 28])),
            ..Default::default()
        }
        .encode_to_vec()
        .into();
        assert!(
            codec
                .decode(forward, &mut k, NtResponseKind::Easy, 1_000)
                .is_err()
        );
        assert!(k == old);
    }

    #[test]
    fn binary_login_cookie_survives_challenges_and_is_forwarded_without_text_conversion() {
        let codec = NtLogin::new().unwrap();
        let cookie = Bytes::from_static(b"\xff\x00\xc0\x80");
        let wire_cookie = Bytes::from_static(b"\x0a\x04\xff\x00\xc0\x80");
        let decoded: auth::NtCookie = proto::decode(wire_cookie.clone()).unwrap();
        assert_eq!(decoded.cookie, Some(cookie.clone()));
        assert_eq!(decoded.encode_to_vec(), wire_cookie.as_ref());
        for (kind, code) in [
            (NtResponseKind::Easy, 140022011),
            (NtResponseKind::Password, 140022008),
            (NtResponseKind::NewDevice, 140022010),
            (NtResponseKind::PasswordVerification, 140022011),
        ] {
            let mut store = Keystore {
                a1: b"retained-a1".to_vec(),
                key_exchange_session: Some(test_session()),
                ..Default::default()
            };
            let common = auth::NtResponse {
                head: Some(auth::NtResponseHead {
                    error: Some(auth::NtError {
                        code: Some(code),
                        ..Default::default()
                    }),
                    cookie: Some(decoded.clone()),
                    ..Default::default()
                }),
                body: Some(Bytes::new()),
            };
            let response = auth::NtForward {
                encrypted: Some(
                    crypto::aes_gcm_encrypt(&common.encode_to_vec(), session_key(&store))
                        .unwrap()
                        .into(),
                ),
                ..Default::default()
            };
            let result = codec
                .decode(response.encode_to_vec().into(), &mut store, kind, 1_000)
                .unwrap();
            assert_eq!(result.code, code);
            assert_eq!(store.a1, b"retained-a1");
            assert_eq!(store.login_cookie.as_slice(), cookie.as_ref());
            let state = SessionState {
                profile: Profile::linux(),
                keystore: store,
                machine_id: "synthetic-machine".into(),
                online: false,
            };
            let request: auth::NtForward = proto::decode(
                codec
                    .encode(&auth::NtLoginBody::default(), &state, kind)
                    .unwrap(),
            )
            .unwrap();
            let clear =
                crypto::aes_gcm_decrypt(&request.encrypted.unwrap(), session_key(&state.keystore))
                    .unwrap();
            let request: auth::NtRequest = proto::decode(clear.as_slice()).unwrap();
            let forwarded = request.head.unwrap().cookie.unwrap();
            assert_eq!(forwarded.cookie, Some(cookie.clone()));
            assert_eq!(forwarded.encode_to_vec(), wire_cookie.as_ref());
        }
    }

    #[test]
    fn easy_ticket_rotation_replaces_transport_tickets_and_preserves_omitted_auxiliary_tickets() {
        let codec = NtLogin::new().unwrap();
        let mut store = Keystore {
            a1: b"old-a1".to_vec(),
            a2: b"old-a2".to_vec(),
            d2: b"old-d2".to_vec(),
            d2_key: vec![1; 16],
            a1_key: b"retained-a1-key".to_vec(),
            a2_key: b"retained-a2-key".to_vec(),
            wt_session_ticket: b"retained-session".to_vec(),
            wt_session_ticket_key: b"retained-session-key".to_vec(),
            st: b"retained-st".to_vec(),
            st_key: b"retained-st-key".to_vec(),
            st_web: b"retained-http-ticket".to_vec(),
            no_pic_sig: b"retained-no-pic".to_vec(),
            key_exchange_session: Some(test_session()),
            ..Default::default()
        };
        let retained = store.clone();
        let tickets = auth::NtTickets {
            a1: Some(Bytes::from_static(b"new-a1")),
            a2: Some(Bytes::from_static(b"new-a2")),
            d2: Some(Bytes::from_static(b"new-d2")),
            d2_key: Some(Bytes::from_static(&[7; 16])),
            ..Default::default()
        };
        let common = auth::NtResponse {
            head: Some(auth::NtResponseHead::default()),
            body: Some(
                auth::NtEasyLoginResponseBody {
                    tickets: Some(tickets),
                    protection: None,
                }
                .encode_to_vec()
                .into(),
            ),
        };
        let response = auth::NtForward {
            encrypted: Some(
                crypto::aes_gcm_encrypt(&common.encode_to_vec(), session_key(&store))
                    .unwrap()
                    .into(),
            ),
            ..Default::default()
        };
        codec
            .decode(
                response.encode_to_vec().into(),
                &mut store,
                NtResponseKind::Easy,
                1_000,
            )
            .unwrap()
            .require_success()
            .unwrap();
        assert_eq!(store.a1, b"new-a1");
        assert_eq!(store.a2, b"new-a2");
        assert_eq!(store.d2, b"new-d2");
        assert_eq!(store.d2_key, [7; 16]);
        assert_eq!(store.a1_key, retained.a1_key);
        assert_eq!(store.a2_key, retained.a2_key);
        assert_eq!(store.wt_session_ticket, retained.wt_session_ticket);
        assert_eq!(store.wt_session_ticket_key, retained.wt_session_ticket_key);
        assert_eq!(store.st, retained.st);
        assert_eq!(store.st_key, retained.st_key);
        assert_eq!(store.st_web, retained.st_web);
        assert_eq!(store.no_pic_sig, retained.no_pic_sig);
    }

    #[test]
    fn key_exchange_verifier_authenticates_the_visible_request_fields() {
        let mut codec = NtLogin::new().unwrap();
        let state = SessionState {
            profile: Profile::linux(),
            keystore: Keystore {
                uin: 123456,
                ..Default::default()
            },
            machine_id: "synthetic-machine".into(),
            online: false,
        };
        let timestamp = u64::from(u32::MAX) + 123;
        let request: auth::KeyExchangeRequest =
            proto::decode(codec.key_exchange(&state, timestamp).unwrap()).unwrap();
        let public = request.public_key.unwrap();
        assert_eq!(public.len(), 65);
        assert_eq!(public[0], 4);
        assert_eq!(request.r#type, Some(1));
        assert_eq!(request.timestamp, Some(timestamp));
        let encrypted = request.encrypted_secret.unwrap();
        let secret = auth::KeyExchangeSecret {
            uin: Some("123456".into()),
            guid: Some(Bytes::copy_from_slice(&state.keystore.guid)),
        };
        assert_eq!(encrypted.len(), secret.encoded_len() + 28);
        let mut verify = Writer::new();
        verify.bytes(&public);
        verify.u32(1);
        verify.bytes(&encrypted);
        verify.u64(timestamp);
        let hash_key =
            hex::decode("e2733bf403149913cbf80c7a95168bd4ca6935ee53cd39764beebe2e007e3aee")
                .unwrap();
        let hash = crypto::aes_gcm_decrypt(&request.encrypted_hash.unwrap(), &hash_key).unwrap();
        assert_eq!(hash, crypto::sha256(&verify.data));
        verify.data.truncate(verify.data.len() - 8);
        verify.u64(timestamp + 1);
        assert_ne!(hash, crypto::sha256(&verify.data));
    }

    #[test]
    fn renewed_key_exchange_rejects_previous_exchange_ciphertext() {
        use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};

        let signing_key = SigningKey::from_slice(&[1; 32]).unwrap();
        let reply = |peer: &Ecdh, public: &[u8], ticket: &'static [u8]| {
            let shared = peer.shared_secret(public, false).unwrap();
            let secret = auth::KeyExchangeSession {
                key: Some(Bytes::from_static(&[7; 16])),
                ticket: Some(Bytes::from_static(ticket)),
                expire_seconds: Some(3600),
            }
            .encode_to_vec();
            let encrypted = crypto::aes_gcm_encrypt(&secret, &shared).unwrap();
            let digest =
                crypto::sha256(&[public, peer.public_key(), encrypted.as_slice()].concat());
            let signature: Signature = signing_key.sign_prehash(&digest).unwrap();
            Bytes::from(
                auth::KeyExchangeResponse {
                    encrypted_secret: Some(encrypted.into()),
                    signature: Some(Bytes::copy_from_slice(signature.to_der().as_bytes())),
                    public_key: Some(Bytes::copy_from_slice(peer.public_key())),
                }
                .encode_to_vec(),
            )
        };

        let mut codec = NtLogin::with_verifier(
            crypto::P256Verifier::new(
                signing_key
                    .verifying_key()
                    .to_encoded_point(false)
                    .as_bytes(),
            )
            .unwrap(),
        )
        .unwrap();
        let state = SessionState {
            profile: Profile::linux(),
            keystore: Keystore::default(),
            machine_id: "synthetic-machine".into(),
            online: false,
        };
        let peer = Ecdh::new(Curve::P256).unwrap();
        let first: auth::KeyExchangeRequest =
            proto::decode(codec.key_exchange(&state, 1_712_345_678).unwrap()).unwrap();
        let old_reply = reply(&peer, first.public_key.as_ref().unwrap(), b"old-exchange");
        assert_eq!(
            codec
                .decode_key_exchange(old_reply.clone(), None)
                .unwrap()
                .material()
                .unwrap()
                .1,
            b"old-exchange".as_slice()
        );
        let second: auth::KeyExchangeRequest =
            proto::decode(codec.key_exchange(&state, 1_712_345_679).unwrap()).unwrap();
        assert_ne!(first.public_key, second.public_key);
        assert!(codec.decode_key_exchange(old_reply, None).is_err());
        let current_reply = reply(
            &peer,
            second.public_key.as_ref().unwrap(),
            b"current-exchange",
        );
        let session = codec
            .decode_key_exchange(current_reply.clone(), None)
            .unwrap();
        let (key, ticket) = session.material().unwrap();
        assert_eq!(ticket, b"current-exchange".as_slice());
        assert_eq!(key, [7; 16]);
        let mut tampered: auth::KeyExchangeResponse = proto::decode(current_reply).unwrap();
        let mut encrypted = tampered.encrypted_secret.take().unwrap().to_vec();
        encrypted[12] ^= 1;
        tampered.encrypted_secret = Some(encrypted.into());
        assert!(
            codec
                .decode_key_exchange(tampered.encode_to_vec().into(), None)
                .is_err()
        );
    }

    #[test]
    fn easy_login_protection_accepts_ciphertext_only_forward_without_replacing_tickets() {
        let codec = NtLogin::new().unwrap();
        let mut store = Keystore {
            key_exchange_session: Some(test_session()),
            a1: b"existing-a1".to_vec(),
            a2: b"existing-a2".to_vec(),
            d2: b"existing-d2".to_vec(),
            ..Default::default()
        };
        let before = store.clone();
        let body = auth::NtEasyLoginResponseBody {
            tickets: None,
            protection: Some(auth::NtUnusualDevice {
                signature: Some(Bytes::from_static(b"synthetic-protection-signature")),
            }),
        };
        let common = auth::NtResponse {
            head: Some(auth::NtResponseHead {
                error: Some(auth::NtError {
                    code: Some(140022011),
                    ..Default::default()
                }),
                cookie: None,
                ..Default::default()
            }),
            body: Some(body.encode_to_vec().into()),
        };
        let forward = auth::NtForward {
            encrypted: Some(
                crypto::aes_gcm_encrypt(&common.encode_to_vec(), session_key(&store))
                    .unwrap()
                    .into(),
            ),
            ticket: None,
            r#type: None,
        };
        let result = codec
            .decode(
                forward.encode_to_vec().into(),
                &mut store,
                NtResponseKind::Easy,
                1_000,
            )
            .unwrap();
        assert_eq!(result.code, 140022011);
        assert!(result.require_success().is_err());
        assert_eq!(
            result.unusual_signature.as_deref(),
            Some(b"synthetic-protection-signature".as_slice())
        );
        assert!(store == before);
    }

    #[test]
    fn expired_easy_identity_preserves_error_without_inventing_device_verification() {
        let codec = NtLogin::new().unwrap();
        let mut store = Keystore {
            key_exchange_session: Some(test_session()),
            a1: b"existing-a1".to_vec(),
            a2: b"existing-a2".to_vec(),
            d2: b"existing-d2".to_vec(),
            uid: "synthetic-existing-uid".into(),
            ..Default::default()
        };
        let before = store.clone();
        let common = auth::NtResponse {
            head: Some(auth::NtResponseHead {
                error: Some(auth::NtError {
                    code: Some(140022015),
                    title: Some("登录失败".into()),
                    message: Some("你的用户身份已失效，为保证账号安全，请你重新登录。".into()),
                    jump_word: Some("重新登录".into()),
                    ..Default::default()
                }),
                cookie: None,
                ..Default::default()
            }),
            body: Some(
                auth::NtEasyLoginResponseBody::default()
                    .encode_to_vec()
                    .into(),
            ),
        };
        let forward = auth::NtForward {
            encrypted: Some(
                crypto::aes_gcm_encrypt(&common.encode_to_vec(), session_key(&store))
                    .unwrap()
                    .into(),
            ),
            ..Default::default()
        };
        let result = codec
            .decode(
                forward.encode_to_vec().into(),
                &mut store,
                NtResponseKind::Easy,
                1_000,
            )
            .unwrap();
        assert_eq!(result.code, 140022015);
        assert!(result.unusual_signature.is_none());
        assert!(result.captcha_url.is_none());
        assert!(matches!(
            result.require_success(),
            Err(Error::Server {
                code: 140022015,
                ..
            })
        ));
        assert!(store == before);
    }

    #[test]
    fn password_response_updates_tickets_account_and_cookie_together() {
        let codec = NtLogin::new().unwrap();
        let mut k = Keystore {
            key_exchange_session: Some(test_session()),
            ..Default::default()
        };
        let body = auth::NtPasswordResponseBody {
            tickets: Some(auth::NtTickets {
                a1: Some(Bytes::from_static(b"new-a1")),
                a2: Some(Bytes::from_static(b"new-a2")),
                d2: Some(Bytes::from_static(b"new-d2")),
                d2_key: Some(Bytes::from_static(&[7; 16])),
                ..Default::default()
            }),
            account: Some(auth::NtAccount {
                uin: Some(123456),
                uid: Some("u_identity".into()),
                profile: Some(auth::NtNickname {
                    nickname: Some("desktop".into()),
                }),
            }),
            captcha: None,
            protection: None,
        };
        let common = auth::NtResponse {
            head: Some(auth::NtResponseHead {
                error: Some(auth::NtError {
                    code: Some(0),
                    ..Default::default()
                }),
                cookie: Some(auth::NtCookie {
                    cookie: Some(Bytes::from_static(b"session-cookie")),
                }),
                ..Default::default()
            }),
            body: Some(body.encode_to_vec().into()),
        }
        .encode_to_vec();
        let forward = auth::NtForward {
            encrypted: Some(
                crypto::aes_gcm_encrypt(&common, session_key(&k))
                    .unwrap()
                    .into(),
            ),
            ..Default::default()
        }
        .encode_to_vec();
        codec
            .decode(forward.into(), &mut k, NtResponseKind::Password, 1_000)
            .unwrap()
            .require_success()
            .unwrap();
        assert_eq!(k.a1, b"new-a1");
        assert_eq!(k.a2, b"new-a2");
        assert_eq!(k.d2, b"new-d2");
        assert_eq!(k.d2_key, [7; 16]);
        assert_eq!(k.uin, 123456);
        assert_eq!(k.uid, "u_identity");
        assert_eq!(k.nickname, "desktop");
        assert_eq!(k.login_cookie, b"session-cookie");
    }

    #[test]
    fn password_a1_has_a_complete_native_layout_without_cached_tgtgt_and_without_uin_truncation() {
        use crate::wire::Reader;
        let digest = crypto::md5(b"synthetic-password");
        for uin in [123456, (1u64 << 32) + 123456] {
            let state = SessionState {
                profile: Profile::linux(),
                keystore: Keystore {
                    uin,
                    guid: vec![0x31; 16],
                    ..Default::default()
                },
                machine_id: "synthetic-machine".into(),
                online: false,
            };
            let a1 = NtLogin::password_a1(&digest, &state).unwrap();
            let mut key = Writer::new();
            key.bytes(digest);
            key.u64(uin);
            let clear = crypto::tea_decrypt(&a1, &crypto::md5(&key.data)).unwrap();
            assert_eq!(clear.len(), 98 + uin.to_string().len());
            let mut r = Reader::new(clear);
            r.skip(18).unwrap();
            assert_eq!(r.u64().unwrap(), uin);
            r.skip(4 + 4 + 1 + 16).unwrap();
            r.bytes(16).unwrap();
            r.skip(4 + 1).unwrap();
            assert_eq!(r.bytes(16).unwrap().as_ref(), state.keystore.guid);
            r.skip(8).unwrap();
            assert_eq!(r.p16().unwrap().as_ref(), uin.to_string().as_bytes());
            assert_eq!(r.remaining(), 0);
        }
    }

    #[test]
    fn password_verification_commits_the_account_from_field_two() {
        let codec = NtLogin::new().unwrap();
        let mut store = Keystore {
            uin: 123456,
            key_exchange_session: Some(test_session()),
            ..Default::default()
        };
        let body = auth::NtPasswordVerificationResponseBody {
            tickets: Some(auth::NtTickets {
                a1: Some(Bytes::from_static(b"verified-a1")),
                a2: Some(Bytes::from_static(b"verified-a2")),
                d2: Some(Bytes::from_static(b"verified-d2")),
                d2_key: Some(Bytes::from_static(&[7; 16])),
                ..Default::default()
            }),
            account: Some(auth::NtAccount {
                uin: Some(987654),
                uid: Some("u_verified".into()),
                ..Default::default()
            }),
        };
        let common = auth::NtResponse {
            head: Some(auth::NtResponseHead::default()),
            body: Some(body.encode_to_vec().into()),
        }
        .encode_to_vec();
        let forward = auth::NtForward {
            encrypted: Some(
                crypto::aes_gcm_encrypt(&common, session_key(&store))
                    .unwrap()
                    .into(),
            ),
            ..Default::default()
        }
        .encode_to_vec();
        codec
            .decode(
                forward.into(),
                &mut store,
                NtResponseKind::PasswordVerification,
                1_000,
            )
            .unwrap()
            .require_success()
            .unwrap();
        assert_eq!(store.uin, 987654);
        assert_eq!(store.uid, "u_verified");
        assert_eq!(store.a1, b"verified-a1");
        assert_eq!(store.d2_key, [7; 16]);
    }

    fn long_cookie_state(uin: u64) -> SessionState {
        SessionState {
            profile: Profile::linux(),
            keystore: Keystore {
                uin,
                key_exchange_session: Some(test_session()),
                ..Default::default()
            },
            machine_id: "synthetic-machine".into(),
            online: false,
        }
    }

    fn long_cookie_response(
        store: &Keystore,
        kind: NtResponseKind,
        code: u64,
        long_cookie: Option<auth::NtCookie>,
    ) -> Bytes {
        let tickets = (code == 0).then(|| auth::NtTickets {
            a1: Some(Bytes::from_static(b"synthetic-a1")),
            a2: Some(Bytes::from_static(b"synthetic-a2")),
            d2: Some(Bytes::from_static(b"synthetic-d2")),
            d2_key: Some(Bytes::from_static(&[7; 16])),
            ..Default::default()
        });
        let account = Some(auth::NtAccount {
            uin: Some(999999),
            ..Default::default()
        });
        let body = match kind {
            NtResponseKind::Password => auth::NtPasswordResponseBody {
                tickets,
                account,
                ..Default::default()
            }
            .encode_to_vec(),
            NtResponseKind::Easy => auth::NtEasyLoginResponseBody {
                tickets,
                ..Default::default()
            }
            .encode_to_vec(),
            NtResponseKind::Refresh => auth::NtRefreshTicketResponseBody {
                tickets,
                account: None,
            }
            .encode_to_vec(),
            NtResponseKind::NewDevice => {
                auth::NtNewDeviceResponseBody { tickets, account }.encode_to_vec()
            }
            NtResponseKind::PasswordVerification => {
                auth::NtPasswordVerificationResponseBody { tickets, account }.encode_to_vec()
            }
        };
        let common = auth::NtResponse {
            head: Some(auth::NtResponseHead {
                error: Some(auth::NtError {
                    code: Some(code),
                    ..Default::default()
                }),
                cookie: Some(auth::NtCookie {
                    cookie: Some(Bytes::from_static(b"challenge-cookie-five")),
                }),
                long_cookie,
            }),
            body: Some(body.into()),
        };
        auth::NtForward {
            encrypted: Some(
                crypto::aes_gcm_encrypt(&common.encode_to_vec(), session_key(store))
                    .unwrap()
                    .into(),
            ),
            ..Default::default()
        }
        .encode_to_vec()
        .into()
    }

    fn consume_long_cookie_response(
        codec: &mut NtLogin,
        state: &mut SessionState,
        kind: NtResponseKind,
        response: Bytes,
    ) -> Result<NtResult> {
        let requested_account = state.keystore.uin.to_string();
        let result = codec.decode(response, &mut state.keystore, kind, 1_000)?;
        codec.finish_response(kind, &requested_account, &result);
        Ok(result)
    }

    fn encoded_login_head(
        codec: &NtLogin,
        state: &SessionState,
        kind: NtResponseKind,
    ) -> auth::NtRequestHead {
        let forward: auth::NtForward = proto::decode(
            codec
                .encode(&auth::NtLoginBody::default(), state, kind)
                .unwrap(),
        )
        .unwrap();
        let clear =
            crypto::aes_gcm_decrypt(&forward.encrypted.unwrap(), session_key(&state.keystore))
                .unwrap();
        let request: auth::NtRequest = proto::decode(clear.as_slice()).unwrap();
        request.head.unwrap()
    }

    #[test]
    fn long_cookie_has_native_wire_presence_and_is_consumed_by_the_next_password_request() {
        let cookie = Bytes::from_static(b"\xff\x00\xc0\x80");
        let head: auth::NtResponseHead =
            proto::decode(Bytes::from_static(b"\x42\x06\x0a\x04\xff\x00\xc0\x80")).unwrap();
        assert_eq!(
            head.long_cookie.as_ref().unwrap().cookie.as_ref(),
            Some(&cookie)
        );
        assert_eq!(head.encode_to_vec(), b"\x42\x06\x0a\x04\xff\x00\xc0\x80");
        let mut codec = NtLogin::new().unwrap();
        let mut state = long_cookie_state(123456);
        assert!(
            encoded_login_head(&codec, &state, NtResponseKind::Password)
                .long_cookie
                .is_none()
        );
        let response = long_cookie_response(
            &state.keystore,
            NtResponseKind::Password,
            140022015,
            head.long_cookie,
        );
        let result = consume_long_cookie_response(
            &mut codec,
            &mut state,
            NtResponseKind::Password,
            response,
        )
        .unwrap();
        assert_eq!(result.long_cookie, Some(cookie.clone()));
        assert_eq!(state.keystore.uin, 123456);
        let head = encoded_login_head(&codec, &state, NtResponseKind::Password);
        assert_eq!(head.long_cookie.unwrap().cookie, Some(cookie));
        assert_eq!(
            head.cookie.unwrap().cookie.as_deref(),
            Some(b"challenge-cookie-five".as_slice()),
        );
        assert!(
            encoded_login_head(&codec, &state, NtResponseKind::Easy)
                .long_cookie
                .is_none()
        );
        state.keystore.login_cookie.clear();
        assert!(
            encoded_login_head(&codec, &state, NtResponseKind::Password)
                .long_cookie
                .is_some()
        );
    }

    #[test]
    fn long_cookie_final_failure_collapses_missing_and_empty_to_removal() {
        for absent in [
            None,
            Some(auth::NtCookie { cookie: None }),
            Some(auth::NtCookie {
                cookie: Some(Bytes::new()),
            }),
        ] {
            let mut codec = NtLogin::new().unwrap();
            let mut state = long_cookie_state(123456);
            let response = long_cookie_response(
                &state.keystore,
                NtResponseKind::Password,
                140022015,
                Some(auth::NtCookie {
                    cookie: Some(Bytes::from_static(b"old-eight")),
                }),
            );
            consume_long_cookie_response(
                &mut codec,
                &mut state,
                NtResponseKind::Password,
                response,
            )
            .unwrap();
            let response =
                long_cookie_response(&state.keystore, NtResponseKind::Password, 140022015, absent);
            let result = consume_long_cookie_response(
                &mut codec,
                &mut state,
                NtResponseKind::Password,
                response,
            )
            .unwrap();
            assert!(result.long_cookie.is_none());
            assert!(
                encoded_login_head(&codec, &state, NtResponseKind::Password)
                    .long_cookie
                    .is_none()
            );
            assert_eq!(state.keystore.login_cookie, b"challenge-cookie-five");
        }
    }

    #[test]
    fn long_cookie_is_isolated_by_request_account_and_codec_lifetime() {
        let mut codec = NtLogin::new().unwrap();
        let mut first = long_cookie_state(123456);
        let mut second = long_cookie_state(654321);
        for (state, cookie) in [
            (&mut first, Bytes::from_static(b"first-eight")),
            (&mut second, Bytes::from_static(b"second-eight")),
        ] {
            let response = long_cookie_response(
                &state.keystore,
                NtResponseKind::Password,
                140022015,
                Some(auth::NtCookie {
                    cookie: Some(cookie),
                }),
            );
            consume_long_cookie_response(&mut codec, state, NtResponseKind::Password, response)
                .unwrap();
        }
        for (state, cookie) in [
            (&first, b"first-eight".as_slice()),
            (&second, b"second-eight".as_slice()),
        ] {
            assert_eq!(
                encoded_login_head(&codec, state, NtResponseKind::Password)
                    .long_cookie
                    .unwrap()
                    .cookie
                    .as_deref(),
                Some(cookie),
            );
            assert!(
                encoded_login_head(&NtLogin::new().unwrap(), state, NtResponseKind::Password,)
                    .long_cookie
                    .is_none()
            );
        }
        assert!(
            encoded_login_head(&codec, &long_cookie_state(999999), NtResponseKind::Password,)
                .long_cookie
                .is_none()
        );
        let response =
            long_cookie_response(&first.keystore, NtResponseKind::Password, 140022015, None);
        consume_long_cookie_response(&mut codec, &mut first, NtResponseKind::Password, response)
            .unwrap();
        assert!(
            encoded_login_head(&codec, &first, NtResponseKind::Password)
                .long_cookie
                .is_none()
        );
        assert!(
            encoded_login_head(&codec, &second, NtResponseKind::Password)
                .long_cookie
                .is_some()
        );
    }

    #[test]
    fn long_cookie_ignores_password_challenges_success_and_other_rpc_responses() {
        for (kind, code) in [
            (NtResponseKind::Password, 0),
            (NtResponseKind::Password, 140022008),
            (NtResponseKind::Password, 140022010),
            (NtResponseKind::Easy, 140022015),
            (NtResponseKind::Refresh, 140022015),
            (NtResponseKind::NewDevice, 140022015),
            (NtResponseKind::PasswordVerification, 140022015),
        ] {
            for cookie in [
                None,
                Some(auth::NtCookie {
                    cookie: Some(Bytes::from_static(b"must-not-replace-eight")),
                }),
            ] {
                let mut codec = NtLogin::new().unwrap();
                let mut state = long_cookie_state(123456);
                let response = long_cookie_response(
                    &state.keystore,
                    NtResponseKind::Password,
                    140022015,
                    Some(auth::NtCookie {
                        cookie: Some(Bytes::from_static(b"retained-eight")),
                    }),
                );
                consume_long_cookie_response(
                    &mut codec,
                    &mut state,
                    NtResponseKind::Password,
                    response,
                )
                .unwrap();
                let response = long_cookie_response(&state.keystore, kind, code, cookie.clone());
                let result =
                    consume_long_cookie_response(&mut codec, &mut state, kind, response).unwrap();
                assert_eq!(result.long_cookie, cookie.and_then(|cookie| cookie.cookie));
                state.keystore.uin = 123456;
                assert_eq!(
                    encoded_login_head(&codec, &state, NtResponseKind::Password)
                        .long_cookie
                        .unwrap()
                        .cookie
                        .as_deref(),
                    Some(b"retained-eight".as_slice()),
                );
                assert!(
                    encoded_login_head(
                        &codec,
                        &long_cookie_state(999999),
                        NtResponseKind::Password,
                    )
                    .long_cookie
                    .is_none()
                );
            }
        }
    }

    #[test]
    fn long_cookie_local_response_errors_and_empty_account_do_not_remove_cached_value() {
        let mut codec = NtLogin::new().unwrap();
        let mut state = long_cookie_state(123456);
        let response = long_cookie_response(
            &state.keystore,
            NtResponseKind::Password,
            140022015,
            Some(auth::NtCookie {
                cookie: Some(Bytes::from_static(b"retained-eight")),
            }),
        );
        let result = consume_long_cookie_response(
            &mut codec,
            &mut state,
            NtResponseKind::Password,
            response,
        )
        .unwrap();
        codec.finish_response(NtResponseKind::Password, "", &result);
        assert!(!codec.long_cookies.contains_key(""));
        let invalid_body = auth::NtResponse {
            head: Some(auth::NtResponseHead {
                error: Some(auth::NtError {
                    code: Some(140022015),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            body: Some(Bytes::from_static(b"\xff")),
        };
        let invalid_body = auth::NtForward {
            encrypted: Some(
                crypto::aes_gcm_encrypt(
                    &invalid_body.encode_to_vec(),
                    session_key(&state.keystore),
                )
                .unwrap()
                .into(),
            ),
            ..Default::default()
        }
        .encode_to_vec();
        let invalid_ciphertext = auth::NtForward {
            encrypted: Some(Bytes::from_static(b"invalid-authentication-tag")),
            ..Default::default()
        }
        .encode_to_vec();
        for response in [vec![0xff], invalid_body, invalid_ciphertext] {
            assert!(
                consume_long_cookie_response(
                    &mut codec,
                    &mut state,
                    NtResponseKind::Password,
                    response.into(),
                )
                .is_err()
            );
            assert_eq!(
                encoded_login_head(&codec, &state, NtResponseKind::Password)
                    .long_cookie
                    .unwrap()
                    .cookie
                    .as_deref(),
                Some(b"retained-eight".as_slice()),
            );
        }
        codec.long_cookies.insert("123456".into(), Bytes::new());
        assert!(
            encoded_login_head(&codec, &state, NtResponseKind::Password)
                .long_cookie
                .is_none()
        );
    }

    #[test]
    fn mobile_uin_password_replays_long_cookie_for_each_profile() {
        for profile in [Profile::iphone(), Profile::ipad()] {
            let mut codec = NtLogin::with_device(Some(IosDevice {
                system_version: "18.0".into(),
                hardware_model: "synthetic-model".into(),
                system_name: "iOS".into(),
            }))
            .unwrap();
            let mut state = long_cookie_state(123456);
            state.profile = profile;
            let response = long_cookie_response(
                &state.keystore,
                NtResponseKind::Password,
                140022015,
                Some(auth::NtCookie {
                    cookie: Some(Bytes::from_static(b"mobile-eight")),
                }),
            );
            consume_long_cookie_response(
                &mut codec,
                &mut state,
                NtResponseKind::Password,
                response,
            )
            .unwrap();
            let head = encoded_login_head(&codec, &state, NtResponseKind::Password);
            assert_eq!(head.account.unwrap().uin.as_deref(), Some("123456"));
            assert_eq!(
                head.long_cookie.unwrap().cookie.as_deref(),
                Some(b"mobile-eight".as_slice())
            );
            assert!(head.security.is_none());
        }
    }

    #[test]
    fn valid_head_only_final_password_failure_removes_long_cookie() {
        let mut codec = NtLogin::new().unwrap();
        let mut state = long_cookie_state(123456);
        let response = long_cookie_response(
            &state.keystore,
            NtResponseKind::Password,
            140022015,
            Some(auth::NtCookie {
                cookie: Some(Bytes::from_static(b"old-eight")),
            }),
        );
        consume_long_cookie_response(&mut codec, &mut state, NtResponseKind::Password, response)
            .unwrap();
        let common = auth::NtResponse {
            head: Some(auth::NtResponseHead {
                error: Some(auth::NtError {
                    code: Some(140022015),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            body: None,
        };
        let response = auth::NtForward {
            encrypted: Some(
                crypto::aes_gcm_encrypt(&common.encode_to_vec(), session_key(&state.keystore))
                    .unwrap()
                    .into(),
            ),
            ..Default::default()
        }
        .encode_to_vec();
        consume_long_cookie_response(
            &mut codec,
            &mut state,
            NtResponseKind::Password,
            response.into(),
        )
        .unwrap();
        assert!(
            encoded_login_head(&codec, &state, NtResponseKind::Password)
                .long_cookie
                .is_none()
        );
    }
}
