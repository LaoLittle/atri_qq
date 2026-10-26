use crate::{
    Error, Result,
    crypto::{self, Curve, Ecdh},
    models::*,
    proto::{self, auth},
    wire::{Writer, malformed},
};
use bytes::Bytes;
use prost::Message;

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
    exchange_prepared: bool,
}
impl NtLogin {
    pub fn new() -> Result<Self> {
        Ok(Self {
            ecdh: Ecdh::new(Curve::P256)?,
            exchange_prepared: false,
        })
    }
    pub fn key_exchange(&mut self, state: &SessionState, timestamp: u32) -> Result<Bytes> {
        if self.exchange_prepared {
            self.ecdh = Ecdh::new(Curve::P256)?;
        }
        self.exchange_prepared = true;
        let server=hex::decode("049d1423332735980edabe7e9ea451b3395b6f35250db8fc56f25889f628cbae3e8e73077914071eeebc108f4e0170057792bb17aa303af652313d17c1ac815e79").map_err(|e|malformed(e.to_string()))?;
        let shared = self.ecdh.shared_secret(&server, false)?;
        let secret = auth::KeyExchangeSecret {
            uin: Some(state.keystore.uin.to_string()),
            guid: Some(Bytes::copy_from_slice(&state.keystore.guid)),
        }
        .encode_to_vec();
        let encrypted = crypto::aes_gcm_encrypt(&secret, &shared)?;
        let mut verify = Writer::new();
        verify.bytes(self.ecdh.public_key());
        verify.u32(1);
        verify.bytes(&encrypted);
        verify.u32(0);
        verify.u32(timestamp);
        let hash_key =
            hex::decode("e2733bf403149913cbf80c7a95168bd4ca6935ee53cd39764beebe2e007e3aee")
                .map_err(|e| malformed(e.to_string()))?;
        let hash = crypto::aes_gcm_encrypt(&crypto::sha256(&verify.data), &hash_key)?;
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
    pub fn decode_key_exchange(&self, data: Bytes) -> Result<(Vec<u8>, Vec<u8>)> {
        let p: auth::KeyExchangeResponse = proto::decode(data)?;
        let public = p
            .public_key
            .ok_or_else(|| malformed("Key exchange peer public key missing"))?;
        let encrypted = p
            .encrypted_secret
            .ok_or_else(|| malformed("Key exchange ciphertext missing"))?;
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
        Ok((ticket.to_vec(), key.to_vec()))
    }
    pub fn encode(&self, body: &impl Message, state: &SessionState) -> Result<Bytes> {
        let p = &state.profile;
        let k = &state.keystore;
        if k.key_exchange_ticket.is_empty() {
            return Err(Error::Authentication("NT key exchange required".into()));
        }
        let platform = match p.os.as_str() {
            "Linux" => 7,
            "Windows" => 4,
            "Mac" | "macOS" => 5,
            _ => 0,
        };
        let head = auth::NtRequestHead {
            account: Some(auth::NtAccountRequest {
                uin: Some(k.uin.to_string()),
            }),
            client: Some(auth::NtClient {
                os: Some(p.os.clone()),
                device_name: Some(k.device_name.clone()),
                platform: Some(platform),
                guid: Some(Bytes::copy_from_slice(&k.guid)),
            }),
            app: Some(auth::NtApp {
                kernel: Some(p.kernel.clone()),
                app_id: Some(p.app_id),
                package_name: Some(p.package_name.clone()),
                qua: Some(p.qua.clone()),
            }),
            cookie: (!k.login_cookie.is_empty()).then(|| auth::NtCookie {
                cookie: Some(Bytes::copy_from_slice(&k.login_cookie)),
            }),
            security: Some(auth::NtSecurity { mode: Some(1) }),
        };
        let common = auth::NtRequest {
            head: Some(head),
            body: Some(body.encode_to_vec().into()),
        }
        .encode_to_vec();
        let encrypted = crypto::aes_gcm_encrypt(&common, &k.key_exchange_key)?;
        Ok(auth::NtForward {
            ticket: Some(Bytes::copy_from_slice(&k.key_exchange_ticket)),
            encrypted: Some(encrypted.into()),
            r#type: Some(1),
        }
        .encode_to_vec()
        .into())
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
        let common: auth::NtResponse = proto::decode(Bytes::from(crypto::aes_gcm_decrypt(
            &encrypted,
            &store.key_exchange_key,
        )?))?;
        let head = common
            .head
            .ok_or_else(|| malformed("NT login response head missing"))?;
        let error = head.error.unwrap_or_default();
        let code = error.code.unwrap_or_default();
        let body = match common.body {
            Some(body) => body,
            None if code != 0 && matches!(kind, NtResponseKind::Refresh) => Bytes::new(),
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
        })
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
        let mut key = Writer::new();
        key.bytes(password_digest);
        key.u64(k.uin);
        let mut tgtgt = [0; 16];
        rand::TryRng::try_fill_bytes(&mut rand::rngs::SysRng, &mut tgtgt)
            .map_err(|error| Error::Crypto(format!("Password login entropy: {error}")))?;
        let mut w = Writer::new();
        w.u16(4);
        w.u32(rand::random::<u32>() % (i32::MAX as u32));
        w.u32(0);
        w.u32(state.profile.app_id);
        w.u32(8001);
        w.u64(k.uin);
        w.u32(super::unix_seconds());
        w.u32(0);
        w.u8(1);
        w.bytes(password_digest);
        w.bytes(tgtgt);
        w.u32(0);
        w.u8(1);
        w.bytes(&k.guid);
        w.u32(1);
        w.u32(1);
        w.p16(k.uin.to_string())?;
        Ok(crypto::tea_encrypt(&w.data, &crypto::md5(&key.data))?.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            }),
            body: (code == 0).then(|| {
                auth::NtRefreshTicketResponseBody { tickets, account }
                    .encode_to_vec()
                    .into()
            }),
        };
        auth::NtForward {
            encrypted: Some(
                crypto::aes_gcm_encrypt(&common.encode_to_vec(), &store.key_exchange_key)
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
            key_exchange_key: vec![42; 16],
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
        codec.decode(response, &mut store, NtResponseKind::Refresh, 1_000)
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
                codec.decode(response, &mut store, NtResponseKind::Refresh, 9_000)
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
        codec.decode(response, &mut store, NtResponseKind::Refresh, 1_000)
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
        let result = codec.decode(response, &mut store, NtResponseKind::Refresh, 1_000)
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
                crypto::aes_gcm_encrypt(&common.encode_to_vec(), &store.key_exchange_key)
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
            key_exchange_key: vec![42; 16],
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
            codec.decode(response, &mut store, NtResponseKind::Easy, 1_000)
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
        codec.decode(response, &mut store, NtResponseKind::Easy, 1_000)
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
            key_exchange_key: vec![42; 16],
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
            key_exchange_key: vec![42; 16],
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
        let encrypted = crypto::aes_gcm_encrypt(&common, &k.key_exchange_key).unwrap();
        let forward = auth::NtForward {
            encrypted: Some(encrypted.into()),
            ..Default::default()
        }
        .encode_to_vec()
        .into();
        assert!(codec.decode(forward, &mut k, NtResponseKind::Easy, 1_000).is_err());
        assert!(k == old);
        let forward = auth::NtForward {
            encrypted: Some(Bytes::from_static(&[0; 28])),
            ..Default::default()
        }
        .encode_to_vec()
        .into();
        assert!(codec.decode(forward, &mut k, NtResponseKind::Easy, 1_000).is_err());
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
                key_exchange_key: vec![42; 16],
                key_exchange_ticket: b"synthetic-exchange-ticket".to_vec(),
                ..Default::default()
            };
            let common = auth::NtResponse {
                head: Some(auth::NtResponseHead {
                    error: Some(auth::NtError {
                        code: Some(code),
                        ..Default::default()
                    }),
                    cookie: Some(decoded.clone()),
                }),
                body: Some(Bytes::new()),
            };
            let response = auth::NtForward {
                encrypted: Some(
                    crypto::aes_gcm_encrypt(&common.encode_to_vec(), &store.key_exchange_key)
                        .unwrap()
                        .into(),
                ),
                ..Default::default()
            };
            let result = codec.decode(response.encode_to_vec().into(), &mut store, kind, 1_000)
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
            let request: auth::NtForward =
                proto::decode(codec.encode(&auth::NtLoginBody::default(), &state).unwrap())
                    .unwrap();
            let clear = crypto::aes_gcm_decrypt(
                &request.encrypted.unwrap(),
                &state.keystore.key_exchange_key,
            )
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
            key_exchange_key: vec![42; 16],
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
                crypto::aes_gcm_encrypt(&common.encode_to_vec(), &store.key_exchange_key)
                    .unwrap()
                    .into(),
            ),
            ..Default::default()
        };
        codec.decode(response.encode_to_vec().into(), &mut store, NtResponseKind::Easy, 1_000)
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
        let timestamp = 1_712_345_678;
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
        verify.u32(0);
        verify.u32(timestamp);
        let hash_key =
            hex::decode("e2733bf403149913cbf80c7a95168bd4ca6935ee53cd39764beebe2e007e3aee")
                .unwrap();
        let hash = crypto::aes_gcm_decrypt(&request.encrypted_hash.unwrap(), &hash_key).unwrap();
        assert_eq!(hash, crypto::sha256(&verify.data));
        verify.data.truncate(verify.data.len() - 4);
        verify.u32(timestamp + 1);
        assert_ne!(hash, crypto::sha256(&verify.data));
    }

    #[test]
    fn renewed_key_exchange_rejects_previous_exchange_ciphertext() {
        fn reply(peer: &Ecdh, public: &[u8], ticket: &'static [u8]) -> Bytes {
            let shared = peer.shared_secret(public, false).unwrap();
            let secret = auth::KeyExchangeSession {
                key: Some(Bytes::from_static(&[7; 16])),
                ticket: Some(Bytes::from_static(ticket)),
            }
            .encode_to_vec();
            auth::KeyExchangeResponse {
                encrypted_secret: Some(crypto::aes_gcm_encrypt(&secret, &shared).unwrap().into()),
                public_key: Some(Bytes::copy_from_slice(peer.public_key())),
            }
            .encode_to_vec()
            .into()
        }

        let mut codec = NtLogin::new().unwrap();
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
            codec.decode_key_exchange(old_reply.clone()).unwrap().0,
            b"old-exchange"
        );
        let second: auth::KeyExchangeRequest =
            proto::decode(codec.key_exchange(&state, 1_712_345_679).unwrap()).unwrap();
        assert_ne!(first.public_key, second.public_key);
        assert!(codec.decode_key_exchange(old_reply).is_err());
        let current_reply = reply(
            &peer,
            second.public_key.as_ref().unwrap(),
            b"current-exchange",
        );
        let (ticket, key) = codec.decode_key_exchange(current_reply).unwrap();
        assert_eq!(ticket, b"current-exchange");
        assert_eq!(key, [7; 16]);
    }

    #[test]
    fn typed_key_exchange_preserves_authenticated_session_material() {
        let codec = NtLogin::new().unwrap();
        let peer = Ecdh::new(Curve::P256).unwrap();
        let shared = peer.shared_secret(codec.ecdh.public_key(), false).unwrap();
        let secret = auth::KeyExchangeSession {
            key: Some(Bytes::from_static(&[7; 16])),
            ticket: Some(Bytes::from_static(b"exchange-ticket")),
        }
        .encode_to_vec();
        let mut reply = auth::KeyExchangeResponse {
            encrypted_secret: Some(crypto::aes_gcm_encrypt(&secret, &shared).unwrap().into()),
            public_key: Some(Bytes::copy_from_slice(peer.public_key())),
        }
        .encode_to_vec();
        reply.extend_from_slice(&[0x12, 72]);
        reply.extend_from_slice(&[0xa5; 72]);
        let (ticket, key) = codec.decode_key_exchange(reply.into()).unwrap();
        assert_eq!(ticket, b"exchange-ticket");
        assert_eq!(key, [7; 16]);
    }

    #[test]
    fn easy_login_protection_accepts_ciphertext_only_forward_without_replacing_tickets() {
        let codec = NtLogin::new().unwrap();
        let mut store = Keystore {
            key_exchange_key: vec![42; 16],
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
            }),
            body: Some(body.encode_to_vec().into()),
        };
        let forward = auth::NtForward {
            encrypted: Some(
                crypto::aes_gcm_encrypt(&common.encode_to_vec(), &store.key_exchange_key)
                    .unwrap()
                    .into(),
            ),
            ticket: None,
            r#type: None,
        };
        let result = codec.decode(forward.encode_to_vec().into(), &mut store, NtResponseKind::Easy, 1_000)
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
            key_exchange_key: vec![42; 16],
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
            }),
            body: Some(
                auth::NtEasyLoginResponseBody::default()
                    .encode_to_vec()
                    .into(),
            ),
        };
        let forward = auth::NtForward {
            encrypted: Some(
                crypto::aes_gcm_encrypt(&common.encode_to_vec(), &store.key_exchange_key)
                    .unwrap()
                    .into(),
            ),
            ..Default::default()
        };
        let result = codec.decode(forward.encode_to_vec().into(), &mut store, NtResponseKind::Easy, 1_000)
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
            key_exchange_key: vec![42; 16],
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
            }),
            body: Some(body.encode_to_vec().into()),
        }
        .encode_to_vec();
        let forward = auth::NtForward {
            encrypted: Some(
                crypto::aes_gcm_encrypt(&common, &k.key_exchange_key)
                    .unwrap()
                    .into(),
            ),
            ..Default::default()
        }
        .encode_to_vec();
        codec.decode(forward.into(), &mut k, NtResponseKind::Password, 1_000)
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
            key_exchange_key: vec![42; 16],
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
                crypto::aes_gcm_encrypt(&common, &store.key_exchange_key)
                    .unwrap()
                    .into(),
            ),
            ..Default::default()
        }
        .encode_to_vec();
        codec.decode(forward.into(), &mut store, NtResponseKind::PasswordVerification, 1_000)
            .unwrap()
            .require_success()
            .unwrap();
        assert_eq!(store.uin, 987654);
        assert_eq!(store.uid, "u_verified");
        assert_eq!(store.a1, b"verified-a1");
        assert_eq!(store.d2_key, [7; 16]);
    }
}
