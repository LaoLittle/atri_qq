use crate::{
    Error, Result,
    client::Client,
    crypto,
    models::*,
    proto::{self, auth},
    wire::{Reader, malformed},
};
use base64::Engine;
use bytes::Bytes;
use prost::Message;
use serde::Deserialize;
use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::oneshot;
mod nt;
mod wt;
use nt::{NtLogin, NtResponseKind, NtResult};

#[cfg(test)]
mod risk_tests;
use wt::{Tlv, WtLogin};

enum PlatformLoginCodecs {
    Linux(WtLogin),
    Ios,
}

pub(crate) struct LoginCodecs {
    platform: PlatformLoginCodecs,
    nt: NtLogin,
    registered_session: bool,
}

impl LoginCodecs {
    #[cfg(test)]
    fn new() -> Result<Self> {
        Self::for_config(&ClientConfig::default())
    }

    fn for_config(config: &ClientConfig) -> Result<Self> {
        let ios = config.profile.platform.is_ios();
        if ios != config.ios().is_some() {
            return Err(Error::Authentication(
                "Login profile and platform resources do not match".into(),
            ));
        }
        Ok(Self {
            platform: if ios {
                PlatformLoginCodecs::Ios
            } else {
                PlatformLoginCodecs::Linux(WtLogin::new()?)
            },
            nt: NtLogin::new()?,
            registered_session: false,
        })
    }

    fn wt(&mut self) -> Result<&mut WtLogin> {
        match &mut self.platform {
            PlatformLoginCodecs::Linux(codec) => Ok(codec),
            PlatformLoginCodecs::Ios => Err(Error::Unsupported(
                "Desktop WT login is unavailable for iOS".into(),
            )),
        }
    }
}
pub(super) fn unix_seconds() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as u32)
}
struct LoginGuard<'a> {
    client: &'a Client,
    armed: bool,
}
impl Drop for LoginGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.client.terminate("Login canceled or failed".into())
        }
    }
}

pub(crate) async fn login(client: &Arc<Client>) -> Result<UserInfo> {
    let _gate = client
        .login_gate
        .try_lock()
        .map_err(|_| Error::Authentication("Login or ticket refresh is already running".into()))?;
    let state = client.snapshot().await;
    if state.online {
        return Ok(UserInfo::from(&state.keystore));
    }
    if state.profile.platform.is_ios() {
        info_sync_for_config_at(
            &state,
            false,
            &client.config,
            client.ios_registration_context()?,
        )?;
        if state.keystore.a1.is_empty()
            && client.config.password.as_deref().is_none_or(str::is_empty)
        {
            return Err(Error::Unsupported(
                "iOS local QR login is not established; provide a native A1 ticket or numeric-UIN password credentials".into(),
            ));
        }
    }
    let mut guard = LoginGuard {
        client,
        armed: true,
    };
    client.connect().await?;
    client.begin_signing_login()?;
    client.start_alive();
    if state.profile.platform.is_ios() {
        client.start_ios_correct_time();
    } else if let Err(error) = client.correct_time().await {
        tracing::warn!(target: "atri_qq_protocol::login", %error, "Server clock correction unavailable");
    }
    let mut codecs = client.codecs.lock().await;
    if codecs.is_none() {
        *codecs = Some(LoginCodecs::for_config(&client.config)?)
    }
    let codecs = codecs.as_mut().unwrap();
    let result = run_login(client, codecs).await;
    match result {
        Ok(()) => {
            codecs.registered_session = true;
            guard.armed = false;
            Ok(UserInfo::from(&client.snapshot().await.keystore))
        }
        Err(error) => {
            guard.armed = false;
            client
                .close_transport(format!("Login failed: {error}"))
                .await;
            Err(error)
        }
    }
}
async fn run_login(client: &Arc<Client>, codecs: &mut LoginCodecs) -> Result<()> {
    // Restored tickets are not proof of a live, previously registered session.
    let reconnect = std::mem::replace(&mut codecs.registered_session, false);
    let state = client.snapshot().await;
    if reconnect && !state.keystore.d2.is_empty() && !state.keystore.a2.is_empty() {
        client.mark_signing_ticket_complete()?;
        if online(client, true).await? {
            return Ok(());
        }
        client.begin_signing_login()?;
    }
    let state = client.snapshot().await;
    if !state.keystore.a1.is_empty() {
        let original_a1 = Bytes::from(state.keystore.a1);
        client.clear_nt_login_cookie();
        let result = nt_call(
            client,
            &mut codecs.nt,
            "SsoNTLoginEasyLogin",
            &auth::NtLoginBody {
                a1: Some(original_a1.clone()),
                ..Default::default()
            },
            NtResponseKind::Easy,
        )
        .await?;
        if result.code == 0 {
            return require_online(client).await;
        }
        if state.profile.platform.is_ios() {
            if result.code == 140022011 {
                client.emit(LoginEvent::Challenge(result.security_challenge()));
                return Err(ios_easy_security_unsupported(&result));
            }
            if client.config.password.as_deref().is_none_or(str::is_empty) {
                return Err(Error::Unsupported(format!(
                    "iOS native A1 login was rejected (stage=easy, code={}); no password is configured and native local QR login is not established",
                    result.code,
                )));
            }
        }
        tracing::info!(target: "atri_qq_protocol::login",
            stage = "easy", code = result.code,
            device_verification = result.code == 140022011,
            next_step = if result.code == 140022011 {
                "unusual_device_qr"
            } else if client.config.password.as_deref().is_some_and(|v| !v.is_empty()) {
                "password_login"
            } else {
                "normal_qr_login"
            },
            "Cached easy login rejected; starting another authentication step");
        if result.code == 140022011 {
            let unusual = result
                .unusual_signature
                .filter(|v| !v.is_empty())
                .ok_or_else(|| malformed("Unusual-device protection signature missing"))?;
            qr_login(
                client,
                codecs,
                QrLoginMode::Verification {
                    kind: QrVerification::Easy,
                    signature: unusual,
                    a1: original_a1,
                },
            )
            .await?;
            return require_online(client).await;
        }
    }
    if let Some(password) = client.config.password.as_deref().filter(|v| !v.is_empty()) {
        password_login(client, codecs, password).await?
    } else {
        qr_login(client, codecs, QrLoginMode::Normal).await?
    }
    require_online(client).await
}
pub(crate) async fn refresh_tickets(client: &Arc<Client>) -> Result<()> {
    refresh_tickets_for_generation(client, client.connection_generation())
        .await
        .map(|_| ())
}

pub(crate) async fn refresh_tickets_for_generation(
    client: &Arc<Client>,
    generation: u64,
) -> Result<bool> {
    let Ok(_gate) = client.login_gate.try_lock() else {
        return Ok(false);
    };
    if !client.ticket_refresh_ready(generation)? {
        return Ok(false);
    }
    let mut codecs = client.codecs.lock().await;
    if codecs.is_none() {
        *codecs = Some(LoginCodecs::for_config(&client.config)?);
    }
    let codec = &mut codecs.as_mut().unwrap().nt;
    let mut state = client.snapshot().await;
    if !state
        .keystore
        .key_exchange_session
        .as_ref()
        .is_some_and(NtKeyExchangeSession::is_reusable)
    {
        let expected = state.keystore.clone();
        let request = codec.key_exchange(&state, client.nt_key_exchange_time()?)?;
        let response = client
            .request_nt_maintenance(
                generation,
                "trpc.login.ecdh.EcdhService.SsoKeyExchange",
                request,
            )
            .await?;
        let session =
            codec.decode_key_exchange(response, state.keystore.key_exchange_session.as_ref())?;
        state.keystore.key_exchange_session = Some(session);
        client.commit_nt_maintenance_state(generation, &expected, state)?;
        state = client.snapshot().await;
    }
    if !client.ticket_refresh_ready(generation)? {
        return Ok(false);
    }
    let request = codec.encode(
        &auth::NtRefreshTicketBody {
            a1: Some(Bytes::copy_from_slice(&state.keystore.a1)),
        },
        &state,
        NtResponseKind::Refresh,
    )?;
    let response = client
        .request_nt_maintenance(
            generation,
            "trpc.login.ecdh.EcdhService.SsoNTLoginRefreshTicket",
            request,
        )
        .await?;
    let expected = state.keystore.clone();
    let result = codec.decode(
        response,
        &mut state.keystore,
        NtResponseKind::Refresh,
        u64::from(client.server_time_seconds()?),
    )?;
    if result.code != 0 {
        client.record_ticket_refresh_result(generation, false)?;
        return Err(Error::Server {
            code: result.code as i32,
            message: format!(
                "{}: {}",
                redact_login_urls(&result.title),
                redact_login_urls(&result.message),
            ),
        });
    }
    let times = state.keystore.nt_ticket_times;
    client.commit_nt_maintenance_state(generation, &expected, state)?;
    client.record_ticket_refresh_result(generation, true)?;
    trace_ticket_times("SsoNTLoginRefreshTicket", times);
    Ok(true)
}
async fn key_exchange(client: &Client, codec: &mut NtLogin) -> Result<()> {
    let state = client.snapshot().await;
    let request = codec.key_exchange(&state, client.nt_key_exchange_time()?)?;
    let response = client
        .call(
            "trpc.login.ecdh.EcdhService.SsoKeyExchange",
            request,
            Encryption::Empty,
        )
        .await?;
    let session =
        codec.decode_key_exchange(response, state.keystore.key_exchange_session.as_ref())?;
    let mut state = client.snapshot().await;
    state.keystore.key_exchange_session = Some(session);
    client.replace_state(state).await;
    Ok(())
}
async fn nt_call(
    client: &Client,
    codec: &mut NtLogin,
    method: &str,
    body: &impl Message,
    kind: NtResponseKind,
) -> Result<NtResult> {
    let mut state = client.snapshot().await;
    if !state
        .keystore
        .key_exchange_session
        .as_ref()
        .is_some_and(NtKeyExchangeSession::is_reusable)
    {
        key_exchange(client, codec).await?;
        state = client.snapshot().await;
    }
    let requested_uin = state.keystore.uin;
    let mut requested_account = itoa::Buffer::new();
    let requested_account = requested_account.format(requested_uin);
    let request = codec.encode(body, &state, kind)?;
    let response = client
        .call(
            &format!("trpc.login.ecdh.EcdhService.{method}"),
            request,
            Encryption::Empty,
        )
        .await?;
    let mut state = client.snapshot().await;
    let result = codec.decode(
        response,
        &mut state.keystore,
        kind,
        u64::from(client.server_time_seconds()?),
    )?;
    if state.profile.platform.is_ios() {
        codec.finish_response(kind, requested_account, &result);
    }
    let cached_a1_invalidated = state.keystore.uin == requested_uin
        && !state.keystore.a1.is_empty()
        && result.code != 0
        && !matches!(
            result.code,
            140022002 | 140022008 | 140022010 | 140022011 | 140022019
        );
    if cached_a1_invalidated {
        state.keystore.a1.clear();
    }
    let ticket_times = state.keystore.nt_ticket_times;
    client.replace_state(state).await;
    if result.code == 0 {
        trace_ticket_times(method, ticket_times);
        client.mark_signing_ticket_complete()?;
    } else {
        // Keep the server's reason even if the caller starts a fresh login.
        // URLs, cookies and signatures are authentication material: log only
        // their presence/length, never their contents.
        tracing::warn!(target: "atri_qq_protocol::login",
            method, code = result.code,
            server_title = %redact_login_urls(&result.title),
            server_message = %redact_login_urls(&result.message),
            server_jump_word = %redact_login_urls(&result.jump_word),
            jump_url_present = !result.jump_url.is_empty(),
            unusual_signature_length = result.unusual_signature.as_ref().map_or(0, |v| v.len()),
            captcha_url_present = result.captcha_url.as_ref().is_some_and(|v| !v.is_empty()),
            cached_a1_invalidated,
            "NT login returned an authentication error");
    }
    Ok(result)
}

fn trace_ticket_times(method: &str, times: Option<NtTicketTimeMetadata>) {
    if let Some(times) = times {
        let selected = times.selected();
        tracing::debug!(target: "atri_qq_protocol::packet_trace",
            stage = "nt_ticket_times", method,
            received_unix_ms = times.received_unix_ms,
            field12_present = times.field12.is_some(),
            field12_raw_field1 = ?times.field12.and_then(|v| v.raw_field1),
            field12_raw_field2 = ?times.field12.and_then(|v| v.raw_field2),
            field16_present = times.field16.is_some(),
            field16_raw_field1 = ?times.field16.and_then(|v| v.raw_field1),
            field16_raw_field2 = ?times.field16.and_then(|v| v.raw_field2),
            selected_field = ?times.field12.map(|_| 12u32).or_else(|| times.field16.map(|_| 16)),
            selected_raw_field1 = ?selected.and_then(|v| v.raw_field1),
            selected_raw_field2 = ?selected.and_then(|v| v.raw_field2),
            next_refresh_unix_seconds = ?times.next_refresh_unix_seconds(),
            "QQ NT ticket time metadata");
    }
}

fn redact_login_urls(text: &str) -> std::borrow::Cow<'_, str> {
    let first_url = |value: &str| {
        [
            value
                .as_bytes()
                .windows(8)
                .position(|bytes| bytes.eq_ignore_ascii_case(b"https://")),
            value
                .as_bytes()
                .windows(7)
                .position(|bytes| bytes.eq_ignore_ascii_case(b"http://")),
        ]
        .into_iter()
        .flatten()
        .min()
    };
    let Some(mut start) = first_url(text) else {
        return std::borrow::Cow::Borrowed(text);
    };
    let mut remaining = text;
    let mut redacted = String::with_capacity(text.len());
    loop {
        redacted.push_str(&remaining[..start]);
        redacted.push_str("[redacted URL]");
        let end = remaining[start..]
            .find(char::is_whitespace)
            .map_or(remaining.len(), |end| start + end);
        remaining = &remaining[end..];
        match first_url(remaining) {
            Some(next) => start = next,
            None => {
                redacted.push_str(remaining);
                return std::borrow::Cow::Owned(redacted);
            }
        }
    }
}

#[cfg(test)]
mod diagnostic_tests {
    #[test]
    fn authentication_links_are_redacted_without_losing_the_error_context() {
        let reason = "client-risk HTTPS://verify.invalid/?ticket=secret-one continue http://verify.invalid/?proof=secret-two retry";
        let safe = super::redact_login_urls(reason);
        assert!(!safe.contains("secret-one"));
        assert!(!safe.contains("secret-two"));
        assert!(safe.starts_with("client-risk "));
        assert!(safe.contains(" continue "));
        assert!(safe.ends_with(" retry"));
    }
}
// No Debug implementation: these values are login credentials.
#[derive(Clone, Copy)]
enum QrVerification {
    Easy,
    Password,
}

enum QrLoginMode {
    Normal,
    Verification {
        kind: QrVerification,
        signature: Bytes,
        a1: Bytes,
    },
}

enum QrConfirmation {
    Normal {
        uin: u64,
        tgtgt_key: Bytes,
        no_pic_sig: Bytes,
        a1: Bytes,
    },
    Verification {
        kind: QrVerification,
        uin: u64,
        a1: Bytes,
        one_click_succeed_sig: Bytes,
    },
}

fn decode_qr_confirmation(
    r: &mut Reader,
    cached: &Keystore,
    mode: &QrLoginMode,
) -> Result<QrConfirmation> {
    use std::fmt::Write;
    let uin = r.u64()?;
    r.skip(4)?;
    let mut tlvs = Tlv::decode(r)?;
    let failure = if uin == 0 {
        Some("QR confirmation UIN is zero")
    } else {
        match mode {
            QrLoginMode::Normal if !tlvs.contains_key(&0x1e) => {
                Some("QR TGTGT key missing (TLV 0x001e absent)")
            }
            QrLoginMode::Normal if tlvs[&0x1e].len() != 16 => {
                Some("QR TGTGT key has invalid length (TLV 0x001e must contain 16 bytes)")
            }
            QrLoginMode::Normal if !tlvs.contains_key(&0x19) => {
                Some("QR no-picture signature missing (TLV 0x0019 absent)")
            }
            QrLoginMode::Normal if tlvs.get(&0x18).is_none_or(|v| v.is_empty()) => {
                Some("QR A1 ticket missing or empty (TLV 0x0018)")
            }
            QrLoginMode::Verification { .. } if tlvs.get(&0x3f).is_none_or(|v| v.is_empty()) => {
                Some("QR one-click success signature missing or empty (TLV 0x003f)")
            }
            _ => None,
        }
    };
    if let Some(failure) = failure {
        let mode_name = match mode {
            QrLoginMode::Normal => "normal",
            QrLoginMode::Verification {
                kind: QrVerification::Easy,
                ..
            } => "easy_verification",
            QrLoginMode::Verification {
                kind: QrVerification::Password,
                ..
            } => "password_verification",
        };
        let mut detail = format!("{failure}; mode={mode_name}; tlv_lengths=[");
        for (index, (tag, value)) in tlvs.iter().enumerate() {
            if index != 0 {
                detail.push_str(", ");
            }
            write!(detail, "0x{tag:04x}:{}", value.len()).expect("writing to String cannot fail");
        }
        write!(
            detail,
            "]; trailing_bytes={}; cached_tgtgt_length={}; cached_account_matches={}",
            r.remaining(),
            cached.tgtgt_key.len(),
            uin != 0 && uin == cached.uin
        )
        .expect("writing to String cannot fail");
        return Err(malformed(detail));
    }
    Ok(match mode {
        QrLoginMode::Normal => QrConfirmation::Normal {
            uin,
            tgtgt_key: tlvs.remove(&0x1e).unwrap(),
            no_pic_sig: tlvs.remove(&0x19).unwrap(),
            a1: tlvs.remove(&0x18).unwrap(),
        },
        QrLoginMode::Verification { kind, a1, .. } => QrConfirmation::Verification {
            kind: *kind,
            uin,
            // Verification continues the retained credential, not QR TLV 0x18.
            a1: a1.clone(),
            one_click_succeed_sig: tlvs.remove(&0x3f).unwrap(),
        },
    })
}

async fn qr_login(client: &Client, codecs: &mut LoginCodecs, mode: QrLoginMode) -> Result<()> {
    let mut state = client.snapshot().await;
    let unusual = match &mode {
        QrLoginMode::Normal => None,
        QrLoginMode::Verification { signature, .. } => Some(signature.as_ref()),
    };
    let request = codecs.wt()?.qr(0x31, unusual, &state)?;
    let response = client
        .call("wtlogin.trans_emp", request, Encryption::Empty)
        .await?;
    let (command, decoded) = codecs.wt()?.decode_qr(response, &state.keystore)?;
    if command != 0x31 {
        return Err(malformed("QR acquisition command mismatch"));
    }
    let mut r = Reader::new(decoded);
    r.skip(6)?;
    let code = r.u8()?;
    if code != 0 {
        return Err(Error::Server {
            code: code.into(),
            message: "QR acquisition rejected".into(),
        });
    }
    let signature = r.p16()?;
    let tlvs = Tlv::decode(&mut r)?;
    let ext = tlvs
        .get(&0xd1)
        .ok_or_else(|| malformed("QR URL extension missing"))?;
    let image = tlvs
        .get(&0x17)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| malformed("QR image missing"))?;
    let url = proto::decode::<auth::QrResponseExtension>(ext.clone())?
        .url
        .ok_or_else(|| malformed("QR URL missing"))?;
    reqwest::Url::parse(&url).map_err(|_| malformed("Invalid QR URL"))?;
    state.keystore.qr_sig = signature.to_vec();
    client.replace_state(state).await;
    client.emit(LoginEvent::QrCode {
        url,
        image: image.to_vec(),
    });
    loop {
        state = client.snapshot().await;
        let query = codecs.wt()?.qr(0x12, None, &state)?;
        let response = client
            .call("wtlogin.trans_emp", query, Encryption::Empty)
            .await?;
        let (command, decoded) = codecs.wt()?.decode_qr(response, &state.keystore)?;
        if command != 0x12 {
            return Err(malformed("QR query command mismatch"));
        }
        let mut r = Reader::new(decoded);
        r.skip(6)?;
        let qr_state = QrState::try_from(r.u8()?)?;
        client.emit(LoginEvent::QrState(qr_state));
        match qr_state {
            QrState::Confirmed => {
                let confirmation = decode_qr_confirmation(&mut r, &state.keystore, &mode)?;
                state = client.snapshot().await;
                match confirmation {
                    QrConfirmation::Normal {
                        uin,
                        tgtgt_key,
                        no_pic_sig,
                        a1,
                    } => {
                        state.keystore.uin = uin;
                        state.keystore.tgtgt_key = tgtgt_key.to_vec();
                        state.keystore.no_pic_sig = no_pic_sig.to_vec();
                        state.keystore.a1 = a1.to_vec();
                        client.replace_state(state).await;
                        wt_login(client, codecs.wt()?).await?;
                    }
                    QrConfirmation::Verification {
                        kind,
                        uin,
                        a1,
                        one_click_succeed_sig,
                    } => {
                        state.keystore.uin = uin;
                        client.replace_state(state).await;
                        let (method, response_kind) = match kind {
                            QrVerification::Easy => {
                                ("SsoNTLoginEasyLoginUnusualDevice", NtResponseKind::Easy)
                            }
                            QrVerification::Password => (
                                "SsoNTLoginPasswordLoginUnusualDevice",
                                NtResponseKind::PasswordVerification,
                            ),
                        };
                        nt_call(
                            client,
                            &mut codecs.nt,
                            method,
                            &auth::NtUnusualLoginBody {
                                a1: Some(a1),
                                one_click_succeed_sig: Some(one_click_succeed_sig),
                            },
                            response_kind,
                        )
                        .await?
                        .require_success()?;
                    }
                }
                return Ok(());
            }
            QrState::Waiting | QrState::Scanned => client.pause(Duration::from_secs(2)).await?,
            _ => {
                return Err(Error::Authentication(format!(
                    "QR login ended: {qr_state:?}"
                )));
            }
        }
    }
}
async fn wt_login(client: &Client, codec: &mut WtLogin) -> Result<()> {
    let state = client.snapshot().await;
    let request = codec.login(&state)?;
    let response = client
        .call("wtlogin.login", request, Encryption::Empty)
        .await?;
    let (command, decoded) = codec.decode(response, &state.keystore)?;
    if command != 0x810 {
        return Err(malformed("WT login command mismatch"));
    }
    let mut r = Reader::new(decoded);
    r.skip(2)?;
    let result = r.u8()?;
    let mut t = Tlv::decode(&mut r)?;
    wt::decode_login_error(result, &t)?;
    if let Some(encrypted) = t.get(&0x119) {
        let mut r = Reader::new(crypto::tea_decrypt(encrypted, &state.keystore.tgtgt_key)?);
        t = Tlv::decode(&mut r)?;
    }
    let mut state = client.snapshot().await;
    wt::apply_tickets(
        &t,
        &mut state.keystore,
        u64::from(client.server_time_seconds()?),
    )?;
    client.replace_state(state).await;
    client.mark_signing_ticket_complete()?;
    Ok(())
}
enum PasswordVerification {
    Captcha(auth::NtCaptcha),
    Device(IosDeviceVerificationResult),
}

struct LoginChallengeWait<'a, T>(&'a Mutex<Option<T>>);

impl<T> Drop for LoginChallengeWait<'_, T> {
    fn drop(&mut self) {
        self.0.lock().unwrap().take();
    }
}

async fn wait_for_login_challenge<T>(
    client: &Client,
    pending: &Mutex<Option<oneshot::Sender<T>>>,
    challenge: LoginChallenge,
) -> Result<T> {
    let cancel = client.cancellation();
    let (tx, rx) = oneshot::channel();
    *pending.lock().unwrap() = Some(tx);
    let _wait = LoginChallengeWait(pending);
    client.emit(LoginEvent::Challenge(challenge));
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(Error::Disconnected),
        answer = rx => answer.map_err(|_| Error::Disconnected),
    }
}
async fn wait_for_security_challenge(
    client: &Client,
    result: &NtResult,
) -> Result<IosLoginSecurityAction> {
    let cancel = client.cancellation();
    let (tx, rx) = oneshot::channel();
    *client.security.lock().unwrap() = Some(crate::client::PendingSecurity {
        challenge: result.security.clone(),
        reply: tx,
    });
    let _wait = LoginChallengeWait(&client.security);
    client.emit(LoginEvent::Challenge(result.security_challenge()));
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(Error::Disconnected),
        answer = rx => answer.map_err(|_| Error::Disconnected),
    }
}

fn ios_easy_security_unsupported(result: &NtResult) -> Error {
    Error::Unsupported(format!(
        "iOS Easy security continuation callbacks are not established (stage=easy, code={}, jump_url_present={}); ordinary Password callbacks and desktop WT QR cannot be applied to Easy",
        result.code,
        !result.jump_url.is_empty(),
    ))
}

async fn password_login(client: &Client, codecs: &mut LoginCodecs, password: &str) -> Result<()> {
    let mut state = client.snapshot().await;
    if client.config.uin > 0 {
        state.keystore.uin = client.config.uin
    }
    if state.keystore.uin == 0 {
        return Err(Error::Authentication(
            "Password login requires a numeric UIN".into(),
        ));
    }
    state.keystore.login_cookie.clear();
    client.replace_state(state).await;
    let password_digest = crypto::md5(password.as_bytes());
    let ios = client.config.profile.platform.is_ios();
    let mut verification = None;
    let mut need_remind_cancellated_status = true;
    loop {
        let device_retry = ios && matches!(&verification, Some(PasswordVerification::Device(_)));
        let a1 = if device_retry {
            Bytes::new()
        } else {
            NtLogin::password_a1(&password_digest, &client.snapshot().await)?
        };
        let body = auth::NtLoginBody {
            a1: (!device_retry).then(|| a1.clone()),
            captcha: match &verification {
                Some(PasswordVerification::Captcha(captcha)) => Some(captcha.clone()),
                _ => None,
            },
            device_check_succeed_sig: match &verification {
                Some(PasswordVerification::Device(result))
                    if ios && !result.signature.is_empty() =>
                {
                    Some(result.signature.clone())
                }
                _ => None,
            },
            login_process: ios.then_some(auth::NtLoginProcess {
                need_remind_cancellated_status: Some(need_remind_cancellated_status),
            }),
        };
        let result = nt_call(
            client,
            &mut codecs.nt,
            "SsoNTLoginPasswordLogin",
            &body,
            NtResponseKind::Password,
        )
        .await?;
        match result.code {
            0 => return Ok(()),
            140022008 => {
                let url = result
                    .captcha_url
                    .filter(|v| !v.is_empty())
                    .unwrap_or(result.jump_url);
                let parsed =
                    reqwest::Url::parse(&url).map_err(|_| malformed("Captcha URL invalid"))?;
                let sid = parsed
                    .query_pairs()
                    .find(|(key, _)| key == "sid")
                    .map(|(_, v)| v.into_owned())
                    .filter(|v| !v.is_empty())
                    .ok_or_else(|| malformed("Captcha URL has no SID"))?;
                let (ticket, random) = wait_for_login_challenge(
                    client,
                    &client.captcha,
                    LoginChallenge::Captcha { url },
                )
                .await?;
                verification = Some(PasswordVerification::Captcha(auth::NtCaptcha {
                    ticket: Some(ticket.into()),
                    random: Some(random.into()),
                    sid: Some(sid.into()),
                }));
            }
            140022010 if ios => {
                if result.jump_url.is_empty() {
                    return Err(malformed("iOS device verification URL missing"));
                }
                let verification_result = wait_for_login_challenge(
                    client,
                    &client.device_verification,
                    LoginChallenge::IosDeviceVerification {
                        url: result.jump_url,
                    },
                )
                .await?;
                verification = Some(PasswordVerification::Device(verification_result));
            }
            140022010 => return new_device_login(client, &mut codecs.nt, &result.jump_url).await,
            140022011 => {
                if ios {
                    if !result.security.can_continue() {
                        client.emit(LoginEvent::Challenge(result.security_challenge()));
                        return result.require_success();
                    }
                    match wait_for_security_challenge(client, &result).await? {
                        IosLoginSecurityAction::Continue { .. } => {
                            need_remind_cancellated_status = false;
                        }
                        IosLoginSecurityAction::WebVerified { .. } => {}
                        IosLoginSecurityAction::Cancel => {
                            return result.require_success();
                        }
                    }
                    verification = None;
                    continue;
                }
                let signature = result
                    .unusual_signature
                    .filter(|v| !v.is_empty())
                    .ok_or_else(|| malformed("Password unusual-device signature missing"))?;
                return qr_login(
                    client,
                    codecs,
                    QrLoginMode::Verification {
                        kind: QrVerification::Password,
                        signature,
                        a1,
                    },
                )
                .await;
            }
            _ => result.require_success()?,
        }
    }
}
async fn require_online(client: &Arc<Client>) -> Result<()> {
    if online(client, false).await? {
        Ok(())
    } else {
        Err(Error::Authentication(
            "InfoSync did not confirm register success".into(),
        ))
    }
}
async fn online(client: &Arc<Client>, reconnect: bool) -> Result<bool> {
    let generation = client.connection_generation();
    let (binding, registration) = match client.start_message_sync(reconnect).await {
        Ok(registration) => registration,
        Err(Error::Authentication(_) | Error::Server { .. }) => {
            client.guild_session.close(generation);
            return Ok(false);
        }
        Err(error) => {
            client.guild_session.close(generation);
            return Err(error);
        }
    };
    client.confirm_message_sync_online(&binding)?;
    client.start_heartbeat(
        registration.server_time.unwrap_or(0),
        registration.heartbeat_interval_seconds.unwrap_or(360),
    );
    client.start_maintenance(binding.generation)?;
    Ok(true)
}
pub(crate) fn registration_confirmed(response: &auth::InfoSyncResponse) -> bool {
    response
        .register
        .as_ref()
        .and_then(|p| p.message.as_deref())
        == Some("register success")
}

pub(crate) fn info_sync_for_config_at(
    state: &SessionState,
    reconnect: bool,
    config: &ClientConfig,
    context: crate::ios_device::registration::Context,
) -> Result<auth::InfoSyncRequest> {
    if !state.profile.platform.is_ios() {
        if !matches!(state.platform, PlatformState::Linux { .. }) || config.ios().is_some() {
            return Err(malformed(
                "Desktop registration requires Linux platform resources",
            ));
        }
        return Ok(info_sync(state, reconnect));
    }
    let PlatformState::Ios { device, .. } = &state.platform else {
        return Err(Error::Authentication(
            "iOS registration requires iOS platform state".into(),
        ));
    };
    device.validate()?;
    if let Some(model) = config.ios_virtual() {
        return crate::ios_device::registration::build(state, reconnect, model, context);
    }
    let resources = &config
        .ios_snapshot()
        .ok_or_else(|| {
            Error::Unsupported(
                "Snapshot iOS registration requires native initial/reconnect InfoSync resources"
                    .into(),
            )
        })?
        .registration;
    let mut request = if reconnect {
        resources.reconnect.clone()
    } else {
        resources.initial.clone()
    };
    if request.sync_flag != Some(1759) {
        return Err(Error::Unsupported(
            "The shared InfoSync coordinator requires a native iOS template with sync_flag 1759"
                .into(),
        ));
    }
    let register = request
        .register
        .as_mut()
        .ok_or_else(|| malformed("iOS InfoSync resource has no registration"))?;
    if register.guid.as_deref().is_none_or(str::is_empty) {
        return Err(malformed(
            "iOS registration requires the native GUID string",
        ));
    }
    register.version = Some(state.profile.version.clone());
    register.device = Some(auth::RegisterDevice {
        name: Some(state.device_name().to_owned()),
        kernel: Some(device.hardware_model.clone()),
        os_version: Some(device.system_version.clone()),
        brand: Some("apple".into()),
        os: Some(device.system_name.clone()),
    });
    Ok(request)
}

pub(crate) fn info_sync(state: &SessionState, reconnect: bool) -> auth::InfoSyncRequest {
    auth::InfoSyncRequest {
        sync_flag: Some(1759),
        request_random: None,
        current_active_status: Some(2),
        group_last_message_time: Some(0),
        group_code: None,
        sync: Some(auth::SyncState {
            current_cookie: Some(Bytes::new()),
            last_message_time: Some(0),
            previous_cookie: Some(Bytes::new()),
        }),
        platform_extension: Some(Bytes::new()),
        register: Some(auth::RegisterInfo {
            guid: Some(hex::encode(&state.keystore.guid)),
            kick_pc: Some(0),
            version: Some(state.profile.version.clone()),
            first_register: Some(u32::from(reconnect)),
            locale: Some(2052),
            device: Some(auth::RegisterDevice {
                name: Some(state.keystore.device_name.clone()),
                kernel: Some(state.profile.kernel.clone()),
                os_version: Some(String::new()),
                brand: Some(String::new()),
                os: Some(state.profile.os.clone()),
            }),
            mute: Some(0),
            vendor_type: Some(0),
            user_trigger: Some(u32::from(!reconnect)),
            business: Some(auth::RegisterBusiness {
                notify_switch: Some(0),
                bound_uin_notify_switch: Some(0),
            }),
            battery_status: Some(0),
            set_status: Some(1),
            flags: Some(auth::RegisterFlags {
                silence_status: Some(0),
                silent_version: Some(0),
            }),
            scene: Some(if reconnect { 4 } else { 7 }),
            background_time: Some(0),
            is_chat_on_focus: Some(false),
        }),
        guild_sync: Some(proto::guild::GuildSyncRequest {
            pull_scene: Some(if reconnect { 2 } else { 0 }),
            memory_increment: Some(proto::guild::GuildMemoryIncrement {
                last_msg_time: Some(0),
                last_pull_time: None,
                entries: Vec::new(),
            }),
        }),
        app: Some(auth::AppState {
            is_delay_req: Some(0),
            app_status: Some(0),
            silence_status: Some(0),
        }),
        ai_sync: Some(auth::AiSyncRequest::default()),
    }
}

#[derive(Deserialize)]
struct NewDeviceResponse {
    #[serde(rename = "str_url")]
    url: Option<String>,
    #[serde(rename = "ActionStatus")]
    action: Option<String>,
    #[serde(rename = "str_nt_succ_token")]
    token: Option<String>,
    #[serde(rename = "ErrorCode")]
    error_code: Option<i64>,
    #[serde(rename = "ErrorInfo")]
    error_info: Option<String>,
}
async fn new_device_request(
    client: &Client,
    http: &reqwest::Client,
    url: &reqwest::Url,
    payload: serde_json::Value,
) -> Result<NewDeviceResponse> {
    let cancel = client.cancellation();
    let request = async {
        let mut response =
            crate::diagnostics::send_http(http.post(url.clone()).json(&payload)).await?;
        if response.content_length().is_some_and(|n| n > 1024 * 1024) {
            return Err(malformed("New-device HTTP response exceeds limit"));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            crate::diagnostics::trace_http_chunk(&response, bytes.len(), &chunk);
            if chunk.len() > 1024 * 1024 - bytes.len() {
                return Err(malformed("New-device HTTP response exceeds limit"));
            }
            bytes.extend_from_slice(&chunk)
        }
        response.error_for_status_ref()?;
        let result: NewDeviceResponse = serde_json::from_slice(&bytes)
            .map_err(|e| malformed(format!("New-device response JSON: {e}")))?;
        if let Some(code) = result.error_code.filter(|v| *v != 0) {
            return Err(Error::Server {
                code: code as i32,
                message: result
                    .error_info
                    .unwrap_or_else(|| "New-device authorization rejected".into()),
            });
        }
        Ok(result)
    };
    tokio::select! {_ = cancel.cancelled()=>Err(Error::Disconnected),result=request=>result}
}
async fn new_device_login(client: &Client, codec: &mut NtLogin, jump: &str) -> Result<()> {
    let state = client.snapshot().await;
    let jump = reqwest::Url::parse(jump)
        .or_else(|_| reqwest::Url::parse(&format!("https://qq.com/?{jump}")))
        .map_err(|_| malformed("New-device jump URL"))?;
    let params: std::collections::BTreeMap<_, _> = jump
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let sig = params
        .get("sig")
        .filter(|v| !v.is_empty())
        .ok_or_else(|| malformed("New-device signature missing"))?;
    let uin_token = params
        .get("uin-token")
        .filter(|v| !v.is_empty())
        .ok_or_else(|| malformed("New-device UIN token missing"))?;
    let endpoint=reqwest::Url::parse(&format!("https://oidb.tim.qq.com/v3/oidbinterface/oidb_0xc9e_8?uid={}&getqrcode=1&sdkappid=39998&actype=2",state.keystore.uin)).map_err(|e|malformed(e.to_string()))?;
    let http = crate::http::client_builder()
        .timeout(client.config.timeout)
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()?;
    let device_name = state.device_name();
    let acquired=new_device_request(client,&http,&endpoint,serde_json::json!({"str_dev_auth_token":sig,"str_uin_token":uin_token,"str_dev_type":state.profile.os,"str_dev_name":device_name,"uint32_flag":1,"uint32_url_type":0})).await?;
    let url = acquired
        .url
        .ok_or_else(|| malformed("New-device QR URL missing"))?;
    let parsed = reqwest::Url::parse(&url).map_err(|_| malformed("New-device QR URL invalid"))?;
    let token_url = parsed
        .query_pairs()
        .find(|(key, _)| key == "str_url")
        .map(|(_, v)| v.into_owned())
        .ok_or_else(|| malformed("New-device QR token missing"))?;
    client.emit(LoginEvent::Challenge(LoginChallenge::NewDevice { url }));
    let normalized = token_url
        .replace('*', "+")
        .replace('-', "/")
        .replace("==", "");
    let token = base64::engine::general_purpose::STANDARD.encode(normalized.as_bytes());
    loop {
        let response = new_device_request(
            client,
            &http,
            &endpoint,
            serde_json::json!({"bytes_token":&token,"uint32_flag":0}),
        )
        .await?;
        if response.action.as_deref() == Some("OK") {
            if let Some(success) = response.token.filter(|v| !v.is_empty()) {
                return nt_call(
                    client,
                    codec,
                    "SsoNTLoginPasswordLoginNewDevice",
                    &auth::NtNewDeviceBody {
                        success_token: Some(success),
                    },
                    NtResponseKind::NewDevice,
                )
                .await?
                .require_success();
            }
        }
        client.pause(Duration::from_secs(2)).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ios_registration_requires_explicit_resources_and_injects_actual_device_fields() {
        for profile in [Profile::iphone(), Profile::ipad()] {
            let state = SessionState {
                profile: profile.clone(),
                keystore: Keystore {
                    device_name: "actual-device-name".into(),
                    ..Default::default()
                },
                platform: PlatformState::Ios {
                    device: IosDevice {
                        system_version: "18.1".into(),
                        hardware_model: "actual-uname-machine".into(),
                        system_name: "actual-system-name".into(),
                    }
                    .into(),
                    device_name: "actual-device-name".into(),
                },
                online: false,
            };
            let mut config = ClientConfig {
                profile,
                ..Default::default()
            };
            let context = crate::ios_device::registration::Context {
                now_seconds: 0,
                background_since: None,
                first_register: true,
            };
            assert!(info_sync_for_config_at(&state, false, &config, context).is_err());
            let template = |guid: &str, locale, notify| auth::InfoSyncRequest {
                sync_flag: Some(1759),
                register: Some(auth::RegisterInfo {
                    guid: Some(guid.into()),
                    locale: Some(locale),
                    mute: Some(1),
                    business: Some(auth::RegisterBusiness {
                        notify_switch: Some(notify),
                        bound_uin_notify_switch: None,
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let PlatformState::Ios { device, .. } = &state.platform else {
                unreachable!()
            };
            config = crate::client::ios_signing_tests::config(config.profile.clone());
            let snapshot = config.ios_snapshot_mut().unwrap();
            snapshot.device = device.as_ref().clone();
            snapshot.registration = IosRegistration {
                initial: template("native-guid-text", 1033, 1),
                reconnect: template("native-reconnect-guid-text", 1028, 2),
            };
            for reconnect in [false, true] {
                let request = info_sync_for_config_at(&state, reconnect, &config, context).unwrap();
                let request: auth::InfoSyncRequest =
                    proto::decode(Bytes::from(request.encode_to_vec())).unwrap();
                let register = request.register.unwrap();
                assert_eq!(
                    register.guid.as_deref(),
                    Some(if reconnect {
                        "native-reconnect-guid-text"
                    } else {
                        "native-guid-text"
                    })
                );
                assert_eq!(register.version.as_deref(), Some("9.3.75"));
                assert_eq!(register.locale, Some(if reconnect { 1028 } else { 1033 }));
                assert_eq!(register.mute, Some(1));
                assert_eq!(
                    register.business.unwrap().notify_switch,
                    Some(if reconnect { 2 } else { 1 })
                );
                assert_eq!(
                    register.device.unwrap(),
                    auth::RegisterDevice {
                        name: Some("actual-device-name".into()),
                        kernel: Some("actual-uname-machine".into()),
                        os_version: Some("18.1".into()),
                        brand: Some("apple".into()),
                        os: Some("actual-system-name".into()),
                    }
                );
                assert!(register.flags.is_none());
                assert!(register.vendor_type.is_none());
            }
            config
                .ios_snapshot_mut()
                .unwrap()
                .registration
                .initial
                .sync_flag = Some(1);
            assert!(info_sync_for_config_at(&state, false, &config, context).is_err());
            config.platform = None;
            assert!(info_sync_for_config_at(&state, true, &config, context).is_err());
        }
    }
    #[test]
    fn login_diagnostics_redact_urls_without_changing_the_server_context() {
        let original =
            "请验证 https://example.invalid/?secret=private 后重试 http://example.invalid/private";
        let diagnostic = redact_login_urls(original);
        assert_eq!(diagnostic, "请验证 [redacted URL] 后重试 [redacted URL]");
        assert!(!diagnostic.contains("private"));
        assert!(original.contains("secret=private"));
        assert!(matches!(
            redact_login_urls("登录失败"),
            std::borrow::Cow::Borrowed(_)
        ));
    }
    #[test]
    fn only_exact_infosync_registration_sets_online() {
        assert!(!registration_confirmed(&auth::InfoSyncResponse::default()));
        assert!(!registration_confirmed(&auth::InfoSyncResponse {
            register: Some(auth::InfoSyncRegisterResponse {
                message: Some("register failed".into()),
                ..Default::default()
            }),
            ..Default::default()
        }));
        assert!(registration_confirmed(&auth::InfoSyncResponse {
            register: Some(auth::InfoSyncRegisterResponse {
                message: Some("register success".into()),
                ..Default::default()
            }),
            ..Default::default()
        }));
        // A success string outside the registration field must not set the session online.
        let unrelated = auth::StatusResponse {
            message: Some("register success".into()),
        }
        .encode_to_vec();
        assert!(!registration_confirmed(
            &proto::decode(Bytes::from(unrelated)).unwrap()
        ));
    }
    #[test]
    fn infosync_success_allows_unrelated_response_metadata() {
        let mut response = auth::InfoSyncResponse {
            request_random: Some(123),
            register: Some(auth::InfoSyncRegisterResponse {
                message: Some("register success".into()),
                server_time: Some(100),
                heartbeat_interval_seconds: Some(360),
                field5: Some(40),
            }),
            ..Default::default()
        }
        .encode_to_vec();
        response.extend_from_slice(&[0x20, 3, 0x30, 52, 0x48, 33, 0x80, 0x01, 1, 0x8a, 0x01, 0]);
        let response: auth::InfoSyncResponse = proto::decode(response.as_slice()).unwrap();
        assert!(registration_confirmed(&response));
        assert_eq!(response.request_random, Some(123));
        let register = response.register.unwrap();
        assert_eq!(register.server_time, Some(100));
        assert_eq!(register.heartbeat_interval_seconds, Some(360));
        assert_eq!(register.field5, Some(40));
    }

    fn qr_confirmation_payload(key: Option<&[u8]>) -> Bytes {
        use crate::wire::Writer;
        let mut body = Writer::new();
        body.u64(123456);
        body.u32(0);
        let mut tlvs = Tlv::default();
        tlvs.add(0x18, b"synthetic-A1-ticket");
        tlvs.add(0x19, b"synthetic-no-picture-signature");
        if let Some(key) = key {
            tlvs.add(0x1e, key);
        }
        body.bytes(tlvs.encode(None).unwrap());
        body.data.into()
    }

    #[test]
    fn qr_confirmation_checks_the_key_boundary_without_accepting_a_partial_collection() {
        let cached = Keystore::default();
        let payload = qr_confirmation_payload(Some(&[0x61; 16]));
        let confirmation = decode_qr_confirmation(
            &mut Reader::new(payload.clone()),
            &cached,
            &QrLoginMode::Normal,
        )
        .unwrap();
        assert!(matches!(confirmation,
            QrConfirmation::Normal { uin: 123456, tgtgt_key, .. } if tgtgt_key.len() == 16));
        for length in [0, 15, 17] {
            assert!(
                decode_qr_confirmation(
                    &mut Reader::new(qr_confirmation_payload(Some(&vec![0x61; length]))),
                    &cached,
                    &QrLoginMode::Normal,
                )
                .is_err()
            );
        }
        for length in 0..payload.len() {
            assert!(
                decode_qr_confirmation(
                    &mut Reader::new(payload.slice(..length)),
                    &cached,
                    &QrLoginMode::Normal,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn qr_failure_diagnostics_never_expose_returned_or_cached_credentials() {
        let secret = b"private-session-material";
        let mut cached = Keystore::default();
        cached.uin = 123456;
        cached.tgtgt_key = secret.to_vec();
        for key in [None, Some(secret.as_slice())] {
            let error = decode_qr_confirmation(
                &mut Reader::new(qr_confirmation_payload(key)),
                &cached,
                &QrLoginMode::Normal,
            )
            .err()
            .expect("invalid confirmation must be rejected");
            let text = error.to_string();
            assert!(!text.contains(std::str::from_utf8(secret).unwrap()));
            assert!(!text.contains(&hex::encode(secret)));
            assert!(!text.contains("123456"));
            assert!(!text.contains("synthetic-A1-ticket"));
        }
    }

    #[test]
    fn unusual_easy_confirmation_uses_the_initial_a1_and_tag_3f_without_wt_tickets() {
        use crate::wire::Writer;
        let mode = QrLoginMode::Verification {
            kind: QrVerification::Easy,
            signature: Bytes::from_static(b"verification"),
            a1: Bytes::from_static(b"initial-easy-credential"),
        };
        for include_other_tickets in [false, true] {
            let mut tlvs = Tlv::default();
            tlvs.add(0x3f, b"fresh-one-click-signature");
            if include_other_tickets {
                tlvs.add(0x18, b"different-QR-A1");
                tlvs.add(0x65, b"different-TGT-QR");
                tlvs.add(0x1e, b"unused-key-with-invalid-length");
            }
            let mut body = Writer::new();
            body.u64(123456);
            body.u32(0);
            body.bytes(tlvs.encode(None).unwrap());
            let confirmation =
                decode_qr_confirmation(&mut Reader::new(body.data), &Keystore::default(), &mode)
                    .unwrap();
            match confirmation {
                QrConfirmation::Verification {
                    kind: QrVerification::Easy,
                    uin,
                    a1,
                    one_click_succeed_sig,
                } => {
                    assert_eq!(uin, 123456);
                    assert_eq!(a1.as_ref(), b"initial-easy-credential");
                    assert_eq!(one_click_succeed_sig.as_ref(), b"fresh-one-click-signature");
                }
                _ => panic!("incorrect QR continuation"),
            }
        }
        for signature in [None, Some(b"".as_slice())] {
            let mut tlvs = Tlv::default();
            tlvs.add(0x65, b"TGT-QR-is-not-one-click-proof");
            if let Some(signature) = signature {
                tlvs.add(0x3f, signature);
            }
            let mut body = Writer::new();
            body.u64(123456);
            body.u32(0);
            body.bytes(tlvs.encode(None).unwrap());
            assert!(
                decode_qr_confirmation(&mut Reader::new(body.data), &Keystore::default(), &mode,)
                    .is_err()
            );
        }
    }
}
