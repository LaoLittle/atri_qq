use super::{DesktopSigner, SigningReport};
use crate::{
    Error, Result,
    models::{ClientPlatform, SessionState},
};
use ::signing::{
    SecureInfo, Signature,
    ios::{command_policy::CommandPolicy, sdk, signer, source::SystemSource, token as ios_token},
    token::{DeviceProperties, ReportResponse, TokenError, XwidAcquisition},
};
use bytes::Bytes;
use prost::Message;
use rand::TryRng;
use std::collections::BTreeMap;
use tokio::time::Instant;

mod virtual_device;

#[derive(Clone)]
pub struct IosSigningResources {
    pub provenance: String,
    pub raw_device_token: Bytes,
    pub raw_device_token_expires_at: u64,
    pub raw_device_token_uin: String,
    pub raw_xwid: Bytes,
    pub channel_state: Option<[u8; 32]>,
    pub command_policy: CommandPolicy,
}

impl IosSigningResources {
    fn validate(&self) -> Result<()> {
        if self.provenance.trim().is_empty() {
            return Err(Error::Malformed(
                "iOS raw signing resources require an explicit snapshot source".into(),
            ));
        }
        if self.raw_xwid.is_empty() {
            return Err(Error::Malformed("iOS signing requires nonempty raw XWID bytes; the previous device-token may be empty before bootstrap".into()));
        }
        Ok(())
    }
}

struct IosSession {
    sdk: sdk::SdkSigner,
    source: SystemSource,
    resource_provenance: String,
    token_state: ios_token::TokenState,
    raw_xwid: Bytes,
    channel_state: Option<[u8; 32]>,
    native_material: Option<[u8; 16]>,
    platform: ClientPlatform,
    qua: Bytes,
    machine_id: String,
    account: Option<u64>,
    generation: u64,
    virtual_device: Option<virtual_device::VirtualSdk>,
}

impl IosSession {
    fn token_state(record: ios_token::TokenRecord) -> ios_token::TokenState {
        let mut state = ios_token::TokenState::default();
        state.restore_record(record);
        state
    }

    fn initialize(&mut self, state: &SessionState) -> Result<()> {
        if state.profile.platform != self.platform {
            return Err(Error::Unsupported(
                "Changing signing platform requires a new client".into(),
            ));
        }
        if self.machine_id != state.machine_id || self.qua.as_ref() != state.profile.qua.as_bytes()
        {
            return Err(Error::Unsupported("Changing iOS device identity or QUA requires a new signing session with matching raw resources".into()));
        }
        Ok(())
    }

    fn bind(&mut self, account: u64) {
        if self.account != Some(account) {
            self.account = Some(account);
            self.generation = self.generation.wrapping_add(1);
            self.token_state.update_account(account.to_string());
        }
    }

    fn require_bound(&mut self, state: &SessionState) -> Result<()> {
        self.initialize(state)?;
        if state.keystore.uin == 0 || self.account != Some(state.keystore.uin) {
            return Err(Error::Malformed(
                "iOS signing session has not been bound to login tickets".into(),
            ));
        }
        Ok(())
    }

    fn sign(
        &mut self,
        command: &str,
        body: Bytes,
        state: &SessionState,
        randomize: bool,
    ) -> Result<Option<SecureInfo>> {
        self.initialize(state)?;
        if !self.sdk.policy.host_requires_security(command) {
            return Ok(None);
        }
        let device_token = if self.sdk.policy.switch(1) == 1 {
            self.token_state
                .record()
                .signing_token_at(crate::o3::unix_seconds()?)
        } else {
            Bytes::new()
        };
        self.before_virtual_sign(state);
        let security = self
            .sdk
            .sign(
                sdk::Inputs {
                    command,
                    body,
                    qua: self.qua.clone(),
                    raw_xwid: self.raw_xwid.clone(),
                    device_token,
                    channel_state: self.channel_state.as_ref(),
                },
                &mut self.source,
            )
            .map_err(|error| Error::Crypto(format!("Native iOS signer: {error}")))?;
        self.after_virtual_sign(state);
        let mut security = SecureInfo {
            sign: security.sign.map_or(Signature::Empty, Signature::Ios),
            token: security.token.to_vec(),
            extra: security.extra.to_vec(),
        };
        if randomize {
            match &mut security.sign {
                Signature::Ios(signer::Signature::Primary(bytes)) => {
                    rand::rngs::SysRng.try_fill_bytes(bytes)
                }
                Signature::Ios(signer::Signature::Compact(bytes)) => {
                    rand::rngs::SysRng.try_fill_bytes(bytes)
                }
                _ => Ok(()),
            }
            .map_err(|error| Error::Crypto(format!("Signing entropy unavailable: {error}")))?;
            rand::rngs::SysRng
                .try_fill_bytes(&mut security.token)
                .map_err(|error| Error::Crypto(format!("Signing entropy unavailable: {error}")))?;
        }
        Ok(Some(security))
    }

    fn validate_token_request(
        &self,
        items: &BTreeMap<i32, Bytes>,
        payload: &ios_token::NativePayload,
    ) -> Result<()> {
        if items.is_empty() {
            return Err(Error::Malformed(
                "iOS token collection returned no properties".into(),
            ));
        }
        if self.sdk.policy.switch(46) == 1 && matches!(payload, ios_token::NativePayload::Disabled)
        {
            return Err(Error::Malformed(
                "iOS token native payload is enabled but no real payload resources were provided"
                    .into(),
            ));
        }
        Ok(())
    }

    fn token_request(
        &self,
        items: &BTreeMap<i32, Bytes>,
        payload: ios_token::NativePayload,
    ) -> ios_token::DeviceTokenRequest {
        if matches!(payload, ios_token::NativePayload::Encoded(_)) {
            return self
                .token_state
                .capture_request()
                .build_request(items, payload);
        }
        let raw_xwid_id = ios_token::DevicePropertyId::RawXwid as i32;
        let end = self
            .raw_xwid
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(self.raw_xwid.len());
        let raw_xwid = if std::str::from_utf8(&self.raw_xwid[..end]).is_ok() {
            self.raw_xwid.slice(..end)
        } else {
            Bytes::new()
        };
        let items = items
            .range(..raw_xwid_id)
            .chain(std::iter::once((&raw_xwid_id, &raw_xwid)))
            .chain(items.range((
                std::ops::Bound::Excluded(raw_xwid_id),
                std::ops::Bound::Unbounded,
            )));
        self.token_state
            .capture_request()
            .build_request(items, payload)
    }
}

enum Backend {
    Desktop(DesktopSigner),
    Ios(IosSession),
}

pub struct SessionSigner {
    backend: Backend,
}

fn desktop_only() -> Error {
    Error::Unsupported("Desktop O3 resources and maintenance are not valid for iOS; update real iOS raw signing snapshots explicitly".into())
}

impl Default for SessionSigner {
    fn default() -> Self {
        Self {
            backend: Backend::Desktop(DesktopSigner::default()),
        }
    }
}

impl SessionSigner {
    pub(crate) fn for_client(
        application_uuid: String,
        state: &SessionState,
        ios: Option<IosSigningResources>,
    ) -> Result<Self> {
        let backend = if state.profile.platform.is_ios() {
            let resources = ios.ok_or_else(|| Error::Malformed("iOS profile requires explicit signing snapshots or a configured virtual device".into()))?;
            resources.validate()?;
            let mut source = SystemSource;
            let core = signer::Signer::new(&mut source).map_err(|error| {
                Error::Crypto(format!("Native iOS signer initialization: {error}"))
            })?;
            Backend::Ios(IosSession {
                sdk: sdk::SdkSigner::new(core, resources.command_policy),
                source,
                resource_provenance: resources.provenance,
                token_state: IosSession::token_state(ios_token::TokenRecord {
                    token: resources.raw_device_token,
                    expires_at: resources.raw_device_token_expires_at,
                    associated_uin: resources.raw_device_token_uin,
                }),
                raw_xwid: resources.raw_xwid,
                channel_state: resources.channel_state,
                native_material: None,
                platform: state.profile.platform,
                qua: Bytes::copy_from_slice(state.profile.qua.as_bytes()),
                machine_id: state.machine_id.clone(),
                account: None,
                generation: 0,
                virtual_device: None,
            })
        } else {
            if ios.is_some() {
                return Err(Error::Malformed(
                    "iOS signing resources require an iPhone or iPad profile".into(),
                ));
            }
            Backend::Desktop(DesktopSigner::with_application_uuid(application_uuid))
        };
        let mut session = Self { backend };
        session.initialize(state)?;
        Ok(session)
    }

    pub fn uses_desktop_maintenance(&self) -> bool {
        matches!(&self.backend, Backend::Desktop(_))
    }

    pub fn ios_resource_provenance(&self) -> Option<&str> {
        match &self.backend {
            Backend::Desktop(_) => None,
            Backend::Ios(session) => Some(&session.resource_provenance),
        }
    }

    pub fn requires_signature(&self, command: &str) -> bool {
        match &self.backend {
            Backend::Desktop(_) => DesktopSigner::requires_signature(command),
            Backend::Ios(session) => session.sdk.policy.host_requires_security(command),
        }
    }

    pub fn initialize(&mut self, state: &SessionState) -> Result<()> {
        match &mut self.backend {
            Backend::Desktop(session) if !state.profile.platform.is_ios() => {
                session.initialize(state)
            }
            Backend::Desktop(_) => Err(Error::Malformed(
                "iOS profile requires an iOS signing session and raw resources".into(),
            )),
            Backend::Ios(session) => session.initialize(state),
        }
    }

    pub fn begin_login(&mut self, state: &SessionState) -> Result<()> {
        self.initialize(state)?;
        match &mut self.backend {
            Backend::Desktop(session) => session.begin_login(state),
            Backend::Ios(session) => {
                session.generation = session.generation.wrapping_add(1);
                session.account = Some(0);
                session.token_state.update_account("0");
                Ok(())
            }
        }
    }

    pub fn ticket_complete(&mut self, state: &SessionState) -> Result<()> {
        self.initialize(state)?;
        match &mut self.backend {
            Backend::Desktop(session) => session.ticket_complete(state),
            Backend::Ios(session) => {
                if state.keystore.uin == 0 {
                    return Err(Error::Malformed(
                        "Cannot bind iOS signer to anonymous login tickets".into(),
                    ));
                }
                session.bind(state.keystore.uin);
                Ok(())
            }
        }
    }

    pub(crate) fn business_session_started(&mut self, state: &SessionState) -> Result<()> {
        match &mut self.backend {
            Backend::Desktop(_) if state.profile.platform.is_ios() => Err(desktop_only()),
            Backend::Desktop(session) => session.business_session_started(state),
            Backend::Ios(session) => session.require_bound(state),
        }
    }

    pub(crate) fn registration_complete(&mut self, state: &SessionState) -> Result<()> {
        match &mut self.backend {
            Backend::Desktop(_) if state.profile.platform.is_ios() => Err(desktop_only()),
            Backend::Desktop(session) => session.registration_complete(state),
            Backend::Ios(session) => session.require_bound(state),
        }
    }

    pub fn generation(&self) -> u64 {
        match &self.backend {
            Backend::Desktop(session) => session.generation(),
            Backend::Ios(session) => session.generation,
        }
    }

    pub fn report_is_current(&self, report: &SigningReport) -> bool {
        match &self.backend {
            Backend::Desktop(session) => session.report_is_current(report),
            Backend::Ios(_) => false,
        }
    }

    pub fn sign(
        &mut self,
        command: &str,
        sequence: i32,
        body: &[u8],
        state: &SessionState,
        randomize_for_testing: bool,
    ) -> Result<Option<SecureInfo>> {
        match &mut self.backend {
            Backend::Desktop(_) if state.profile.platform.is_ios() => Err(Error::Malformed(
                "iOS profile requires an iOS signing session and raw resources".into(),
            )),
            Backend::Desktop(session) => {
                session.sign(command, sequence, body, state, randomize_for_testing)
            }
            Backend::Ios(session) => {
                if !session.sdk.policy.host_requires_security(command) {
                    session.initialize(state)?;
                    return Ok(None);
                }
                session.sign(
                    command,
                    Bytes::copy_from_slice(body),
                    state,
                    randomize_for_testing,
                )
            }
        }
    }

    pub(crate) fn sign_shared(
        &mut self,
        command: &str,
        sequence: i32,
        body: Bytes,
        state: &SessionState,
        randomize_for_testing: bool,
    ) -> Result<Option<SecureInfo>> {
        match &mut self.backend {
            Backend::Desktop(_) if state.profile.platform.is_ios() => Err(Error::Malformed(
                "iOS profile requires an iOS signing session and raw resources".into(),
            )),
            Backend::Desktop(session) => {
                session.sign(command, sequence, &body, state, randomize_for_testing)
            }
            Backend::Ios(session) => session.sign(command, body, state, randomize_for_testing),
        }
    }

    pub fn set_ios_resources(&mut self, resources: IosSigningResources) -> Result<()> {
        resources.validate()?;
        match &mut self.backend {
            Backend::Desktop(_) => Err(Error::Unsupported(
                "iOS resources cannot update a desktop signing session".into(),
            )),
            Backend::Ios(session) => {
                if session.virtual_device.is_some() {
                    return Err(Error::Unsupported("A virtual iOS device owns its signing resources; snapshot replacement requires snapshot mode".into()));
                }
                session.sdk.policy = resources.command_policy;
                session.resource_provenance = resources.provenance;
                if session.token_state.record().token != resources.raw_device_token
                    || session.token_state.record().expires_at
                        != resources.raw_device_token_expires_at
                    || session.token_state.record().associated_uin != resources.raw_device_token_uin
                {
                    session.token_state.restore_record(ios_token::TokenRecord {
                        token: resources.raw_device_token,
                        expires_at: resources.raw_device_token_expires_at,
                        associated_uin: resources.raw_device_token_uin,
                    });
                }
                session.raw_xwid = resources.raw_xwid;
                session.channel_state = resources.channel_state;
                Ok(())
            }
        }
    }

    pub fn ios_resources_snapshot(&self) -> Result<IosSigningResources> {
        match &self.backend {
            Backend::Desktop(_) => Err(desktop_only()),
            Backend::Ios(session) => Ok(IosSigningResources {
                provenance: session.resource_provenance.clone(),
                raw_device_token: session.token_state.record().token.clone(),
                raw_device_token_expires_at: session.token_state.record().expires_at,
                raw_device_token_uin: session.token_state.record().associated_uin.clone(),
                raw_xwid: session.raw_xwid.clone(),
                channel_state: session.channel_state,
                command_policy: session.sdk.policy.clone(),
            }),
        }
    }

    pub(crate) fn apply_ios_switches(&mut self, update: &crate::o3::ios::SwitchUpdate) {
        if let Backend::Ios(session) = &mut self.backend {
            for (index, value) in update.values.iter().enumerate() {
                if let Some(value) = value {
                    session.sdk.policy.set_switch(index as u32 + 1, *value);
                }
            }
        }
    }

    pub(crate) fn create_ios_native_payload(
        &mut self,
        state: &SessionState,
        fingerprint: [u8; 32],
        now: u64,
    ) -> Result<ios_token::NativePayloadResources> {
        let Backend::Ios(session) = &mut self.backend else {
            return Err(desktop_only());
        };
        session.native_payload_resources(state, fingerprint, now)
    }

    pub(crate) fn create_ios_token_request(
        &mut self,
        state: &SessionState,
        items: &BTreeMap<i32, Bytes>,
        payload: ios_token::NativePayload,
    ) -> Result<ios_token::DeviceTokenRequest> {
        let Backend::Ios(session) = &mut self.backend else {
            return Err(desktop_only());
        };
        session.initialize(state)?;
        session.validate_token_request(items, &payload)?;
        Ok(session.token_request(items, payload))
    }

    pub(crate) fn prepare_ios_token(
        &mut self,
        state: &SessionState,
        items: &BTreeMap<i32, Bytes>,
        payload: ios_token::NativePayload,
        now: u64,
    ) -> Result<(Bytes, ios_token::TokenSubmission)> {
        let Backend::Ios(session) = &mut self.backend else {
            return Err(desktop_only());
        };
        session.initialize(state)?;
        session.validate_token_request(items, &payload)?;
        if !session.token_state.begin_refresh(now, true) {
            return Err(Error::Authentication(
                "iOS token collection is already in progress".into(),
            ));
        }
        let body = session.token_request(items, payload).encode_to_vec().into();
        let submission = session.token_state.capture_submission();
        session.token_state.collection_worker_exited();
        Ok((body, submission))
    }

    pub(crate) fn complete_ios_token(
        &mut self,
        submission: &ios_token::TokenSubmission,
        response: Result<Bytes>,
    ) -> Result<Option<ios_token::TokenPersistence>> {
        let Backend::Ios(session) = &mut self.backend else {
            return Err(desktop_only());
        };
        match response {
            Ok(body) => session
                .token_state
                .commit_response_bytes(submission, body)
                .map_err(Into::into),
            Err(error) => {
                session.token_state.commit_failure();
                Err(error)
            }
        }
    }

    pub fn set_resources(
        &mut self,
        properties: Option<DeviceProperties>,
        persistent_xwid_switch: Option<Vec<u8>>,
        report_module_paths: Option<Vec<String>>,
    ) -> Result<()> {
        match &mut self.backend {
            Backend::Desktop(session) => {
                session.set_resources(properties, persistent_xwid_switch, report_module_paths)
            }
            Backend::Ios(_) => Err(desktop_only()),
        }
    }

    pub(crate) fn telemetry_deadline(&self) -> Option<Instant> {
        match &self.backend {
            Backend::Desktop(session) => session.telemetry_deadline(),
            Backend::Ios(_) => None,
        }
    }

    pub(crate) fn poll_telemetry(&mut self, state: &SessionState) -> Result<()> {
        match &mut self.backend {
            Backend::Desktop(_) if state.profile.platform.is_ios() => Err(desktop_only()),
            Backend::Desktop(session) => session.poll_telemetry(state),
            Backend::Ios(_) => Err(desktop_only()),
        }
    }

    pub(crate) fn poll_token(&mut self) -> Result<()> {
        match &mut self.backend {
            Backend::Desktop(session) => session.poll_token(),
            Backend::Ios(_) => Err(desktop_only()),
        }
    }

    pub(crate) fn cancel_token_reports(&mut self) {
        if let Backend::Desktop(session) = &mut self.backend {
            session.cancel_token_reports();
        }
    }

    pub(crate) fn refresh_token_task(&mut self) -> Result<()> {
        match &mut self.backend {
            Backend::Desktop(session) => session.refresh_token_task(),
            Backend::Ios(_) => Err(desktop_only()),
        }
    }

    pub(crate) fn channel_report(&self, method: &str, body: Vec<u8>) -> Result<SigningReport> {
        match &self.backend {
            Backend::Desktop(session) => Ok(session.channel_report(method, body)),
            Backend::Ios(_) => Err(desktop_only()),
        }
    }

    pub(crate) fn apply_channel_config(
        &mut self,
        config: &crate::proto::o3::ChannelConfig,
    ) -> Result<()> {
        match &mut self.backend {
            Backend::Desktop(session) => {
                session.apply_channel_config(config);
                Ok(())
            }
            Backend::Ios(_) => Err(desktop_only()),
        }
    }

    pub(crate) fn drain_token_reports(&mut self) -> Vec<SigningReport> {
        match &mut self.backend {
            Backend::Desktop(session) => session.drain_token_reports(),
            Backend::Ios(_) => Vec::new(),
        }
    }

    pub fn drain_reports(&mut self) -> Vec<SigningReport> {
        match &mut self.backend {
            Backend::Desktop(session) => session.drain_reports(),
            Backend::Ios(_) => Vec::new(),
        }
    }

    pub fn drain_telemetry_reports(&mut self) -> Vec<SigningReport> {
        match &mut self.backend {
            Backend::Desktop(session) => session.drain_telemetry_reports(),
            Backend::Ios(_) => Vec::new(),
        }
    }

    pub fn complete_report(
        &mut self,
        report: &SigningReport,
        response: ReportResponse,
    ) -> Result<()> {
        match &mut self.backend {
            Backend::Desktop(session) => session.complete_report(report, response),
            Backend::Ios(_) => Err(desktop_only()),
        }
    }

    pub(crate) fn token_status(&self) -> (usize, Option<i64>) {
        match &self.backend {
            Backend::Desktop(session) => session.token_status(),
            Backend::Ios(session) => {
                let record = session.token_state.record();
                (
                    record.token.len(),
                    (record.expires_at != 0)
                        .then(|| i64::try_from(record.expires_at).ok())
                        .flatten(),
                )
            }
        }
    }

    pub fn complete_xwid(&mut self, acquisition: XwidAcquisition) -> Result<()> {
        match &mut self.backend {
            Backend::Desktop(session) => {
                session.complete_xwid(acquisition);
                Ok(())
            }
            Backend::Ios(_) => Err(desktop_only()),
        }
    }

    pub fn take_token_error(&mut self) -> Option<TokenError> {
        match &mut self.backend {
            Backend::Desktop(session) => session.take_token_error(),
            Backend::Ios(_) => None,
        }
    }

    pub fn set_footer_seed(&mut self, seed: &[u8; 48]) -> Result<()> {
        match &mut self.backend {
            Backend::Desktop(session) => {
                session.set_footer_seed(seed);
                Ok(())
            }
            Backend::Ios(_) => Err(desktop_only()),
        }
    }

    pub fn answer_property_challenge(&mut self, requested: &[u8]) -> Result<Vec<u8>> {
        match &mut self.backend {
            Backend::Desktop(session) => session.answer_property_challenge(requested),
            Backend::Ios(_) => Err(desktop_only()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Keystore, Profile};
    use ::signing::ios::{
        command_policy::{COMMAND_MODE_SWITCH, SIGN_SWITCH},
        proto::SecurityExtra,
    };
    use prost::Message;

    fn resources() -> IosSigningResources {
        IosSigningResources {
            provenance: "synthetic-unit-test-only".into(),
            raw_device_token: Bytes::from_static(b"synthetic-raw-token"),
            raw_device_token_expires_at: u64::MAX,
            raw_device_token_uin: "0".into(),
            raw_xwid: Bytes::from_static(b"synthetic-raw-xwid"),
            channel_state: None,
            command_policy: CommandPolicy::default(),
        }
    }

    fn ios_state() -> SessionState {
        SessionState {
            profile: Profile::iphone(),
            machine_id: "synthetic-ios-device".into(),
            keystore: Keystore::default(),
            online: false,
        }
    }

    #[test]
    fn mobile_configuration_is_explicit_and_desktop_cannot_accept_it() {
        let state = ios_state();
        assert!(SessionSigner::for_client("desktop-only".into(), &state, None).is_err());
        let mut missing_source = resources();
        missing_source.provenance.clear();
        assert!(
            SessionSigner::for_client("desktop-only".into(), &state, Some(missing_source)).is_err()
        );
        let desktop = SessionState {
            profile: Profile::default(),
            ..state
        };
        assert!(
            SessionSigner::for_client("desktop-only".into(), &desktop, Some(resources())).is_err()
        );
        assert!(SessionSigner::default().initialize(&ios_state()).is_err());
    }

    #[test]
    fn native_signature_modes_and_extra_match_sdk_semantics() {
        let state = ios_state();
        let mut resources = resources();
        resources.command_policy.set_switch(SIGN_SWITCH, 1);
        let mut session =
            SessionSigner::for_client("not-used".into(), &state, Some(resources.clone())).unwrap();
        assert!(!session.uses_desktop_maintenance());
        assert!(!session.requires_signature("not.a.signed.command"));
        assert!(
            session
                .sign("not.a.signed.command", 1, b"body", &state, false)
                .unwrap()
                .is_none()
        );
        for (mode, expected_length) in [(2, 96), (1, 28), (0, 4)] {
            resources
                .command_policy
                .set_switch(COMMAND_MODE_SWITCH, mode);
            session.set_ios_resources(resources.clone()).unwrap();
            let output = session
                .sign("AvatarInfoSvr.QQHeadUrlReq", 1, b"body", &state, false)
                .unwrap()
                .unwrap();
            assert_eq!(output.sign.as_ref().len(), expected_length);
            assert_eq!(output.token.as_slice(), resources.raw_device_token.as_ref());
            let extra = SecurityExtra::decode(output.extra.as_slice()).unwrap();
            assert_eq!(extra.qua.as_ref(), state.profile.qua.as_bytes());
            assert_eq!(extra.raw_xwid, resources.raw_xwid);
            if mode == 0 {
                let mut source = SystemSource;
                let core = signer::Signer::new(&mut source).unwrap();
                let mut independent = sdk::SdkSigner::new(core, resources.command_policy.clone());
                let expected = independent
                    .sign(
                        sdk::Inputs {
                            command: "AvatarInfoSvr.QQHeadUrlReq",
                            body: Bytes::from_static(b"body"),
                            qua: Bytes::copy_from_slice(state.profile.qua.as_bytes()),
                            raw_xwid: resources.raw_xwid.clone(),
                            device_token: resources.raw_device_token.clone(),
                            channel_state: None,
                        },
                        &mut source,
                    )
                    .unwrap();
                assert_eq!(output.sign.as_ref(), expected.signature_bytes());
                assert_eq!(output.extra.as_slice(), expected.extra.as_ref());
                assert_eq!(output.token.as_slice(), expected.token.as_ref());
            }
        }
        let empty = session
            .sign("AvatarInfoSvr.QQHeadUrlReq", 1, b"", &state, false)
            .unwrap()
            .unwrap();
        assert!(empty.sign.as_ref().is_empty());
        assert_eq!(empty.token.as_slice(), resources.raw_device_token.as_ref());
        assert!(session.drain_reports().is_empty());
        assert!(session.poll_token().is_err());
        assert!(session.set_footer_seed(&[0; 48]).is_err());
        assert!(session.set_resources(None, None, None).is_err());
        assert!(session.answer_property_challenge(&[]).is_err());
        assert!(session.channel_report("heartbeat", vec![1]).is_err());
    }

    #[test]
    fn resource_updates_preserve_process_seed_and_thread_state() {
        let mut state = ios_state();
        let mut resources = resources();
        resources.command_policy.set_switch(SIGN_SWITCH, 1);
        resources.command_policy.set_switch(COMMAND_MODE_SWITCH, 1);
        let mut session =
            SessionSigner::for_client("not-used".into(), &state, Some(resources.clone())).unwrap();
        session
            .sign("AvatarInfoSvr.QQHeadUrlReq", 1, b"body", &state, false)
            .unwrap();
        session
            .sign("MessageSvc.PbSendMsg", 2, b"body", &state, false)
            .unwrap();
        let (before_process, before_thread) = match &session.backend {
            Backend::Ios(ios) => (
                ios.sdk.core.snapshot(),
                ios.sdk.core.current_thread_snapshot(),
            ),
            _ => unreachable!(),
        };
        assert!(before_thread.engine.is_some());
        resources.raw_device_token = Bytes::from_static(b"updated-synthetic-token");
        resources.raw_xwid = Bytes::from_static(b"updated-synthetic-xwid");
        resources
            .command_policy
            .append_persisted_host_commands("explicit.additional.command");
        session.set_ios_resources(resources.clone()).unwrap();
        session.begin_login(&state).unwrap();
        state.keystore.uin = 1234;
        session.ticket_complete(&state).unwrap();
        session.business_session_started(&state).unwrap();
        session.registration_complete(&state).unwrap();
        match &session.backend {
            Backend::Ios(ios) => {
                assert_eq!(ios.sdk.core.snapshot(), before_process);
                assert_eq!(ios.sdk.core.current_thread_snapshot(), before_thread);
            }
            _ => unreachable!(),
        }
        let output = session
            .sign("explicit.additional.command", 3, b"body", &state, false)
            .unwrap()
            .unwrap();
        assert_eq!(output.token.as_slice(), resources.raw_device_token.as_ref());
        assert!(session.drain_reports().is_empty());
        assert!(session.telemetry_deadline().is_none());
        state.profile = Profile::ipad();
        assert!(session.initialize(&state).is_err());
    }
}
