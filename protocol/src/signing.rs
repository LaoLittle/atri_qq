//! Session signing state and device resources.
use crate::{
    Error, Result,
    models::{SessionState, random_bytes},
    o3,
};
use ::signing::{
    self as signing_engine, Context, SecureInfo, SignResources, Signer,
    extra::ExtraEntropy,
    metadata::{EntropyRead, MetadataResources},
    token::{
        AcquisitionMode, DeviceProperties, ReportDelivery, ReportResponse, TokenError,
        TokenResources, XwidAcquisition,
    },
};
use rand::TryRng;
use std::{
    collections::VecDeque,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::Instant;

const FILE_TELEMETRY_INTERVAL: Duration = Duration::from_secs(3600);

mod commands {
    include!("signed_commands.rs");
}

mod session;
pub use session::{IosSigningResources, SessionSigner};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningReport {
    pub method: String,
    pub account: Vec<u8>,
    pub body: Vec<u8>,
    /// Captured lifecycle generation; stale asynchronous replies must be rejected.
    pub generation: u64,
    /// Inventory snapshot version; only SsoReport depends on this resource.
    pub report_resources_generation: u64,
}
struct LocalDeviceIdentity {
    machine_id: String,
    guid: [u8; 16],
    device_name: String,
}

#[derive(Default)]
pub struct SigningResources {
    pub properties: Option<DeviceProperties>,
    pub persistent_xwid_switch: Option<Vec<u8>>,
    pub report_module_paths: Option<Vec<String>>,
    report_resources_generation: u64,
    reports: VecDeque<SigningReport>,
    application_uuid: String,
    local_identity: Option<LocalDeviceIdentity>,
    generation: u64,
}
impl ExtraEntropy for SigningResources {
    type Error = Error;
    fn clock_ns(&mut self) -> Result<u64> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        u64::try_from(elapsed.as_nanos())
            .map_err(|_| Error::Crypto("Wall clock exceeds u64 nanoseconds".into()))
    }
    fn random_u32(&mut self) -> Result<u32> {
        rand::rngs::SysRng
            .try_next_u32()
            .map_err(|error| Error::Crypto(format!("Signing entropy unavailable: {error}")))
    }
}
impl TokenResources for SigningResources {
    fn unix_seconds(&mut self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs().min(i64::MAX as u64) as i64)
    }
    fn persistent_xwid_switch(&mut self) -> std::result::Result<Option<&[u8]>, TokenError> {
        Ok(self.persistent_xwid_switch.as_deref())
    }
    fn acquire_xwid(
        &mut self,
        _mode: AcquisitionMode,
    ) -> std::result::Result<Option<XwidAcquisition>, TokenError> {
        Ok(Some(XwidAcquisition::native_default(
            self.unix_seconds(),
            0,
        )))
    }
    fn collect_properties(&mut self) -> std::result::Result<DeviceProperties, TokenError> {
        let properties = if let Some(properties) = &self.properties {
            properties.clone()
        } else {
            let identity = self
                .local_identity
                .as_ref()
                .ok_or_else(|| TokenError::Resource {
                    operation: "collect_properties",
                    message: "O3 session device resources have not been initialized".into(),
                })?;
            o3::local_device_properties(&identity.machine_id, &self.application_uuid).map_err(
                |_| TokenError::Resource {
                    operation: "collect_properties",
                    message: "O3 application machine identity is invalid".into(),
                },
            )?
        };
        o3::validate_properties(&properties)?;
        Ok(properties)
    }
    fn send_report(
        &mut self,
        method: &str,
        account: &[u8],
        packet: &[u8],
    ) -> std::result::Result<ReportDelivery, TokenError> {
        if self.reports.len() >= 64 {
            return Err(TokenError::Resource {
                operation: "send_report",
                message: "Pending O3 report queue is full".into(),
            });
        }
        self.reports.push_back(SigningReport {
            method: method.into(),
            account: account.into(),
            body: packet.into(),
            generation: self.generation,
            report_resources_generation: self.report_resources_generation,
        });
        Ok(ReportDelivery::Pending)
    }
}
impl SignResources for SigningResources {
    fn metadata_resources(&mut self, needs_entropy: bool) -> Result<MetadataResources> {
        let entropy_read = if needs_entropy {
            let mut bytes = [0; 16];
            match rand::rngs::SysRng.try_fill_bytes(&mut bytes) {
                Ok(()) => EntropyRead::Complete(bytes),
                Err(_) => EntropyRead::Unavailable,
            }
        } else {
            EntropyRead::Unavailable
        };
        let checksum_seconds = self.unix_seconds() as u32;
        let trailer_seconds = self.unix_seconds() as u32;
        Ok(MetadataResources {
            checksum_seconds,
            trailer_seconds,
            entropy_read,
        })
    }
}
struct DesktopSigner {
    signer: Signer,
    resources: SigningResources,
    account: Option<u64>,
    empty_token_reported: bool,
    business_session_started: bool,
    telemetry_deadline: Option<Instant>,
}
impl Default for DesktopSigner {
    fn default() -> Self {
        Self::with_application_uuid(o3::generate_application_uuid())
    }
}
impl DesktopSigner {
    pub(crate) fn with_application_uuid(application_uuid: String) -> Self {
        let mut signer = Signer::default();
        signer.initialize_desktop_resource();
        Self {
            signer,
            resources: SigningResources {
                application_uuid,
                ..Default::default()
            },
            account: None,
            empty_token_reported: false,
            business_session_started: false,
            telemetry_deadline: None,
        }
    }
    pub fn requires_signature(command: &str) -> bool {
        commands::SIGNED_COMMANDS.contains(&command)
    }
    pub fn initialize(&mut self, state: &SessionState) -> Result<()> {
        let local_identity_changed =
            self.resources
                .local_identity
                .as_ref()
                .is_none_or(|identity| {
                    identity.machine_id != state.machine_id
                        || identity.guid.as_slice() != state.keystore.guid.as_slice()
                        || identity.device_name != state.keystore.device_name
                });
        if local_identity_changed
            || self.signer.context().qua != state.profile.qua.as_bytes()
            || self.signer.context().machine_id != state.machine_id.as_bytes()
        {
            self.telemetry_deadline = None;
            self.resources.report_resources_generation =
                self.resources.report_resources_generation.wrapping_add(1);
            self.resources
                .reports
                .retain(|report| report.method != o3::REPORT_COMMAND);
        }
        if local_identity_changed {
            o3::validate_local_identity(&state.machine_id)?;
            let guid = state.keystore.guid.as_slice().try_into().map_err(|_| {
                Error::Malformed("Signing context requires a sixteen-byte device GUID".into())
            })?;
            self.resources.local_identity = Some(LocalDeviceIdentity {
                machine_id: state.machine_id.clone(),
                guid,
                device_name: state.keystore.device_name.clone(),
            });
        }
        if self.resources.persistent_xwid_switch.is_none() {
            if let Some(value) = state.keystore.o3_xwid_switch {
                self.resources.persistent_xwid_switch = Some(value.to_string().into_bytes());
            }
        }
        let account = self.account.unwrap_or(0);
        if self.account.is_none()
            || self.signer.context().qua != state.profile.qua.as_bytes()
            || self.signer.context().machine_id != state.machine_id.as_bytes()
        {
            self.initialize_account(account, state)?;
        }
        Ok(())
    }
    fn initialize_account(&mut self, account: u64, state: &SessionState) -> Result<()> {
        if self.account != Some(account) {
            self.resources.generation = self.resources.generation.wrapping_add(1);
            self.business_session_started = false;
            self.telemetry_deadline = None;
        }
        self.signer
            .initialize(
                Context::new(
                    account.to_string().into_bytes(),
                    state.profile.qua.as_bytes().to_vec(),
                    state.machine_id.as_bytes().to_vec(),
                ),
                &mut self.resources,
            )
            .map_err(|e| Error::Crypto(format!("Signer initialization: {e:?}")))?;
        self.account = Some(account);
        let generation = self.resources.generation;
        let account = &self.signer.context().uin;
        self.resources
            .reports
            .retain(|report| report.generation == generation && report.account == *account);
        Ok(())
    }

    pub fn begin_login(&mut self, state: &SessionState) -> Result<()> {
        self.initialize(state)?;
        self.resources.generation = self.resources.generation.wrapping_add(1);
        self.empty_token_reported = false;
        self.business_session_started = false;
        self.telemetry_deadline = None;
        self.initialize_account(0, state)
    }
    /// Invoke after real login tickets are available, before establishing O3's
    /// channel. QR confirmation alone is too early (wtlogin.login still uses 0).
    pub fn ticket_complete(&mut self, state: &SessionState) -> Result<()> {
        if state.keystore.uin == 0 {
            return Err(Error::Malformed(
                "Cannot bind O3 signer to anonymous login tickets".into(),
            ));
        }
        self.initialize(state)?;
        if self.account != Some(state.keystore.uin) {
            self.empty_token_reported = false;
            self.initialize_account(state.keystore.uin, state)?;
        }
        let account = state.keystore.uin.to_string().into_bytes();
        let has_token = self
            .signer
            .tokens
            .account_token(&account)
            .is_some_and(|token| {
                !token.bytes.is_empty() && token.expires_at > self.resources.unix_seconds()
            });
        if !has_token && !self.empty_token_reported {
            if self.resources.reports.len() >= 64 {
                return Err(Error::Crypto("Pending O3 report queue is full".into()));
            }
            self.resources.reports.push_back(SigningReport {
                method: o3::REPORT_COMMAND.into(),
                account,
                body: o3::empty_token_telemetry(state),
                generation: self.resources.generation,
                report_resources_generation: self.resources.report_resources_generation,
            });
            self.empty_token_reported = true;
        }
        Ok(())
    }
    pub(crate) fn business_session_started(&mut self, state: &SessionState) -> Result<()> {
        if state.keystore.uin == 0 || self.account != Some(state.keystore.uin) {
            return Err(Error::Malformed(
                "Cannot start business session before signer ticket binding".into(),
            ));
        }
        self.initialize(state)?;
        if state.keystore.uid.is_empty() || self.business_session_started {
            return Ok(());
        }
        self.business_session_started = true;
        tracing::debug!(
            target: "atri_qq_protocol::packet_trace",
            stage = "o3_state",
            phase = "business_session_bound",
            get_token_pending = self.signer.tokens.report_pending(),
            "QQ O3 state"
        );
        self.signer
            .tokens
            .refresh_active_account(&mut self.resources)
            .map_err(|error| Error::Crypto(format!("O3 business session token refresh: {error:?}")))
    }

    fn telemetry_scope_matches(&self, state: &SessionState) -> bool {
        state.keystore.uin != 0
            && self.account == Some(state.keystore.uin)
            && self.signer.context().qua == state.profile.qua.as_bytes()
            && self.signer.context().machine_id == state.machine_id.as_bytes()
            && self
                .resources
                .local_identity
                .as_ref()
                .is_some_and(|identity| {
                    identity.machine_id == state.machine_id
                        && identity.guid.as_slice() == state.keystore.guid.as_slice()
                        && identity.device_name == state.keystore.device_name
                })
    }

    pub(crate) fn registration_complete(&mut self, state: &SessionState) -> Result<()> {
        if !self.telemetry_scope_matches(state) {
            self.telemetry_deadline = None;
            return Err(Error::Malformed(
                "Cannot report file telemetry before signer ticket binding".into(),
            ));
        }
        if self.telemetry_deadline.is_none() {
            self.telemetry_deadline = Some(Instant::now());
            self.poll_telemetry(state)?;
        }
        Ok(())
    }

    pub(crate) fn telemetry_deadline(&self) -> Option<Instant> {
        self.telemetry_deadline
    }

    pub(crate) fn poll_telemetry(&mut self, state: &SessionState) -> Result<()> {
        self.poll_telemetry_at(state, Instant::now())
    }

    fn poll_telemetry_at(&mut self, state: &SessionState, now: Instant) -> Result<()> {
        if !self.telemetry_scope_matches(state) {
            self.telemetry_deadline = None;
            return Ok(());
        }
        if self
            .telemetry_deadline
            .is_none_or(|deadline| deadline > now)
        {
            return Ok(());
        }
        self.telemetry_deadline = Some(now + FILE_TELEMETRY_INTERVAL);
        if self.resources.reports.len() >= 64 {
            return Err(Error::Crypto("Pending O3 report queue is full".into()));
        }
        self.resources.reports.push_back(SigningReport {
            method: o3::REPORT_COMMAND.into(),
            account: state.keystore.uin.to_string().into_bytes(),
            body: o3::verify_file_telemetry(state, self.resources.report_module_paths.as_deref()),
            generation: self.resources.generation,
            report_resources_generation: self.resources.report_resources_generation,
        });
        Ok(())
    }
    pub fn generation(&self) -> u64 {
        self.resources.generation
    }
    pub fn report_is_current(&self, report: &SigningReport) -> bool {
        report.generation == self.resources.generation
            && self.signer.context().uin == report.account
            && (report.method != o3::REPORT_COMMAND
                || report.report_resources_generation == self.resources.report_resources_generation)
    }
    pub fn sign(
        &mut self,
        command: &str,
        sequence: i32,
        body: &[u8],
        state: &SessionState,
        randomize_for_testing: bool,
    ) -> Result<Option<SecureInfo>> {
        if !Self::requires_signature(command) {
            return Ok(None);
        }
        self.initialize(state)?;
        let mut signature = self
            .signer
            .sign(command, sequence, body, &mut self.resources)
            .map_err(|e| Error::Crypto(format!("Native signer: {e:?}")))?;
        if randomize_for_testing {
            signature.sign = match signature.sign {
                signing_engine::Signature::Empty => signing_engine::Signature::Empty,
                signing_engine::Signature::Sequence(_) => {
                    signing_engine::Signature::Sequence(random_bytes(16).try_into().unwrap())
                }
                signing_engine::Signature::Full(_) => {
                    signing_engine::Signature::Full(random_bytes(48).try_into().unwrap())
                }
                signature @ signing_engine::Signature::Ios(_) => signature,
            };
            rand::rngs::SysRng
                .try_fill_bytes(&mut signature.token)
                .map_err(|error| Error::Crypto(format!("Signing entropy unavailable: {error}")))?;
        }
        Ok(Some(signature))
    }
    pub fn set_resources(
        &mut self,
        properties: Option<DeviceProperties>,
        persistent_xwid_switch: Option<Vec<u8>>,
        report_module_paths: Option<Vec<String>>,
    ) -> Result<()> {
        if let Some(paths) = &report_module_paths {
            o3::validate_report_module_paths(paths)?;
        }
        if self.resources.report_module_paths != report_module_paths {
            self.resources.report_resources_generation =
                self.resources.report_resources_generation.wrapping_add(1);
            self.resources
                .reports
                .retain(|report| report.method != o3::REPORT_COMMAND);
        }
        self.resources.properties = properties;
        self.resources.persistent_xwid_switch = persistent_xwid_switch;
        self.resources.report_module_paths = report_module_paths;
        Ok(())
    }
    pub(crate) fn poll_token(&mut self) -> Result<()> {
        if self.account.unwrap_or_default() == 0 {
            return Ok(());
        }
        self.signer
            .poll_token(&mut self.resources)
            .map_err(|error| Error::Crypto(format!("O3 token refresh: {error:?}")))
    }

    pub(crate) fn cancel_token_reports(&mut self) {
        self.resources
            .reports
            .retain(|report| report.method != "getToken");
        if self.signer.tokens.report_pending() {
            let _ = self.signer.tokens.complete_report(
                &[],
                ReportResponse {
                    bytes: Vec::new(),
                    transport_succeeded: false,
                    error_code: 999,
                },
            );
        }
    }

    pub(crate) fn refresh_token_task(&mut self) -> Result<()> {
        self.signer
            .tokens
            .refresh_active_account(&mut self.resources)
            .map_err(|error| Error::Crypto(format!("O3 background token task: {error:?}")))
    }

    pub(crate) fn channel_report(&self, method: &str, body: Vec<u8>) -> SigningReport {
        SigningReport {
            method: method.into(),
            account: self.signer.context().uin.clone(),
            body,
            generation: self.resources.generation,
            report_resources_generation: self.resources.report_resources_generation,
        }
    }

    pub(crate) fn apply_channel_config(&mut self, config: &crate::proto::o3::ChannelConfig) {
        self.signer.sign_enabled = config.option2 != 0;
        self.signer.tokens.set_xwid_selector(config.option6 as i32);
        self.resources.persistent_xwid_switch = Some(config.option6.to_string().into_bytes());
    }

    pub(crate) fn drain_token_reports(&mut self) -> Vec<SigningReport> {
        let mut reports = Vec::new();
        for _ in 0..self.resources.reports.len() {
            let report = self.resources.reports.pop_front().unwrap();
            if report.method == "getToken" {
                reports.push(report);
            } else {
                self.resources.reports.push_back(report);
            }
        }
        reports
    }

    pub fn drain_reports(&mut self) -> Vec<SigningReport> {
        self.resources.reports.drain(..).collect()
    }
    /// Drain only sendable telemetry. Raw getToken payloads remain available to
    /// the trusted encrypted-channel adapter; they are not SsoReport bodies.
    pub fn drain_telemetry_reports(&mut self) -> Vec<SigningReport> {
        let mut telemetry = Vec::new();
        for _ in 0..self.resources.reports.len() {
            let report = self.resources.reports.pop_front().unwrap();
            if report.method == o3::REPORT_COMMAND {
                telemetry.push(report);
            } else {
                self.resources.reports.push_back(report);
            }
        }
        telemetry
    }
    pub fn complete_report(
        &mut self,
        report: &SigningReport,
        response: ReportResponse,
    ) -> Result<()> {
        if !self.report_is_current(report) {
            return Err(Error::Crypto(
                "Stale O3 report account or lifecycle generation".into(),
            ));
        }
        if report.method == o3::REPORT_COMMAND {
            return o3::complete_telemetry(&response);
        }
        if report.method != "getToken" {
            return Err(Error::Malformed("Unknown O3 report method".into()));
        }
        self.signer
            .tokens
            .complete_report(&report.account, response)
            .map_err(|e| Error::Crypto(format!("O3 report: {e:?}")))
    }
    pub(crate) fn token_status(&self) -> (usize, Option<i64>) {
        self.signer
            .tokens
            .account_token(&self.signer.context().uin)
            .map_or((0, None), |token| {
                (token.bytes.len(), Some(token.expires_at))
            })
    }
    pub fn complete_xwid(&mut self, acquisition: XwidAcquisition) {
        self.signer.tokens.complete_xwid(acquisition)
    }
    pub fn take_token_error(&mut self) -> Option<TokenError> {
        self.signer.take_token_error()
    }
    pub fn set_footer_seed(&mut self, seed: &[u8; 48]) {
        self.signer.set_footer_seed(seed)
    }
    pub fn answer_property_challenge(&mut self, requested: &[u8]) -> Result<Vec<u8>> {
        self.signer
            .tokens
            .answer_property_challenge(requested, &mut self.resources)
            .map_err(|e| Error::Crypto(format!("O3 properties: {e:?}")))
    }
}
#[cfg(test)]
mod tests {
    use super::DesktopSigner as SessionSigner;
    use super::*;
    use crate::models::{Keystore, Profile};
    fn state(uin: u64) -> SessionState {
        SessionState {
            profile: Profile::linux(),
            keystore: Keystore {
                uin,
                ..Default::default()
            },
            machine_id: "explicit-machine-id".into(),
            online: false,
        }
    }
    #[test]
    fn anonymous_signer_does_not_bind_to_qr_account_until_tickets_complete() {
        let mut signer = SessionSigner::default();
        let state = state(12345678);
        signer
            .sign("wtlogin.login", 17, b"request", &state, false)
            .unwrap()
            .unwrap();
        assert_eq!(signer.signer.context().uin, b"0");
        assert!(signer.take_token_error().is_none());
        assert!(signer.drain_reports().is_empty());
        let counter = signer.signer.command_policy.counter();
        signer.ticket_complete(&state).unwrap();
        assert_eq!(
            signer.signer.context().uin,
            state.keystore.uin.to_string().as_bytes()
        );
        assert_eq!(signer.signer.command_policy.counter(), counter);
        let reports = signer.drain_reports();
        assert_eq!(reports.len(), 2);
        assert!(
            reports
                .iter()
                .all(|report| signer.report_is_current(report))
        );
        assert_eq!(reports[0].method, "getToken");
        assert_eq!(reports[1].method, o3::REPORT_COMMAND);
        signer.ticket_complete(&state).unwrap();
        assert!(signer.drain_reports().is_empty());
    }
    #[test]
    fn file_telemetry_starts_once_per_registration_and_old_replies_are_rejected() {
        let mut signer = SessionSigner::default();
        let state = state(1234);
        assert!(signer.registration_complete(&state).is_err());
        signer.ticket_complete(&state).unwrap();
        signer.drain_reports();
        signer.registration_complete(&state).unwrap();
        let first = signer.drain_reports().pop().unwrap();
        signer.registration_complete(&state).unwrap();
        assert!(signer.drain_reports().is_empty());
        signer.begin_login(&state).unwrap();
        assert!(!signer.report_is_current(&first));
        assert!(
            signer
                .complete_report(
                    &first,
                    ReportResponse {
                        bytes: vec![],
                        transport_succeeded: true,
                        error_code: 0,
                    }
                )
                .is_err()
        );
        assert!(signer.registration_complete(&state).is_err());
        signer.ticket_complete(&state).unwrap();
        signer.drain_reports();
        signer.registration_complete(&state).unwrap();
        let current = signer.drain_reports().pop().unwrap();
        assert!(signer.report_is_current(&current));
        assert_ne!(first.generation, current.generation);
        assert!(signer.signer.tokens.account_token(b"1234").is_none());
    }
    #[test]
    fn inventory_snapshots_replace_per_session_and_bind_pending_telemetry_only() {
        use prost::Message;
        let mut a = SessionSigner::default();
        let mut b = SessionSigner::default();
        let state = state(1234);
        let inventory = vec![
            "/trusted/modules/z.js".into(),
            "/trusted/modules/a.js".into(),
        ];
        a.set_resources(None, None, Some(inventory.clone()))
            .unwrap();
        a.ticket_complete(&state).unwrap();
        let pending = a.drain_reports();
        let token = pending
            .iter()
            .find(|report| report.method == "getToken")
            .unwrap();
        let telemetry = pending
            .iter()
            .find(|report| report.method == o3::REPORT_COMMAND)
            .unwrap();
        a.registration_complete(&state).unwrap();
        let first = a.drain_reports().pop().unwrap();
        let decode_paths = |report: &SigningReport| -> Vec<String> {
            let report = crate::proto::o3::TelemetryReport::decode(report.body.as_slice()).unwrap();
            serde_json::from_str(&report.data[0].values[4]).unwrap()
        };
        assert_eq!(decode_paths(&first), inventory);
        a.set_resources(None, None, Some(vec![])).unwrap();
        assert!(!a.report_is_current(telemetry));
        assert!(!a.report_is_current(&first));
        assert!(
            a.complete_report(
                &first,
                ReportResponse {
                    bytes: vec![],
                    transport_succeeded: true,
                    error_code: 0
                },
            )
            .is_err()
        );
        assert!(a.report_is_current(token));
        assert!(a.signer.tokens.report_pending());
        a.registration_complete(&state).unwrap();
        assert!(
            a.drain_reports().is_empty(),
            "resource changes must not replay events"
        );
        a.begin_login(&state).unwrap();
        a.ticket_complete(&state).unwrap();
        a.drain_reports();
        a.registration_complete(&state).unwrap();
        assert!(decode_paths(&a.drain_reports().pop().unwrap()).is_empty());
        b.ticket_complete(&state).unwrap();
        b.drain_reports();
        b.registration_complete(&state).unwrap();
        let defaults = decode_paths(&b.drain_reports().pop().unwrap());
        assert_ne!(defaults, inventory);
        assert!(!defaults.is_empty());
        a.set_resources(None, None, None).unwrap();
        a.begin_login(&state).unwrap();
        a.ticket_complete(&state).unwrap();
        a.drain_reports();
        a.registration_complete(&state).unwrap();
        assert_eq!(decode_paths(&a.drain_reports().pop().unwrap()), defaults);
    }
    #[test]
    fn invalid_inventory_is_atomic_and_identical_inventory_keeps_pending_binding() {
        let mut signer = SessionSigner::default();
        let state = state(1234);
        let inventory = Some(vec!["/trusted/module.js".into()]);
        let properties = DeviceProperties::from([(7, b"original".to_vec())]);
        signer
            .set_resources(Some(properties.clone()), None, inventory.clone())
            .unwrap();
        signer.ticket_complete(&state).unwrap();
        signer.drain_reports();
        signer.registration_complete(&state).unwrap();
        let report = signer.drain_reports().pop().unwrap();
        signer
            .set_resources(Some(properties.clone()), None, inventory)
            .unwrap();
        assert!(signer.report_is_current(&report));
        for paths in [
            vec![String::new()],
            vec!["/trusted/\0module".into()],
            vec!["x".repeat(1024 * 1024 + 1)],
            vec!["x".into(); 4097],
        ] {
            assert!(
                signer
                    .set_resources(Some(DeviceProperties::new()), None, Some(paths))
                    .is_err()
            );
            assert_eq!(signer.resources.collect_properties().unwrap(), properties);
            assert!(signer.report_is_current(&report));
        }
        signer.registration_complete(&state).unwrap();
        assert!(signer.drain_reports().is_empty());
    }
    #[test]
    fn independent_bots_do_not_share_native_signing_state() {
        let mut a = SessionSigner::default();
        let mut b = SessionSigner::default();
        a.sign("wtlogin.login", 1, b"a", &state(1234), false)
            .unwrap();
        b.sign("wtlogin.login", 2, b"b", &state(5678), false)
            .unwrap();
        a.sign("wtlogin.login", 3, b"c", &state(1234), false)
            .unwrap();
        assert_eq!(a.signer.command_policy.counter(), 2);
        assert_eq!(b.signer.command_policy.counter(), 1);
    }
    #[test]
    fn explicit_overrides_replace_defaults_and_none_restores_local_identity() {
        let mut signer = SessionSigner::default();
        let state = state(1234);
        signer.initialize(&state).unwrap();
        let defaults = signer.resources.collect_properties().unwrap();
        let overrides = DeviceProperties::from([(999, b"external-observation".to_vec())]);
        signer
            .set_resources(Some(overrides.clone()), None, None)
            .unwrap();
        assert_eq!(signer.resources.collect_properties().unwrap(), overrides);
        signer
            .set_resources(Some(DeviceProperties::new()), None, None)
            .unwrap();
        assert!(signer.resources.collect_properties().unwrap().is_empty());
        // None resets only the external override, not the session's local identity.
        signer.set_resources(None, None, None).unwrap();
        signer.initialize(&state).unwrap();
        let restored = signer.resources.collect_properties().unwrap();
        assert_eq!(restored[&16], state.machine_id.as_bytes());
        assert_eq!(restored[&24], defaults[&24]);
        assert!(!restored.contains_key(&999));
    }

    #[test]
    fn application_uuid_survives_account_and_guid_replacement() {
        use prost::Message;
        fn application_uuid(signer: &mut SessionSigner) -> Vec<u8> {
            let answer = signer
                .answer_property_challenge(&24i16.to_be_bytes())
                .unwrap();
            signing_engine::proto::TokenReport::decode(answer.as_slice())
                .unwrap()
                .properties
                .into_iter()
                .find(|property| property.id == 24)
                .unwrap()
                .value
        }

        let expected = b"00112233-4455-4677-8899-aabbccddeeff";
        let mut signer =
            SessionSigner::with_application_uuid(String::from_utf8(expected.to_vec()).unwrap());
        let mut session = state(1234);
        signer
            .sign("wtlogin.login", 1, b"first", &session, false)
            .unwrap();
        assert_eq!(application_uuid(&mut signer), expected);
        session.keystore.uin = 5678;
        session.keystore.guid.fill(0x22);
        session.keystore.device_name = "replacement-device".into();
        session.machine_id = "replacement-application-machine".into();
        signer
            .sign("wtlogin.login", 2, b"second", &session, false)
            .unwrap();
        assert_eq!(application_uuid(&mut signer), expected);
    }

    #[test]
    fn delayed_reports_cannot_publish_into_another_login_generation() {
        let mut signer = SessionSigner::default();
        let state = state(1234);
        signer.ticket_complete(&state).unwrap();
        let report = signer
            .drain_reports()
            .into_iter()
            .find(|report| report.method == "getToken")
            .unwrap();
        signer.begin_login(&state).unwrap();
        signer.ticket_complete(&state).unwrap();
        assert!(!signer.report_is_current(&report));
        assert!(
            signer
                .complete_report(
                    &report,
                    ReportResponse {
                        bytes: vec![],
                        transport_succeeded: true,
                        error_code: 0,
                    }
                )
                .is_err()
        );
        assert!(
            signer
                .signer
                .tokens
                .account_token(&report.account)
                .is_none()
        );
    }
    #[test]
    fn local_challenges_reuse_wrapper_property_serialization() {
        use prost::Message;
        let mut signer = SessionSigner::default();
        let state = state(1234);
        signer.initialize(&state).unwrap();
        let answer = signer
            .answer_property_challenge(&[0, 16, 0, 41, 0, 99])
            .unwrap();
        let decoded = signing_engine::proto::TokenReport::decode(answer.as_slice()).unwrap();
        assert_eq!(decoded.properties.len(), 3);
        assert_eq!(decoded.properties[0].id, 16);
        assert_eq!(decoded.properties[0].value, state.machine_id.as_bytes());
        assert_eq!(decoded.properties[2].id, 99);
        assert_eq!(decoded.properties[2].value, b"-1");
        assert!(signer.answer_property_challenge(&[0]).is_err());
    }
    #[test]
    fn empty_telemetry_completion_does_not_clear_token_report_pending() {
        let mut signer = SessionSigner::default();
        signer.ticket_complete(&state(1234)).unwrap();
        let telemetry = signer
            .drain_reports()
            .into_iter()
            .find(|report| report.method == o3::REPORT_COMMAND)
            .unwrap();
        assert!(signer.signer.tokens.report_pending());
        signer
            .complete_report(
                &telemetry,
                ReportResponse {
                    bytes: vec![],
                    transport_succeeded: true,
                    error_code: 0,
                },
            )
            .unwrap();
        assert!(signer.signer.tokens.report_pending());
        assert!(signer.signer.tokens.account_token(b"1234").is_none());
    }
    #[test]
    fn repeated_login_attempts_release_stale_report_capacity() {
        let mut signer = SessionSigner::default();
        let state = state(1234);
        for _ in 0..80 {
            signer.begin_login(&state).unwrap();
            signer.ticket_complete(&state).unwrap();
        }
        let reports = signer.drain_reports();
        assert!(
            reports
                .iter()
                .all(|report| signer.report_is_current(report))
        );
        let current = reports
            .into_iter()
            .find(|report| report.method == "getToken")
            .unwrap();
        use prost::Message;
        signer
            .complete_report(
                &current,
                ReportResponse {
                    bytes: signing_engine::proto::IssuedTokenReply {
                        token: b"current-attempt".to_vec(),
                        expires_at: 4_000_000_000,
                    }
                    .encode_to_vec(),
                    transport_succeeded: true,
                    error_code: 0,
                },
            )
            .unwrap();
        assert_eq!(
            signer.signer.tokens.account_token(b"1234").unwrap().bytes,
            b"current-attempt"
        );
    }

    fn issue_token(signer: &mut SessionSigner) {
        use prost::Message;
        let report = signer
            .drain_reports()
            .into_iter()
            .find(|report| report.method == "getToken")
            .unwrap();
        signer
            .complete_report(
                &report,
                ReportResponse {
                    bytes: signing_engine::proto::IssuedTokenReply {
                        token: b"synthetic-issued-token".to_vec(),
                        expires_at: 4_000_000_000,
                    }
                    .encode_to_vec(),
                    transport_succeeded: true,
                    error_code: 0,
                },
            )
            .unwrap();
    }

    #[test]
    fn business_session_refreshes_a_valid_token_once_after_uid_arrives() {
        let mut signer = SessionSigner::default();
        let mut state = state(1234);
        assert!(signer.business_session_started(&state).is_err());
        signer.ticket_complete(&state).unwrap();
        issue_token(&mut signer);
        let status = signer.token_status();
        signer.business_session_started(&state).unwrap();
        assert!(!signer.business_session_started);
        assert!(signer.drain_reports().is_empty());
        state.keystore.uid = "u_synthetic".into();
        signer.business_session_started(&state).unwrap();
        assert!(signer.business_session_started);
        assert_eq!(signer.token_status(), status);
        let reports = signer.drain_reports();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].method, "getToken");
        signer.business_session_started(&state).unwrap();
        assert!(signer.drain_reports().is_empty());
    }

    #[test]
    fn business_session_does_not_append_a_refresh_after_an_inflight_report() {
        let mut signer = SessionSigner::default();
        let mut state = state(1234);
        state.keystore.uid = "u_synthetic".into();
        signer.ticket_complete(&state).unwrap();
        signer.business_session_started(&state).unwrap();
        assert!(signer.business_session_started);
        issue_token(&mut signer);
        signer.business_session_started(&state).unwrap();
        assert!(signer.drain_reports().is_empty());
        assert!(!signer.signer.tokens.report_pending());
    }

    #[test]
    fn business_session_gate_resets_for_new_login_and_account_generations() {
        let mut signer = SessionSigner::default();
        let mut first = state(1234);
        first.keystore.uid = "u_first".into();
        signer.ticket_complete(&first).unwrap();
        issue_token(&mut signer);
        signer.business_session_started(&first).unwrap();
        issue_token(&mut signer);
        let generation = signer.generation();
        signer.begin_login(&first).unwrap();
        assert!(!signer.business_session_started);
        assert!(signer.business_session_started(&first).is_err());
        signer.ticket_complete(&first).unwrap();
        signer.drain_reports();
        signer.business_session_started(&first).unwrap();
        assert_ne!(signer.generation(), generation);
        assert_eq!(
            signer
                .resources
                .reports
                .iter()
                .filter(|report| report.method == "getToken")
                .count(),
            1
        );
        issue_token(&mut signer);
        let mut second = state(5678);
        second.keystore.uid = "u_second".into();
        signer.ticket_complete(&second).unwrap();
        assert!(!signer.business_session_started);
        issue_token(&mut signer);
        signer.business_session_started(&second).unwrap();
        let reports = signer.drain_reports();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].method, "getToken");
    }

    #[test]
    fn file_telemetry_repeats_hourly_without_catchup_or_token_side_effects() {
        let mut signer = SessionSigner::default();
        let state = state(1234);
        signer.ticket_complete(&state).unwrap();
        assert!(signer.telemetry_deadline().is_none());
        signer.poll_telemetry(&state).unwrap();
        assert!(signer.telemetry_deadline().is_none());
        signer.drain_reports();
        signer.registration_complete(&state).unwrap();
        assert_eq!(signer.drain_reports().len(), 1);
        let deadline = signer.telemetry_deadline().unwrap();
        let token_status = signer.token_status();
        signer
            .poll_telemetry_at(&state, deadline - Duration::from_nanos(1))
            .unwrap();
        assert!(signer.drain_reports().is_empty());
        signer.poll_telemetry_at(&state, deadline).unwrap();
        let reports = signer.drain_reports();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].method, o3::REPORT_COMMAND);
        assert!(signer.signer.tokens.report_pending());
        assert_eq!(signer.token_status(), token_status);
        let late = deadline + FILE_TELEMETRY_INTERVAL * 5;
        signer.poll_telemetry_at(&state, late).unwrap();
        assert_eq!(signer.drain_reports().len(), 1);
        assert_eq!(
            signer.telemetry_deadline(),
            Some(late + FILE_TELEMETRY_INTERVAL)
        );
    }

    #[test]
    fn next_file_telemetry_cycle_uses_current_inventory_without_immediate_replay() {
        use prost::Message;
        let mut signer = SessionSigner::default();
        let state = state(1234);
        signer.ticket_complete(&state).unwrap();
        signer.drain_reports();
        signer.registration_complete(&state).unwrap();
        signer.drain_reports();
        let deadline = signer.telemetry_deadline().unwrap();
        let inventory = vec!["/synthetic/new-module.js".to_string()];
        signer
            .set_resources(None, None, Some(inventory.clone()))
            .unwrap();
        assert_eq!(signer.telemetry_deadline(), Some(deadline));
        signer.poll_telemetry(&state).unwrap();
        assert!(signer.drain_reports().is_empty());
        signer.poll_telemetry_at(&state, deadline).unwrap();
        let report = signer.drain_reports().pop().unwrap();
        let decoded = crate::proto::o3::TelemetryReport::decode(report.body.as_slice()).unwrap();
        let paths: Vec<String> = serde_json::from_str(&decoded.data[0].values[4]).unwrap();
        assert_eq!(paths, inventory);
    }

    #[test]
    fn full_file_telemetry_queue_advances_deadline_without_dropping_token_work() {
        let mut signer = SessionSigner::default();
        let state = state(1234);
        signer.ticket_complete(&state).unwrap();
        signer.drain_reports();
        for _ in 0..64 {
            let report = signer.channel_report("getToken", vec![1]);
            signer.resources.reports.push_back(report);
        }
        assert!(signer.registration_complete(&state).is_err());
        let deadline = signer.telemetry_deadline().unwrap();
        signer.poll_telemetry(&state).unwrap();
        assert_eq!(signer.resources.reports.len(), 64);
        assert!(signer.poll_telemetry_at(&state, deadline).is_err());
        assert_eq!(
            signer.telemetry_deadline(),
            Some(deadline + FILE_TELEMETRY_INTERVAL)
        );
        assert_eq!(signer.drain_token_reports().len(), 64);
    }

    #[test]
    fn file_telemetry_scope_changes_cancel_until_registration() {
        let mut signer = SessionSigner::default();
        let mut state = state(1234);
        signer.ticket_complete(&state).unwrap();
        let token = signer
            .drain_reports()
            .into_iter()
            .find(|report| report.method == "getToken")
            .unwrap();
        let status = signer.token_status();
        signer.registration_complete(&state).unwrap();
        let report = signer.drain_reports().pop().unwrap();
        state.machine_id = "another-machine".into();
        signer.poll_telemetry(&state).unwrap();
        assert!(signer.telemetry_deadline().is_none());
        signer.initialize(&state).unwrap();
        assert!(!signer.report_is_current(&report));
        assert!(signer.report_is_current(&token));
        assert!(signer.signer.tokens.report_pending());
        assert_eq!(signer.token_status(), status);
        signer.registration_complete(&state).unwrap();
        assert!(signer.telemetry_deadline().is_some());
        signer.begin_login(&state).unwrap();
        assert!(signer.telemetry_deadline().is_none());
        signer.ticket_complete(&state).unwrap();
        assert!(signer.telemetry_deadline().is_none());
        state.keystore.uin = 5678;
        signer.poll_telemetry(&state).unwrap();
        assert!(signer.telemetry_deadline().is_none());
    }
}
