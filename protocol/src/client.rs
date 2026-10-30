use crate::{
    Error, Result, credentials, login,
    models::*,
    proto::auth,
    signing::{SessionSigner, SigningReport},
    wire::{self, SsoFrameCodec},
};
use ::signing as signing_engine;
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt, future::Either, stream::FuturesUnordered};
use prost::Message;
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::{Arc, Mutex, Weak},
    time::{Duration, SystemTime},
};
use tokio::{
    net::TcpStream,
    sync::{Notify, broadcast, mpsc, oneshot, watch},
    task::JoinHandle,
    time::{Instant, timeout_at},
};
use tokio_util::{codec::Framed, sync::CancellationToken};

mod file_transfer;
mod ios_discovery;
mod ios_guild;
mod ios_header;
mod ios_heartbeat;
mod ios_network;
mod ios_o3;
mod ios_probe;
mod ios_response;
mod message_sync;
mod network;
mod personal_events;
mod robot_ranges;

#[cfg(test)]
pub(crate) mod ios_signing_tests;

#[cfg(test)]
mod ios_heartbeat_tests;

#[cfg(test)]
mod ios_heartbeat_source_tests;

#[async_trait]
pub trait ServiceClient: Send + Sync {
    async fn request(
        &self,
        command: &str,
        body: Bytes,
        request_type: RequestType,
        encryption: Encryption,
        timeout: Duration,
    ) -> Result<Bytes>;
    async fn snapshot(&self) -> SessionState;
    async fn replace_state(&self, state: SessionState);
    fn subscribe(&self) -> broadcast::Receiver<IncomingPacket>;
    fn message_sync_snapshot(&self) -> Result<crate::message_sync::Snapshot> {
        Err(Error::Unsupported(
            "Message synchronization snapshots are unavailable".into(),
        ))
    }
    async fn media_download_key(
        &self,
        _business_type: u32,
        _store_id: u32,
    ) -> Result<crate::media::MediaDownloadKey> {
        Err(Error::Unsupported(
            "Media download key provider is unavailable".into(),
        ))
    }
    async fn fetch_friend_statuses(&self) -> Result<Arc<crate::contacts::FriendStatusSnapshot>> {
        Err(Error::Unsupported(
            "Friend status provider is unavailable".into(),
        ))
    }
}
struct Pending {
    id: u64,
    command: String,
    key: Vec<u8>,
    reply: oneshot::Sender<Result<Bytes>>,
    cancel: CancellationToken,
    ios: Option<ios_network::RequestTiming>,
    replay: Option<ios_header::Replay>,
    message_sync: Option<(
        Arc<crate::message_sync::Binding>,
        Arc<crate::message_sync::Request>,
    )>,
}
enum RequestBinding<'a> {
    Connection(u64),
    IosControl {
        generation: u64,
        source: &'a CancellationToken,
    },
    Online(u64),
    FriendStatus(&'a Arc<crate::lifecycle::status::Binding>),
    Credentials(&'a Arc<credentials::Session>),
    FileTransfer(&'a Arc<credentials::file_transfer::Binding>),
    IosO3(&'a ios_o3::Binding),
    SigningReport {
        generation: u64,
        report: &'a SigningReport,
    },
}
struct Outgoing {
    command: String,
    sequence: i32,
    attempt: u64,
    frame: Bytes,
    deadline: Instant,
    cancel: CancellationToken,
    required_control: bool,
    terminal: bool,
}
impl Outgoing {
    fn trace(&self, generation: u64) {
        tracing::debug!(target: "atri_qq_protocol::packet_trace", direction = "send", stage = "wire", command = self.command, sequence = self.sequence, generation, length = self.frame.len(), raw_hex = %hex::encode(&self.frame), "QQ packet");
    }
}
struct Connection {
    generation: u64,
    sender: mpsc::Sender<Outgoing>,
}
enum PlatformRuntime {
    Linux(crate::o3::Session),
    Ios(IosRuntime),
}
struct IosRuntime {
    transport: IosTransportResources,
    network: Option<crate::ios_device::network::IosNetworkSession>,
    header: ios_header::State,
    response: ios_response::State,
    block_check: ios_network::BlockCheck,
    heartbeat_source: Option<Arc<dyn crate::heartbeat::IosSource>>,
    first_register: bool,
    channel: Option<crate::o3::ios::Channel>,
    discovery: ios_discovery::State,
    probes: ios_probe::State,
}
struct Inner {
    state: SessionState,
    signer: SessionSigner,
    platform: PlatformRuntime,
    connection_cookie: Bytes,
    clock: crate::clock::ServerClock,
    sequence: i32,
    next_id: u64,
    generation: u64,
    connection: Option<Connection>,
    cancel: CancellationToken,
    transport_cancel: CancellationToken,
    pending: HashMap<i32, Pending>,
    previous_keys: Vec<Vec<u8>>,
    last_activity: Instant,
    alive_cancel: CancellationToken,
    heartbeat_cancel: CancellationToken,
    control_replies: VecDeque<(&'static str, Bytes)>,
    signing_cancel: CancellationToken,
    signing_ready: bool,
    credentials: credentials::Cache,
    maintenance_started: bool,
    maintenance_cancel: CancellationToken,
    ticket_refresh_failures: u8,
    ticket_refresh_schedule: watch::Sender<crate::ticket_refresh::Schedule>,
    friend_statuses: crate::lifecycle::status::Cache,
    kick_reason: Option<String>,
    ip_direct_configuration: Option<(
        Arc<credentials::Session>,
        Arc<crate::network::IpDirectConfiguration>,
    )>,
    sso_configuration: Option<Arc<crate::network::SsoConfiguration>>,
    server_cursor: usize,
    file_transfer: credentials::file_transfer::Cache,
    file_transfer_worker: Option<Arc<credentials::file_transfer::Binding>>,
    robot_ranges: crate::contacts::robot_ranges::State,
}
impl Inner {
    fn ios(&self) -> Option<&IosRuntime> {
        match &self.platform {
            PlatformRuntime::Ios(runtime) => Some(runtime),
            PlatformRuntime::Linux(_) => None,
        }
    }
    fn ios_mut(&mut self) -> Option<&mut IosRuntime> {
        match &mut self.platform {
            PlatformRuntime::Ios(runtime) => Some(runtime),
            PlatformRuntime::Linux(_) => None,
        }
    }
    fn linux_o3(&self) -> Option<&crate::o3::Session> {
        match &self.platform {
            PlatformRuntime::Linux(session) => Some(session),
            PlatformRuntime::Ios(_) => None,
        }
    }
    fn linux_o3_mut(&mut self) -> Option<&mut crate::o3::Session> {
        match &mut self.platform {
            PlatformRuntime::Linux(session) => Some(session),
            PlatformRuntime::Ios(_) => None,
        }
    }
}
pub(crate) struct PendingSecurity {
    pub challenge: IosLoginSecurityChallenge,
    pub reply: oneshot::Sender<IosLoginSecurityAction>,
}

pub struct Client {
    pub(crate) config: ClientConfig,
    pub(crate) guild_session: Arc<crate::guild::Session>,
    pub(crate) message_sync: Arc<crate::message_sync::Coordinator>,
    pub(crate) personal_events: crate::personal_events::Coordinator,
    pub(crate) media_keys: Arc<crate::lifecycle::maintenance::Session>,
    inner: Mutex<Inner>,
    connect_gate: tokio::sync::Mutex<()>,
    friend_status_gate: tokio::sync::Mutex<()>,
    file_transfer_gate: tokio::sync::Mutex<()>,
    robot_ranges_gate: tokio::sync::Mutex<()>,
    pub(crate) login_gate: tokio::sync::Mutex<()>,
    pub(crate) codecs: tokio::sync::Mutex<Option<login::LoginCodecs>>,
    pub(crate) captcha: Mutex<Option<oneshot::Sender<(String, String)>>>,
    pub(crate) device_verification: Mutex<Option<oneshot::Sender<IosDeviceVerificationResult>>>,
    pub(crate) security: Mutex<Option<PendingSecurity>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    events: broadcast::Sender<LoginEvent>,
    packets: broadcast::Sender<IncomingPacket>,
    login_notifications: broadcast::Sender<Arc<crate::network::LoginNotification>>,
    activity: Arc<Notify>,
    background_work: Arc<Notify>,
    signing_work: Arc<Notify>,
    credential_work: Arc<Notify>,
    file_transfer_work: Arc<Notify>,
    weak: Weak<Client>,
}
impl Client {
    pub fn new(mut config: ClientConfig, mut keystore: Keystore) -> Result<Arc<Self>> {
        if config.timeout.is_zero() || config.host.is_empty() || config.port == 0 {
            return Err(wire::malformed("Invalid SSO endpoint/timeout"));
        }
        if keystore.guid.len() != 16
            || keystore.random_key.len() != 16
            || keystore.d2_key.len() != 16
        {
            return Err(wire::malformed(
                "Device GUID, random key and D2 key must each be sixteen bytes",
            ));
        }
        if config.profile.qua.is_empty() || config.profile.qua.contains('\0') {
            return Err(wire::malformed("Explicit QUA must be a nonempty C string"));
        }
        match (&config.platform, config.profile.platform.is_ios()) {
            (None, false) => config.platform = Some(PlatformConfig::Linux(LinuxConfig::default())),
            (Some(PlatformConfig::Linux(_)), false) | (Some(PlatformConfig::Ios(_)), true) => {}
            _ => {
                return Err(wire::malformed(
                    "Client platform resources do not match its profile",
                ));
            }
        }
        keystore.qr_sig.clear();
        keystore.key_exchange_session = None;
        keystore.login_cookie.clear();
        let (state, signer, platform) = match config.platform.as_ref().unwrap() {
            PlatformConfig::Linux(linux) => {
                if linux.machine_id.is_empty() || linux.machine_id.contains('\0') {
                    return Err(wire::malformed(
                        "Explicit machine ID must be a nonempty C string",
                    ));
                }
                let state = SessionState {
                    profile: config.profile.clone(),
                    platform: PlatformState::Linux {
                        machine_id: linux.machine_id.clone(),
                    },
                    keystore,
                    online: false,
                };
                let signer = SessionSigner::for_linux(linux.application_uuid.clone(), &state)?;
                (
                    state,
                    signer,
                    PlatformRuntime::Linux(crate::o3::Session::default()),
                )
            }
            PlatformConfig::Ios(ios) => {
                keystore.ensure_ios_identity()?;
                let (
                    device,
                    device_name,
                    signing,
                    transport,
                    network,
                    heartbeat_source,
                    virtual_device,
                ) = match ios {
                    IosConfig::Virtual(model) => {
                        let heartbeat = model.application.heartbeat_resources()?;
                        let now_micros =
                            u64::try_from(signing_engine::ios::source::SystemSource.unix_micros()?)
                                .map_err(|_| {
                                    wire::malformed(
                                        "Virtual iOS device creation precedes Unix epoch",
                                    )
                                })?;
                        let (runtime, identity) = crate::ios_device::IosVirtualRuntime::initialize(
                            model.clone(),
                            &config.profile,
                            &mut keystore,
                            now_micros,
                        )?;
                        let signing =
                            runtime.signing_resources(keystore.ios_virtual_state.as_ref().unwrap());
                        let network = crate::ios_device::network::IosNetworkSession::new(
                            model,
                            (now_micros / 1000) as i64,
                        );
                        (
                            identity,
                            model.device_name(config.profile.platform).to_owned(),
                            signing,
                            model.transport_resources()?,
                            Some(network),
                            Some(Arc::new(heartbeat) as Arc<dyn crate::heartbeat::IosSource>),
                            Some(runtime),
                        )
                    }
                    IosConfig::Snapshot(snapshot) => (
                        snapshot.device.clone(),
                        keystore.device_name.clone(),
                        snapshot.signing.clone(),
                        snapshot.transport.clone(),
                        None,
                        None,
                        None,
                    ),
                };
                device.validate()?;
                transport.validate()?;
                let state = SessionState {
                    profile: config.profile.clone(),
                    platform: PlatformState::Ios {
                        device: device.into(),
                        device_name: device_name.into(),
                    },
                    keystore,
                    online: false,
                };
                let mut signer = SessionSigner::for_ios(&state, signing)?;
                if let Some(device) = virtual_device {
                    signer.enable_ios_virtual(device)?;
                }
                (
                    state,
                    signer,
                    PlatformRuntime::Ios(IosRuntime {
                        transport,
                        network,
                        header: ios_header::State::default(),
                        response: ios_response::State::default(),
                        block_check: ios_network::BlockCheck::default(),
                        heartbeat_source,
                        first_register: true,
                        channel: None,
                        discovery: ios_discovery::State::default(),
                        probes: ios_probe::State::default(),
                    }),
                )
            }
        };
        let (events, _) = broadcast::channel(128);
        let (packets, _) = broadcast::channel(256);
        let (login_notifications, _) = broadcast::channel(64);
        let (ticket_refresh_schedule, _) =
            watch::channel(crate::ticket_refresh::Schedule::default());
        let guild_session = Arc::new(crate::guild::Session::default());
        let cancel = CancellationToken::new();
        let transport_cancel = cancel.child_token();
        Ok(Arc::new_cyclic(|weak| Self {
            config,
            guild_session: guild_session.clone(),
            message_sync: Arc::new(crate::message_sync::Coordinator::with_guild(
                guild_session.clone(),
            )),
            personal_events: crate::personal_events::Coordinator::default(),
            media_keys: Arc::new(crate::lifecycle::maintenance::Session::default()),
            inner: Mutex::new(Inner {
                state,
                signer,
                platform,
                connection_cookie: Bytes::new(),
                clock: crate::clock::ServerClock::default(),
                sequence: rand::random::<u32>().wrapping_rem(4_900_001) as i32 + 5_000_000,
                next_id: 0,
                generation: 0,
                connection: None,
                cancel,
                transport_cancel,
                pending: HashMap::new(),
                previous_keys: vec![],
                last_activity: Instant::now(),
                alive_cancel: CancellationToken::new(),
                heartbeat_cancel: CancellationToken::new(),
                control_replies: VecDeque::new(),
                signing_cancel: CancellationToken::new(),
                signing_ready: false,
                credentials: credentials::Cache::default(),
                maintenance_started: false,
                maintenance_cancel: CancellationToken::new(),
                ticket_refresh_failures: 0,
                ticket_refresh_schedule,
                friend_statuses: crate::lifecycle::status::Cache::default(),
                kick_reason: None,
                ip_direct_configuration: None,
                sso_configuration: None,
                server_cursor: 0,
                file_transfer: credentials::file_transfer::Cache::default(),
                file_transfer_worker: None,
                robot_ranges: crate::contacts::robot_ranges::State::default(),
            }),
            connect_gate: tokio::sync::Mutex::new(()),
            friend_status_gate: tokio::sync::Mutex::new(()),
            file_transfer_gate: tokio::sync::Mutex::new(()),
            robot_ranges_gate: tokio::sync::Mutex::new(()),
            login_gate: tokio::sync::Mutex::new(()),
            codecs: tokio::sync::Mutex::new(None),
            captcha: Mutex::new(None),
            device_verification: Mutex::new(None),
            security: Mutex::new(None),
            tasks: Mutex::new(vec![]),
            events,
            packets,
            login_notifications,
            activity: Arc::new(Notify::new()),
            background_work: Arc::new(Notify::new()),
            signing_work: Arc::new(Notify::new()),
            credential_work: Arc::new(Notify::new()),
            file_transfer_work: Arc::new(Notify::new()),
            weak: weak.clone(),
        }))
    }
    pub fn login_events(&self) -> broadcast::Receiver<LoginEvent> {
        self.events.subscribe()
    }
    pub fn subscribe(&self) -> broadcast::Receiver<IncomingPacket> {
        self.packets.subscribe()
    }
    pub async fn snapshot(&self) -> SessionState {
        self.inner.lock().unwrap().state.clone()
    }
    pub(crate) fn clear_nt_login_cookie(&self) {
        self.inner
            .lock()
            .unwrap()
            .state
            .keystore
            .login_cookie
            .clear();
    }
    pub async fn replace_state(&self, state: SessionState) {
        let mut inner = self.inner.lock().unwrap();
        self.replace_state_locked(&mut inner, state);
    }
    fn replace_state_locked(&self, inner: &mut Inner, mut state: SessionState) {
        if inner.kick_reason.is_some()
            || !matches!(
                (
                    &inner.platform,
                    &state.platform,
                    state.profile.platform.is_ios()
                ),
                (
                    PlatformRuntime::Linux(_),
                    PlatformState::Linux { .. },
                    false
                ) | (PlatformRuntime::Ios(_), PlatformState::Ios { .. }, true)
            )
        {
            return;
        }
        state.keystore.ios_server_lists = inner.state.keystore.ios_server_lists.clone();
        if inner.signer.has_ios_virtual_device()
            && state.keystore.ios_virtual_state != inner.state.keystore.ios_virtual_state
        {
            state.keystore.ios_virtual_state = inner.state.keystore.ios_virtual_state.clone();
        }
        let account_changed = inner.state.keystore.uin != state.keystore.uin
            || inner.state.keystore.uid != state.keystore.uid;
        if inner.state.keystore.uin != state.keystore.uin {
            if let Some(ios) = inner.ios_mut() {
                ios.first_register = true;
            }
        }
        if inner.state.profile.platform.is_ios()
            && (account_changed
                || inner.state.platform != state.platform
                || inner.state.profile.qua != state.profile.qua
                || inner.state.profile.platform != state.profile.platform
                || inner.state.keystore.guid != state.keystore.guid)
        {
            inner.signing_cancel.cancel();
            inner.signing_cancel = CancellationToken::new();
        }
        if account_changed {
            self.message_sync
                .replace_identity(state.keystore.uin, &state.keystore.uid);
            self.personal_events
                .replace_identity(state.keystore.uin, &state.keystore.uid);
            inner.robot_ranges.clear();
            inner.ticket_refresh_failures = 0;
            inner.sso_configuration = None;
            inner.server_cursor = 0;
            inner
                .ticket_refresh_schedule
                .send_replace(crate::ticket_refresh::Schedule::default());
        }
        let tickets_changed = inner.state.keystore.d2 != state.keystore.d2
            || inner.state.keystore.d2_key != state.keystore.d2_key
            || inner.state.keystore.a2 != state.keystore.a2;
        // Only an authenticated InfoSync response may raise the online flag.
        // A stale service snapshot must not resurrect a closed or different account.
        state.online &= inner.state.online
            && inner.connection.is_some()
            && !inner.cancel.is_cancelled()
            && !account_changed;
        if account_changed
            || inner.state.keystore.a2 != state.keystore.a2
            || inner.state.keystore.guid != state.keystore.guid
            || !state.online
        {
            inner.file_transfer.invalidate();
            inner.file_transfer_worker = None;
        }
        if account_changed || tickets_changed || (inner.state.online && !state.online) {
            inner.credentials.invalidate(account_changed);
            inner.ip_direct_configuration = None;
            if account_changed || !state.online {
                inner.friend_statuses.clear();
                self.guild_session.close(inner.generation);
                self.message_sync.close(inner.generation);
                self.personal_events.cancel();
                self.media_keys.close(inner.generation);
                inner.maintenance_cancel.cancel();
                inner.maintenance_started = false;
            } else {
                let generation = inner.generation;
                let cancel = inner.cancel.clone();
                inner.credentials.activate(generation, &cancel);
                if inner.maintenance_started {
                    inner.credentials.start();
                }
            }
            self.credential_work.notify_one();
        }
        if inner.state.keystore.d2_key != state.keystore.d2_key {
            let old = inner.state.keystore.d2_key.clone();
            inner
                .previous_keys
                .retain(|k| k != &old && k != &state.keystore.d2_key);
            if old.len() == 16 {
                inner.previous_keys.insert(0, old);
                inner.previous_keys.truncate(8)
            }
        }
        if inner.state.keystore != state.keystore {
            self.emit(LoginEvent::KeystoreChanged(state.keystore.clone()))
        }
        inner.state = state;
        Self::update_ticket_refresh_schedule(inner);
        if inner.state.online {
            let Inner { state, signer, .. } = inner;
            if let Err(error) = signer.business_session_started(state) {
                tracing::warn!(%error, "O3 business session could not be bound");
            }
            self.signing_work.notify_one();
        }
    }
    #[cfg(test)]
    pub(crate) fn confirm_online(&self, generation: u64) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        self.confirm_online_locked(&mut inner, generation)
    }
    fn confirm_online_locked(&self, inner: &mut Inner, generation: u64) -> Result<()> {
        if inner.generation != generation
            || inner.connection.is_none()
            || inner.cancel.is_cancelled()
            || inner.kick_reason.is_some()
        {
            return Err(Error::Disconnected);
        }
        if inner.state.keystore.uin != 0 {
            let Inner { state, signer, .. } = inner;
            if let Err(error) = signer.business_session_started(state) {
                tracing::warn!(%error, "O3 business session could not be bound");
            }
            signer.registration_complete(state)?;
            if let Some(saved) = &mut state.keystore.ios_virtual_state {
                if saved.confirm_registration(state.keystore.uin) {
                    self.emit(LoginEvent::KeystoreChanged(state.keystore.clone()));
                }
            }
            if signer.has_ios_virtual_device() {
                let mut uin = itoa::Buffer::new();
                if let Err(error) =
                    signer.update_ios_logged_accounts(state, &[uin.format(state.keystore.uin)])
                {
                    tracing::warn!(%error, "Mobile authenticated-account token collection failed");
                }
            }
            self.background_work.notify_one();
            self.signing_work.notify_one();
        }
        inner.state.online = true;
        let cancel = inner.cancel.clone();
        inner.credentials.activate(generation, &cancel);
        self.media_keys.activate(
            generation,
            inner.state.keystore.uin,
            &inner.state.keystore.uid,
            &cancel,
        );
        Self::update_ticket_refresh_schedule(inner);
        self.emit(LoginEvent::Online {
            uin: inner.state.keystore.uin,
            uid: inner.state.keystore.uid.clone(),
        });
        Ok(())
    }
    pub(crate) fn emit(&self, event: LoginEvent) {
        let _ = self.events.send(event);
    }
    pub(crate) fn cancellation(&self) -> CancellationToken {
        self.inner.lock().unwrap().cancel.clone()
    }
    pub(crate) fn media_download_key_binding(
        &self,
    ) -> Result<crate::lifecycle::maintenance::Binding> {
        let inner = self.inner.lock().unwrap();
        if !inner.state.online || inner.connection.is_none() || inner.cancel.is_cancelled() {
            return Err(Error::Disconnected);
        }
        self.media_keys.binding(
            inner.generation,
            inner.state.keystore.uin,
            &inner.state.keystore.uid,
        )
    }
    pub(crate) fn connection_generation(&self) -> u64 {
        self.inner.lock().unwrap().generation
    }
    pub fn account_uin(&self) -> u64 {
        self.inner.lock().unwrap().state.keystore.uin
    }
    pub(crate) fn server_time_seconds(&self) -> Result<u32> {
        self.inner.lock().unwrap().clock.unix_seconds()
    }
    pub(crate) fn nt_key_exchange_time(&self) -> Result<u64> {
        let inner = self.inner.lock().unwrap();
        if inner.state.profile.platform.is_ios() {
            inner.clock.unix_millis().map(|millis| millis / 1000 * 1000)
        } else {
            inner.clock.unix_seconds().map(u64::from)
        }
    }
    pub(crate) fn start_ios_correct_time(&self) {
        let (generation, cancel) = {
            let inner = self.inner.lock().unwrap();
            if inner.ios().is_none() || inner.connection.is_none() || inner.cancel.is_cancelled() {
                return;
            }
            (inner.generation, inner.transport_cancel.clone())
        };
        let weak = self.weak.clone();
        let task = tokio::spawn(async move {
            for attempt in 0..3 {
                let Some(client) = weak.upgrade() else { return };
                let result = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return,
                    result = client.correct_time_for_generation(generation, true, &cancel) => result,
                };
                match result {
                    Ok(()) => return,
                    Err(Error::Timeout) if attempt < 2 && !cancel.is_cancelled() => {}
                    Err(Error::Server { code, .. })
                        if attempt < 2
                            && !cancel.is_cancelled()
                            && ios_response::Action::classify(code)
                                == ios_response::Action::Failure => {}
                    Err(error) => {
                        if !cancel.is_cancelled() {
                            tracing::warn!(target: "atri_qq_protocol::login", %error, generation, "Server clock correction unavailable");
                        }
                        return;
                    }
                }
            }
        });
        let mut tasks = self.tasks.lock().unwrap();
        tasks.retain(|task| !task.is_finished());
        tasks.push(task);
    }

    pub(crate) async fn correct_time(&self) -> Result<()> {
        let (generation, ios, source) = {
            let inner = self.inner.lock().unwrap();
            (
                inner.generation,
                inner.state.profile.platform.is_ios(),
                inner.transport_cancel.clone(),
            )
        };
        self.correct_time_for_generation(generation, ios, &source)
            .await
    }

    async fn correct_time_for_generation(
        &self,
        generation: u64,
        ios: bool,
        source: &CancellationToken,
    ) -> Result<()> {
        if source.is_cancelled() {
            return Err(Error::Disconnected);
        }
        let started = Instant::now();
        let response = self
            .request_inner(
                "Client.CorrectTime",
                Bytes::from_static(&[0, 0, 0, 4]),
                RequestType::Simple,
                Encryption::None,
                Duration::from_secs(if ios { 60 } else { 7 }),
                Some(if ios {
                    RequestBinding::IosControl { generation, source }
                } else {
                    RequestBinding::Connection(generation)
                }),
            )
            .await?;
        if started.elapsed() > Duration::from_secs(7) {
            return Err(wire::malformed(
                "CorrectTime round trip exceeds seven seconds",
            ));
        }
        let server = u32::from_be_bytes(
            response
                .as_ref()
                .try_into()
                .map_err(|_| wire::malformed("CorrectTime response must contain four bytes"))?,
        );
        let mut inner = self.inner.lock().unwrap();
        if inner.generation != generation
            || inner.connection.is_none()
            || inner.cancel.is_cancelled()
            || source.is_cancelled()
        {
            return Err(Error::Disconnected);
        }
        inner.clock.correction(server, SystemTime::now());
        tracing::debug!(target: "atri_qq_protocol::packet_trace", stage = "clock", generation, server_time = server, "QQ clock corrected");
        Ok(())
    }
    pub(crate) fn is_current_online(&self, generation: u64) -> bool {
        let inner = self.inner.lock().unwrap();
        Self::current_online(&inner, generation)
    }
    fn current_online(inner: &Inner, generation: u64) -> bool {
        inner.generation == generation
            && inner
                .connection
                .as_ref()
                .is_some_and(|connection| connection.generation == generation)
            && inner.state.online
            && !inner.cancel.is_cancelled()
    }
    fn update_ticket_refresh_schedule(inner: &mut Inner) {
        let selected_time = inner
            .state
            .keystore
            .nt_ticket_times
            .and_then(|times| times.selected())
            .is_some();
        let generation = inner.generation;
        inner.ticket_refresh_schedule.send_if_modified(|schedule| {
            let previous = *schedule;
            if schedule.generation != generation {
                *schedule = crate::ticket_refresh::Schedule {
                    generation,
                    ..Default::default()
                };
            }
            schedule.selected_time = selected_time;
            *schedule != previous
        });
    }
    pub(crate) fn ticket_refresh_schedule(
        &self,
        generation: u64,
    ) -> Result<watch::Receiver<crate::ticket_refresh::Schedule>> {
        let mut inner = self.inner.lock().unwrap();
        if !Self::current_online(&inner, generation) {
            return Err(Error::Disconnected);
        }
        Self::update_ticket_refresh_schedule(&mut inner);
        Ok(inner.ticket_refresh_schedule.subscribe())
    }
    pub(crate) fn set_ticket_refresh_interval(&self, generation: u64, seconds: i32) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if !Self::current_online(&inner, generation) {
            return Err(Error::Disconnected);
        }
        Self::update_ticket_refresh_schedule(&mut inner);
        inner.ticket_refresh_schedule.send_if_modified(|schedule| {
            if schedule.interval_seconds == Some(seconds) {
                return false;
            }
            schedule.interval_seconds = Some(seconds);
            true
        });
        Ok(())
    }
    pub(crate) fn ticket_refresh_ready(&self, generation: u64) -> Result<bool> {
        let inner = self.inner.lock().unwrap();
        if !Self::current_online(&inner, generation) {
            return Err(Error::Disconnected);
        }
        if inner.state.keystore.a1.is_empty() {
            return Err(Error::Authentication(
                "NT ticket refresh requires A1".into(),
            ));
        }
        if inner.ticket_refresh_failures >= 10 {
            return Ok(false);
        }
        let Some(next) = inner.state.keystore.next_ticket_refresh_unix_seconds() else {
            return Ok(false);
        };
        Ok(next <= u64::from(inner.clock.unix_seconds()?))
    }
    pub(crate) fn record_ticket_refresh_result(
        &self,
        generation: u64,
        succeeded: bool,
    ) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if !Self::current_online(&inner, generation) {
            return Err(Error::Disconnected);
        }
        inner.ticket_refresh_failures = if succeeded {
            0
        } else {
            inner.ticket_refresh_failures.saturating_add(1)
        };
        Ok(())
    }
    pub(crate) fn commit_nt_maintenance_state(
        &self,
        generation: u64,
        expected: &Keystore,
        updated: SessionState,
    ) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if !Self::current_online(&inner, generation) {
            return Err(Error::Disconnected);
        }
        if inner.state.keystore != *expected
            || inner.state.profile != updated.profile
            || inner.state.platform != updated.platform
            || expected.uin != updated.keystore.uin
            || expected.uid != updated.keystore.uid
            || !updated.online
        {
            return Err(Error::Authentication(
                "NT maintenance session state changed".into(),
            ));
        }
        self.replace_state_locked(&mut inner, updated);
        Ok(())
    }
    pub(crate) fn business_identity(&self, generation: u64) -> Result<(u64, String)> {
        let inner = self.inner.lock().unwrap();
        if inner.generation != generation
            || inner
                .connection
                .as_ref()
                .is_none_or(|connection| connection.generation != generation)
            || !inner.state.online
            || inner.cancel.is_cancelled()
            || inner.state.keystore.uin == 0
        {
            return Err(Error::Disconnected);
        }
        Ok((inner.state.keystore.uin, inner.state.keystore.qimei.clone()))
    }
    pub fn cached_friend_statuses(&self) -> Option<Arc<crate::contacts::FriendStatusSnapshot>> {
        let inner = self.inner.lock().unwrap();
        if !Self::current_online(&inner, inner.generation) {
            return None;
        }
        let binding = inner.friend_statuses.binding.as_ref()?;
        if !Self::friend_status_current(&inner, binding) {
            return None;
        }
        inner.friend_statuses.snapshot.clone()
    }

    pub async fn fetch_friend_statuses(
        &self,
    ) -> Result<Arc<crate::contacts::FriendStatusSnapshot>> {
        self.fetch_friend_statuses_generation(self.connection_generation())
            .await
    }

    pub(crate) async fn fetch_friend_statuses_generation(
        &self,
        generation: u64,
    ) -> Result<Arc<crate::contacts::FriendStatusSnapshot>> {
        let _gate = self.friend_status_gate.lock().await;
        let (binding, has_local) = {
            let mut inner = self.inner.lock().unwrap();
            if !Self::current_online(&inner, generation)
                || inner.state.keystore.uin == 0
                || inner.state.keystore.uid.is_empty()
            {
                return Err(Error::Disconnected);
            }
            if inner
                .friend_statuses
                .binding
                .as_ref()
                .is_none_or(|binding| !Self::friend_status_current(&inner, binding))
            {
                inner.friend_statuses.clear();
                inner.friend_statuses.binding = Some(Arc::new(crate::lifecycle::status::Binding {
                    generation,
                    uin: inner.state.keystore.uin,
                    uid: inner.state.keystore.uid.clone(),
                    cancel: inner.cancel.child_token(),
                }));
            }
            (
                inner.friend_statuses.binding.as_ref().unwrap().clone(),
                inner.friend_statuses.snapshot.is_some(),
            )
        };
        crate::lifecycle::status::fetch(self, &binding, has_local).await
    }

    fn friend_status_current(
        inner: &Inner,
        binding: &Arc<crate::lifecycle::status::Binding>,
    ) -> bool {
        Self::current_online(inner, binding.generation)
            && inner.state.keystore.uin == binding.uin
            && inner.state.keystore.uid == binding.uid
            && inner.friend_statuses.is_current(binding)
    }

    pub(crate) fn commit_friend_statuses(
        &self,
        binding: &Arc<crate::lifecycle::status::Binding>,
        snapshot: Arc<crate::contacts::FriendStatusSnapshot>,
    ) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if !Self::friend_status_current(&inner, binding) {
            return Err(Error::Disconnected);
        }
        inner.friend_statuses.snapshot = Some(snapshot);
        Ok(())
    }

    pub(crate) async fn request_friend_status(
        &self,
        binding: &Arc<crate::lifecycle::status::Binding>,
        body: Bytes,
    ) -> Result<Bytes> {
        self.request_inner(
            crate::lifecycle::status::COMMAND,
            body,
            RequestType::D2,
            Encryption::D2,
            Duration::from_secs(30),
            Some(RequestBinding::FriendStatus(binding)),
        )
        .await
    }

    pub(crate) fn start_maintenance(&self, generation: u64) -> Result<()> {
        let cancel = {
            let mut inner = self.inner.lock().unwrap();
            if inner.generation != generation
                || !inner.state.online
                || inner.connection.is_none()
                || inner.cancel.is_cancelled()
            {
                return Err(Error::Disconnected);
            }
            if inner.maintenance_started {
                return Ok(());
            }
            inner.maintenance_cancel = inner.cancel.child_token();
            inner.maintenance_started = true;
            inner.credentials.start();
            inner.maintenance_cancel.clone()
        };
        let refresh = tokio::spawn(credentials::run(
            self.weak.clone(),
            generation,
            cancel.clone(),
            self.credential_work.clone(),
        ));
        let lifecycle = tokio::spawn(crate::lifecycle::run(
            self.weak.clone(),
            generation,
            cancel.clone(),
        ));
        let robots = tokio::spawn(robot_ranges::run(
            self.weak.clone(),
            generation,
            cancel.clone(),
        ));
        let tickets = tokio::spawn(crate::ticket_refresh::run(
            self.weak.clone(),
            generation,
            cancel,
        ));
        self.tasks
            .lock()
            .unwrap()
            .extend([refresh, lifecycle, tickets, robots]);
        Ok(())
    }
    fn credential_session(&self) -> Result<Arc<credentials::Session>> {
        let inner = self.inner.lock().unwrap();
        if !inner.state.online || inner.connection.is_none() || inner.cancel.is_cancelled() {
            return Err(Error::Disconnected);
        }
        inner.credentials.session()
    }
    /// Returns the current session's client key only while its server TTL is valid.
    pub fn cached_client_key(&self) -> Option<crate::contacts::ClientKey> {
        let mut inner = self.inner.lock().unwrap();
        if !inner.state.online || inner.connection.is_none() || inner.cancel.is_cancelled() {
            return None;
        }
        inner.credentials.client_key()
    }
    /// Returns all requested PSKeys only when every domain has a valid server expiry.
    pub fn cached_cookies(&self, domains: &[String]) -> Option<BTreeMap<String, String>> {
        let mut inner = self.inner.lock().unwrap();
        if !inner.state.online || inner.connection.is_none() || inner.cancel.is_cancelled() {
            return None;
        }
        inner.credentials.cookies(domains)
    }
    /// Uses the session cache, fetching and committing a fresh key on a cache miss.
    /// `Operations::fetch_client_key` remains the unconditional RPC interface.
    pub async fn client_key(&self) -> Result<crate::contacts::ClientKey> {
        if let Some(key) = self.cached_client_key() {
            return Ok(key);
        }
        let session = self.credential_session()?;
        self.refresh_client_key(&session).await
    }
    /// Uses per-domain session caches; missing/expired server expiries are never reused.
    /// `Operations::fetch_cookies` remains the unconditional RPC interface.
    pub async fn cookies(&self, domains: &[String]) -> Result<BTreeMap<String, String>> {
        if let Some(cookies) = self.cached_cookies(domains) {
            return Ok(cookies);
        }
        let session = self.credential_session()?;
        self.refresh_cookies(&session, domains).await
    }
    pub(crate) async fn refresh_client_key(
        &self,
        session: &Arc<credentials::Session>,
    ) -> Result<crate::contacts::ClientKey> {
        let client = self.weak.upgrade().ok_or(Error::Disconnected)?;
        let operations = crate::contacts::Operations::new(client);
        let key = tokio::select! {
            biased;
            _ = session.cancel.cancelled() => return Err(Error::Disconnected),
            result = operations.fetch_client_key() => result?,
        };
        let mut inner = self.inner.lock().unwrap();
        if !inner.state.online
            || inner.generation != session.generation
            || !inner.credentials.is_current(session)
        {
            return Err(Error::Disconnected);
        }
        inner.credentials.commit_client_key(&key);
        self.credential_work.notify_one();
        Ok(key)
    }
    pub(crate) async fn refresh_cookies(
        &self,
        session: &Arc<credentials::Session>,
        domains: &[String],
    ) -> Result<BTreeMap<String, String>> {
        let client = self.weak.upgrade().ok_or(Error::Disconnected)?;
        let operations = crate::contacts::Operations::new(client);
        let response = tokio::select! {
            biased;
            _ = session.cancel.cancelled() => return Err(Error::Disconnected),
            result = operations.fetch_cookie_batch(domains) => result?,
        };
        let mut inner = self.inner.lock().unwrap();
        if !inner.state.online
            || inner.generation != session.generation
            || !inner.credentials.is_current(session)
        {
            return Err(Error::Disconnected);
        }
        inner
            .credentials
            .commit_cookies(domains, &response.values, &response.expirations);
        self.credential_work.notify_one();
        Ok(response.values)
    }
    pub(crate) fn credential_work(&self, generation: u64) -> Result<credentials::Work> {
        let inner = self.inner.lock().unwrap();
        if inner.generation != generation || !inner.state.online || inner.cancel.is_cancelled() {
            return Err(Error::Disconnected);
        }
        inner.credentials.work()
    }
    pub(crate) fn credential_refresh_failed(
        &self,
        session: &Arc<credentials::Session>,
        client_key: bool,
        domains: &[String],
    ) {
        let mut inner = self.inner.lock().unwrap();
        if inner.credentials.is_current(session) {
            inner.credentials.failed(client_key, domains);
        }
    }
    pub(crate) async fn pause(&self, duration: Duration) -> Result<()> {
        let cancel = self.cancellation();
        tokio::select! {_ = cancel.cancelled()=>Err(Error::Disconnected),_ = tokio::time::sleep(duration)=>Ok(())}
    }
    pub async fn connect(&self) -> Result<()> {
        let _gate = self.connect_gate.lock().await;
        self.tasks
            .lock()
            .unwrap()
            .retain(|task| !task.is_finished());
        let (generation, cancel) = {
            let mut i = self.inner.lock().unwrap();
            if i.ios().is_some_and(|ios| ios.response.reconnecting) {
                return Err(Error::Disconnected);
            }
            if i.connection.is_some() {
                return Ok(());
            }
            if i.cancel.is_cancelled() {
                i.cancel = CancellationToken::new()
            }
            i.signing_ready = false;
            if let Some(ios) = i.ios_mut() {
                ios.discovery.cancel_pending();
            }
            i.generation = i.generation.checked_add(1).ok_or_else(|| {
                Error::Unsupported("Connection generation space exhausted".into())
            })?;
            i.connection_cookie = Bytes::new();
            let generation = i.generation;
            if let Some(ios) = i.ios_mut() {
                ios.header.reset(generation);
            }
            self.prepare_ios_connection(&mut i)?;
            (i.generation, i.cancel.clone())
        };
        self.start_ios_discovery(generation, false);
        let socket = tokio::select! {
            _=cancel.cancelled()=>return Err(Error::Disconnected),
            result=tokio::time::timeout(self.config.timeout,self.connect_socket())=>match result {
                Ok(Ok(socket)) => socket,
                result => {
                    self.start_ios_discovery(generation, true);
                    return Err(match result { Ok(Err(error)) => error, _ => Error::Timeout });
                }
            },
        };
        self.install_transport(socket, generation)?;
        self.start_background_work(generation);
        if self.inner.lock().unwrap().linux_o3().is_some() {
            self.start_signing_work(generation, crate::o3::Channel::new());
        } else {
            self.start_ios_signing_work(generation);
        }
        self.start_ios_network_work(generation);
        Ok(())
    }
    fn install_transport(&self, socket: TcpStream, generation: u64) -> Result<()> {
        let cancel = {
            let mut inner = self.inner.lock().unwrap();
            if inner.generation != generation
                || inner.cancel.is_cancelled()
                || inner.kick_reason.is_some()
            {
                return Err(Error::Disconnected);
            }
            inner.transport_cancel.cancel();
            inner.transport_cancel = inner.cancel.child_token();
            inner.transport_cancel.clone()
        };
        socket.set_nodelay(true)?;
        let ios_peer = self
            .config
            .ios_virtual()
            .map(|_| socket.peer_addr())
            .transpose()?;
        let framed = Framed::new(socket, SsoFrameCodec);
        let (mut sink, mut source) = framed.split();
        let (sender, mut queue) = mpsc::channel::<Outgoing>(512);
        {
            let mut i = self.inner.lock().unwrap();
            if i.generation != generation || cancel.is_cancelled() {
                return Err(Error::Disconnected);
            }
            if let (Some(network), Some(peer)) =
                (i.ios_mut().and_then(|ios| ios.network.as_mut()), ios_peer)
            {
                network.connected(peer, crate::ios_device::network::wall_millis()?);
            }
            i.connection = Some(Connection { generation, sender });
            self.start_ios_probe_worker(&mut i);
        }
        let weak = self.weak.clone();
        let read_cancel = cancel.clone();
        let reader = tokio::spawn(async move {
            loop {
                let next = tokio::select! {biased;_ = read_cancel.cancelled()=>return,next=source.next()=>next};
                match next {
                    Some(Ok(frame)) => {
                        let Some(client) = weak.upgrade() else { return };
                        if let Err(error) =
                            client.receive_from_transport(frame, generation, Some(&read_cancel))
                        {
                            tracing::warn!(target: "atri_qq_protocol::packet", %error,
                                "Ignored incoming QQ packet; keeping the transport open");
                        }
                    }
                    Some(Err(error)) => {
                        if let Some(client) = weak.upgrade() {
                            client.record_ios_connection_failure(generation, &read_cancel);
                            client.terminate_transport(generation, &read_cancel, error.to_string())
                        }
                        return;
                    }
                    None => {
                        if let Some(client) = weak.upgrade() {
                            client.record_ios_connection_failure(generation, &read_cancel);
                            client.terminate_transport(
                                generation,
                                &read_cancel,
                                "TCP peer closed".into(),
                            )
                        }
                        return;
                    }
                }
            }
        });
        let weak = self.weak.clone();
        let write_cancel = cancel;
        let writer = tokio::spawn(async move {
            loop {
                let item = tokio::select! {biased;_ = write_cancel.cancelled()=>return,item=queue.recv()=>item};
                let Some(item) = item else { return };
                if item.cancel.is_cancelled() {
                    continue;
                }
                if weak.upgrade().is_none_or(|client| {
                    let inner = client.inner.lock().unwrap();
                    inner.generation != generation
                        || (inner.kick_reason.is_some() && !item.terminal)
                }) {
                    continue;
                }
                if Instant::now() >= item.deadline {
                    if item.required_control {
                        if let Some(client) = weak.upgrade() {
                            client.terminate_transport(
                                generation,
                                &write_cancel,
                                "Required control response expired in the write queue".into(),
                            );
                        }
                        return;
                    }
                    continue;
                }
                // Once a frame starts, request cancellation MUST NOT abandon its tail.
                // A successful response can precede sink.flush completion; it never cancels this write.
                item.trace(generation);
                if let Some(client) = weak.upgrade() {
                    if let Err(error) = client.mark_ios_send_started(
                        generation,
                        item.sequence,
                        item.attempt,
                        &write_cancel,
                    ) {
                        client.terminate_transport(generation, &write_cancel, error.to_string());
                        return;
                    }
                }
                let result = tokio::select! {biased;_ = write_cancel.cancelled()=>return,result=timeout_at(item.deadline,sink.send(item.frame))=>result};
                match result {
                    Ok(Ok(())) => {
                        if let Some(client) = weak.upgrade() {
                            if let Err(error) = client.mark_activity(
                                generation,
                                item.sequence,
                                &item.command,
                                item.attempt,
                                &write_cancel,
                            ) {
                                client.terminate_transport(
                                    generation,
                                    &write_cancel,
                                    error.to_string(),
                                );
                                return;
                            }
                            if item.terminal {
                                client.terminate_transport(
                                    generation,
                                    &write_cancel,
                                    String::new(),
                                );
                                return;
                            }
                        }
                    }
                    Ok(Err(error)) => {
                        if let Some(client) = weak.upgrade() {
                            client.record_ios_connection_failure(generation, &write_cancel);
                            client.terminate_transport(
                                generation,
                                &write_cancel,
                                format!("TCP write failed: {error}"),
                            )
                        }
                        return;
                    }
                    Err(_) => {
                        if let Some(client) = weak.upgrade() {
                            client.record_ios_connection_failure(generation, &write_cancel);
                            client.terminate_transport(
                                generation,
                                &write_cancel,
                                "TCP write deadline expired; frame transmission uncertain".into(),
                            )
                        }
                        return;
                    }
                }
            }
        });
        let mut tasks = self.tasks.lock().unwrap();
        tasks.retain(|task| !task.is_finished());
        tasks.extend([reader, writer]);
        Ok(())
    }
    #[cfg(test)]
    fn receive(&self, frame: Bytes, generation: u64) -> Result<()> {
        self.receive_from_transport(frame, generation, None)
    }
    fn receive_from_transport(
        &self,
        frame: Bytes,
        generation: u64,
        source: Option<&CancellationToken>,
    ) -> Result<()> {
        let mut i = self.inner.lock().unwrap();
        if i.generation != generation
            || i.connection.as_ref().map(|c| c.generation) != Some(generation)
            || source.is_some_and(CancellationToken::is_cancelled)
        {
            tracing::debug!(target: "atri_qq_protocol::packet_trace", direction = "receive", stage = "wire", command = "<unavailable>", generation, decode_error = "stale connection generation", length = frame.len(), raw_hex = %hex::encode(&frame), "QQ packet");
            return Ok(());
        }
        let mut keys = vec![i.state.keystore.d2_key.as_slice()];
        keys.extend(i.previous_keys.iter().map(Vec::as_slice));
        for pending in i.pending.values() {
            if !keys.contains(&pending.key.as_slice()) {
                keys.push(pending.key.as_slice())
            }
        }
        let (packet, extra) = wire::decode_sso(frame.clone(), &keys).inspect_err(|error| {
            tracing::debug!(target: "atri_qq_protocol::packet_trace", direction = "receive", stage = "wire", command = "<unavailable>", generation, decode_error = %error, length = frame.len(), raw_hex = %hex::encode(&frame), "QQ packet");
            crate::diagnostics::log_raw_error("SSO", &frame, error);
        })?;
        if i.state.profile.platform.is_ios()
            && i.connection_cookie.is_empty()
            && !packet.header.message_cookie.is_empty()
        {
            i.connection_cookie = packet.header.message_cookie.clone();
        }
        tracing::debug!(target: "atri_qq_protocol::packet_trace", direction = "receive", stage = "wire", command = packet.command, sequence = packet.sequence, generation, length = frame.len(), raw_hex = %hex::encode(&frame), "QQ packet");
        tracing::debug!(target: "atri_qq_protocol::packet_trace", direction = "receive", stage = "decoded", generation, command = packet.command, sequence = packet.sequence, return_code = packet.return_code, extra, packet = ?packet, body_hex = %hex::encode(&packet.body), "QQ packet");
        let action = if i.ios().is_some() {
            ios_response::Action::classify(packet.return_code)
        } else if packet.return_code == 0 {
            ios_response::Action::Deliver
        } else {
            ios_response::Action::Failure
        };
        if action == ios_response::Action::Failure {
            crate::diagnostics::log_transport_error(&packet, &extra, &frame);
        }
        i.last_activity = Instant::now();
        self.activity.notify_one();
        let reserve = i.ios().and_then(|_| {
            (!packet.header.server_reserve.is_empty())
                .then(|| {
                    crate::proto::sso::Reserved::decode(packet.header.server_reserve.clone()).ok()
                })
                .flatten()
        });
        if matches!(
            action,
            ios_response::Action::Deliver | ios_response::Action::DeliverStatus
        ) && let (Some(ios), Some(reserve)) = (i.ios_mut(), reserve.as_ref())
        {
            ios.response.signature.accept(reserve);
        }
        if i.ios().is_some_and(|ios| ios.network.is_some()) {
            let (created, sent) = i
                .pending
                .get(&packet.sequence)
                .filter(|request| request.command == packet.command)
                .and_then(|request| request.ios.as_ref())
                .map(|timing| (Some(timing.created), timing.sent))
                .unwrap_or((None, None));
            let correction = reserve
                .as_ref()
                .and_then(|reserve| reserve.rtt_correction_ms)
                .map(|value| value as i32);
            i.ios_mut().unwrap().network.as_mut().unwrap().response(
                &packet.command,
                created,
                sent,
                correction,
                crate::ios_device::network::wall_millis()?,
            );
        }
        if i.kick_reason.is_some() {
            return Ok(());
        }
        let matched = i
            .pending
            .get(&packet.sequence)
            .is_some_and(|pending| pending.command == packet.command);
        let accepted = matches!(
            action,
            ios_response::Action::Deliver | ios_response::Action::DeliverStatus
        );
        let config_push =
            (!matched && accepted && packet.command == crate::network::PUSH_REQUEST_COMMAND)
                .then(|| crate::network::decode_push_with_delivery(packet.body.clone()));
        if accepted
            && reserve.is_some()
            && i.ios().is_some()
            && ios_response::host_delivered(
                &packet,
                matched,
                config_push
                    .as_ref()
                    .is_some_and(|result| result.as_ref().is_ok_and(|(_, consumed)| *consumed)),
            )
        {
            i.ios_mut()
                .unwrap()
                .response
                .signature
                .host_delivery(reserve.as_ref().unwrap());
        }
        match action {
            ios_response::Action::Full => {
                return if matched {
                    self.resend_ios(&mut i, packet.sequence, generation, true)
                } else {
                    Ok(())
                };
            }
            ios_response::Action::Ability => {
                i.ios_mut().unwrap().response.disabled_abilities |= 1;
                return if matched {
                    self.resend_ios(&mut i, packet.sequence, generation, false)
                } else {
                    Ok(())
                };
            }
            ios_response::Action::Reconnect => {
                self.reconnect_ios_transport(
                    &mut i,
                    generation,
                    matched.then_some(packet.sequence),
                );
                return Ok(());
            }
            ios_response::Action::Consume => {
                if matched {
                    self.consume_ios_response(&mut i, packet.sequence);
                }
                return Ok(());
            }
            _ => {}
        }
        if packet.command == "trpc.qq_new_tech.status_svc.StatusService.KickNT"
            && packet.return_code != 0
        {
            let error = Error::Server {
                code: packet.return_code,
                message: extra,
            };
            drop(i);
            self.terminate_generation(generation, format!("Kicked: {error}"));
            return Ok(());
        }
        if packet.command == "trpc.qq_new_tech.status_svc.StatusService.KickNT" {
            let kick = crate::proto::decode::<auth::Kick>(packet.body.clone())?;
            drop(i);
            let _ = self.packets.send(packet);
            return self.begin_kick(generation, kick);
        }
        if i.pending
            .get(&packet.sequence)
            .is_some_and(|p| p.command == packet.command)
        {
            let eligible = i.pending[&packet.sequence]
                .replay
                .as_ref()
                .is_some_and(|replay| replay.eligible);
            if let Some(ios) = i.ios_mut() {
                ios.header.response(eligible);
            }
            let pending = i.pending.remove(&packet.sequence).unwrap();
            self.accept_ios_block_check(&mut i, &pending);
            // Deliberately do not cancel pending.cancel on a matching response.
            let result = if action == ios_response::Action::DeliverStatus {
                let body = packet.body.clone();
                if !pending
                    .replay
                    .as_ref()
                    .is_some_and(|replay| replay.internal_control)
                {
                    let _ = self.packets.send(packet);
                }
                Ok(body)
            } else if action == ios_response::Action::Deliver {
                Ok(packet.body)
            } else {
                Err(Error::Server {
                    code: packet.return_code,
                    message: extra,
                })
            };
            if let Some((binding, request)) = pending.message_sync {
                let actions = self.message_sync.direct(&binding, &request, result);
                self.record_ios_registration(&mut i, &binding);
                let _ = pending.reply.send(Ok(Bytes::new()));
                drop(i);
                self.sync_ios_guild_cursor(generation);
                self.spawn_message_sync_actions(binding, actions);
                return Ok(());
            }
            let _ = pending.reply.send(result);
            return Ok(());
        }
        let sync = if accepted {
            self.message_sync
                .ingest(generation, &i.state, &packet.command, packet.body.clone())
        } else {
            Ok((false, None, Vec::new()))
        };
        if let Ok((_, Some(binding), _)) = &sync {
            self.record_ios_registration(&mut i, binding);
        }
        drop(i);
        match sync {
            Ok((accepted, binding, actions)) => {
                if accepted && packet.command != crate::message_sync::INFO_PUSH {
                    if let Err(error) = self.guild_session.ingest(generation, &packet) {
                        tracing::warn!(%error, command = packet.command, "QQ guild synchronization push rejected");
                    }
                }
                if let Some(binding) = binding {
                    self.spawn_message_sync_actions(binding, actions);
                }
            }
            Err(error) => {
                tracing::warn!(%error, command = packet.command, "QQ message synchronization push rejected");
            }
        }
        self.sync_ios_guild_cursor(generation);
        if action == ios_response::Action::Failure {
            return Err(Error::Server {
                code: packet.return_code,
                message: extra,
            });
        }
        if packet.command == crate::network::LOGIN_NOTIFICATION_COMMAND {
            let notification = crate::network::decode_login_notification(packet.body.clone())
                .inspect_err(|_| {
                    let _ = self.packets.send(packet.clone());
                })?;
            let inner = self.inner.lock().unwrap();
            if inner.generation == generation
                && inner.connection.is_some()
                && inner.kick_reason.is_none()
            {
                let _ = self.login_notifications.send(Arc::new(notification));
            }
        }
        let control_reply = match packet.command.as_str() {
            "trpc.msg.olpush.OlPushService.MsgPush" => wire::encode_push_ack(packet.body.clone())?
                .map(|body| ("trpc.msg.olpush.OlPushService.SsoPushAck", body)),
            "ConfigPushSvc.PushReq" => config_push
                .unwrap()
                .and_then(|(push, _)| self.apply_network_push(generation, push))
                .inspect_err(|_| {
                    let _ = self.packets.send(packet.clone());
                })?
                .map(|body| ("ConfigPushSvc.PushResp", body)),
            crate::guild::PUSH_COMMAND => crate::guild::encode_push_ack(packet.body.clone())
                .inspect_err(|_| {
                    let _ = self.packets.send(packet.clone());
                })?
                .map(|body| (crate::guild::PUSH_RESPONSE_COMMAND, body)),
            _ => None,
        };
        if let Some(reply) = control_reply {
            let mut inner = self.inner.lock().unwrap();
            if inner.generation != generation || inner.connection.is_none() {
                return Ok(());
            }
            if inner.control_replies.len() >= 4096 {
                drop(inner);
                self.terminate_generation(
                    generation,
                    "Too many pending required control responses".into(),
                );
                return Err(Error::Unsupported(
                    "Too many pending required control responses".into(),
                ));
            }
            inner.control_replies.push_back(reply);
            self.background_work.notify_one();
        }
        let _ = self.packets.send(packet);
        Ok(())
    }
    fn begin_kick(&self, generation: u64, kick: auth::Kick) -> Result<()> {
        let reason = format!(
            "Kicked: {} {} app_id={:?} instance_id={:?} kicked_type={:?} security_kicked_type={:?}",
            kick.title.unwrap_or_default(),
            kick.message.unwrap_or_default(),
            kick.app_id,
            kick.instance_id,
            kick.kicked_type,
            kick.security_kicked_type,
        );
        let deadline = match Instant::now().checked_add(self.config.timeout) {
            Some(deadline) => deadline,
            None => {
                self.terminate_generation(generation, reason);
                return Err(wire::malformed("Kick cleanup deadline overflow"));
            }
        };
        let (sender, outgoing) = {
            let mut inner = self.inner.lock().unwrap();
            if inner.generation != generation || inner.connection.is_none() {
                return Ok(());
            }
            if inner.kick_reason.is_some() {
                return Ok(());
            }
            inner.kick_reason = Some(reason);
            self.message_sync.close(generation);
            self.personal_events.cancel();
            inner.state.online = false;
            inner.signing_ready = false;
            inner.alive_cancel.cancel();
            inner.heartbeat_cancel.cancel();
            inner.signing_cancel.cancel();
            inner.maintenance_cancel.cancel();
            inner.maintenance_started = false;
            inner.credentials.invalidate(true);
            inner.ip_direct_configuration = None;
            inner.file_transfer.invalidate();
            inner.file_transfer_worker = None;
            inner.friend_statuses.clear();
            inner.control_replies.clear();
            for (_, pending) in inner.pending.drain() {
                pending.cancel.cancel();
                let _ = pending.reply.send(Err(Error::Disconnected));
            }
            let command = "trpc.qq_new_tech.status_svc.StatusService.UnRegister";
            let prepared = self.prepare_frame(
                &mut inner,
                command,
                Self::unregister_body(true),
                RequestType::D2,
                Encryption::D2,
            );
            let (sequence, frame) = match prepared {
                Ok(frame) => frame,
                Err(error) => {
                    drop(inner);
                    self.terminate_generation(generation, String::new());
                    return Err(error);
                }
            };
            let sender = inner.connection.as_ref().unwrap().sender.clone();
            let outgoing = Outgoing {
                command: command.into(),
                sequence,
                attempt: 0,
                frame,
                deadline,
                cancel: inner.cancel.clone(),
                required_control: true,
                terminal: true,
            };
            (sender, outgoing)
        };
        self.guild_session.close(generation);
        self.media_keys.close(generation);
        match sender.try_send(outgoing) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.terminate_generation(generation, String::new());
            }
            Err(mpsc::error::TrySendError::Full(outgoing)) => {
                let weak = self.weak.clone();
                let cancel = outgoing.cancel.clone();
                let task = tokio::spawn(async move {
                    let result = tokio::select! {
                        biased;
                        _ = cancel.cancelled() => return,
                        result = timeout_at(deadline, sender.send(outgoing)) => result,
                    };
                    if !matches!(result, Ok(Ok(())))
                        && let Some(client) = weak.upgrade()
                    {
                        client.terminate_generation(generation, String::new());
                    }
                });
                self.tasks.lock().unwrap().push(task);
            }
        }
        Ok(())
    }
    fn prepare_frame(
        &self,
        inner: &mut Inner,
        command: &str,
        body: Bytes,
        request_type: RequestType,
        encryption: Encryption,
    ) -> Result<(i32, Bytes)> {
        self.prepare_frame_from(
            inner,
            command,
            body,
            request_type,
            encryption,
            true,
            false,
            None,
        )
    }
    fn prepare_frame_from(
        &self,
        inner: &mut Inner,
        command: &str,
        body: Bytes,
        request_type: RequestType,
        encryption: Encryption,
        is_nt_request: bool,
        ios_internal_control: bool,
        replay: Option<&mut ios_header::Replay>,
    ) -> Result<(i32, Bytes)> {
        if let Some(ios) = inner.ios() {
            let resources = &ios.transport;
            resources.validate()?;
            if command == "PushService.get"
                && resources.push_service_get_statistics.is_none()
                && ios.network.is_none()
            {
                return Err(Error::Authentication(
                    "PushService.get requires actual iOS transport statistics".into(),
                ));
            }
        }
        inner.sequence = inner.sequence.checked_add(1).ok_or_else(|| {
            Error::Unsupported("SSO sequence space exhausted; reconnect required".into())
        })?;
        let sequence = inner.sequence;
        let frame = self.prepare_frame_at(
            inner,
            command,
            body,
            request_type,
            encryption,
            is_nt_request,
            ios_internal_control,
            sequence,
            false,
            replay,
        )?;
        Ok((sequence, frame))
    }
    fn prepare_frame_at(
        &self,
        inner: &mut Inner,
        command: &str,
        body: Bytes,
        request_type: RequestType,
        encryption: Encryption,
        is_nt_request: bool,
        ios_internal_control: bool,
        sequence: i32,
        force_full: bool,
        replay: Option<&mut ios_header::Replay>,
    ) -> Result<Bytes> {
        let is_replay = replay.as_ref().is_some_and(|replay| replay.attempt != 0);
        let invokes_signer = !is_replay
            && !ios_internal_control
            && inner
                .ios()
                .is_none_or(|ios| ios.response.signature.invokes());
        let signing_generation = invokes_signer.then(|| inner.signer.generation());
        let signature = if is_replay {
            replay.as_ref().and_then(|replay| replay.signature.clone())
        } else if !invokes_signer {
            None
        } else {
            inner
                .signer
                .sign_shared(
                    command,
                    sequence,
                    body.clone(),
                    &inner.state,
                    self.config.randomize_signature_for_testing,
                )?
                .map(|security| crate::proto::sso::SecureInfo {
                    sign: Some(Bytes::copy_from_slice(security.sign.as_ref())),
                    token: Some(security.token.into()),
                    extra: Some(security.extra.into()),
                })
        };
        if !is_replay {
            if let Some(replay) = replay {
                replay.signature = signature.clone();
            }
        }
        if signing_generation.is_some_and(|generation| inner.signer.generation() != generation) {
            inner.signing_cancel.cancel();
            inner.signing_cancel = CancellationToken::new();
        }
        if signature.is_some() && !is_replay {
            self.signing_work.notify_one();
        }
        let signature = if inner
            .ios()
            .is_some_and(|ios| !ios.response.signature.attaches())
        {
            None
        } else {
            signature
        };
        let Inner {
            state,
            platform,
            connection_cookie,
            generation,
            ..
        } = inner;
        let ios = match platform {
            PlatformRuntime::Ios(ios) => Some(ios),
            PlatformRuntime::Linux(_) => None,
        };
        let mut ios = ios;
        if command == "PushService.get" {
            if let Some(ios) = ios.as_deref_mut() {
                if let Some(network) = &mut ios.network {
                    ios.transport.push_service_get_statistics =
                        Some(network.take_push_statistics());
                }
            }
        }
        let request_type = if let Some(ios) = ios.as_deref_mut() {
            ios.header.select(
                *generation,
                command,
                &ios.transport,
                &state.keystore,
                force_full,
            )
        } else {
            request_type
        };
        let encryption = if ios_internal_control {
            Encryption::None
        } else {
            encryption
        };
        tracing::debug!(target: "atri_qq_protocol::packet_trace", direction = "send", stage = "prepared", command, sequence, generation = *generation, request_type = ?request_type, encryption = ?encryption, body_hex = %hex::encode(&body), "QQ packet");
        let (transport, network, qimei) = match ios.as_deref_mut() {
            Some(ios) => (
                Some((&ios.transport, connection_cookie.as_ref())),
                ios.network.as_ref(),
                Some(&mut ios.header.qimei_materialized),
            ),
            None => (None, None, None),
        };
        let frame = wire::encode_sso(
            command,
            sequence,
            body,
            request_type,
            encryption,
            state,
            signature,
            transport,
            network,
            is_nt_request,
            qimei,
            ios_internal_control,
        );
        if command == "PushService.get" {
            if let Some(ios) = ios {
                ios.transport.push_service_get_statistics = Some(IosPushStatistics::default());
            }
        }
        frame
    }
    async fn send_only(&self, command: &str, body: Bytes, generation: u64) -> Result<()> {
        let deadline = Instant::now()
            .checked_add(self.config.timeout)
            .ok_or_else(|| wire::malformed("Send deadline overflow"))?;
        let (sender, sequence, frame, cancel) = {
            let mut inner = self.inner.lock().unwrap();
            if inner.generation != generation
                || inner.kick_reason.is_some()
                || inner.ios().is_some_and(|ios| ios.response.reconnecting)
            {
                return Err(Error::Disconnected);
            }
            let sender = inner
                .connection
                .as_ref()
                .ok_or(Error::Disconnected)?
                .sender
                .clone();
            let (sequence, frame) =
                self.prepare_frame(&mut inner, command, body, RequestType::D2, Encryption::D2)?;
            (sender, sequence, frame, inner.cancel.clone())
        };
        timeout_at(
            deadline,
            sender.send(Outgoing {
                command: command.to_owned(),
                sequence,
                attempt: 0,
                frame,
                deadline,
                cancel,
                required_control: true,
                terminal: false,
            }),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|_| Error::Disconnected)
    }
    pub async fn request(
        &self,
        command: &str,
        body: Bytes,
        request_type: RequestType,
        encryption: Encryption,
        timeout: Duration,
    ) -> Result<Bytes> {
        self.request_inner(command, body, request_type, encryption, timeout, None)
            .await
    }
    pub(crate) async fn request_online(
        &self,
        generation: u64,
        command: &str,
        body: Bytes,
        timeout: Duration,
    ) -> Result<Bytes> {
        self.request_inner(
            command,
            body,
            RequestType::D2,
            Encryption::D2,
            timeout,
            Some(RequestBinding::Online(generation)),
        )
        .await
    }
    pub(crate) async fn request_nt_maintenance(
        &self,
        generation: u64,
        command: &str,
        body: Bytes,
    ) -> Result<Bytes> {
        self.request_inner(
            command,
            body,
            RequestType::D2,
            Encryption::Empty,
            self.config.timeout,
            Some(RequestBinding::Online(generation)),
        )
        .await
    }
    async fn request_inner(
        &self,
        command: &str,
        body: Bytes,
        request_type: RequestType,
        encryption: Encryption,
        timeout: Duration,
        binding: Option<RequestBinding<'_>>,
    ) -> Result<Bytes> {
        if timeout.is_zero() {
            return Err(Error::Timeout);
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| wire::malformed("Request deadline overflow"))?;
        let (sequence, id, sender, frame, cancel, reply) = {
            let mut i = self.inner.lock().unwrap();
            let current = match binding {
                None => true,
                Some(RequestBinding::Connection(generation)) => i.generation == generation,
                Some(RequestBinding::IosControl { generation, source }) => {
                    i.generation == generation && !source.is_cancelled()
                }
                Some(RequestBinding::IosO3(binding)) => binding.is_current(&i),
                Some(RequestBinding::Online(generation)) => {
                    i.generation == generation && i.state.online
                }
                Some(RequestBinding::FriendStatus(binding)) => {
                    Self::friend_status_current(&i, binding)
                }
                Some(RequestBinding::Credentials(session)) => {
                    Self::current_online(&i, session.generation)
                        && i.credentials.is_current(session)
                }
                Some(RequestBinding::FileTransfer(binding)) => {
                    Self::file_transfer_current(&i, binding)
                }
                Some(RequestBinding::SigningReport { generation, report }) => {
                    i.generation == generation
                        && i.signer.report_is_current(report)
                        && std::str::from_utf8(&report.account)
                            .ok()
                            .and_then(|account| account.parse::<u64>().ok())
                            == Some(i.state.keystore.uin)
                }
            };
            if !current
                || i.kick_reason.is_some()
                || i.ios().is_some_and(|ios| ios.response.reconnecting)
            {
                return Err(Error::Disconnected);
            }
            let sender = i
                .connection
                .as_ref()
                .ok_or(Error::Disconnected)?
                .sender
                .clone();
            if i.pending.len() >= 4096 {
                return Err(Error::Unsupported(
                    "Too many outstanding SSO requests".into(),
                ));
            }
            let ios = ios_network::RequestTiming::new(&i)?;
            let is_nt_request = !matches!(
                binding,
                Some(
                    RequestBinding::Connection(_)
                        | RequestBinding::IosControl { .. }
                        | RequestBinding::IosO3(_)
                        | RequestBinding::Credentials(_)
                )
            );
            let ios_internal_control = matches!(binding, Some(RequestBinding::IosControl { .. }));
            let mut replay = ios_header::Replay::new(
                &i,
                &body,
                request_type,
                encryption,
                is_nt_request,
                ios_internal_control,
                deadline,
            );
            let (sequence, frame) = self.prepare_frame_from(
                &mut i,
                command,
                body,
                request_type,
                encryption,
                is_nt_request,
                ios_internal_control,
                replay.as_mut(),
            )?;
            i.next_id = i
                .next_id
                .checked_add(1)
                .ok_or_else(|| Error::Unsupported("Request identity space exhausted".into()))?;
            let id = i.next_id;
            let key = i.state.keystore.d2_key.clone();
            let (tx, rx) = oneshot::channel();
            let cancel = match binding {
                Some(RequestBinding::FriendStatus(binding)) => binding.cancel.child_token(),
                Some(RequestBinding::Credentials(session)) => session.cancel.child_token(),
                Some(RequestBinding::FileTransfer(binding)) => binding.cancel.child_token(),
                _ => CancellationToken::new(),
            };
            i.pending.insert(
                sequence,
                Pending {
                    id,
                    command: command.into(),
                    key,
                    reply: tx,
                    cancel: cancel.clone(),
                    ios,
                    replay,
                    message_sync: None,
                },
            );
            self.arm_ios_block_checks(&mut i);
            (sequence, id, sender, frame, cancel, rx)
        };
        let _guard = PendingGuard {
            client: self,
            sequence,
            id,
        };
        timeout_at(deadline, async {
            sender
                .send(Outgoing {
                    command: command.to_owned(),
                    sequence,
                    attempt: 0,
                    frame,
                    deadline,
                    cancel,
                    required_control: false,
                    terminal: false,
                })
                .await
                .map_err(|_| Error::Disconnected)?;
            reply.await.map_err(|_| Error::Disconnected)?
        })
        .await
        .map_err(|_| {
            self.note_ios_timeout(sequence, id);
            Error::Timeout
        })?
    }
    pub(crate) async fn call(
        &self,
        command: &str,
        body: Bytes,
        encryption: Encryption,
    ) -> Result<Bytes> {
        self.request(
            command,
            body,
            RequestType::D2,
            encryption,
            self.config.timeout,
        )
        .await
    }
    pub async fn login(self: &Arc<Self>) -> Result<UserInfo> {
        login::login(self).await
    }
    pub async fn refresh_tickets(self: &Arc<Self>) -> Result<()> {
        login::refresh_tickets(self).await
    }
    pub async fn submit_captcha(&self, ticket: String, random: String) -> Result<()> {
        if ticket.is_empty() || random.is_empty() {
            return Err(Error::Authentication(
                "Captcha ticket and random string must not be empty".into(),
            ));
        }
        self.captcha
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| Error::Authentication("No captcha challenge is active".into()))?
            .send((ticket, random))
            .map_err(|_| Error::Disconnected)
    }
    pub async fn submit_device_verification(
        &self,
        result: IosDeviceVerificationResult,
    ) -> Result<()> {
        if result.signature.is_empty() && result.authentication_type == 0 {
            return Err(Error::Authentication(
                "Device verification requires the webpage's ntVerifySig or a nonzero authentication_type".into(),
            ));
        }
        self.device_verification
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| {
                Error::Authentication("No iOS device verification challenge is active".into())
            })?
            .send(result)
            .map_err(|_| Error::Disconnected)
    }
    pub async fn submit_security_action(&self, action: IosLoginSecurityAction) -> Result<()> {
        let mut pending = self.security.lock().unwrap();
        let active = pending
            .as_ref()
            .ok_or_else(|| Error::Authentication("No iOS security challenge is active".into()))?;
        active.challenge.validate_action(&action)?;
        pending
            .take()
            .unwrap()
            .reply
            .send(action)
            .map_err(|_| Error::Disconnected)
    }
    fn unregister_body(kicked: bool) -> Bytes {
        auth::UnregisterRequest {
            r#type: Some(0),
            device: Some(auth::StatusDevice {
                name: Some(Bytes::new()),
                kernel: Some(Bytes::new()),
                vendor: Some(Bytes::new()),
                model: Some(Bytes::new()),
                os: Some(Bytes::new()),
            }),
            reason: Some(u32::from(kicked)),
        }
        .encode_to_vec()
        .into()
    }
    pub async fn logout(&self) -> Result<()> {
        let state = self.snapshot().await;
        let result = if state.online {
            let body = Self::unregister_body(false);
            match self
                .call(
                    "trpc.qq_new_tech.status_svc.StatusService.UnRegister",
                    body,
                    Encryption::D2,
                )
                .await
            {
                Ok(response) => match crate::proto::decode::<auth::StatusResponse>(response) {
                    Ok(p) if p.message.as_deref() == Some("unregister success") => Ok(()),
                    Ok(p) => Err(Error::Authentication(
                        p.message
                            .unwrap_or_else(|| "Unregister was not confirmed".into()),
                    )),
                    Err(e) => Err(e),
                },
                Err(e) => Err(e),
            }
        } else {
            Ok(())
        };
        self.close_transport("Logout".into()).await;
        result
    }
    pub async fn close(&self) {
        let _ = self.logout().await;
    }
    pub(crate) async fn close_transport(&self, reason: String) {
        self.terminate(reason.clone());
        let _gate = self.connect_gate.lock().await;
        self.terminate(reason);
        let tasks = std::mem::take(&mut *self.tasks.lock().unwrap());
        for task in tasks {
            let _ = task.await;
        }
    }
    pub(crate) fn terminate(&self, reason: String) {
        let generation = self.inner.lock().unwrap().generation;
        self.terminate_generation(generation, reason)
    }
    fn terminate_generation(&self, generation: u64, reason: String) {
        self.terminate_generation_with_policy(generation, reason, false, None);
    }
    fn terminate_transport(&self, generation: u64, source: &CancellationToken, reason: String) {
        self.terminate_generation_with_policy(
            generation,
            reason,
            false,
            Some(&|_| !source.is_cancelled()),
        );
    }
    fn terminate_generation_with_policy(
        &self,
        generation: u64,
        reason: String,
        preserve_kick: bool,
        condition: Option<&dyn Fn(&Inner) -> bool>,
    ) {
        {
            let mut i = self.inner.lock().unwrap();
            if i.generation != generation
                || (preserve_kick && i.kick_reason.is_some())
                || condition.is_some_and(|condition| !condition(&i))
            {
                return;
            }
            let reason = i.kick_reason.take().unwrap_or(reason);
            i.cancel.cancel();
            if let Some(ios) = i.ios_mut() {
                ios.discovery.cancel_pending();
                ios.probes.clear();
            }
            i.maintenance_cancel.cancel();
            i.maintenance_started = false;
            i.credentials.invalidate(true);
            i.ip_direct_configuration = None;
            i.file_transfer.invalidate();
            i.file_transfer_worker = None;
            i.friend_statuses.clear();
            let connected = i.connection.take().is_some();
            i.connection_cookie = Bytes::new();
            if let Some(ios) = i.ios_mut() {
                ios.header.reset(generation);
                ios.response.reconnecting = false;
                ios.block_check = ios_network::BlockCheck::default();
                if let Some(network) = &mut ios.network {
                    network.disconnect();
                }
            }
            let online = i.state.online;
            i.state.online = false;
            i.control_replies.clear();
            for (_, pending) in i.pending.drain() {
                pending.cancel.cancel();
                let _ = pending.reply.send(Err(Error::Disconnected));
            }
            if connected || online {
                self.emit(LoginEvent::Offline { reason })
            }
        }
        self.guild_session.close(generation);
        self.message_sync.close(generation);
        self.personal_events.cancel();
        self.media_keys.close(generation);
        self.captcha.lock().unwrap().take();
        self.device_verification.lock().unwrap().take();
        self.security.lock().unwrap().take();
    }
    fn mark_activity(
        &self,
        generation: u64,
        sequence: i32,
        command: &str,
        attempt: u64,
        source: &CancellationToken,
    ) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.generation == generation && inner.connection.is_some() && !source.is_cancelled() {
            if let Some(network) = inner.ios_mut().and_then(|ios| ios.network.as_mut()) {
                network.sent(command);
                if let Some(request) = inner.pending.get_mut(&sequence).filter(|request| {
                    request
                        .replay
                        .as_ref()
                        .is_none_or(|replay| replay.attempt == attempt)
                }) {
                    if let Some(timing) = &mut request.ios {
                        timing.sent = Some(crate::ios_device::network::wall_millis()?);
                    }
                }
            }
            if let Some(replay) = inner
                .pending
                .get_mut(&sequence)
                .and_then(|request| request.replay.as_mut())
                .filter(|replay| replay.attempt == attempt)
            {
                replay.phase = ios_header::Phase::Awaiting(Instant::now());
            }
            inner.last_activity = Instant::now();
            self.activity.notify_one();
        }
        Ok(())
    }
    pub(crate) fn start_alive(self: &Arc<Self>) {
        let (generation, cancel) = {
            let mut inner = self.inner.lock().unwrap();
            if inner.state.profile.platform.is_ios() {
                self.arm_ios_block_checks(&mut inner);
                return;
            }
            inner.alive_cancel.cancel();
            inner.alive_cancel = inner.cancel.child_token();
            (inner.generation, inner.alive_cancel.clone())
        };
        let weak = self.weak.clone();
        let activity = self.activity.clone();
        let task = tokio::spawn(async move {
            let mut first = true;
            loop {
                if !first {
                    loop {
                        let notified = activity.notified();
                        tokio::pin!(notified);
                        notified.as_mut().enable();
                        let Some(client) = weak.upgrade() else { return };
                        let deadline = {
                            let inner = client.inner.lock().unwrap();
                            inner.last_activity + Duration::from_secs(10)
                        };
                        drop(client);
                        tokio::select! {
                            biased;
                            _ = cancel.cancelled() => return,
                            _ = &mut notified => continue,
                            _ = tokio::time::sleep_until(deadline) => break,
                        }
                    }
                }
                first = false;
                let Some(client) = weak.upgrade() else { return };
                let result = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return,
                    result = client.request_inner(
                        "Heartbeat.Alive",
                        Bytes::from_static(&[0, 0, 0, 4]),
                        RequestType::Simple,
                        Encryption::None,
                        client.config.timeout,
                        Some(RequestBinding::Connection(generation)),
                    ) => result,
                };
                if let Err(error) = result {
                    if !cancel.is_cancelled() {
                        client
                            .terminate_generation(generation, format!("Keepalive failed: {error}"));
                    }
                    return;
                }
            }
        });
        self.tasks.lock().unwrap().push(task);
    }
    pub(crate) fn start_heartbeat(self: &Arc<Self>, server_time: u64, heartbeat_seconds: u32) {
        let (cancel, mobile) = {
            let mut inner = self.inner.lock().unwrap();
            inner.heartbeat_cancel.cancel();
            inner.heartbeat_cancel = inner.cancel.child_token();
            (
                inner.heartbeat_cancel.clone(),
                inner.state.profile.platform.is_ios(),
            )
        };
        let mut trigger_time = if mobile {
            match self.ios_heartbeat_time() {
                Ok(time) => time,
                Err(error) => {
                    tracing::warn!(%error, "Cannot arm mobile heartbeat without epoch time");
                    return;
                }
            }
        } else {
            server_time
        };
        let weak = self.weak.clone();
        let task = tokio::spawn(async move {
            let reference = Instant::now();
            let mut interval = heartbeat_seconds.clamp(120, 500);
            loop {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(Duration::from_secs(u64::from(interval))) => {},
                }
                let Some(client) = weak.upgrade() else { return };
                let body = client.heartbeat_body(trigger_time);
                let result = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return,
                    result = client.call(
                        "trpc.qq_new_tech.status_svc.StatusService.SsoHeartBeat",
                        body,
                        Encryption::D2,
                    ) => result.and_then(crate::proto::decode::<auth::HeartbeatResponse>),
                };
                match result {
                    Ok(response) => {
                        interval = response.interval_seconds.unwrap_or(0).clamp(120, 500);
                    }
                    Err(error) => {
                        if cancel.is_cancelled() {
                            return;
                        }
                        tracing::warn!(%error, "SSO heartbeat failed; retaining periodic schedule");
                    }
                }
                trigger_time = if mobile {
                    match client.ios_heartbeat_time() {
                        Ok(time) => time,
                        Err(error) => {
                            tracing::warn!(%error, "Cannot rearm mobile heartbeat without epoch time");
                            return;
                        }
                    }
                } else {
                    server_time.saturating_add(reference.elapsed().as_secs())
                };
            }
        });
        self.tasks.lock().unwrap().push(task);
    }
    pub(crate) fn begin_signing_login(&self) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.signing_ready = false;
        inner.signing_cancel.cancel();
        inner.signing_cancel = CancellationToken::new();
        let Inner { state, signer, .. } = &mut *inner;
        signer.begin_login(state)
    }
    pub(crate) fn mark_signing_ticket_complete(&self) -> Result<()> {
        {
            let mut inner = self.inner.lock().unwrap();
            let signing_generation = inner.signer.generation();
            let Inner { state, signer, .. } = &mut *inner;
            signer.ticket_complete(state)?;
            if inner.signer.generation() != signing_generation {
                inner.signing_cancel.cancel();
                inner.signing_cancel = CancellationToken::new();
            }
            inner.signing_ready = inner.signer.uses_desktop_maintenance();
        }
        self.background_work.notify_one();
        self.signing_work.notify_one();
        Ok(())
    }
    fn start_signing_work(&self, generation: u64, channel: crate::o3::Channel) {
        if self.inner.lock().unwrap().signer.has_ios_virtual_device() {
            self.start_ios_signing_work(generation);
            return;
        }
        {
            let mut inner = self.inner.lock().unwrap();
            if inner.generation != generation || !inner.signer.uses_desktop_maintenance() {
                return;
            }
            if inner
                .linux_o3()
                .unwrap()
                .transport_generation
                .is_some_and(|previous| previous != generation)
            {
                inner.signer.cancel_token_reports();
            }
            let o3 = inner.linux_o3_mut().unwrap();
            o3.transport_generation = Some(generation);
            if o3.scope.is_none() {
                o3.channel = channel;
            } else if o3.channel.is_establishing() {
                o3.channel.reset();
            }
        }
        let weak = self.weak.clone();
        let notify = self.signing_work.clone();
        let cancel = self.cancellation();
        let task = tokio::spawn(async move {
            let mut ticks = tokio::time::interval(Duration::from_secs(60));
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut scope = None;
            let mut queued = VecDeque::new();
            let mut pending = FuturesUnordered::new();
            loop {
                let notified = notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                let Some(client) = weak.upgrade() else { return };
                let (reports, active_scope) = {
                    let mut inner = client.inner.lock().unwrap();
                    if inner.generation != generation || inner.connection.is_none() {
                        return;
                    }
                    if inner.signing_ready {
                        let binding = (inner.signer.generation(), inner.state.keystore.uin);
                        let o3 = inner.linux_o3_mut().unwrap();
                        if o3.scope != Some(binding) {
                            o3.channel.reset();
                            o3.heartbeat.reset();
                            o3.scope = Some(binding);
                        }
                        if let Err(error) = inner.signer.poll_token() {
                            tracing::warn!(%error, "O3 token refresh could not be queued");
                        }
                        (inner.signer.drain_token_reports(), Some(binding))
                    } else {
                        (Vec::new(), None)
                    }
                };
                if scope != active_scope {
                    pending.clear();
                    queued.clear();
                    scope = active_scope;
                }
                queued.extend(reports.into_iter().map(crate::o3::Work::Report));
                if active_scope.is_some() {
                    let mut inner = client.inner.lock().unwrap();
                    if inner.signing_ready && inner.generation == generation {
                        let Inner {
                            state,
                            platform,
                            signer,
                            ..
                        } = &mut *inner;
                        let PlatformRuntime::Linux(o3) = platform else {
                            return;
                        };
                        match o3.heartbeat.take_due(state) {
                            Ok(Some(body)) => match signer.channel_report("heartbeat", body) {
                                Ok(report) => queued.push_back(crate::o3::Work::Report(report)),
                                Err(error) => {
                                    tracing::warn!(%error, "O3 heartbeat signing scope rejected")
                                }
                            },
                            Ok(None) => {}
                            Err(error) => {
                                tracing::warn!(%error, "O3 heartbeat could not be prepared")
                            }
                        }
                    }
                }
                while let Some(work) = queued.pop_front() {
                    let mut report = match work {
                        crate::o3::Work::Report(report) => report,
                        crate::o3::Work::Compute(task_report) => {
                            let Some(task_scope) = active_scope else {
                                continue;
                            };
                            let report_cancel = {
                                let inner = client.inner.lock().unwrap();
                                if inner.generation != generation
                                    || inner
                                        .connection
                                        .as_ref()
                                        .map(|connection| connection.generation)
                                        != Some(generation)
                                    || !inner.signing_ready
                                    || inner.linux_o3().unwrap().scope != Some(task_scope)
                                    || inner.state.keystore.uin != task_scope.1
                                    || !inner.signer.report_is_current(task_report.binding())
                                    || inner.signing_cancel.is_cancelled()
                                {
                                    continue;
                                }
                                inner.signing_cancel.clone()
                            };
                            let job = tokio::task::spawn_blocking(move || task_report.execute());
                            let cancel = cancel.clone();
                            pending.push(Either::Right(async move {
                                let completion = tokio::select! {
                                    biased;
                                    _ = cancel.cancelled() => None,
                                    _ = report_cancel.cancelled() => None,
                                    completion = job => Some(completion),
                                };
                                Either::Right((task_scope, completion, report_cancel))
                            }));
                            continue;
                        }
                        crate::o3::Work::RotatePeer {
                            material,
                            generation: signing_generation,
                            account,
                        } => {
                            let mut inner = client.inner.lock().unwrap();
                            if inner.generation != generation || inner.connection.is_none() {
                                return;
                            }
                            if inner.signing_ready
                                && inner.signer.generation() == signing_generation
                                && inner.state.keystore.uin == account
                            {
                                if let Err(error) =
                                    inner.linux_o3_mut().unwrap().channel.rotate_peer(&material)
                                {
                                    tracing::warn!(%error, "O3 peer rotation rejected");
                                } else {
                                    tracing::debug!(target: "atri_qq_protocol::packet_trace", stage = "o3_state", generation, phase = "peer_rotated", "QQ O3 state");
                                }
                            }
                            continue;
                        }
                    };
                    let (report, request, report_cancel) = {
                        let mut inner = client.inner.lock().unwrap();
                        if inner.generation != generation || inner.connection.is_none() {
                            return;
                        }
                        if !inner.signing_ready
                            || !inner.signer.report_is_current(&report)
                            || active_scope != Some((report.generation, inner.state.keystore.uin))
                            || inner.signing_cancel.is_cancelled()
                        {
                            continue;
                        }
                        if inner.linux_o3().unwrap().channel.is_establishing() {
                            queued.push_front(crate::o3::Work::Report(report));
                            break;
                        }
                        let body = Bytes::from(std::mem::take(&mut report.body));
                        let request = match crate::o3::unix_seconds().and_then(|now| {
                            inner
                                .linux_o3_mut()
                                .unwrap()
                                .channel
                                .prepare(&report.method, body, now)
                        }) {
                            Ok(request) => request,
                            Err(error) => {
                                if report.method == "getToken" {
                                    let _ = inner.signer.complete_report(
                                        &report,
                                        signing_engine::token::ReportResponse {
                                            bytes: Vec::new(),
                                            transport_succeeded: false,
                                            error_code: 999,
                                        },
                                    );
                                }
                                tracing::warn!(%error, method = report.method, "O3 request could not be prepared");
                                continue;
                            }
                        };
                        (report, request, inner.signing_cancel.clone())
                    };
                    let client = client.clone();
                    let cancel = cancel.clone();
                    pending.push(Either::Left(async move {
                        let response = tokio::select! {
                            biased;
                            _ = cancel.cancelled() => Err(Error::Disconnected),
                            _ = report_cancel.cancelled() => Err(Error::Disconnected),
                            response = client.request_inner(
                                request.command,
                                request.body.clone(),
                                RequestType::D2,
                                Encryption::D2,
                                client.config.timeout,
                                Some(RequestBinding::SigningReport { generation, report: &report }),
                            ) => response,
                        };
                        Either::Left((report, request, response, report_cancel))
                    }));
                }
                let heartbeat_deadline = if active_scope.is_some() {
                    client
                        .inner
                        .lock()
                        .unwrap()
                        .linux_o3()
                        .unwrap()
                        .heartbeat
                        .deadline()
                } else {
                    None
                };
                drop(client);
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return,
                    Some(completion) = pending.next(), if !pending.is_empty() => {
                        let (report, request, response, report_cancel) = match completion {
                            Either::Left(completion) => completion,
                            Either::Right((task_scope, completion, report_cancel)) => {
                                let Some(client) = weak.upgrade() else { return };
                                let inner = client.inner.lock().unwrap();
                                if inner.generation != generation
                                    || inner.connection.as_ref().map(|connection| connection.generation) != Some(generation)
                                    || !inner.signing_ready
                                    || inner.linux_o3().unwrap().scope != Some(task_scope)
                                    || inner.state.keystore.uin != task_scope.1
                                    || inner.signer.generation() != task_scope.0
                                    || report_cancel.is_cancelled()
                                    || cancel.is_cancelled()
                                {
                                    continue;
                                }
                                match completion {
                                    Some(Ok(Some(report))) => {
                                        if inner.signer.report_is_current(&report) {
                                            queued.push_back(crate::o3::Work::Report(report));
                                        }
                                    }
                                    Some(Ok(None)) | None => {}
                                    Some(Err(error)) => {
                                        tracing::warn!(%error, "O3 calculation worker failed");
                                    }
                                }
                                continue;
                            }
                        };
                        let Some(client) = weak.upgrade() else { return };
                        let mut inner = client.inner.lock().unwrap();
                        if inner.generation != generation || !inner.signer.report_is_current(&report) {
                            continue;
                        }
                        let command = request.command;
                        let result = match response {
                            Ok(response) => crate::o3::unix_seconds()
                                .and_then(|now| inner.linux_o3_mut().unwrap().channel.complete(request, response, now)),
                            Err(error) => {
                                inner.linux_o3_mut().unwrap().channel.failed(&request);
                                Err(error)
                            }
                        };
                        match result {
                            Ok(reply) => {
                                tracing::debug!(target: "atri_qq_protocol::packet_trace", stage = "o3_state", generation, method = report.method, command, phase = "authenticated_reply", channel_expires_at = ?inner.linux_o3().unwrap().channel.expires_at(), "QQ O3 state");
                                if let Some(config) = reply.config {
                                    if let Err(error) = inner.signer.apply_channel_config(&config) {
                                        tracing::warn!(%error, "O3 configuration signing scope rejected");
                                        continue;
                                    }
                                    inner.linux_o3_mut().unwrap().heartbeat.configure(config.option4 != 0);
                                    tracing::debug!(target: "atri_qq_protocol::packet_trace", stage = "o3_state", generation, phase = "configuration_applied", heartbeat_enabled = config.option4 != 0, sign_enabled = config.option2 != 0, xwid_selector = config.option6, "QQ O3 state");
                                    if inner.state.keystore.o3_xwid_switch != Some(config.option6) {
                                        inner.state.keystore.o3_xwid_switch = Some(config.option6);
                                        let _ = client.events.send(LoginEvent::KeystoreChanged(
                                            inner.state.keystore.clone(),
                                        ));
                                    }
                                }
                                if report.method == "getToken" {
                                    let completion = signing_engine::token::ReportResponse {
                                        bytes: reply.body.to_vec(),
                                        transport_succeeded: true,
                                        error_code: 0,
                                    };
                                    if let Err(error) = inner.signer.complete_report(&report, completion) {
                                        tracing::warn!(%error, "O3 issued token reply rejected");
                                    }
                                    let (token_length, token_expires_at) = inner.signer.token_status();
                                    tracing::debug!(target: "atri_qq_protocol::packet_trace", stage = "o3_state", generation, phase = "token_completion", token_length, token_expires_at = ?token_expires_at, "QQ O3 state");
                                } else {
                                    let Inner { state, signer, platform, .. } = &mut *inner;
                                    let PlatformRuntime::Linux(o3) = platform else { return };
                                    match o3.heartbeat.complete(reply.body, state, signer) {
                                        Ok(reports) => queued.extend(reports),
                                        Err(error) => tracing::warn!(%error, method = report.method, "O3 task response rejected"),
                                    }
                                }
                            }
                            Err(error) => {
                                tracing::debug!(target: "atri_qq_protocol::packet_trace", stage = "o3_state", generation, method = report.method, command, phase = "failed", %error, "QQ O3 state");
                                if report.method == "getToken" {
                                    let completion = signing_engine::token::ReportResponse {
                                        bytes: Vec::new(),
                                        transport_succeeded: false,
                                        error_code: 999,
                                    };
                                    let _ = inner.signer.complete_report(&report, completion);
                                }
                                if !report_cancel.is_cancelled() {
                                    tracing::warn!(%error, method = report.method, "O3 request failed; retaining reusable channel and cached token");
                                }
                            }
                        }
                    }
                    _ = &mut notified => {},
                    _ = ticks.tick() => {},
                    _ = tokio::time::sleep_until(heartbeat_deadline.unwrap_or_else(Instant::now)), if heartbeat_deadline.is_some() => {},
                }
            }
        });
        self.tasks.lock().unwrap().push(task);
    }

    fn start_background_work(&self, generation: u64) {
        let weak = self.weak.clone();
        let notify = self.background_work.clone();
        let cancel = self.inner.lock().unwrap().transport_cancel.clone();
        let task = tokio::spawn(async move {
            loop {
                let notified = notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                let Some(client) = weak.upgrade() else { return };
                let (replies, reports, telemetry_deadline) = {
                    let mut inner = client.inner.lock().unwrap();
                    if inner.generation != generation
                        || inner.connection.is_none()
                        || inner.kick_reason.is_some()
                    {
                        return;
                    }
                    let Inner { state, signer, .. } = &mut *inner;
                    if signer.uses_desktop_maintenance()
                        && let Err(error) = signer.poll_telemetry(state)
                    {
                        tracing::warn!(%error, "O3 periodic file report could not be queued");
                    }
                    let replies: Vec<_> = inner.control_replies.drain(..).collect();
                    let reports = inner.signer.drain_telemetry_reports();
                    (replies, reports, inner.signer.telemetry_deadline())
                };
                for (command, body) in replies {
                    let result = tokio::select! {
                        biased;
                        _ = cancel.cancelled() => return,
                        result = client.send_only(command, body, generation) => result,
                    };
                    if let Err(error) = result {
                        if !cancel.is_cancelled() {
                            client.terminate_generation_with_policy(
                                generation,
                                format!("Required control response failed: {error}"),
                                true,
                                Some(&|_| !cancel.is_cancelled()),
                            );
                        }
                        return;
                    }
                }
                for report in reports {
                    client.start_telemetry_report(report, generation, cancel.clone());
                }
                drop(client);
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return,
                    _ = &mut notified => {},
                    _ = tokio::time::sleep_until(telemetry_deadline.unwrap_or_else(Instant::now)), if telemetry_deadline.is_some() => {},
                }
            }
        });
        self.tasks.lock().unwrap().push(task);
    }
    fn start_telemetry_report(
        &self,
        report: SigningReport,
        generation: u64,
        cancel: CancellationToken,
    ) {
        let weak = self.weak.clone();
        let task = tokio::spawn(async move {
            let Some(client) = weak.upgrade() else { return };
            let mut report = report;
            let body = Bytes::from(std::mem::take(&mut report.body));
            let result = tokio::select! {
                biased;
                _ = cancel.cancelled() => return,
                result = client.request_inner(
                    &report.method,
                    body,
                    RequestType::D2,
                    Encryption::D2,
                    client.config.timeout,
                    Some(RequestBinding::SigningReport { generation, report: &report }),
                ) => result,
            };
            let mut inner = client.inner.lock().unwrap();
            if inner.generation != generation || !inner.signer.report_is_current(&report) {
                return;
            }
            match result {
                Ok(response) => {
                    let completion = ::signing::token::ReportResponse {
                        bytes: response.to_vec(),
                        transport_succeeded: true,
                        error_code: 0,
                    };
                    if let Err(error) = inner.signer.complete_report(&report, completion) {
                        tracing::warn!(%error, "O3 telemetry reply rejected");
                    }
                }
                Err(error) if !cancel.is_cancelled() => {
                    tracing::warn!(%error, "O3 telemetry delivery failed");
                }
                Err(_) => {}
            }
        });
        self.tasks.lock().unwrap().push(task);
    }
    pub fn drain_signing_reports(&self) -> Vec<SigningReport> {
        self.inner.lock().unwrap().signer.drain_reports()
    }
    pub fn complete_signing_report(
        &self,
        report: &SigningReport,
        response: signing_engine::token::ReportResponse,
    ) -> Result<()> {
        self.inner
            .lock()
            .unwrap()
            .signer
            .complete_report(report, response)
    }
    pub fn set_signing_resources(
        &self,
        properties: Option<::signing::token::DeviceProperties>,
        persistent_xwid_switch: Option<Vec<u8>>,
        report_module_paths: Option<Vec<String>>,
    ) -> Result<()> {
        self.inner.lock().unwrap().signer.set_resources(
            properties,
            persistent_xwid_switch,
            report_module_paths,
        )
    }
    pub fn set_ios_signing_resources(
        &self,
        resources: crate::signing::IosSigningResources,
    ) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.signer.set_ios_resources(resources)?;
        inner.signing_cancel.cancel();
        inner.signing_cancel = CancellationToken::new();
        Ok(())
    }
    pub fn set_ios_transport_resources(&self, resources: IosTransportResources) -> Result<()> {
        resources.validate()?;
        let mut inner = self.inner.lock().unwrap();
        let ios = inner.ios_mut().ok_or_else(|| {
            Error::Unsupported("iOS transport resources require an iPhone or iPad client".into())
        })?;
        ios.transport = resources;
        self.start_ios_probe_worker(&mut inner);
        Ok(())
    }
    pub fn take_signing_token_error(&self) -> Option<::signing::token::TokenError> {
        self.inner.lock().unwrap().signer.take_token_error()
    }
    pub fn complete_signing_xwid(
        &self,
        acquisition: ::signing::token::XwidAcquisition,
    ) -> Result<()> {
        self.inner.lock().unwrap().signer.complete_xwid(acquisition)
    }
    pub fn set_signing_footer_seed(&self, seed: &[u8; 48]) -> Result<()> {
        self.inner.lock().unwrap().signer.set_footer_seed(seed)
    }
    pub fn answer_signing_property_challenge(&self, ids: &[u8]) -> Result<Vec<u8>> {
        self.inner
            .lock()
            .unwrap()
            .signer
            .answer_property_challenge(ids)
    }
}
struct PendingGuard<'a> {
    client: &'a Client,
    sequence: i32,
    id: u64,
}
impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        let mut i = self.client.inner.lock().unwrap();
        if i.pending
            .get(&self.sequence)
            .is_some_and(|p| p.id == self.id)
        {
            if let Some(p) = i.pending.remove(&self.sequence) {
                p.cancel.cancel();
            }
        }
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        self.inner.get_mut().unwrap().cancel.cancel();
        for task in self.tasks.get_mut().unwrap().drain(..) {
            task.abort();
        }
    }
}
#[async_trait]
impl ServiceClient for Client {
    async fn request(
        &self,
        command: &str,
        body: Bytes,
        request_type: RequestType,
        encryption: Encryption,
        timeout: Duration,
    ) -> Result<Bytes> {
        Client::request(self, command, body, request_type, encryption, timeout).await
    }
    async fn snapshot(&self) -> SessionState {
        Client::snapshot(self).await
    }
    async fn replace_state(&self, state: SessionState) {
        Client::replace_state(self, state).await
    }
    fn subscribe(&self) -> broadcast::Receiver<IncomingPacket> {
        Client::subscribe(self)
    }
    fn message_sync_snapshot(&self) -> Result<crate::message_sync::Snapshot> {
        Ok(Client::message_sync_snapshot(self))
    }
    async fn media_download_key(
        &self,
        business_type: u32,
        store_id: u32,
    ) -> Result<crate::media::MediaDownloadKey> {
        Client::media_download_key(self, business_type, store_id).await
    }
    async fn fetch_friend_statuses(&self) -> Result<Arc<crate::contacts::FriendStatusSnapshot>> {
        Client::fetch_friend_statuses(self).await
    }
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;

#[cfg(test)]
mod platform_tests {
    use super::*;

    #[test]
    fn desktop_defaults_only_initialize_linux_resources() {
        let store = Keystore::default();
        let client = Client::new(ClientConfig::default(), store.clone()).unwrap();
        let inner = client.inner.lock().unwrap();
        assert!(inner.ios().is_none());
        assert!(inner.linux_o3().is_some());
        let Some(PlatformConfig::Linux(config)) = &client.config.platform else {
            panic!()
        };
        assert!(!config.machine_id.is_empty());
        assert!(!config.application_uuid.is_empty());
        assert_eq!(
            inner.state.linux_machine_id(),
            Some(config.machine_id.as_str())
        );
        assert!(inner.state.keystore.ios_virtual_state == store.ios_virtual_state);
        assert_eq!(inner.state.keystore.ios_msf_imei, store.ios_msf_imei);
    }

    #[test]
    fn platform_resources_must_match_profile() {
        for profile in [Profile::iphone(), Profile::ipad()] {
            assert!(
                Client::new(
                    ClientConfig {
                        profile: profile.clone(),
                        ..Default::default()
                    },
                    Keystore::default()
                )
                .is_err()
            );
            assert!(
                Client::new(
                    ClientConfig {
                        profile: profile.clone(),
                        platform: Some(PlatformConfig::Linux(LinuxConfig::default())),
                        ..Default::default()
                    },
                    Keystore::default()
                )
                .is_err()
            );
            let mut snapshot = ios_signing_tests::config(profile);
            snapshot.profile = Profile::linux();
            assert!(Client::new(snapshot, Keystore::default()).is_err());
        }
        assert!(
            Client::new(
                ClientConfig {
                    platform: Some(PlatformConfig::Ios(IosConfig::Virtual(Arc::new(
                        crate::ios_device::IosVirtualConfig::default(),
                    )))),
                    ..Default::default()
                },
                Keystore::default()
            )
            .is_err()
        );
    }

    #[test]
    fn ios_sources_own_runtime_and_session_identity() {
        for profile in [Profile::iphone(), Profile::ipad()] {
            let store = Keystore {
                device_name: "snapshot-device".into(),
                ..Default::default()
            };
            let client = Client::new(ios_signing_tests::config(profile.clone()), store).unwrap();
            let inner = client.inner.lock().unwrap();
            assert!(inner.linux_o3().is_none());
            assert!(inner.state.linux_machine_id().is_none());
            assert_eq!(inner.state.device_name(), "snapshot-device");
            assert!(inner.ios().unwrap().network.is_none());
            assert!(inner.ios().unwrap().heartbeat_source.is_none());
            drop(inner);
            let model = Arc::new(crate::ios_device::IosVirtualConfig::default());
            let client = Client::new(
                ClientConfig {
                    profile: profile.clone(),
                    platform: Some(PlatformConfig::Ios(IosConfig::Virtual(model.clone()))),
                    ..Default::default()
                },
                Keystore {
                    device_name: "desktop-name".into(),
                    ..Default::default()
                },
            )
            .unwrap();
            let inner = client.inner.lock().unwrap();
            assert!(inner.linux_o3().is_none());
            assert!(inner.state.linux_machine_id().is_none());
            assert_eq!(
                inner.state.device_name(),
                model.device_name(profile.platform)
            );
            assert_eq!(inner.state.keystore.device_name, "desktop-name");
            assert!(inner.ios().unwrap().network.is_some());
            assert!(inner.ios().unwrap().heartbeat_source.is_some());
            assert!(inner.signer.has_ios_virtual_device());
        }
    }

    #[tokio::test]
    async fn state_replacement_cannot_change_runtime_branch() {
        let linux = Client::new(ClientConfig::default(), Keystore::default()).unwrap();
        let ios = Client::new(
            ios_signing_tests::config(Profile::ipad()),
            Keystore::default(),
        )
        .unwrap();
        let linux_state = linux.snapshot().await;
        let ios_state = ios.snapshot().await;
        linux.replace_state(ios_state.clone()).await;
        ios.replace_state(linux_state.clone()).await;
        assert_eq!(linux.snapshot().await.platform, linux_state.platform);
        assert_eq!(ios.snapshot().await.platform, ios_state.platform);
        let mut invalid = ios_state.clone();
        invalid.profile = Profile::linux();
        ios.replace_state(invalid).await;
        assert_eq!(ios.snapshot().await.profile, ios_state.profile);
    }

    #[test]
    fn ios_maintenance_rejects_changed_device_or_name() {
        let client = Client::new(
            ios_signing_tests::config(Profile::ipad()),
            Keystore::default(),
        )
        .unwrap();
        let (sender, _receiver) = mpsc::channel(1);
        let original = {
            let mut inner = client.inner.lock().unwrap();
            inner.generation = 7;
            inner.connection = Some(Connection {
                generation: 7,
                sender,
            });
            inner.state.keystore.uin = 42;
            inner.state.online = true;
            inner.state.clone()
        };
        for change_device in [false, true] {
            let mut updated = original.clone();
            let PlatformState::Ios {
                device,
                device_name,
            } = &mut updated.platform
            else {
                panic!()
            };
            if change_device {
                Arc::make_mut(device).hardware_model.push_str("-changed");
            } else {
                *device_name = format!("{device_name}-changed").into();
            }
            assert!(
                client
                    .commit_nt_maintenance_state(7, &original.keystore, updated)
                    .is_err()
            );
        }
    }
}

#[cfg(test)]
mod ticket_refresh_tests {
    use super::*;

    fn online_client() -> (Arc<Client>, mpsc::Receiver<Outgoing>) {
        let client = Client::new(ClientConfig::default(), Keystore::default()).unwrap();
        let (sender, receiver) = mpsc::channel(8);
        {
            let mut inner = client.inner.lock().unwrap();
            inner.generation = 7;
            inner.connection = Some(Connection {
                generation: 7,
                sender,
            });
            inner.state.online = true;
            inner.state.keystore.uin = 42;
            inner.state.keystore.uid = "synthetic-user".into();
            inner.state.keystore.a1 = vec![1];
            inner.state.keystore.nt_ticket_times = Some(times(0));
            inner.clock.correction(100, SystemTime::now());
        }
        (client, receiver)
    }

    fn times(next: u64) -> NtTicketTimeMetadata {
        NtTicketTimeMetadata {
            field12: Some(NtTicketTimeValues {
                raw_field1: Some(next),
                raw_field2: None,
            }),
            field16: None,
            received_unix_ms: 0,
        }
    }

    #[test]
    fn readiness_checks_identity_a1_and_corrected_deadline() {
        let (client, _queue) = online_client();
        assert!(client.ticket_refresh_ready(7).unwrap());
        assert!(matches!(
            client.ticket_refresh_ready(6),
            Err(Error::Disconnected)
        ));
        {
            let mut inner = client.inner.lock().unwrap();
            inner.state.keystore.nt_ticket_times = Some(times(1_000));
        }
        assert!(!client.ticket_refresh_ready(7).unwrap());
        client.inner.lock().unwrap().state.keystore.nt_ticket_times = Some(times(100));
        assert!(client.ticket_refresh_ready(7).unwrap());
        client.inner.lock().unwrap().state.keystore.a1.clear();
        assert!(matches!(
            client.ticket_refresh_ready(7),
            Err(Error::Authentication(_))
        ));
        client.inner.lock().unwrap().cancel.cancel();
        assert!(matches!(
            client.ticket_refresh_ready(7),
            Err(Error::Disconnected)
        ));
    }

    #[tokio::test]
    async fn server_failure_limit_survives_reconnection_but_not_account_replacement() {
        let (client, _queue) = online_client();
        for _ in 0..9 {
            client.record_ticket_refresh_result(7, false).unwrap();
        }
        assert!(client.ticket_refresh_ready(7).unwrap());
        client.record_ticket_refresh_result(7, false).unwrap();
        assert!(!client.ticket_refresh_ready(7).unwrap());
        {
            let mut inner = client.inner.lock().unwrap();
            inner.generation = 8;
            inner.connection.as_mut().unwrap().generation = 8;
        }
        assert!(!client.ticket_refresh_ready(8).unwrap());
        assert!(matches!(
            client.record_ticket_refresh_result(7, true),
            Err(Error::Disconnected)
        ));
        client.record_ticket_refresh_result(8, true).unwrap();
        assert!(client.ticket_refresh_ready(8).unwrap());
        client.record_ticket_refresh_result(8, false).unwrap();
        let mut state = client.snapshot().await;
        state.keystore.uin = 43;
        state.keystore.uid = "another-synthetic-user".into();
        client.replace_state(state).await;
        let inner = client.inner.lock().unwrap();
        assert_eq!(inner.ticket_refresh_failures, 0);
        assert!(!inner.state.online);
    }

    #[test]
    fn configuration_updates_are_generation_bound_and_preserve_stop_values() {
        let (client, _queue) = online_client();
        let mut updates = client.ticket_refresh_schedule(7).unwrap();
        assert!(updates.borrow().interval_seconds.is_none());
        client.set_ticket_refresh_interval(7, 15).unwrap();
        assert_eq!(updates.borrow_and_update().interval_seconds, Some(15));
        {
            let mut inner = client.inner.lock().unwrap();
            inner.generation = 8;
            inner.connection.as_mut().unwrap().generation = 8;
        }
        client.set_ticket_refresh_interval(8, 22).unwrap();
        assert!(matches!(
            client.set_ticket_refresh_interval(7, 1),
            Err(Error::Disconnected)
        ));
        assert_eq!(updates.borrow().generation, 8);
        assert_eq!(updates.borrow().interval_seconds, Some(22));
        for seconds in [0, -3] {
            client.set_ticket_refresh_interval(8, seconds).unwrap();
            assert_eq!(updates.borrow().interval_seconds, Some(seconds));
        }
        client.inner.lock().unwrap().cancel.cancel();
        assert!(matches!(
            client.set_ticket_refresh_interval(8, 1),
            Err(Error::Disconnected)
        ));
    }

    #[tokio::test]
    async fn maintenance_commit_is_atomic_and_reuses_key_rotation_and_events() {
        let (client, _queue) = online_client();
        let mut events = client.login_events();
        let original = client.snapshot().await;
        let mut updated = original.clone();
        updated.keystore.d2 = vec![2];
        updated.keystore.d2_key = vec![3; 16];
        updated.keystore.nt_ticket_times = Some(times(200));
        client.record_ticket_refresh_result(7, false).unwrap();
        client
            .commit_nt_maintenance_state(7, &original.keystore, updated.clone())
            .unwrap();
        {
            let inner = client.inner.lock().unwrap();
            assert!(inner.state.keystore == updated.keystore);
            assert!(inner.previous_keys.contains(&original.keystore.d2_key));
            assert_eq!(inner.ticket_refresh_failures, 1);
        }
        assert!(matches!(
            events.recv().await.unwrap(),
            LoginEvent::KeystoreChanged(_)
        ));
        assert!(
            client
                .commit_nt_maintenance_state(7, &original.keystore, updated.clone())
                .is_err()
        );
        let mut wrong_profile = updated.clone();
        wrong_profile.profile.qua.push_str("-changed");
        assert!(
            client
                .commit_nt_maintenance_state(7, &updated.keystore, wrong_profile)
                .is_err()
        );
        let mut wrong_machine = updated.clone();
        let PlatformState::Linux { machine_id } = &mut wrong_machine.platform else {
            panic!()
        };
        machine_id.push_str("-changed");
        assert!(
            client
                .commit_nt_maintenance_state(7, &updated.keystore, wrong_machine)
                .is_err()
        );
        assert!(client.inner.lock().unwrap().state.keystore == updated.keystore);
        assert!(matches!(
            client.commit_nt_maintenance_state(6, &updated.keystore, updated.clone()),
            Err(Error::Disconnected)
        ));
        client.inner.lock().unwrap().cancel.cancel();
        assert!(matches!(
            client.commit_nt_maintenance_state(7, &updated.keystore, updated.clone()),
            Err(Error::Disconnected)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn worker_waits_for_ticket_state_and_skips_busy_login_without_failures() {
        let (client, mut queue) = online_client();
        client.inner.lock().unwrap().state.keystore.nt_ticket_times = None;
        let cancel = CancellationToken::new();
        let task = tokio::spawn(crate::ticket_refresh::run(
            Arc::downgrade(&client),
            7,
            cancel.clone(),
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(10_000)).await;
        tokio::task::yield_now().await;
        assert!(queue.try_recv().is_err());
        let busy = client.login_gate.lock().await;
        client.inner.lock().unwrap().state.keystore.nt_ticket_times = Some(times(0));
        client.set_ticket_refresh_interval(7, 3).unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(3)).await;
        tokio::task::yield_now().await;
        assert!(queue.try_recv().is_err());
        assert_eq!(client.inner.lock().unwrap().ticket_refresh_failures, 0);
        client.set_ticket_refresh_interval(7, 0).unwrap();
        tokio::task::yield_now().await;
        drop(busy);
        tokio::time::advance(Duration::from_secs(100)).await;
        tokio::task::yield_now().await;
        assert!(queue.try_recv().is_err());
        cancel.cancel();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn waiting_worker_does_not_keep_the_client_alive() {
        let (client, _queue) = online_client();
        client.set_ticket_refresh_interval(7, 3600).unwrap();
        let weak = Arc::downgrade(&client);
        let task = tokio::spawn(crate::ticket_refresh::run(
            weak.clone(),
            7,
            CancellationToken::new(),
        ));
        tokio::task::yield_now().await;
        drop(client);
        assert!(weak.upgrade().is_none());
        task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn disabling_checks_does_not_discard_an_inflight_authenticated_refresh() {
        let (client, mut queue) = online_client();
        {
            let mut inner = client.inner.lock().unwrap();
            inner.state.keystore.key_exchange_session = Some(
                crate::models::NtKeyExchangeSession::new(
                    inner.state.profile.platform,
                    Bytes::from_static(&[42; 16]),
                    Bytes::from_static(b"synthetic-exchange-ticket"),
                    3600,
                )
                .unwrap(),
            );
        }
        let mut events = client.login_events();
        client.set_ticket_refresh_interval(7, 1).unwrap();
        let cancel = CancellationToken::new();
        let worker = tokio::spawn(crate::ticket_refresh::run(
            Arc::downgrade(&client),
            7,
            cancel.clone(),
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        let outgoing = tokio::time::timeout(Duration::from_secs(3), queue.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            outgoing.command,
            "trpc.login.ecdh.EcdhService.SsoNTLoginRefreshTicket"
        );
        client.set_ticket_refresh_interval(7, 0).unwrap();
        tokio::task::yield_now().await;
        let common = auth::NtResponse {
            head: Some(auth::NtResponseHead::default()),
            body: Some(
                auth::NtRefreshTicketResponseBody {
                    tickets: Some(auth::NtTickets {
                        a1: Some(Bytes::from_static(b"refreshed-after-disable")),
                        raw_time_field12: Some(auth::NtTicketTimeValues {
                            raw_field1: Some(1000),
                            raw_field2: None,
                        }),
                        ..Default::default()
                    }),
                    account: None,
                }
                .encode_to_vec()
                .into(),
            ),
        };
        let reply = auth::NtForward {
            encrypted: Some(
                crate::crypto::aes_gcm_encrypt(&common.encode_to_vec(), &[42; 16])
                    .unwrap()
                    .into(),
            ),
            ..Default::default()
        }
        .encode_to_vec()
        .into();
        let pending = client
            .inner
            .lock()
            .unwrap()
            .pending
            .remove(&outgoing.sequence)
            .unwrap();
        assert!(pending.reply.send(Ok(reply)).is_ok());
        loop {
            if let LoginEvent::KeystoreChanged(store) = events.recv().await.unwrap() {
                assert_eq!(store.a1, b"refreshed-after-disable");
                break;
            }
        }
        assert_eq!(
            client.snapshot().await.keystore.a1,
            b"refreshed-after-disable"
        );
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;
        assert!(queue.try_recv().is_err());
        cancel.cancel();
        worker.await.unwrap();
    }
}

#[cfg(test)]
mod friend_status_tests {
    use super::*;
    use crate::{
        contacts::{FriendStatus, FriendStatusSnapshot},
        lifecycle::status,
        proto::{contacts::OidbEnvelope, status as pb},
    };

    fn online_client() -> (Arc<Client>, mpsc::Receiver<Outgoing>) {
        let client = Client::new(ClientConfig::default(), Keystore::default()).unwrap();
        let (sender, receiver) = mpsc::channel(8);
        {
            let mut inner = client.inner.lock().unwrap();
            inner.generation = 7;
            inner.connection = Some(Connection {
                generation: 7,
                sender,
            });
            inner.state.online = true;
            inner.state.keystore.uin = 42;
            inner.state.keystore.uid = "u_synthetic_self".into();
        }
        (client, receiver)
    }

    fn reply(client: &Client, sequence: i32, response: Result<Bytes>) {
        let pending = client
            .inner
            .lock()
            .unwrap()
            .pending
            .remove(&sequence)
            .unwrap();
        assert!(pending.reply.send(response).is_ok());
    }

    fn response() -> Bytes {
        OidbEnvelope {
            command: Some(0x116d),
            service: Some(1),
            code: Some(0),
            body: Some(
                pb::FriendStatusResponse {
                    self_uid: Some("u_synthetic_self".into()),
                    interval_minutes: Some(30),
                    over: Some(1),
                    next_start: Some(400),
                    online_info: vec![pb::FriendOnlineInfo {
                        uid: Some("u_synthetic_friend".into()),
                        status: Some(10),
                        status_override: Some(11),
                        ..Default::default()
                    }],
                    ..Default::default()
                }
                .encode_to_vec()
                .into(),
            ),
            ..Default::default()
        }
        .encode_to_vec()
        .into()
    }

    #[tokio::test(start_paused = true)]
    async fn polls_after_login_every_thirty_minutes_and_stops_without_losing_error_semantics() {
        let (client, mut queue) = online_client();
        let cancel = CancellationToken::new();
        let worker = tokio::spawn(status::run(Arc::downgrade(&client), 7, cancel.clone()));
        let initial = queue.recv().await.unwrap();
        reply(&client, initial.sequence, Ok(response()));
        tokio::task::yield_now().await;
        let snapshot = client.cached_friend_statuses().unwrap();
        tokio::time::advance(Duration::from_secs(1799)).await;
        tokio::task::yield_now().await;
        assert!(queue.try_recv().is_err());
        tokio::time::advance(Duration::from_secs(1)).await;
        let poll = queue.recv().await.unwrap();
        reply(
            &client,
            poll.sequence,
            Err(Error::Server {
                code: 17,
                message: "synthetic rejection".into(),
            }),
        );
        tokio::task::yield_now().await;
        assert!(client.is_current_online(7));
        assert!(Arc::ptr_eq(
            &snapshot,
            &client.cached_friend_statuses().unwrap()
        ));
        cancel.cancel();
        worker.await.unwrap();
        tokio::time::advance(Duration::from_secs(3600)).await;
        assert!(queue.try_recv().is_err());
    }

    #[tokio::test]
    async fn account_aba_cancels_queued_frames_and_rejects_old_cache_commits() {
        let (client, mut queue) = online_client();
        let fetch_client = client.clone();
        let fetch = tokio::spawn(async move { fetch_client.fetch_friend_statuses().await });
        let outgoing = queue.recv().await.unwrap();
        let binding = client
            .inner
            .lock()
            .unwrap()
            .friend_statuses
            .binding
            .clone()
            .unwrap();
        let mut state = client.snapshot().await;
        state.keystore.uin = 43;
        state.keystore.uid = "u_other_synthetic".into();
        client.replace_state(state).await;
        assert!(binding.cancel.is_cancelled());
        assert!(outgoing.cancel.is_cancelled());
        assert!(matches!(fetch.await.unwrap(), Err(Error::Disconnected)));
        assert!(client.cached_friend_statuses().is_none());
        {
            let mut inner = client.inner.lock().unwrap();
            inner.state.keystore.uin = binding.uin;
            inner.state.keystore.uid = binding.uid.clone();
            inner.state.online = true;
        }
        let snapshot = Arc::new(FriendStatusSnapshot {
            statuses: BTreeMap::<String, FriendStatus>::new(),
            interval_minutes: Some(30),
            received_unix_ms: 0,
        });
        assert!(matches!(
            client.commit_friend_statuses(&binding, snapshot),
            Err(Error::Disconnected)
        ));
        assert!(matches!(
            client.request_friend_status(&binding, Bytes::new()).await,
            Err(Error::Disconnected)
        ));
        assert!(queue.try_recv().is_err());
    }

    #[tokio::test]
    async fn old_generation_response_cannot_commit_into_new_connection() {
        let (client, mut queue) = online_client();
        let fetch_client = client.clone();
        let fetch = tokio::spawn(async move { fetch_client.fetch_friend_statuses().await });
        let outgoing = queue.recv().await.unwrap();
        {
            let mut inner = client.inner.lock().unwrap();
            inner.generation = 8;
            inner.connection.as_mut().unwrap().generation = 8;
        }
        reply(&client, outgoing.sequence, Ok(response()));
        assert!(matches!(fetch.await.unwrap(), Err(Error::Disconnected)));
        assert!(client.cached_friend_statuses().is_none());
    }

    #[tokio::test]
    async fn stopped_or_unconfirmed_context_never_starts_polling() {
        let (client, mut queue) = online_client();
        let cancel = CancellationToken::new();
        cancel.cancel();
        status::run(Arc::downgrade(&client), 7, cancel).await;
        client.inner.lock().unwrap().state.online = false;
        status::run(Arc::downgrade(&client), 7, CancellationToken::new()).await;
        assert!(queue.try_recv().is_err());
    }
}
