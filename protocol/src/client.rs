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
use futures_util::{SinkExt, StreamExt, stream::FuturesUnordered};
use prost::Message;
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::{Arc, Mutex, Weak},
    time::{Duration, SystemTime},
};
use tokio::{
    net::TcpStream,
    sync::{Notify, broadcast, mpsc, oneshot},
    task::JoinHandle,
    time::{Instant, timeout_at},
};
use tokio_util::{codec::Framed, sync::CancellationToken};

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
}
struct Pending {
    id: u64,
    command: String,
    key: Vec<u8>,
    reply: oneshot::Sender<Result<Bytes>>,
    cancel: CancellationToken,
}
enum RequestBinding<'a> {
    Connection(u64),
    Online(u64),
    SigningReport {
        generation: u64,
        report: &'a SigningReport,
    },
}
struct Outgoing {
    command: String,
    sequence: i32,
    frame: Bytes,
    deadline: Instant,
    cancel: CancellationToken,
    required_control: bool,
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
struct Inner {
    state: SessionState,
    signer: SessionSigner,
    o3: crate::o3::Session,
    clock: crate::clock::ServerClock,
    sequence: i32,
    next_id: u64,
    generation: u64,
    connection: Option<Connection>,
    cancel: CancellationToken,
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
}
pub struct Client {
    pub(crate) config: ClientConfig,
    pub(crate) guild_session: Arc<crate::guild::Session>,
    inner: Mutex<Inner>,
    connect_gate: tokio::sync::Mutex<()>,
    pub(crate) login_gate: tokio::sync::Mutex<()>,
    pub(crate) codecs: tokio::sync::Mutex<Option<login::LoginCodecs>>,
    pub(crate) captcha: Mutex<Option<oneshot::Sender<(String, String)>>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    events: broadcast::Sender<LoginEvent>,
    packets: broadcast::Sender<IncomingPacket>,
    activity: Arc<Notify>,
    background_work: Arc<Notify>,
    signing_work: Arc<Notify>,
    credential_work: Arc<Notify>,
    weak: Weak<Client>,
}
impl Client {
    pub fn new(config: ClientConfig, mut keystore: Keystore) -> Result<Arc<Self>> {
        if config.timeout.is_zero() || config.host.is_empty() || config.port == 0 {
            return Err(wire::malformed("Invalid desktop endpoint/timeout"));
        }
        if keystore.guid.len() != 16
            || keystore.random_key.len() != 16
            || keystore.d2_key.len() != 16
        {
            return Err(wire::malformed(
                "Device GUID, random key and D2 key must each be sixteen bytes",
            ));
        }
        if config.machine_id.is_empty()
            || config.profile.qua.is_empty()
            || config.machine_id.contains('\0')
            || config.profile.qua.contains('\0')
        {
            return Err(wire::malformed(
                "Explicit machine ID and QUA must be nonempty C strings",
            ));
        }
        // A new client cannot resume another NT manager's challenge/session state.
        keystore.qr_sig.clear();
        keystore.key_exchange_ticket.clear();
        keystore.key_exchange_key.clear();
        keystore.login_cookie.clear();
        let (events, _) = broadcast::channel(128);
        let (packets, _) = broadcast::channel(256);
        let state = SessionState {
            profile: config.profile.clone(),
            machine_id: config.machine_id.clone(),
            keystore,
            online: false,
        };
        let mut signer = SessionSigner::default();
        signer.initialize(&state)?;
        Ok(Arc::new_cyclic(|weak| Self {
            config,
            guild_session: Arc::new(crate::guild::Session::default()),
            inner: Mutex::new(Inner {
                state,
                signer,
                o3: crate::o3::Session::default(),
                clock: crate::clock::ServerClock::default(),
                sequence: rand::random::<u32>().wrapping_rem(4_900_001) as i32 + 5_000_000,
                next_id: 0,
                generation: 0,
                connection: None,
                cancel: CancellationToken::new(),
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
            }),
            connect_gate: tokio::sync::Mutex::new(()),
            login_gate: tokio::sync::Mutex::new(()),
            codecs: tokio::sync::Mutex::new(None),
            captcha: Mutex::new(None),
            tasks: Mutex::new(vec![]),
            events,
            packets,
            activity: Arc::new(Notify::new()),
            background_work: Arc::new(Notify::new()),
            signing_work: Arc::new(Notify::new()),
            credential_work: Arc::new(Notify::new()),
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
    pub async fn replace_state(&self, mut state: SessionState) {
        let mut inner = self.inner.lock().unwrap();
        let account_changed = inner.state.keystore.uin != state.keystore.uin
            || inner.state.keystore.uid != state.keystore.uid;
        let tickets_changed = inner.state.keystore.d2 != state.keystore.d2
            || inner.state.keystore.d2_key != state.keystore.d2_key
            || inner.state.keystore.a2 != state.keystore.a2;
        // Only an authenticated InfoSync response may raise the online flag.
        // A stale service snapshot must not resurrect a closed or different account.
        state.online &= inner.state.online
            && inner.connection.is_some()
            && !inner.cancel.is_cancelled()
            && !account_changed;
        if account_changed || tickets_changed || (inner.state.online && !state.online) {
            inner.credentials.invalidate(account_changed);
            if account_changed || !state.online {
                self.guild_session.close(inner.generation);
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
        if inner.state.online {
            let Inner { state, signer, .. } = &mut *inner;
            if let Err(error) = signer.business_session_started(state) {
                tracing::warn!(%error, "O3 business session could not be bound");
            }
            self.signing_work.notify_one();
        }
    }
    pub(crate) fn confirm_online(&self, generation: u64) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.generation != generation
            || inner.connection.is_none()
            || inner.cancel.is_cancelled()
        {
            return Err(Error::Disconnected);
        }
        if inner.state.keystore.uin != 0 {
            let Inner { state, signer, .. } = &mut *inner;
            if let Err(error) = signer.business_session_started(state) {
                tracing::warn!(%error, "O3 business session could not be bound");
            }
            signer.registration_complete(state)?;
            self.background_work.notify_one();
            self.signing_work.notify_one();
        }
        inner.state.online = true;
        let cancel = inner.cancel.clone();
        inner.credentials.activate(generation, &cancel);
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
    pub(crate) fn connection_generation(&self) -> u64 {
        self.inner.lock().unwrap().generation
    }
    pub fn account_uin(&self) -> u64 {
        self.inner.lock().unwrap().state.keystore.uin
    }
    pub(crate) fn server_time_seconds(&self) -> Result<u32> {
        self.inner.lock().unwrap().clock.unix_seconds()
    }
    pub(crate) async fn correct_time(&self) -> Result<()> {
        let generation = self.connection_generation();
        let started = Instant::now();
        let response = self
            .request_inner(
                "Client.CorrectTime",
                Bytes::from_static(&[0, 0, 0, 4]),
                RequestType::Simple,
                Encryption::None,
                Duration::from_secs(7),
                Some(RequestBinding::Connection(generation)),
            )
            .await?;
        if started.elapsed() > Duration::from_secs(7) {
            return Err(wire::malformed("CorrectTime round trip exceeds seven seconds"));
        }
        let server = u32::from_be_bytes(
            response
                .as_ref()
                .try_into()
                .map_err(|_| wire::malformed("CorrectTime response must contain four bytes"))?,
        );
        let mut inner = self.inner.lock().unwrap();
        if inner.generation != generation || inner.connection.is_none() || inner.cancel.is_cancelled() {
            return Err(Error::Disconnected);
        }
        inner.clock.correction(server, SystemTime::now());
        tracing::debug!(target: "atri_qq_protocol::packet_trace", stage = "clock", generation, server_time = server, "QQ clock corrected");
        Ok(())
    }
    pub(crate) fn is_current_online(&self, generation: u64) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.generation == generation
            && inner
                .connection
                .as_ref()
                .is_some_and(|connection| connection.generation == generation)
            && inner.state.online
            && !inner.cancel.is_cancelled()
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
        let lifecycle = tokio::spawn(crate::lifecycle::run(self.weak.clone(), generation, cancel));
        self.tasks.lock().unwrap().extend([refresh, lifecycle]);
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
            if i.connection.is_some() {
                return Ok(());
            }
            if i.cancel.is_cancelled() {
                i.cancel = CancellationToken::new()
            }
            i.signing_ready = false;
            i.generation = i.generation.checked_add(1).ok_or_else(|| {
                Error::Unsupported("Connection generation space exhausted".into())
            })?;
            (i.generation, i.cancel.clone())
        };
        let socket = tokio::select! {
            _=cancel.cancelled()=>return Err(Error::Disconnected),
            result=tokio::time::timeout(self.config.timeout,TcpStream::connect((self.config.host.as_str(),self.config.port)))=>result.map_err(|_|Error::Timeout)??,
        };
        socket.set_nodelay(true)?;
        let framed = Framed::new(socket, SsoFrameCodec);
        let (mut sink, mut source) = framed.split();
        let (sender, mut queue) = mpsc::channel::<Outgoing>(512);
        {
            let mut i = self.inner.lock().unwrap();
            if i.generation != generation || cancel.is_cancelled() {
                return Err(Error::Disconnected);
            }
            i.connection = Some(Connection { generation, sender });
        }
        let weak = self.weak.clone();
        let read_cancel = cancel.clone();
        let reader = tokio::spawn(async move {
            loop {
                let next = tokio::select! {biased;_ = read_cancel.cancelled()=>return,next=source.next()=>next};
                match next {
                    Some(Ok(frame)) => {
                        let Some(client) = weak.upgrade() else { return };
                        if let Err(error) = client.receive(frame, generation) {
                            tracing::warn!(target: "atri_qq_protocol::packet", %error,
                                "Ignored incoming QQ packet; keeping the transport open");
                        }
                    }
                    Some(Err(error)) => {
                        if let Some(client) = weak.upgrade() {
                            client.terminate_generation(generation, error.to_string())
                        }
                        return;
                    }
                    None => {
                        if let Some(client) = weak.upgrade() {
                            client.terminate_generation(generation, "TCP peer closed".into())
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
                if Instant::now() >= item.deadline {
                    if item.required_control {
                        if let Some(client) = weak.upgrade() {
                            client.terminate_generation(
                                generation,
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
                let result = tokio::select! {biased;_ = write_cancel.cancelled()=>return,result=timeout_at(item.deadline,sink.send(item.frame))=>result};
                match result {
                    Ok(Ok(())) => {
                        if let Some(client) = weak.upgrade() {
                            client.mark_activity(generation);
                        }
                    }
                    Ok(Err(error)) => {
                        if let Some(client) = weak.upgrade() {
                            client.terminate_generation(
                                generation,
                                format!("TCP write failed: {error}"),
                            )
                        }
                        return;
                    }
                    Err(_) => {
                        if let Some(client) = weak.upgrade() {
                            client.terminate_generation(
                                generation,
                                "TCP write deadline expired; frame transmission uncertain".into(),
                            )
                        }
                        return;
                    }
                }
            }
        });
        self.tasks.lock().unwrap().extend([reader, writer]);
        self.start_background_work(generation);
        self.start_signing_work(generation, crate::o3::Channel::new());
        Ok(())
    }
    fn receive(&self, frame: Bytes, generation: u64) -> Result<()> {
        let mut i = self.inner.lock().unwrap();
        if i.connection.as_ref().map(|c| c.generation) != Some(generation) {
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
        tracing::debug!(target: "atri_qq_protocol::packet_trace", direction = "receive", stage = "wire", command = packet.command, sequence = packet.sequence, generation, length = frame.len(), raw_hex = %hex::encode(&frame), "QQ packet");
        tracing::debug!(target: "atri_qq_protocol::packet_trace", direction = "receive", stage = "decoded", generation, command = packet.command, sequence = packet.sequence, return_code = packet.return_code, extra, packet = ?packet, body_hex = %hex::encode(&packet.body), "QQ packet");
        if packet.return_code != 0 {
            crate::diagnostics::log_transport_error(&packet, &extra, &frame);
        }
        i.last_activity = Instant::now();
        self.activity.notify_one();
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
        if i.pending
            .get(&packet.sequence)
            .is_some_and(|p| p.command == packet.command)
        {
            let pending = i.pending.remove(&packet.sequence).unwrap();
            // Deliberately do not cancel pending.cancel on a matching response.
            let result = if packet.return_code == 0 {
                Ok(packet.body)
            } else {
                Err(Error::Server {
                    code: packet.return_code,
                    message: extra,
                })
            };
            let _ = pending.reply.send(result);
            return Ok(());
        }
        drop(i);
        if let Err(error) = self.guild_session.ingest(generation, &packet) {
            tracing::warn!(%error, command = packet.command, "QQ guild synchronization push rejected");
        }
        if packet.return_code != 0 {
            return Err(Error::Server {
                code: packet.return_code,
                message: extra,
            });
        }
        let control_reply = match packet.command.as_str() {
            "trpc.msg.olpush.OlPushService.MsgPush" => wire::encode_push_ack(packet.body.clone())?
                .map(|body| ("trpc.msg.olpush.OlPushService.SsoPushAck", body)),
            "ConfigPushSvc.PushReq" => wire::encode_config_push_response(packet.body.clone())
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
        let is_kick = packet.command == "trpc.qq_new_tech.status_svc.StatusService.KickNT";
        let reason = if is_kick {
            let p = crate::proto::decode::<auth::Kick>(packet.body.clone())?;
            Some(format!(
                "Kicked: {} {}",
                p.title.unwrap_or_default(),
                p.message.unwrap_or_default()
            ))
        } else {
            None
        };
        let _ = self.packets.send(packet);
        if let Some(reason) = reason {
            self.terminate_generation(generation, reason)
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
        inner.sequence = inner.sequence.checked_add(1).ok_or_else(|| {
            Error::Unsupported("SSO sequence space exhausted; reconnect required".into())
        })?;
        let sequence = inner.sequence;
        let signing_generation = inner.signer.generation();
        let signature = inner.signer.sign(
            command,
            sequence,
            &body,
            &inner.state,
            self.config.randomize_signature_for_testing,
        )?;
        if inner.signer.generation() != signing_generation {
            inner.signing_cancel.cancel();
            inner.signing_cancel = CancellationToken::new();
        }
        if signature.is_some() {
            self.signing_work.notify_one();
        }
        tracing::debug!(target: "atri_qq_protocol::packet_trace", direction = "send", stage = "prepared", command, sequence, generation = inner.generation, request_type = ?request_type, encryption = ?encryption, body_hex = %hex::encode(&body), "QQ packet");
        let frame = wire::encode_sso(
            command,
            sequence,
            body,
            request_type,
            encryption,
            &inner.state,
            signature,
        )?;
        Ok((sequence, frame))
    }
    async fn send_only(&self, command: &str, body: Bytes, generation: u64) -> Result<()> {
        let deadline = Instant::now()
            .checked_add(self.config.timeout)
            .ok_or_else(|| wire::malformed("Send deadline overflow"))?;
        let (sender, sequence, frame, cancel) = {
            let mut inner = self.inner.lock().unwrap();
            if inner.generation != generation {
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
                frame,
                deadline,
                cancel,
                required_control: true,
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
                Some(RequestBinding::Online(generation)) => {
                    i.generation == generation && i.state.online
                }
                Some(RequestBinding::SigningReport { generation, report }) => {
                    i.generation == generation && i.signer.report_is_current(report)
                }
            };
            if !current {
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
            let (sequence, frame) =
                self.prepare_frame(&mut i, command, body, request_type, encryption)?;
            i.next_id = i
                .next_id
                .checked_add(1)
                .ok_or_else(|| Error::Unsupported("Request identity space exhausted".into()))?;
            let id = i.next_id;
            let key = i.state.keystore.d2_key.clone();
            let (tx, rx) = oneshot::channel();
            let cancel = CancellationToken::new();
            i.pending.insert(
                sequence,
                Pending {
                    id,
                    command: command.into(),
                    key,
                    reply: tx,
                    cancel: cancel.clone(),
                },
            );
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
                    frame,
                    deadline,
                    cancel,
                    required_control: false,
                })
                .await
                .map_err(|_| Error::Disconnected)?;
            reply.await.map_err(|_| Error::Disconnected)?
        })
        .await
        .map_err(|_| Error::Timeout)?
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
    pub async fn logout(&self) -> Result<()> {
        let state = self.snapshot().await;
        let result = if state.online {
            let body = auth::UnregisterRequest {
                r#type: Some(0),
                device: Some(auth::StatusDevice {
                    name: Some(Bytes::new()),
                    kernel: Some(Bytes::new()),
                    vendor: Some(Bytes::new()),
                    model: Some(Bytes::new()),
                    os: Some(Bytes::new()),
                }),
                reason: Some(0),
            }
            .encode_to_vec()
            .into();
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
        {
            let mut i = self.inner.lock().unwrap();
            if i.generation != generation {
                return;
            }
            i.cancel.cancel();
            i.maintenance_cancel.cancel();
            i.maintenance_started = false;
            i.credentials.invalidate(true);
            let connected = i.connection.take().is_some();
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
        self.captcha.lock().unwrap().take();
    }
    fn mark_activity(&self, generation: u64) {
        let mut inner = self.inner.lock().unwrap();
        if inner.generation == generation && inner.connection.is_some() {
            inner.last_activity = Instant::now();
            self.activity.notify_one();
        }
    }
    pub(crate) fn start_alive(self: &Arc<Self>) {
        let (generation, cancel) = {
            let mut inner = self.inner.lock().unwrap();
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
                    result = client.request(
                        "Heartbeat.Alive",
                        Bytes::from_static(&[0, 0, 0, 4]),
                        RequestType::Simple,
                        Encryption::None,
                        client.config.timeout,
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
        let cancel = {
            let mut inner = self.inner.lock().unwrap();
            inner.heartbeat_cancel.cancel();
            inner.heartbeat_cancel = inner.cancel.child_token();
            inner.heartbeat_cancel.clone()
        };
        let weak = self.weak.clone();
        let task = tokio::spawn(async move {
            let reference = Instant::now();
            let mut trigger_time = server_time;
            let mut interval = heartbeat_seconds.clamp(120, 500);
            loop {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(Duration::from_secs(u64::from(interval))) => {},
                }
                let Some(client) = weak.upgrade() else { return };
                let body = auth::HeartbeatRequest {
                    r#type: Some(1),
                    state: Some(auth::HeartbeatState {
                        status: Some(0),
                        field2: Some(0),
                    }),
                    local_silence: Some(0),
                    server_time: Some(trigger_time),
                }
                .encode_to_vec()
                .into();
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
                // Field 4 is the preceding timer-arm time, not this request's send time.
                trigger_time = server_time.saturating_add(reference.elapsed().as_secs());
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
            inner.signing_ready = true;
        }
        self.background_work.notify_one();
        self.signing_work.notify_one();
        Ok(())
    }
    fn start_signing_work(&self, generation: u64, channel: crate::o3::Channel) {
        {
            let mut inner = self.inner.lock().unwrap();
            if inner.generation != generation {
                return;
            }
            if inner
                .o3
                .transport_generation
                .is_some_and(|previous| previous != generation)
            {
                inner.signer.cancel_token_reports();
            }
            inner.o3.transport_generation = Some(generation);
            if inner.o3.scope.is_none() {
                inner.o3.channel = channel;
            } else if inner.o3.channel.is_establishing() {
                inner.o3.channel.reset();
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
                        if inner.o3.scope != Some(binding) {
                            inner.o3.channel.reset();
                            inner.o3.heartbeat.reset();
                            inner.o3.scope = Some(binding);
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
                            state, o3, signer, ..
                        } = &mut *inner;
                        match o3.heartbeat.take_due(state) {
                            Ok(Some(body)) => {
                                queued.push_back(crate::o3::Work::Report(
                                    signer.channel_report("heartbeat", body),
                                ));
                            }
                            Ok(None) => {}
                            Err(error) => {
                                tracing::warn!(%error, "O3 heartbeat could not be prepared")
                            }
                        }
                    }
                }
                loop {
                    let (report, request, report_cancel) = {
                        let mut inner = client.inner.lock().unwrap();
                        if inner.generation != generation || inner.connection.is_none() {
                            return;
                        }
                        let Some(work) = queued.pop_front() else {
                            break;
                        };
                        let mut report = match work {
                            crate::o3::Work::Report(report) => report,
                            crate::o3::Work::RotatePeer { material, generation: signing_generation, account } => {
                                if inner.signing_ready
                                    && inner.signer.generation() == signing_generation
                                    && inner.state.keystore.uin == account
                                {
                                    if let Err(error) = inner.o3.channel.rotate_peer(&material) {
                                        tracing::warn!(%error, "O3 peer rotation rejected");
                                    } else {
                                        tracing::debug!(target: "atri_qq_protocol::packet_trace", stage = "o3_state", generation, phase = "peer_rotated", "QQ O3 state");
                                    }
                                }
                                continue;
                            }
                        };
                        if !inner.signing_ready || !inner.signer.report_is_current(&report) {
                            continue;
                        }
                        if inner.o3.channel.is_establishing() {
                            queued.push_front(crate::o3::Work::Report(report));
                            break;
                        }
                        let body = Bytes::from(std::mem::take(&mut report.body));
                        let request = match crate::o3::unix_seconds()
                            .and_then(|now| inner.o3.channel.prepare(&report.method, body, now))
                        {
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
                    pending.push(async move {
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
                        (report, request, response, report_cancel)
                    });
                }
                let heartbeat_deadline = if active_scope.is_some() {
                    client.inner.lock().unwrap().o3.heartbeat.deadline()
                } else {
                    None
                };
                drop(client);
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return,
                    Some((report, request, response, report_cancel)) = pending.next(), if !pending.is_empty() => {
                        let Some(client) = weak.upgrade() else { return };
                        let mut inner = client.inner.lock().unwrap();
                        if inner.generation != generation || !inner.signer.report_is_current(&report) {
                            continue;
                        }
                        let command = request.command;
                        let result = match response {
                            Ok(response) => crate::o3::unix_seconds()
                                .and_then(|now| inner.o3.channel.complete(request, response, now)),
                            Err(error) => {
                                inner.o3.channel.failed(&request);
                                Err(error)
                            }
                        };
                        match result {
                            Ok(reply) => {
                                tracing::debug!(target: "atri_qq_protocol::packet_trace", stage = "o3_state", generation, method = report.method, command, phase = "authenticated_reply", channel_expires_at = ?inner.o3.channel.expires_at(), "QQ O3 state");
                                if let Some(config) = reply.config {
                                    inner.signer.apply_channel_config(&config);
                                    inner.o3.heartbeat.configure(config.option4 != 0);
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
                                    let Inner { state, signer, o3, .. } = &mut *inner;
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
        let cancel = self.cancellation();
        let task = tokio::spawn(async move {
            loop {
                let notified = notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                let Some(client) = weak.upgrade() else { return };
                let (replies, reports, telemetry_deadline) = {
                    let mut inner = client.inner.lock().unwrap();
                    if inner.generation != generation || inner.connection.is_none() {
                        return;
                    }
                    let Inner { state, signer, .. } = &mut *inner;
                    if let Err(error) = signer.poll_telemetry(state) {
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
                            client.terminate_generation(
                                generation,
                                format!("Required control response failed: {error}"),
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
    pub fn take_signing_token_error(&self) -> Option<::signing::token::TokenError> {
        self.inner.lock().unwrap().signer.take_token_error()
    }
    pub fn complete_signing_xwid(&self, acquisition: ::signing::token::XwidAcquisition) {
        self.inner.lock().unwrap().signer.complete_xwid(acquisition)
    }
    pub fn set_signing_footer_seed(&self, seed: &[u8; 48]) {
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
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;

