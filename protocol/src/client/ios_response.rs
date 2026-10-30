use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Action {
    Deliver,
    DeliverStatus,
    Full,
    Ability,
    Reconnect,
    Consume,
    Failure,
}

impl Action {
    pub(super) fn classify(code: i32) -> Self {
        match code {
            0 => Self::Deliver,
            -10000 | -10007 => Self::DeliverStatus,
            -10008 => Self::Full,
            -10119 => Self::Ability,
            -10114 => Self::Reconnect,
            -10113 => Self::Consume,
            _ => Self::Failure,
        }
    }
}

#[derive(Default)]
pub(super) struct State {
    pub disabled_abilities: u32,
    pub sideway_disabled: bool,
    pub reconnecting: bool,
    pub signature: SignatureState,
}

pub(super) struct SignatureState {
    pub host: i32,
    pub attachment: i32,
}

impl Default for SignatureState {
    fn default() -> Self {
        Self {
            host: 2,
            attachment: 2,
        }
    }
}

impl SignatureState {
    pub fn accept(&mut self, reserve: &crate::proto::sso::Reserved) {
        if let Some(flag) = reserve.secure_signature_flag
            && flag != u32::MAX
        {
            self.attachment = flag as i32;
        }
    }

    pub fn host_delivery(&mut self, reserve: &crate::proto::sso::Reserved) {
        self.host = reserve.secure_signature_flag.unwrap_or(u32::MAX) as i32;
    }

    pub fn invokes(&self) -> bool {
        self.host != 0
    }

    pub fn attaches(&self) -> bool {
        matches!(self.attachment, 1 | 2)
    }
}

pub(super) fn host_delivered(
    packet: &IncomingPacket,
    matched: bool,
    config_push_consumed: bool,
) -> bool {
    if packet.command.is_empty() || packet.body.is_empty() {
        return false;
    }
    if matched {
        return match packet.command.as_str() {
            "Client.CorrectTime"
            | "PhSigLcId.Check"
            | "GrayUinPro.Check"
            | "login.auth"
            | "login.chgTok"
            | "account.reg"
            | "account.search"
            | "login.getSid"
            | "Heartbeat.Alive"
            | "ConfigPushSvc.GetIpDirect"
            | "ConfigPushSvc.GetNoLoginIpDirect" => false,
            "trpc.qqaccess.dispatch.DispatchService.GetIpDirect" => {
                !crate::proto::network::IosDispatchDomainConfiguration::decode(packet.body.clone())
                    .is_ok_and(|configuration| !configuration.domains.is_empty())
            }
            _ => true,
        };
    }
    match packet.command.as_str() {
        "SSO.HelloPush" | "OverLoadPush.notify" | "ConfigPushSvc.PushDomain" => false,
        "ConfigPushSvc.PushReq" => !config_push_consumed,
        "trpc.qqaccess.dispatch.DispatchService.Push" => {
            let Ok(push) = crate::proto::network::IosDispatchPush::decode(packet.body.clone())
            else {
                return true;
            };
            let kind = push.push_type();
            let body = push.buffer.unwrap_or_default();
            !match kind {
                crate::proto::network::IosDispatchPushType::SsoServers => {
                    crate::proto::network::IosDispatchServerConfiguration::decode(body).is_ok()
                }
                crate::proto::network::IosDispatchPushType::Domains => {
                    crate::proto::network::IosDispatchDomainConfiguration::decode(body).is_ok()
                }
                _ => false,
            }
        }
        _ => true,
    }
}

impl Client {
    pub(super) fn consume_ios_response(&self, inner: &mut Inner, sequence: i32) {
        let Some(pending) = inner.pending.remove(&sequence) else {
            return;
        };
        let deadline = pending.replay.as_ref().unwrap().deadline;
        let cancel = inner.cancel.clone();
        let mut reply = pending.reply;
        let task = tokio::spawn(async move {
            tokio::select! {
                biased;
                _ = reply.closed() => {},
                _ = cancel.cancelled() => {
                    let _ = reply.send(Err(Error::Disconnected));
                },
                _ = tokio::time::sleep_until(deadline) => {
                    let _ = reply.send(Err(Error::Timeout));
                },
            }
        });
        let mut tasks = self.tasks.lock().unwrap();
        tasks.retain(|task| !task.is_finished());
        tasks.push(task);
    }

    pub(super) fn reconnect_ios_transport(
        &self,
        inner: &mut Inner,
        generation: u64,
        sequence: Option<i32>,
    ) {
        let ios = inner.ios_mut().unwrap();
        ios.response.sideway_disabled = true;
        if ios.response.reconnecting {
            return;
        }
        ios.response.reconnecting = true;
        inner.transport_cancel.cancel();
        inner.connection_cookie = Bytes::new();
        let retained = sequence.and_then(|sequence| {
            inner
                .pending
                .remove(&sequence)
                .map(|pending| (sequence, pending))
        });
        for (_, pending) in inner.pending.drain() {
            pending.cancel.cancel();
            let _ = pending.reply.send(Err(Error::Disconnected));
        }
        if let Some((sequence, mut pending)) = retained {
            if let Some(replay) = &mut pending.replay {
                replay.phase = ios_header::Phase::Queued;
                replay.accumulated_wait = 0;
            }
            inner.pending.insert(sequence, pending);
        }
        let ios = inner.ios_mut().unwrap();
        ios.header.reset(generation);
        ios.block_check = ios_network::BlockCheck::default();
        if let Some(network) = &mut ios.network {
            network.disconnect();
        }
        let account = inner.state.keystore.uin;
        let uid = inner.state.keystore.uid.clone();
        let guid = inner.state.keystore.guid.clone();
        let platform = inner.state.platform.clone();
        let qua = inner.state.profile.qua.clone();
        let cancel = inner.cancel.clone();
        let weak = self.weak.clone();
        let task = tokio::spawn(async move {
            let Some(client) = weak.upgrade() else { return };
            let _gate = tokio::select! {
                biased;
                _ = cancel.cancelled() => return,
                gate = client.connect_gate.lock() => gate,
            };
            let current = |inner: &Inner| {
                inner.generation == generation
                    && !cancel.is_cancelled()
                    && inner.kick_reason.is_none()
                    && inner.state.keystore.uin == account
                    && inner.state.keystore.uid == uid
                    && inner.state.keystore.guid == guid
                    && inner.state.platform == platform
                    && inner.state.profile.qua == qua
            };
            let result = async {
                {
                    let mut inner = client.inner.lock().unwrap();
                    if !current(&inner) {
                        return Err(Error::Disconnected);
                    }
                    client.prepare_ios_connection(&mut inner)?;
                }
                let socket = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return Err(Error::Disconnected),
                    result = tokio::time::timeout(client.config.timeout, client.connect_socket()) => {
                        result.map_err(|_| Error::Timeout)??
                    },
                };
                {
                    let inner = client.inner.lock().unwrap();
                    if !current(&inner) {
                        return Err(Error::Disconnected);
                    }
                }
                client.install_transport(socket, generation)?;
                let mut inner = client.inner.lock().unwrap();
                if !current(&inner) {
                    return Err(Error::Disconnected);
                }
                inner.ios_mut().unwrap().response.reconnecting = false;
                if let Some(sequence) = sequence.filter(|sequence| inner.pending.contains_key(sequence)) {
                    client.resend_ios(&mut inner, sequence, generation, false)?;
                }
                client.arm_ios_block_checks(&mut inner);
                drop(inner);
                client.start_background_work(generation);
                client.start_ios_correct_time();
                client.signing_work.notify_one();
                Ok(())
            }.await;
            if let Err(error) = result {
                client.terminate_generation_with_policy(
                    generation,
                    format!("SSO forced TCP reconnect failed: {error}"),
                    false,
                    Some(&current),
                );
                let mut inner = client.inner.lock().unwrap();
                if inner.generation == generation && !current(&inner) {
                    inner.ios_mut().unwrap().response.reconnecting = false;
                    if inner.kick_reason.is_none() {
                        inner.transport_cancel.cancel();
                        inner.connection.take();
                    }
                    if let Some(pending) =
                        sequence.and_then(|sequence| inner.pending.remove(&sequence))
                    {
                        pending.cancel.cancel();
                        let _ = pending.reply.send(Err(Error::Disconnected));
                    }
                }
            }
        });
        self.tasks.lock().unwrap().push(task);
    }
}
