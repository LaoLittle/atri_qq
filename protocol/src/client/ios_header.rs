use super::*;

#[cfg(test)]
mod tests;

#[derive(Default)]
pub(super) struct State {
    generation: u64,
    identity: Option<Identity>,
    trim_enabled: bool,
    full_selected: bool,
    pub qimei_materialized: bool,
}

struct Identity {
    account_type: u8,
    text: AccountText,
    uid: String,
}

enum AccountText {
    Uin(u64),
    Explicit(Bytes),
}

impl State {
    pub(super) fn reset(&mut self, generation: u64) {
        *self = Self {
            generation,
            ..Self::default()
        };
    }

    pub(super) fn select(
        &mut self,
        generation: u64,
        command: &str,
        resources: &IosTransportResources,
        store: &Keystore,
        force_full: bool,
    ) -> RequestType {
        if self.generation != generation || command == "wtlogin.login" {
            self.reset(generation);
        }
        if exempt(command) {
            return RequestType::D2;
        }
        let account_type = match &resources.account {
            IosTransportAccount::Uin { account_type }
            | IosTransportAccount::Explicit { account_type, .. } => *account_type,
        };
        if account_type == 6 {
            return RequestType::D2;
        }
        let unchanged = self.identity.as_ref().is_some_and(|identity| {
            identity.account_type == account_type
                && identity.uid == store.uid
                && match (&identity.text, &resources.account) {
                    (AccountText::Uin(uin), IosTransportAccount::Uin { .. }) => *uin == store.uin,
                    (
                        AccountText::Explicit(text),
                        IosTransportAccount::Explicit { text: current, .. },
                    ) => text == current,
                    (AccountText::Uin(uin), IosTransportAccount::Explicit { text, .. }) => {
                        text_is_uin(text, *uin)
                    }
                    (AccountText::Explicit(text), IosTransportAccount::Uin { .. }) => {
                        text_is_uin(text, store.uin)
                    }
                }
        });
        if !unchanged {
            self.reset(generation);
            self.identity = Some(Identity {
                account_type,
                text: match &resources.account {
                    IosTransportAccount::Uin { .. } => AccountText::Uin(store.uin),
                    IosTransportAccount::Explicit { text, .. } => {
                        AccountText::Explicit(text.clone())
                    }
                },
                uid: store.uid.clone(),
            });
        }
        if unchanged
            && self.trim_enabled
            && !force_full
            && (!resources.reserved.has_qimei() || self.qimei_materialized)
            && command != crate::message_sync::INFO_COMMAND
            && !command.starts_with("RegPrxySvc.info")
            && command != "wtlogin.exchange"
        {
            RequestType::Simple
        } else {
            self.full_selected = true;
            RequestType::D2
        }
    }

    pub(super) fn response(&mut self, eligible: bool) {
        if eligible && self.full_selected {
            self.trim_enabled = true;
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum Phase {
    Queued,
    Writing(Instant),
    Awaiting(Instant),
}

impl Phase {
    pub(super) fn sent(self) -> Option<Instant> {
        match self {
            Self::Queued => None,
            Self::Writing(sent) | Self::Awaiting(sent) => Some(sent),
        }
    }
}

pub(super) struct Replay {
    pub body: Bytes,
    pub request_type: RequestType,
    pub encryption: Encryption,
    pub is_nt_request: bool,
    pub internal_control: bool,
    pub signature: Option<crate::proto::sso::SecureInfo>,
    pub force_full: bool,
    pub deadline: Instant,
    pub eligible: bool,
    pub created: Instant,
    pub phase: Phase,
    pub accumulated_wait: u64,
    pub attempt: u64,
}

impl Replay {
    pub(super) fn new(
        inner: &Inner,
        body: &Bytes,
        request_type: RequestType,
        encryption: Encryption,
        is_nt_request: bool,
        internal_control: bool,
        deadline: Instant,
    ) -> Option<Self> {
        inner.state.profile.platform.is_ios().then(|| Self {
            body: body.clone(),
            request_type,
            encryption,
            is_nt_request,
            internal_control,
            signature: None,
            force_full: false,
            deadline,
            created: Instant::now(),
            phase: Phase::Queued,
            accumulated_wait: 0,
            attempt: 0,
            eligible: !internal_control
                && !inner.state.keystore.a2.is_empty()
                && !inner.state.keystore.ios_msf_imei.is_empty(),
        })
    }
}

fn text_is_uin(text: &[u8], uin: u64) -> bool {
    if text.is_empty() || (text.len() > 1 && text[0] == b'0') {
        return false;
    }
    text.iter().try_fold(0u64, |value, byte| {
        if !byte.is_ascii_digit() {
            return None;
        }
        value.checked_mul(10)?.checked_add(u64::from(byte - b'0'))
    }) == Some(uin)
}

impl Client {
    pub(super) fn resend_ios(
        &self,
        inner: &mut Inner,
        sequence: i32,
        generation: u64,
        force_full: bool,
    ) -> Result<()> {
        let mut pending = inner.pending.remove(&sequence).unwrap();
        let replay = pending.replay.as_mut().unwrap();
        replay.force_full |= force_full;
        if replay.deadline <= Instant::now() || pending.cancel.is_cancelled() {
            inner.pending.insert(sequence, pending);
            return Ok(());
        }
        let Some(attempt) = replay.attempt.checked_add(1) else {
            pending.cancel.cancel();
            let _ = pending.reply.send(Err(Error::Unsupported(
                "SSO send attempt space exhausted".into(),
            )));
            return Ok(());
        };
        replay.attempt = attempt;
        replay.phase = Phase::Queued;
        replay.accumulated_wait = 0;
        let frame = match self.prepare_frame_at(
            inner,
            &pending.command,
            replay.body.clone(),
            replay.request_type,
            replay.encryption,
            replay.is_nt_request,
            replay.internal_control,
            sequence,
            replay.force_full,
            Some(&mut *replay),
        ) {
            Ok(frame) => frame,
            Err(error) => {
                pending.cancel.cancel();
                let _ = pending.reply.send(Err(error));
                return Ok(());
            }
        };
        replay.eligible = !replay.internal_control
            && !inner.state.keystore.a2.is_empty()
            && !inner.state.keystore.ios_msf_imei.is_empty();
        let outgoing = Outgoing {
            command: pending.command.clone(),
            sequence,
            attempt,
            frame,
            deadline: replay.deadline,
            cancel: pending.cancel.clone(),
            required_control: false,
            terminal: false,
        };
        let id = pending.id;
        inner.pending.insert(sequence, pending);
        let sender = inner.connection.as_ref().unwrap().sender.clone();
        match sender.try_send(outgoing) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Closed(_)) => {
                let pending = inner.pending.remove(&sequence).unwrap();
                pending.cancel.cancel();
                let _ = pending.reply.send(Err(Error::Disconnected));
            }
            Err(mpsc::error::TrySendError::Full(outgoing)) => {
                let weak = self.weak.clone();
                let cancel = outgoing.cancel.clone();
                let connection_cancel = inner.cancel.clone();
                let deadline = outgoing.deadline;
                let task = tokio::spawn(async move {
                    let result = tokio::select! {
                        biased;
                        _ = cancel.cancelled() => return,
                        _ = connection_cancel.cancelled() => return,
                        result = timeout_at(deadline, sender.send(outgoing)) => result,
                    };
                    let error = match result {
                        Ok(Ok(())) => return,
                        Ok(Err(_)) => Error::Disconnected,
                        Err(_) => Error::Timeout,
                    };
                    let Some(client) = weak.upgrade() else { return };
                    let mut inner = client.inner.lock().unwrap();
                    if inner.generation == generation
                        && inner
                            .pending
                            .get(&sequence)
                            .is_some_and(|pending| pending.id == id)
                    {
                        let pending = inner.pending.remove(&sequence).unwrap();
                        pending.cancel.cancel();
                        let _ = pending.reply.send(Err(error));
                    }
                });
                self.tasks.lock().unwrap().push(task);
            }
        }
        Ok(())
    }
}

fn exempt(command: &str) -> bool {
    matches!(
        command,
        "Heartbeat.Alive"
            | "Heartbeat.Ping"
            | "Client.CorrectTime"
            | "GrayUinPro.Check"
            | "ConfigService.ClientReq"
            | "PhSigLcId.Check"
            | "login.auth"
            | "wtlogin.name2uin"
            | "wtlogin.login"
            | "wtlogin.exchange_emp"
            | "wtlogin.trans_emp"
            | "wtlogin.fastlogin"
            | "SSO.HelloPush"
            | "account.RequestVerifyWTLogin_emp"
            | "account.RequestReBindMblWTLogin_emp"
            | "wtlogin64.exchange_emp"
            | "wtlogin64.trans_emp"
            | "wtlogin64.login"
            | "wtlogin64.name2uin"
            | "ConnAuthSvr.get_app_info_emp"
            | "ConnAuthSvr.get_auth_api_list_emp"
            | "ConnAuthSvr.sdk_auth_api_emp"
            | "loginfb.register"
            | "CliLogSvc.UploadReq"
            | "QQConnectLogin.pre_auth_emp"
            | "OidbSvc.0x4aa_202"
            | "CliLogSvc.upload_emp"
            | "QQConnectLogin.auth_emp"
            | "trpc.o3.ecdh_access.EcdhAccess.SsoEstablishShareKey"
            | "trpc.o3.ecdh_access.EcdhAccess.SsoSecureAccess"
            | "trpc.o3.report.Report.SsoReport"
            | "trpc.onseac1.login_svr.phone_svr.SecCheck"
            | "trpc.onseac1.login_svr.phone_svr.GetSMSCode"
            | "trpc.onseac1.login_svr.phone_svr.AccessToken"
            | "trpc.login.account_logic.AccountLogicService.SsoThirdPartQueryEncryptedBind"
            | "trpc.qqlog.qqlog_push.Portal.SsoPullReportRule"
            | "trpc.group_pro.configdistribution.ConfigDistributionSvr.SsoGetNoLoginConfig"
            | "wtlogin.log_report"
            | "wtlogin.register"
            | "QQConnectLogin.get_promote_page_emp"
            | "QQConnectLogin.submit_promote_page_emp"
            | "trpc.zplan.avatar_head_info.Config.SsoGetRegisterHeadConfig"
            | "trpc.login.ecdh.EcdhService.SsoOIDB0x90cd"
            | "trpc.login.ecdh.EcdhService.SsoOIDB0x90ce"
            | "trpc.login.ecdh.EcdhService.SsoKeyExchange"
            | "trpc.login.ecdh.EcdhService.SsoOIDB0x913a"
            | "trpc.login.ecdh.EcdhService.SsoNTLoginPasswordLogin"
            | "trpc.login.ecdh.EcdhService.SsoNTLoginOptimusLogin"
            | "trpc.login.ecdh.EcdhService.SsoNTLoginGetSaltList"
            | "trpc.login.ecdh.EcdhService.SsoNTLoginCheckA1List"
            | "trpc.login.ecdh.EcdhService.SsoNTLoginGetSms"
            | "trpc.login.ecdh.EcdhService.SsoNTLoginCheckSms"
            | "trpc.login.ecdh.EcdhService.SsoNTLoginCheckGateWayCode"
            | "trpc.login.ecdh.EcdhService.SsoNTLoginCheckThirdCode"
            | "trpc.login.ecdh.EcdhService.SsoNTLoginRefreshTicket"
            | "trpc.login.ecdh.EcdhService.SsoNTLoginAuthNewDevice"
            | "trpc.login.ecdh.EcdhService.SsoOIDB0x916a"
            | "trpc.login.ecdh.EcdhService.SsoOIDB0x916b"
            | "trpc.login.ecdh.EcdhService.SsoOIDB0x916c"
            | "trpc.login.ecdh.EcdhService.SsoOIDB0x916d"
            | "trpc.login.ecdh.EcdhService.SsoNTLoginRapidLogin"
            | "trpc.login.ecdh.EcdhService.SsoNTLoginRefreshA2"
            | "trpc.qqlog.qqlog_server.Portal.SsoNoStateReport"
            | "trpc.qqlog.qqlog_server.Portal.SsoGetNoStateURLReport"
            | "trpc.qqlog.qqlog_server.Portal.SsoGetQimeiCheckReport"
            | "OidbSvcTrpcTcp.0x930b_0"
            | "OidbSvcTrpcTcp.0x930c_0"
            | "OidbSvcTrpcTcp.0x930d_0"
            | "OidbSvcTrpcTcp.0x92eb_0"
            | "OidbSvcTrpcTcp.0x930e_0"
            | "MQUpdateSvc_com_qq_ti.web.OidbSvcTrpcJsapiTcp.0x9008_2"
            | "OidbSvcTrpcTcp.0x955f_1"
            | "OidbSvcTrpcTcp.0x9560_1"
            | "OidbSvcTrpcTcp.0x9689_1"
            | "trpc.login.ecdh.EcdhService.SsoNTLoginEasyLogin"
            | "ConfigPushSvc.GetNoLoginIpDirect"
            | "trpc.o3.mobile_security.MobileSecurity.SsoCheckSwitch"
            | "trpc.login.ecdh.EcdhService.SsoNTLoginPasswordLoginNewDevice"
            | "trpc.login.ecdh.EcdhService.SsoNTLoginPasswordLoginUnusualDevice"
            | "trpc.login.ecdh.EcdhService.SsoNTLoginEasyLoginUnusualDevice"
            | "trpc.login.ecdh.EcdhService.SsoNTLoginAuthCodeLogin"
            | "OidbSvcTrpcTcp.0x9cdf_1"
            | "OidbSvcTrpcTcp.0x9de9_1"
            | "trpc.qpay.gateway.Gateway.SsoForbid"
    )
}
