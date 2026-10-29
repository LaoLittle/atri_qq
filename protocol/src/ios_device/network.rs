use super::IosVirtualConfig;
use crate::{
    Result,
    models::{
        IosAccountRecord80, IosPushStatistics, IosReservedTemplate, IosTransportAccount,
        IosTransportResources,
    },
    proto::sso,
};
use bytes::Bytes;
use prost::Message;
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    num::Wrapping,
};

#[derive(Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IosVirtualNetworkKind {
    Unavailable,
    #[default]
    Wifi,
    Cellular,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum IosIpStack {
    Unavailable = 0,
    Ipv4 = 1,
    Ipv6 = 2,
    Dual = 3,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IosNetworkLimits {
    pub phase_limit_ms: u32,
    pub srtt_high_ms: u32,
    pub srtt_low_ms: u32,
    pub block_limit_ms: u32,
    pub heartbeat_block_enabled: bool,
}

impl Default for IosNetworkLimits {
    fn default() -> Self {
        Self {
            phase_limit_ms: 1500,
            srtt_high_ms: 1500,
            srtt_low_ms: 500,
            block_limit_ms: 1000,
            heartbeat_block_enabled: true,
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IosVirtualNetwork {
    pub kind: IosVirtualNetworkKind,
    pub cellular_subtype: Option<u8>,
    pub ip_stack: Option<IosIpStack>,
    pub bssid: Option<String>,
    pub endpoint_origin_bit: bool,
    pub limits: IosNetworkLimits,
}

impl IosVirtualNetwork {
    pub(crate) fn network_type(&self) -> u8 {
        match self.kind {
            IosVirtualNetworkKind::Unavailable => 0,
            IosVirtualNetworkKind::Wifi => 1,
            IosVirtualNetworkKind::Cellular => self
                .cellular_subtype
                .filter(|value| matches!(value, 20 | 98 | 99 | 101..=119))
                .unwrap_or(2),
        }
    }
}

impl IosVirtualConfig {
    pub(crate) fn transport_resources(&self) -> Result<IosTransportResources> {
        let reserved = sso::Reserved {
            locale_id: Some(self.registration_locale()),
            imsi: Some(0),
            network_type: Some(u32::from(self.network.network_type())),
            nt_core_version: Some(100),
            ..Default::default()
        };
        let mut flags = [0; 11];
        flags[10] = 4;
        Ok(IosTransportResources {
            network_type: self.network.network_type(),
            effective_flags: flags,
            account_record_0x80: IosAccountRecord80(Bytes::new()),
            carrier_mcc: self
                .carrier
                .as_ref()
                .map(|carrier| carrier.mobile_country_code.clone())
                .unwrap_or_default(),
            carrier_mnc: self
                .carrier
                .as_ref()
                .map(|carrier| carrier.mobile_network_code.clone())
                .unwrap_or_default(),
            cf_bundle_version: self.bundle_version.clone(),
            account: IosTransportAccount::Uin { account_type: 0 },
            reserved: IosReservedTemplate::new(reserved.encode_to_vec().into())?,
            push_service_get_statistics: None,
        })
    }
}

#[derive(Clone, Copy)]
enum Phase {
    Reset,
    Prepared,
    Connecting,
    Connected,
    Received,
}

struct NetworkQuality {
    phase: Phase,
    base: i64,
    prepare_ms: i64,
    connect_ms: i64,
    srtt: f64,
    block_sample: f64,
    bad: bool,
    limits: IosNetworkLimits,
}

impl NetworkQuality {
    fn new(now: i64, limits: IosNetworkLimits) -> Self {
        Self {
            phase: Phase::Reset,
            base: now,
            prepare_ms: 0,
            connect_ms: 0,
            srtt: 0.0,
            block_sample: 0.0,
            bad: false,
            limits,
        }
    }
    fn check(&mut self, now: i64) {
        self.bad = match self.phase {
            Phase::Reset | Phase::Connecting => {
                self.bad || delta(now, self.base) > i64::from(self.limits.phase_limit_ms)
            }
            Phase::Prepared => self.prepare_ms > i64::from(self.limits.phase_limit_ms),
            Phase::Connected => self.bad || self.connect_ms > i64::from(self.limits.phase_limit_ms),
            Phase::Received => {
                let blocked = self.block_sample >= f64::from(self.limits.block_limit_ms);
                if blocked {
                    self.block_sample = 0.0;
                }
                blocked
                    || self.srtt >= f64::from(self.limits.srtt_high_ms)
                    || (self.bad && self.srtt > f64::from(self.limits.srtt_low_ms))
            }
        };
    }
    fn prepare(&mut self, now: i64) {
        self.prepare_ms = delta(now, self.base);
        self.base = now;
        self.phase = Phase::Prepared;
        self.check(now);
        self.phase = Phase::Connecting;
        self.base = now;
        self.check(now);
    }
    fn connected(&mut self, now: i64) {
        self.connect_ms = delta(now, self.base);
        self.base = now;
        self.phase = Phase::Connected;
        self.check(now);
    }
    fn response(&mut self, command: &str, sent: Option<i64>, correction: Option<i32>, now: i64) {
        let correction = correction.unwrap_or(0);
        if let Some(sent) = sent.filter(|_| correction > 0 || command == "Heartbeat.Alive") {
            let sample = delta(now, (Wrapping(sent) + Wrapping(i64::from(correction))).0) as f64;
            self.srtt = if self.srtt > 0.0 {
                0.6 * self.srtt + 0.4 * sample
            } else {
                sample
            };
        }
        self.phase = Phase::Received;
        self.check(now);
    }
    fn heartbeat_timeout(&mut self) {
        if self.limits.heartbeat_block_enabled && matches!(self.phase, Phase::Received) {
            self.block_sample = f64::from(self.limits.block_limit_ms);
            self.srtt = if self.srtt > 0.0 {
                0.6 * self.srtt + 0.4 * self.block_sample
            } else {
                self.block_sample
            };
        }
    }
}

#[derive(Default)]
struct PushWindow {
    count: Wrapping<u32>,
    elapsed: Wrapping<i64>,
    timeouts: Wrapping<u32>,
}

impl PushWindow {
    fn response(&mut self, created: i64, now: i64) {
        self.count += Wrapping(1);
        let elapsed = delta(now, created);
        if elapsed >= 0 {
            self.elapsed += Wrapping(elapsed);
        }
    }
    fn timeout(&mut self, gate: Option<i32>) {
        if gate.is_some_and(|value| value as u8 == 1) {
            self.timeouts += Wrapping(1);
        }
    }
    fn take(&mut self) -> IosPushStatistics {
        let window = std::mem::take(self);
        IosPushStatistics {
            count: window.count.0 as i32,
            elapsed: window.elapsed.0,
            value: window.timeouts.0 as i32,
        }
    }
}

pub(crate) struct IosNetworkSession {
    quality: NetworkQuality,
    push: PushWindow,
    sequence: Bytes,
    stack_override: Option<IosIpStack>,
    stack: u8,
    ip_origin: Option<u32>,
    origin_bit: bool,
    wifi_empty: bool,
    application_state: u32,
}

impl IosNetworkSession {
    pub(crate) fn new(config: &IosVirtualConfig, now: i64) -> Self {
        Self {
            quality: NetworkQuality::new(now, config.network.limits.clone()),
            push: PushWindow::default(),
            sequence: Bytes::new(),
            stack_override: config.network.ip_stack,
            stack: 0,
            ip_origin: None,
            origin_bit: config.network.endpoint_origin_bit,
            wifi_empty: config.network.network_type() == 1
                && config.network.bssid.as_deref().is_none_or(str::is_empty),
            application_state: if config.application.foreground { 1 } else { 2 },
        }
    }
    pub(crate) fn prepare(
        &mut self,
        saved: &mut Option<u32>,
        wall_seconds: u32,
        adjusted_seconds: u32,
        now: i64,
    ) {
        let next = (Wrapping(saved.unwrap_or(wall_seconds)) + Wrapping(1))
            .0
            .max(adjusted_seconds);
        *saved = Some(next);
        self.sequence = Bytes::from(next.to_string());
        self.quality.prepare(now);
        self.ip_origin = None;
    }
    pub(crate) fn connected(&mut self, peer: SocketAddr, now: i64) {
        self.stack = self
            .stack_override
            .map(|value| value as u8)
            .unwrap_or(match peer.ip() {
                IpAddr::V4(_) => 1,
                IpAddr::V6(_) => 2,
            });
        self.ip_origin = Some(if self.origin_bit { 3 } else { 1 });
        self.quality.connected(now);
        self.push = PushWindow::default();
    }
    pub(crate) fn disconnect(&mut self) {
        self.ip_origin = None;
        self.quality.block_sample = 0.0;
    }
    pub(crate) fn tick(&mut self, now: i64) {
        self.quality.check(now);
    }
    pub(crate) fn sent(&mut self, command: &str) {
        if command == "Heartbeat.Alive" {
            self.quality.block_sample = 0.0;
        }
    }
    pub(crate) fn response(
        &mut self,
        command: &str,
        created: Option<i64>,
        sent: Option<i64>,
        correction: Option<i32>,
        now: i64,
    ) {
        if let Some(created) = created {
            self.push.response(created, now);
        }
        self.quality.response(command, sent, correction, now);
    }
    pub(crate) fn timeout(&mut self, command: &str, gate: Option<i32>) {
        self.push.timeout(gate);
        if command == "Heartbeat.Alive" {
            self.quality.heartbeat_timeout();
        }
    }
    pub(crate) fn take_push_statistics(&mut self) -> IosPushStatistics {
        self.push.take()
    }
    pub(crate) fn ip_stack(&self) -> u8 {
        self.stack
    }
    pub(crate) fn apply_reserved(
        &self,
        reserved: &mut sso::Reserved,
        is_nt_request: bool,
        ordinary: bool,
    ) {
        reserved.flag =
            Some(u32::from(ordinary && self.wifi_empty) | (u32::from(self.quality.bad) << 1));
        reserved.message_type = Some(u32::from(is_nt_request) << 5);
        reserved.application_state = Some(self.application_state);
        if ordinary {
            reserved.ip_stack_type = Some(u32::from(self.stack));
            reserved.ip_origin = self.ip_origin;
        }
        reserved.trans_info.push(sso::TransInfo {
            key: Some("client_conn_seq".into()),
            value: Some(self.sequence.clone()),
        });
    }
}

pub(crate) fn wall_millis() -> Result<i64> {
    Ok(::signing::ios::source::SystemSource.unix_micros()? / 1000)
}

fn delta(now: i64, then: i64) -> i64 {
    (Wrapping(now) - Wrapping(then)).0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn network_flag_tracks_real_phase_limits_and_rtt_hysteresis() {
        let mut state = NetworkQuality::new(0, IosNetworkLimits::default());
        state.prepare(1500);
        assert!(!state.bad);
        state.connected(3001);
        assert!(state.bad);
        state.response("Heartbeat.Alive", Some(3001), None, 3501);
        assert!(!state.bad);
        state.response("Heartbeat.Alive", Some(3501), None, 6501);
        assert!(state.bad);
        for now in [6501, 6502] {
            state.response("Heartbeat.Alive", Some(now), None, now);
            assert!(state.bad);
        }
        state.response("Heartbeat.Alive", Some(6503), None, 6503);
        assert!(!state.bad);
    }
    #[test]
    fn unmatched_or_uncorrected_business_response_does_not_invent_an_rtt_sample() {
        let mut state = NetworkQuality::new(0, IosNetworkLimits::default());
        state.prepare(0);
        state.connected(10);
        state.response("business", Some(10), None, 10000);
        assert!(!state.bad);
        state.response("business", Some(10000), Some(100), 11600);
        assert!(state.bad);
        state.heartbeat_timeout();
        state.check(11601);
        assert!(state.bad);
    }
    #[test]
    fn push_window_counts_negative_deltas_and_consumes_only_its_accumulated_window() {
        let mut window = PushWindow::default();
        window.response(100, 90);
        window.response(100, 125);
        window.timeout(Some(-1));
        window.timeout(Some(257));
        let first = window.take();
        assert_eq!((first.count, first.elapsed, first.value), (2, 25, 1));
        window.response(200, 240);
        let second = window.take();
        assert_eq!((second.count, second.elapsed, second.value), (1, 40, 0));
    }
}
