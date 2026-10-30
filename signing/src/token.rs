use std::collections::BTreeMap;

use crate::digest::{derive_xwid, md5_parts};
use crate::proto::{DeviceProperty, IssuedTokenReply, append_bytes_field, encoded_bytes_len};

pub type DeviceProperties = BTreeMap<i32, Vec<u8>>;

pub fn property_digest(contents: &[u8], suffix: &[u8]) -> [u8; 32] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = md5_parts(&[contents, suffix]);
    let mut output = [0; 32];
    for (index, byte) in digest.into_iter().enumerate() {
        output[index * 2] = HEX[usize::from(byte >> 4)];
        output[index * 2 + 1] = HEX[usize::from(byte & 15)];
    }
    output
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedToken {
    pub bytes: Vec<u8>,
    pub expires_at: i64,
}

#[derive(Clone, Copy, Debug)]
pub struct TokenPolicy {
    pub token_enabled: bool,
    pub xwid_enabled: bool,
    pub token_refresh_margin: i64,
    pub retry_interval: i64,
    pub xwid_max_age: i64,
    pub xwid_refresh_age: i64,
}

impl Default for TokenPolicy {
    fn default() -> Self {
        Self {
            token_enabled: true,
            xwid_enabled: false,
            token_refresh_margin: 300,
            retry_interval: 60,
            xwid_max_age: 3600,
            xwid_refresh_age: 3480,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcquisitionMode {
    ColdOrExpired,
    RefreshWindow,
}

#[derive(Debug)]
pub struct XwidAcquisition {
    pub xwid: Vec<u8>,
    pub auxiliary: Vec<u8>,
    pub started_at: i64,
    pub elapsed_nanoseconds: i64,
}

impl XwidAcquisition {
    pub fn native_default(started_at: i64, elapsed_nanoseconds: i64) -> Self {
        Self {
            xwid: Vec::new(),
            auxiliary: Vec::new(),
            started_at,
            elapsed_nanoseconds,
        }
    }
}

#[derive(Debug)]
pub struct ReportResponse {
    pub bytes: Vec<u8>,
    pub transport_succeeded: bool,
    pub error_code: u32,
}

#[derive(Debug)]
pub enum ReportDelivery {
    Complete(ReportResponse),
    Pending,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenError {
    Resource {
        operation: &'static str,
        message: String,
    },
    PropertyCollection(i32),
    Protobuf {
        code: u32,
        offset: usize,
    },
    PropertyRequestTruncated {
        offset: usize,
    },
    Transport(u32),
}

pub trait TokenResources {
    fn unix_seconds(&mut self) -> i64;
    fn persistent_xwid_switch(&mut self) -> Result<Option<&[u8]>, TokenError>;
    fn acquire_xwid(
        &mut self,
        mode: AcquisitionMode,
    ) -> Result<Option<XwidAcquisition>, TokenError>;
    fn collect_properties(&mut self) -> Result<DeviceProperties, TokenError>;
    fn send_report(
        &mut self,
        method: &str,
        account: &[u8],
        packet: &[u8],
    ) -> Result<ReportDelivery, TokenError>;
}

#[derive(Debug)]
pub struct TokenRead {
    pub bytes: Vec<u8>,
    pub report_error: Option<TokenError>,
    pub first_empty_token: bool,
}

#[derive(Debug, Default)]
pub struct TokenState {
    pub policy: TokenPolicy,
    account_tokens: BTreeMap<Vec<u8>, IssuedToken>,
    active_account: Vec<u8>,
    xwid: Vec<u8>,
    xwid_token: Vec<u8>,
    auxiliary: Vec<u8>,
    xwid_timestamp: i64,
    xwid_acquisition_milliseconds: i64,
    xwid_pending: bool,
    report_pending: bool,
    failed_times: u32,
    last_attempt: i64,
    empty_token_event_recorded: bool,
    xwid_selector: Option<i32>,
}

impl TokenState {
    pub fn initialize_xwid_switch(&mut self, stored_value: Option<&[u8]>) {
        if self.xwid_selector.is_some() {
            return;
        }
        let value = stored_value.unwrap_or_default();
        let value = value.split(|&byte| byte == 0).next().unwrap_or_default();
        let parsed = if value.is_empty() {
            1
        } else {
            parse_atoi(value)
        };
        let selector = if parsed == -1 { 1 } else { parsed };
        self.xwid_selector = if selector == 2 { None } else { Some(selector) };
        self.policy.xwid_enabled = selector == 1;
    }

    pub fn xwid_selector(&self) -> i32 {
        self.xwid_selector.unwrap_or(2)
    }

    pub fn set_xwid_selector(&mut self, selector: i32) {
        self.xwid_selector = if selector == 2 { None } else { Some(selector) };
        self.policy.xwid_enabled = selector == 1;
    }

    pub fn change_account(
        &mut self,
        account: &[u8],
        resources: &mut impl TokenResources,
    ) -> Result<(), TokenError> {
        let previous_report = self.refresh_active_account(resources);
        self.active_account.clear();
        self.active_account.extend_from_slice(account);
        self.report_pending = false;
        self.last_attempt = 0;
        self.empty_token_event_recorded = false;
        previous_report
    }

    pub fn failed_times(&self) -> u32 {
        self.failed_times
    }

    pub fn last_attempt(&self) -> i64 {
        self.last_attempt
    }

    pub fn report_pending(&self) -> bool {
        self.report_pending
    }

    pub fn account_token(&self, account: &[u8]) -> Option<&IssuedToken> {
        self.account_tokens.get(account)
    }

    pub fn auxiliary(&self) -> &[u8] {
        &self.auxiliary
    }

    pub fn xwid_acquisition_milliseconds(&self) -> i64 {
        self.xwid_acquisition_milliseconds
    }

    pub fn complete_xwid(&mut self, acquisition: XwidAcquisition) {
        self.xwid = acquisition.xwid;
        self.xwid_acquisition_milliseconds = acquisition.elapsed_nanoseconds / 1_000_000;
        if !self.xwid.is_empty() {
            let token = derive_xwid(&self.xwid);
            self.xwid_token.clear();
            self.xwid_token.extend_from_slice(&token);
        }
        self.auxiliary = acquisition.auxiliary;
        self.xwid_timestamp = acquisition.started_at;
        self.xwid_pending = false;
    }

    pub fn complete_report(
        &mut self,
        captured_account: &[u8],
        response: ReportResponse,
    ) -> Result<(), TokenError> {
        self.report_pending = false;
        if !response.transport_succeeded {
            self.failed_times = self.failed_times.wrapping_add(1);
            return Err(TokenError::Transport(response.error_code));
        }
        match decode_issued_token(&response.bytes) {
            Ok(token) => {
                self.failed_times = 0;
                if !token.bytes.is_empty() {
                    self.account_tokens.insert(captured_account.to_vec(), token);
                }
                Ok(())
            }
            Err(error) => {
                self.failed_times = self.failed_times.wrapping_add(1);
                Err(error)
            }
        }
    }

    pub fn token(
        &mut self,
        current_account: &[u8],
        resources: &mut impl TokenResources,
    ) -> Result<TokenRead, TokenError> {
        let mut bytes = Vec::new();
        if self.xwid_selector.is_none() {
            self.initialize_xwid_switch(resources.persistent_xwid_switch()?);
        }
        if self.policy.xwid_enabled {
            let now = resources.unix_seconds();
            let elapsed = now.wrapping_sub(self.xwid_timestamp);
            let cold_or_expired = self.xwid.is_empty() || elapsed > self.policy.xwid_max_age;
            if cold_or_expired {
                self.acquire(AcquisitionMode::ColdOrExpired, resources)?;
            } else if elapsed > self.policy.xwid_refresh_age {
                self.acquire(AcquisitionMode::RefreshWindow, resources)?;
            } else {
                bytes.extend_from_slice(&self.xwid_token);
            }
        }
        if !self.policy.token_enabled {
            return Ok(TokenRead {
                bytes,
                report_error: None,
                first_empty_token: false,
            });
        }
        let now = resources.unix_seconds();
        let needs_report = match self.account_tokens.get(current_account) {
            Some(token) => {
                let remaining = token.expires_at.wrapping_sub(now);
                if remaining <= 0 {
                    true
                } else {
                    bytes.clear();
                    bytes.extend_from_slice(&token.bytes);
                    remaining < self.policy.token_refresh_margin
                }
            }
            None => true,
        };
        if !needs_report
            || current_account != self.active_account
            || self.active_account.len() < 4
            || self.report_pending
        {
            return Ok(self.finish_read(bytes, None));
        }
        let now = resources.unix_seconds();
        if now.wrapping_sub(self.last_attempt) < self.policy.retry_interval {
            return Ok(self.finish_read(bytes, None));
        }
        self.last_attempt = now;
        let report_error = self.report_for_account(current_account, resources).err();
        Ok(self.finish_read(bytes, report_error))
    }

    pub fn poll(
        &mut self,
        current_account: &[u8],
        resources: &mut impl TokenResources,
    ) -> Result<(), TokenError> {
        if !self.policy.token_enabled
            || self.report_pending
            || current_account != self.active_account
            || self.active_account.len() < 4
        {
            return Ok(());
        }
        let now = resources.unix_seconds();
        if self
            .account_tokens
            .get(current_account)
            .is_some_and(|token| {
                let remaining = token.expires_at.wrapping_sub(now);
                remaining > 0 && remaining >= self.policy.token_refresh_margin
            })
            || now.wrapping_sub(self.last_attempt) < self.policy.retry_interval
        {
            return Ok(());
        }
        self.last_attempt = now;
        self.report_for_account(current_account, resources)
    }

    pub fn refresh_active_account(
        &mut self,
        resources: &mut impl TokenResources,
    ) -> Result<(), TokenError> {
        if self.active_account.len() < 4 || self.report_pending {
            return Ok(());
        }
        let account = std::mem::take(&mut self.active_account);
        let result = self.report_for_account(&account, resources);
        self.active_account = account;
        result
    }

    fn report_for_account(
        &mut self,
        account: &[u8],
        resources: &mut impl TokenResources,
    ) -> Result<(), TokenError> {
        let properties = resources.collect_properties()?;
        let previous = self
            .account_tokens
            .get(account)
            .map_or(&[][..], |token| token.bytes.as_slice());
        let packet = encode_report(properties, previous);
        self.report_pending = true;
        let delivery = match resources.send_report("getToken", account, &packet) {
            Ok(delivery) => delivery,
            Err(error) => {
                self.report_pending = false;
                return Err(error);
            }
        };
        match delivery {
            ReportDelivery::Complete(response) => self.complete_report(account, response),
            ReportDelivery::Pending => Ok(()),
        }
    }

    fn finish_read(&mut self, bytes: Vec<u8>, report_error: Option<TokenError>) -> TokenRead {
        let first_empty_token = bytes.is_empty() && !self.empty_token_event_recorded;
        self.empty_token_event_recorded |= first_empty_token;
        TokenRead {
            bytes,
            report_error,
            first_empty_token,
        }
    }

    pub fn answer_property_challenge(
        &mut self,
        requested_ids: &[u8],
        resources: &mut impl TokenResources,
    ) -> Result<Vec<u8>, TokenError> {
        if requested_ids.len() % 2 != 0 {
            return Err(TokenError::PropertyRequestTruncated {
                offset: requested_ids.len() - 1,
            });
        }
        let mut ids: Vec<i32> = requested_ids
            .chunks_exact(2)
            .map(|bytes| i32::from(i16::from_be_bytes([bytes[0], bytes[1]])))
            .collect();
        ids.sort_unstable();
        ids.dedup();
        let mut properties = resources.collect_properties()?;
        let mut output = Vec::new();
        for id in ids {
            match properties.remove(&id) {
                Some(value) => put_property(id, value, &mut output),
                None => put_missing_property(id, &mut output),
            }
        }
        let previous = self
            .account_tokens
            .get(self.active_account.as_slice())
            .map_or(&[][..], |token| token.bytes.as_slice());
        append_bytes_field(&mut output, 2, previous);
        Ok(output)
    }

    fn acquire(
        &mut self,
        mode: AcquisitionMode,
        resources: &mut impl TokenResources,
    ) -> Result<(), TokenError> {
        if self.xwid_pending {
            return Ok(());
        }
        self.xwid_pending = true;
        match resources.acquire_xwid(mode) {
            Ok(Some(acquisition)) => self.complete_xwid(acquisition),
            Ok(None) => {}
            Err(error) => {
                self.xwid_pending = false;
                return Err(error);
            }
        }
        Ok(())
    }
}

fn parse_atoi(input: &[u8]) -> i32 {
    let mut remaining = input;
    while remaining
        .first()
        .is_some_and(|byte| matches!(*byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c))
    {
        remaining = &remaining[1..];
    }
    let negative = remaining.first() == Some(&b'-');
    if negative || remaining.first() == Some(&b'+') {
        remaining = &remaining[1..];
    }
    let limit = (i64::MAX as u64) + u64::from(negative);
    let mut magnitude = 0u64;
    for &byte in remaining {
        if !byte.is_ascii_digit() {
            break;
        }
        magnitude = magnitude
            .saturating_mul(10)
            .saturating_add(u64::from(byte - b'0'))
            .min(limit);
    }
    if negative {
        (magnitude as i64).wrapping_neg() as i32
    } else {
        magnitude as i32
    }
}

pub fn encode_report(properties: DeviceProperties, previous_token: &[u8]) -> Vec<u8> {
    let capacity = properties
        .iter()
        .map(|(&id, value)| {
            let length = property_length(id, value);
            if length == 0 {
                0
            } else {
                1 + prost::encoding::encoded_len_varint(length as u64) + length
            }
        })
        .sum::<usize>()
        + encoded_bytes_len(previous_token);
    let mut output = Vec::with_capacity(capacity);
    for (id, value) in properties {
        put_property(id, value, &mut output);
    }
    append_bytes_field(&mut output, 2, previous_token);
    output
}

fn property_length(id: i32, value: &[u8]) -> usize {
    let id = id as u32;
    let id_length = if id == 0 {
        0
    } else {
        1 + prost::encoding::encoded_len_varint(u64::from(id))
    };
    id_length + encoded_bytes_len(value)
}

fn put_property(id: i32, value: Vec<u8>, output: &mut Vec<u8>) {
    let property = DeviceProperty {
        id: id as u32,
        value,
    };

    if property.id != 0 || !property.value.is_empty() {
        prost::encoding::message::encode(1, &property, output);
    }
}

fn put_missing_property(id: i32, output: &mut Vec<u8>) {
    let length = property_length(id, b"-1");
    prost::encoding::encode_key(1, prost::encoding::WireType::LengthDelimited, output);
    prost::encoding::encode_varint(length as u64, output);
    if id != 0 {
        prost::encoding::uint32::encode(1, &(id as u32), output);
    }
    append_bytes_field(output, 2, b"-1");
}

pub fn decode_issued_token(input: &[u8]) -> Result<IssuedToken, TokenError> {
    let mut offset = 0;
    let mut token = IssuedTokenReply::default();
    while offset < input.len() {
        let key = read_varint(input, &mut offset)? as u32;
        let field = key >> 3;
        let wire = key & 7;
        match (field, wire) {
            (1, 2) => {
                let value = read_bytes(input, &mut offset)?;
                token.token.clear();
                token.token.extend_from_slice(value);
            }
            (2, 0) => token.expires_at = read_varint(input, &mut offset)?,
            (_, 0) => {
                read_varint(input, &mut offset)?;
            }
            (_, 1) => advance(input, &mut offset, 8)?,
            (_, 2) => {
                read_bytes(input, &mut offset)?;
            }
            (_, 5) => advance(input, &mut offset, 4)?,
            _ => {
                return Err(TokenError::Protobuf {
                    code: 0x155,
                    offset,
                });
            }
        }
    }
    Ok(IssuedToken {
        bytes: token.token,
        expires_at: token.expires_at as i64,
    })
}

fn read_varint(input: &[u8], offset: &mut usize) -> Result<u64, TokenError> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let byte = *input.get(*offset).ok_or(TokenError::Protobuf {
            code: 0x101,
            offset: *offset,
        })?;
        *offset += 1;
        value |= u64::from(byte & 0x7f).wrapping_shl(shift);
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(TokenError::Protobuf {
        code: 0x102,
        offset: *offset,
    })
}

fn read_bytes<'a>(input: &'a [u8], offset: &mut usize) -> Result<&'a [u8], TokenError> {
    let length = read_varint(input, offset)? as u32 as usize;
    let start = *offset;
    advance(input, offset, length)?;
    Ok(&input[start..*offset])
}

fn advance(input: &[u8], offset: &mut usize, length: usize) -> Result<(), TokenError> {
    let end = offset
        .checked_add(length)
        .filter(|&end| end <= input.len())
        .ok_or(TokenError::Protobuf {
            code: 0x101,
            offset: *offset,
        })?;
    *offset = end;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_uses_nested_property_fields_and_previous_token() {
        let properties = BTreeMap::from([(3, b"xy".to_vec())]);
        assert_eq!(
            encode_report(properties, b"z"),
            b"\x0a\x06\x08\x03\x12\x02xy\x12\x01z",
        );
    }

    #[test]
    fn report_keeps_signed_order_and_omits_only_the_empty_zero_id_entry() {
        use prost::Message;

        let properties = BTreeMap::from([(-1, Vec::new()), (0, Vec::new()), (4, b"live".to_vec())]);
        let packet = encode_report(properties, b"previous");
        let report = crate::proto::TokenReport::decode(packet.as_slice()).unwrap();
        assert_eq!(
            report.properties,
            vec![
                DeviceProperty {
                    id: u32::MAX,
                    value: Vec::new()
                },
                DeviceProperty {
                    id: 4,
                    value: b"live".to_vec()
                },
            ]
        );
        assert_eq!(report.previous_token, b"previous");
    }

    #[test]
    fn genuine_response_boundary_publishes_to_captured_account() {
        let mut state = TokenState::default();
        let response = ReportResponse {
            bytes: b"\x0a\x03abc\x10\x00".to_vec(),
            transport_succeeded: true,
            error_code: 0,
        };
        state.complete_report(b"1234", response).unwrap();
        assert_eq!(
            state.account_token(b"1234"),
            Some(&IssuedToken {
                bytes: b"abc".to_vec(),
                expires_at: 0
            }),
        );
        assert_eq!(
            state.complete_report(
                b"1234",
                ReportResponse {
                    bytes: Vec::new(),
                    transport_succeeded: false,
                    error_code: 999,
                }
            ),
            Err(TokenError::Transport(999)),
        );
        assert_eq!(state.failed_times(), 1);
        assert_eq!(state.account_token(b"1234").unwrap().bytes, b"abc");
    }

    #[test]
    fn xwid_fallback_uses_nine_raw_digest_bytes() {
        let mut state = TokenState::default();
        state.complete_xwid(XwidAcquisition {
            xwid: b"abc".to_vec(),
            auxiliary: b"aux".to_vec(),
            started_at: 42,
            elapsed_nanoseconds: 2_999_999,
        });
        assert_eq!(state.xwid_token, b"kAFQmDzST7DW");
        assert_eq!(state.xwid_timestamp, 42);
        assert_eq!(state.xwid_acquisition_milliseconds(), 2);
        assert_eq!(state.auxiliary(), b"aux");
    }

    #[derive(Default)]
    struct PendingXwidResources {
        now: i64,
        switch: Option<Vec<u8>>,
        reads: usize,
        acquisitions: Vec<AcquisitionMode>,
    }

    impl TokenResources for PendingXwidResources {
        fn unix_seconds(&mut self) -> i64 {
            self.now
        }

        fn persistent_xwid_switch(&mut self) -> Result<Option<&[u8]>, TokenError> {
            self.reads += 1;
            Ok(self.switch.as_deref())
        }

        fn acquire_xwid(
            &mut self,
            mode: AcquisitionMode,
        ) -> Result<Option<XwidAcquisition>, TokenError> {
            self.acquisitions.push(mode);
            Ok(None)
        }

        fn collect_properties(&mut self) -> Result<DeviceProperties, TokenError> {
            panic!("disabled token reporting must not collect properties")
        }

        fn send_report(
            &mut self,
            _: &str,
            _: &[u8],
            _: &[u8],
        ) -> Result<ReportDelivery, TokenError> {
            panic!("disabled token reporting must not send reports")
        }
    }

    #[test]
    fn persistent_switch_publishes_sdk_default_and_atoi_values() {
        for (value, selector) in [
            (None, 1),
            (Some(&b""[..]), 1),
            (Some(&b"-1"[..]), 1),
            (Some(&b" \x0b+1tail"[..]), 1),
            (Some(&b"0"[..]), 0),
            (Some(&b"invalid"[..]), 0),
            (Some(&b"2"[..]), 2),
        ] {
            let mut state = TokenState::default();
            state.initialize_xwid_switch(value);
            assert_eq!(state.xwid_selector(), selector);
            assert_eq!(state.policy.xwid_enabled, selector == 1);
        }
    }

    #[test]
    fn selector_two_remains_lazy_and_other_values_are_cached() {
        let mut state = TokenState::default();
        state.policy.token_enabled = false;
        let mut resources = PendingXwidResources {
            switch: Some(b"2".to_vec()),
            ..Default::default()
        };
        state.token(b"1234", &mut resources).unwrap();
        assert_eq!(state.xwid_selector(), 2);
        resources.switch = None;
        state.token(b"1234", &mut resources).unwrap();
        state.token(b"1234", &mut resources).unwrap();
        assert_eq!(resources.reads, 2);
        assert_eq!(resources.acquisitions, [AcquisitionMode::ColdOrExpired]);
    }

    #[test]
    fn refresh_window_and_expiry_do_not_copy_cached_fallback() {
        for (age, expected_mode) in [
            (3480, None),
            (3481, Some(AcquisitionMode::RefreshWindow)),
            (3600, Some(AcquisitionMode::RefreshWindow)),
            (3601, Some(AcquisitionMode::ColdOrExpired)),
        ] {
            let mut state = TokenState::default();
            state.initialize_xwid_switch(None);
            state.policy.token_enabled = false;
            state.complete_xwid(XwidAcquisition {
                xwid: b"abc".to_vec(),
                auxiliary: Vec::new(),
                started_at: 0,
                elapsed_nanoseconds: 0,
            });
            let mut resources = PendingXwidResources {
                now: age,
                ..Default::default()
            };
            let read = state.token(b"1234", &mut resources).unwrap();
            if let Some(mode) = expected_mode {
                assert!(read.bytes.is_empty());
                assert_eq!(resources.acquisitions, [mode]);
                state.token(b"1234", &mut resources).unwrap();
                assert_eq!(resources.acquisitions.len(), 1);
            } else {
                assert_eq!(read.bytes, b"kAFQmDzST7DW");
                assert!(resources.acquisitions.is_empty());
            }
        }
    }

    #[test]
    fn malformed_response_does_not_issue_a_token() {
        assert!(matches!(
            decode_issued_token(b"\x0a\x04a"),
            Err(TokenError::Protobuf { code: 0x101, .. }),
        ));
        assert!(matches!(
            decode_issued_token(&[0x80; 10]),
            Err(TokenError::Protobuf { code: 0x102, .. }),
        ));
    }

    #[derive(Default)]
    struct ReportResources {
        now: i64,
        packets: Vec<Vec<u8>>,
        response: Option<ReportResponse>,
    }

    impl TokenResources for ReportResources {
        fn unix_seconds(&mut self) -> i64 {
            self.now
        }

        fn persistent_xwid_switch(&mut self) -> Result<Option<&[u8]>, TokenError> {
            Ok(Some(b"0"))
        }

        fn acquire_xwid(
            &mut self,
            _: AcquisitionMode,
        ) -> Result<Option<XwidAcquisition>, TokenError> {
            panic!("fresh companion cache must not acquire xwid")
        }

        fn collect_properties(&mut self) -> Result<DeviceProperties, TokenError> {
            Ok(DeviceProperties::new())
        }

        fn send_report(
            &mut self,
            _: &str,
            _: &[u8],
            packet: &[u8],
        ) -> Result<ReportDelivery, TokenError> {
            self.packets.push(packet.to_vec());
            Ok(match self.response.take() {
                Some(response) => ReportDelivery::Complete(response),
                None => ReportDelivery::Pending,
            })
        }
    }

    #[test]
    fn empty_issued_token_preserves_cache_and_completes_refresh() {
        use prost::Message;

        const NOW: i64 = 1_700_000_000;
        for had_token in [false, true] {
            for expiry in [0, NOW as u64 + 7200] {
                let mut state = TokenState::default();
                let mut resources = ReportResources {
                    now: NOW,
                    ..Default::default()
                };
                state.change_account(b"1234", &mut resources).unwrap();
                if had_token {
                    state
                        .complete_report(
                            b"1234",
                            ReportResponse {
                                bytes: IssuedTokenReply {
                                    token: b"still-valid".to_vec(),
                                    expires_at: NOW as u64 + 3600,
                                }
                                .encode_to_vec(),
                                transport_succeeded: true,
                                error_code: 0,
                            },
                        )
                        .unwrap();
                }
                let _ = state.complete_report(
                    b"1234",
                    ReportResponse {
                        bytes: Vec::new(),
                        transport_succeeded: false,
                        error_code: 999,
                    },
                );
                state.refresh_active_account(&mut resources).unwrap();
                assert!(state.report_pending());
                state
                    .complete_report(
                        b"1234",
                        ReportResponse {
                            bytes: IssuedTokenReply {
                                token: Vec::new(),
                                expires_at: expiry,
                            }
                            .encode_to_vec(),
                            transport_succeeded: true,
                            error_code: 0,
                        },
                    )
                    .unwrap();
                assert!(!state.report_pending());
                assert_eq!(state.failed_times(), 0);
                if had_token {
                    assert_eq!(
                        state.account_token(b"1234"),
                        Some(&IssuedToken {
                            bytes: b"still-valid".to_vec(),
                            expires_at: NOW + 3600,
                        })
                    );
                    assert_eq!(
                        state.token(b"1234", &mut resources).unwrap().bytes,
                        b"still-valid"
                    );
                } else {
                    assert!(state.account_token(b"1234").is_none());
                    assert!(
                        state
                            .token(b"1234", &mut resources)
                            .unwrap()
                            .bytes
                            .is_empty()
                    );
                }
            }
        }
    }

    #[test]
    fn token_expiry_and_refresh_margin_have_distinct_strict_boundaries() {
        const NOW: i64 = 1_700_000_000;
        for remaining in [-1, 0, 1, 299, 300] {
            let mut state = TokenState::default();
            state.initialize_xwid_switch(None);
            state.active_account = b"1234".to_vec();
            state.complete_xwid(XwidAcquisition {
                xwid: b"abc".to_vec(),
                auxiliary: Vec::new(),
                started_at: NOW,
                elapsed_nanoseconds: 0,
            });
            state.account_tokens.insert(
                b"1234".to_vec(),
                IssuedToken {
                    bytes: b"server".to_vec(),
                    expires_at: NOW + remaining,
                },
            );
            let mut resources = ReportResources {
                now: NOW,
                ..Default::default()
            };
            let selected = state.token(b"1234", &mut resources).unwrap();
            assert_eq!(
                selected.bytes,
                if remaining > 0 {
                    &b"server"[..]
                } else {
                    &b"kAFQmDzST7DW"[..]
                },
                "remaining={remaining}",
            );
            assert_eq!(state.report_pending(), remaining < 300);
            assert_eq!(resources.packets.len(), usize::from(remaining < 300));
            if remaining < 300 {
                assert_eq!(resources.packets[0], b"\x12\x06server");
            }
            assert_eq!(state.account_token(b"1234").unwrap().bytes, b"server");
        }
    }

    #[test]
    fn polling_refreshes_at_server_margin_without_sign_calls_or_pending_retries() {
        const NOW: i64 = 1_700_000_000;
        let mut state = TokenState::default();
        state.active_account = b"1234".to_vec();
        state.account_tokens.insert(
            b"1234".to_vec(),
            IssuedToken {
                bytes: b"server".to_vec(),
                expires_at: NOW + 3600,
            },
        );
        let mut resources = ReportResources {
            now: NOW + 3300,
            ..Default::default()
        };
        state.poll(b"1234", &mut resources).unwrap();
        assert!(!state.report_pending());
        assert!(resources.packets.is_empty());
        resources.now = NOW + 3301;
        state.poll(b"1234", &mut resources).unwrap();
        assert!(state.report_pending());
        resources.now += 10;
        state.poll(b"1234", &mut resources).unwrap();
        assert_eq!(resources.packets.len(), 1);
        assert_eq!(
            state.complete_report(
                b"1234",
                ReportResponse {
                    bytes: Vec::new(),
                    transport_succeeded: false,
                    error_code: 999,
                }
            ),
            Err(TokenError::Transport(999))
        );
        resources.now = NOW + 3360;
        state.poll(b"1234", &mut resources).unwrap();
        assert!(!state.report_pending());
        assert_eq!(resources.packets.len(), 1);
        resources.now += 1;
        state.poll(b"1234", &mut resources).unwrap();
        assert!(state.report_pending());
        assert_eq!(resources.packets.len(), 2);
        let report: crate::proto::TokenReport =
            prost::Message::decode(resources.packets[1].as_slice()).unwrap();
        assert_eq!(report.previous_token, b"server");
        assert_eq!(state.account_token(b"1234").unwrap().bytes, b"server");
    }

    #[test]
    fn synchronous_refresh_publishes_only_for_the_next_token_read() {
        for (expiry, expected) in [(0, &b""[..]), (101, &b"old"[..])] {
            let mut state = TokenState::default();
            state.initialize_xwid_switch(Some(b"0"));
            state.active_account = b"1234".to_vec();
            state.account_tokens.insert(
                b"1234".to_vec(),
                IssuedToken {
                    bytes: b"old".to_vec(),
                    expires_at: expiry,
                },
            );
            let mut resources = ReportResources {
                now: 100,
                response: Some(ReportResponse {
                    bytes: b"\x0a\x03new\x10\x90\x03".to_vec(),
                    transport_succeeded: true,
                    error_code: 0,
                }),
                ..Default::default()
            };
            assert_eq!(
                state.token(b"1234", &mut resources).unwrap().bytes,
                expected
            );
            assert_eq!(resources.packets, [b"\x12\x03old".to_vec()]);
            assert!(!state.report_pending());
            assert_eq!(state.token(b"1234", &mut resources).unwrap().bytes, b"new");
            assert_eq!(resources.packets.len(), 1);
        }
    }
}
