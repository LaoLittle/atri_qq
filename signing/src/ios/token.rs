use bytes::Bytes;
use prost::Message;
use serde::{Deserialize, Serialize};

pub use super::proto::{
    DevicePropertyId, DeviceTokenItem, DeviceTokenRequest, DeviceTokenResponse,
};
pub use super::token_payload::NativePayloadResources;

pub const TOKEN_BUSINESS: &str = "getToken";
pub const TOKEN_PERSISTENCE_PREFIX: &str = "dtck_20260129_";
pub const PROACTIVE_REFRESH_SECONDS: u64 = 300;
pub const RETRY_BASE_SECONDS: u64 = 60;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRecord {
    pub expires_at: u64,
    pub token: Bytes,
    pub associated_uin: String,
}

impl TokenRecord {
    pub fn is_valid_at(&self, now: u64) -> bool {
        !self.token.is_empty() && self.expires_at > now
    }
    pub fn signing_token_at(&self, now: u64) -> Bytes {
        if self.is_valid_at(now) {
            self.token.clone()
        } else {
            Bytes::new()
        }
    }

    pub fn needs_refresh_at(&self, now: u64, core_current_uin: &str) -> bool {
        !self.is_valid_at(now)
            || self.expires_at.saturating_sub(now) < PROACTIVE_REFRESH_SECONDS
            || (is_account(core_current_uin) && core_current_uin != self.associated_uin)
    }

    pub fn persistence_entry(&self) -> TokenPersistence {
        let expiry = self.expires_at.to_string();
        let mut value =
            Vec::with_capacity(expiry.len() + self.token.len() + self.associated_uin.len() + 2);
        value.extend_from_slice(expiry.as_bytes());
        value.push(b'|');
        value.extend_from_slice(&self.token);
        value.push(b'|');
        value.extend_from_slice(self.associated_uin.as_bytes());
        TokenPersistence {
            key: format!("{TOKEN_PERSISTENCE_PREFIX}{}", self.associated_uin),
            value: value.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenPersistence {
    pub key: String,
    pub value: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenRefresh {
    pub previous_token: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenSubmission {
    pub request_uin: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativePayload {
    Disabled,
    Encoded(Bytes),
    Generate(NativePayloadResources),
}

impl TokenRefresh {
    pub fn build_request<'a>(
        &self,
        items: impl IntoIterator<Item = (&'a i32, &'a Bytes)>,
        native_payload: NativePayload,
    ) -> DeviceTokenRequest {
        let mut request = DeviceTokenRequest {
            items: items
                .into_iter()
                .map(|(&id, data)| DeviceTokenItem {
                    id,
                    data: data.clone(),
                })
                .collect(),
            previous_token: self.previous_token.clone(),
            native_payload: Bytes::new(),
        };
        request.native_payload = match native_payload {
            NativePayload::Disabled => Bytes::new(),
            NativePayload::Encoded(payload) => payload,
            NativePayload::Generate(resources) => resources.encode(&request.items),
        };
        request
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningTokenSnapshot {
    pub record: TokenRecord,
    pub token: Bytes,
    pub refresh_started: bool,
}

#[derive(Debug)]
pub struct TokenState {
    record: TokenRecord,
    current_uin: String,
    collecting: bool,
    failure_count: u32,
    last_request_time: u64,
}

impl Default for TokenState {
    fn default() -> Self {
        Self {
            record: TokenRecord::default(),
            current_uin: "0".into(),
            collecting: false,
            failure_count: 0,
            last_request_time: 0,
        }
    }
}

impl TokenState {
    pub fn record(&self) -> &TokenRecord {
        &self.record
    }
    pub fn current_uin(&self) -> &str {
        &self.current_uin
    }
    pub fn is_collecting(&self) -> bool {
        self.collecting
    }
    pub fn failure_count(&self) -> u32 {
        self.failure_count
    }
    pub fn last_request_time(&self) -> u64 {
        self.last_request_time
    }

    pub fn restore_record(&mut self, record: TokenRecord) {
        self.record = record;
    }

    pub fn update_account(&mut self, uin: impl Into<String>) -> bool {
        let uin = uin.into();
        if uin == self.current_uin || (!is_account(&uin) && !is_account(&self.current_uin)) {
            return false;
        }
        self.current_uin = uin;
        self.collecting = false;
        self.last_request_time = 0;
        true
    }

    pub fn retry_delay_seconds(&self) -> u64 {
        RETRY_BASE_SECONDS * (1u64 << (self.failure_count % 5))
    }

    pub fn begin_refresh(&mut self, now: u64, force: bool) -> bool {
        if self.collecting
            || (!force && now.saturating_sub(self.last_request_time) < self.retry_delay_seconds())
        {
            return false;
        }
        self.collecting = true;
        self.last_request_time = now;
        true
    }

    pub fn capture_request(&self) -> TokenRefresh {
        TokenRefresh {
            previous_token: self.record.token.clone(),
        }
    }

    pub fn capture_submission(&self) -> TokenSubmission {
        TokenSubmission {
            request_uin: self.current_uin.clone(),
        }
    }

    pub fn snapshot_for_signing(
        &mut self,
        now: u64,
        core_current_uin: &str,
    ) -> SigningTokenSnapshot {
        let record = self.record.clone();
        let refresh_started =
            record.needs_refresh_at(now, core_current_uin) && self.begin_refresh(now, false);
        SigningTokenSnapshot {
            token: record.signing_token_at(now),
            record,
            refresh_started,
        }
    }

    pub fn collection_worker_exited(&mut self) {
        self.collecting = false;
    }

    pub fn commit_failure(&mut self) {
        self.failure_count = self.failure_count.wrapping_add(1);
    }

    pub fn commit_success(
        &mut self,
        request: &TokenSubmission,
        response: DeviceTokenResponse,
    ) -> Option<TokenPersistence> {
        self.failure_count = 0;
        if response.token.is_empty() {
            return None;
        }
        self.record = TokenRecord {
            expires_at: response.expires_at,
            token: response.token,
            associated_uin: request.request_uin.clone(),
        };
        Some(self.record.persistence_entry())
    }

    pub fn commit_response_bytes(
        &mut self,
        request: &TokenSubmission,
        response: Bytes,
    ) -> Result<Option<TokenPersistence>, prost::DecodeError> {
        match DeviceTokenResponse::decode(response) {
            Ok(response) => Ok(self.commit_success(request, response)),
            Err(error) => {
                self.commit_failure();
                Err(error)
            }
        }
    }
}

fn is_account(uin: &str) -> bool {
    !uin.is_empty() && uin != "0"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn record(expiry: u64) -> TokenRecord {
        TokenRecord {
            expires_at: expiry,
            token: Bytes::from_static(b"old"),
            associated_uin: "1".into(),
        }
    }

    #[test]
    fn signing_snapshot_omits_expired_token_without_erasing_refresh_material() {
        let mut state = TokenState::default();
        state.restore_record(record(100));
        let expired = state.snapshot_for_signing(100, "1");
        assert!(expired.token.is_empty());
        assert!(expired.refresh_started);
        assert_eq!(expired.record.token.as_ref(), b"old");
        assert_eq!(state.capture_request().previous_token.as_ref(), b"old");
        state.collection_worker_exited();
        state.restore_record(record(400));
        let valid = state.snapshot_for_signing(100, "1");
        assert_eq!(valid.token.as_ref(), b"old");
        assert!(!valid.refresh_started);
        assert_eq!(state.record().expires_at, 400);
    }

    #[test]
    fn expiry_margin_and_snapshot_are_exact() {
        assert!(record(400).is_valid_at(399));
        assert!(!record(400).is_valid_at(400));
        assert!(!record(400).needs_refresh_at(100, "1"));
        assert!(record(400).needs_refresh_at(101, "1"));
        assert!(record(400).needs_refresh_at(100, "2"));
        let mut state = TokenState::default();
        state.restore_record(record(99));
        let snapshot = state.snapshot_for_signing(100, "1");
        assert_eq!(snapshot.record.token, Bytes::from_static(b"old"));
        assert!(snapshot.refresh_started);
    }

    #[test]
    fn force_backoff_and_worker_exit_are_separate_from_response() {
        let mut state = TokenState::default();
        assert!(!state.begin_refresh(59, false));
        assert!(state.begin_refresh(60, false));
        let request = state.capture_submission();
        assert!(!state.begin_refresh(61, true));
        state.commit_failure();
        assert!(state.is_collecting());
        state.collection_worker_exited();
        assert!(!state.begin_refresh(179, false));
        assert!(state.begin_refresh(180, false));
        state.collection_worker_exited();
        for expected in [240, 480, 960, 60] {
            state.commit_failure();
            assert_eq!(state.retry_delay_seconds(), expected);
        }
        assert!(state.begin_refresh(181, true));
        state.commit_success(&request, DeviceTokenResponse::default());
        assert_eq!(state.failure_count(), 0);
        assert!(state.is_collecting());
    }

    #[test]
    fn account_change_keeps_old_token_and_accepts_captured_account() {
        let mut state = TokenState::default();
        assert!(!state.update_account(""));
        state.update_account("1");
        state.restore_record(record(200));
        assert!(state.begin_refresh(100, false));
        let request = state.capture_submission();
        state.commit_failure();
        assert!(!state.update_account("1"));
        assert!(state.is_collecting());
        assert!(state.update_account("2"));
        assert!(!state.is_collecting());
        assert_eq!(state.last_request_time(), 0);
        assert_eq!(state.failure_count(), 1);
        assert_eq!(state.record().token, Bytes::from_static(b"old"));
        let persistence = state
            .commit_success(
                &request,
                DeviceTokenResponse {
                    token: Bytes::from_static(b"new\xff|token"),
                    expires_at: 500,
                },
            )
            .unwrap();
        assert_eq!(state.record().associated_uin, "1");
        assert_eq!(persistence.key, "dtck_20260129_1");
        assert_eq!(persistence.value.as_ref(), b"500|new\xff|token|1");
        assert!(
            state
                .commit_success(&request, DeviceTokenResponse::default())
                .is_none()
        );
        assert_eq!(state.record().token, Bytes::from_static(b"new\xff|token"));
    }

    #[test]
    fn callback_account_is_captured_after_collection_not_at_reservation() {
        let mut state = TokenState::default();
        state.update_account("1");
        state.restore_record(record(500));
        assert!(state.begin_refresh(100, false));
        let construction = state.capture_request();
        state.update_account("2");
        let encoded = construction
            .build_request(&BTreeMap::new(), NativePayload::Disabled)
            .encode_to_vec();
        let submission = state.capture_submission();
        assert!(!encoded.is_empty());
        assert_eq!(submission.request_uin, "2");
        state.update_account("3");
        state.commit_success(
            &submission,
            DeviceTokenResponse {
                token: Bytes::from_static(b"server"),
                expires_at: 900,
            },
        );
        assert_eq!(state.record().associated_uin, "2");
    }

    #[test]
    fn malformed_response_counts_failure_without_destroying_old_record() {
        let mut state = TokenState::default();
        state.restore_record(record(500));
        let submission = state.capture_submission();
        assert!(
            state
                .commit_response_bytes(&submission, Bytes::from_static(b"\x0a\x05x"))
                .is_err()
        );
        assert_eq!(state.failure_count(), 1);
        assert_eq!(state.record(), &record(500));
    }
}
