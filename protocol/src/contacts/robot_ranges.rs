use crate::{Error, Result, proto::robot_ranges as pb};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

pub(crate) const COMMAND: &str = "OidbSvcTrpcTcp.0x496_0";
const MAX_CACHE_AGE_MS: u64 = 259_200_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RobotUinRange {
    pub min_uin: u64,
    pub max_uin: u64,
}

impl RobotUinRange {
    pub fn contains(&self, uin: u64) -> bool {
        self.min_uin <= uin && uin <= self.max_uin
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RobotUinRangesSnapshot {
    pub version: u32,
    pub ranges: Vec<RobotUinRange>,
    pub received_unix_ms: u64,
}

impl RobotUinRangesSnapshot {
    pub fn is_robot_uin(&self, uin: u64) -> bool {
        self.ranges.iter().any(|range| range.contains(uin))
    }

    pub fn needs_refresh(&self, now_unix_ms: u64) -> bool {
        now_unix_ms.wrapping_sub(self.received_unix_ms) > MAX_CACHE_AGE_MS
    }

    fn validate(&self) -> Result<()> {
        if self.ranges.is_empty()
            || self
                .ranges
                .iter()
                .any(|range| range.min_uin > range.max_uin)
        {
            return Err(Error::Malformed("Invalid robot UIN range cache".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RobotUinRangesCache {
    pub account_uin: u64,
    pub account_uid: String,
    pub snapshot: RobotUinRangesSnapshot,
}

pub(crate) struct Binding {
    pub(crate) generation: u64,
    pub(crate) account_uin: u64,
    pub(crate) account_uid: String,
    pub(crate) cancel: CancellationToken,
}

pub(crate) struct State {
    account: Option<(u64, String)>,
    snapshot: Option<Arc<RobotUinRangesSnapshot>>,
    binding: Option<Arc<Binding>>,
    changed: watch::Sender<()>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            account: None,
            snapshot: None,
            binding: None,
            changed: watch::channel(()).0,
        }
    }
}

impl State {
    pub(crate) fn clear(&mut self) {
        if let Some(binding) = self.binding.take() {
            binding.cancel.cancel();
        }
        self.account = None;
        self.snapshot = None;
        self.changed.send_replace(());
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<()> {
        self.changed.subscribe()
    }

    pub(crate) fn snapshot(&self, uin: u64, uid: &str) -> Option<Arc<RobotUinRangesSnapshot>> {
        self.account
            .as_ref()
            .filter(|account| account.0 == uin && account.1 == uid)?;
        self.snapshot.clone()
    }

    pub(crate) fn cache(&self, uin: u64, uid: &str) -> Option<RobotUinRangesCache> {
        Some(RobotUinRangesCache {
            account_uin: uin,
            account_uid: uid.to_owned(),
            snapshot: self.snapshot(uin, uid)?.as_ref().clone(),
        })
    }

    pub(crate) fn restore(
        &mut self,
        cache: RobotUinRangesCache,
        uin: u64,
        uid: &str,
    ) -> Result<()> {
        if uin == 0 || uid.is_empty() || cache.account_uin != uin || cache.account_uid != uid {
            return Err(Error::Authentication(
                "Robot range cache belongs to another account".into(),
            ));
        }
        cache.snapshot.validate()?;
        self.clear();
        self.account = Some((uin, cache.account_uid));
        self.snapshot = Some(Arc::new(cache.snapshot));
        self.changed.send_replace(());
        Ok(())
    }

    pub(crate) fn begin(
        &mut self,
        generation: u64,
        uin: u64,
        uid: &str,
        cancel: &CancellationToken,
    ) -> Arc<Binding> {
        if self
            .account
            .as_ref()
            .is_none_or(|account| account.0 != uin || account.1 != uid)
        {
            self.clear();
            self.account = Some((uin, uid.to_owned()));
        }
        if let Some(previous) = self.binding.take() {
            previous.cancel.cancel();
        }
        let binding = Arc::new(Binding {
            generation,
            account_uin: uin,
            account_uid: uid.to_owned(),
            cancel: cancel.child_token(),
        });
        self.binding = Some(binding.clone());
        binding
    }

    pub(crate) fn current(&self, binding: &Arc<Binding>) -> bool {
        !binding.cancel.is_cancelled()
            && self
                .binding
                .as_ref()
                .is_some_and(|active| Arc::ptr_eq(active, binding))
    }

    pub(crate) fn request(&self, now_unix_ms: u64) -> Option<pb::RobotUinRangeRequest> {
        if self
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| !snapshot.needs_refresh(now_unix_ms))
        {
            return None;
        }
        Some(pb::RobotUinRangeRequest {
            just_fetch_msg_config: Some(1),
            r#type: Some(1),
            version: Some(
                self.snapshot
                    .as_ref()
                    .filter(|snapshot| snapshot.received_unix_ms != 0)
                    .map_or(0, |snapshot| snapshot.version),
            ),
            aio_keyword_version: Some(0),
        })
    }

    pub(crate) fn apply(
        &mut self,
        binding: &Arc<Binding>,
        response: pb::RobotUinRangeResponse,
        now_unix_ms: u64,
    ) -> Result<Arc<RobotUinRangesSnapshot>> {
        if !self.current(binding) {
            return Err(Error::Disconnected);
        }
        let config = response
            .robot_config
            .ok_or_else(|| Error::Malformed("Robot range response has no configuration".into()))?;
        let version = config
            .version
            .ok_or_else(|| Error::Malformed("Robot range response has no version".into()))?;
        let ranges = config
            .ranges
            .into_iter()
            .map(|range| {
                let min_uin = range
                    .min_uin
                    .ok_or_else(|| Error::Malformed("Robot range has no lower bound".into()))?;
                let max_uin = range
                    .max_uin
                    .ok_or_else(|| Error::Malformed("Robot range has no upper bound".into()))?;
                Ok(RobotUinRange { min_uin, max_uin })
            })
            .collect::<Result<Vec<_>>>()?;
        let snapshot = RobotUinRangesSnapshot {
            version,
            ranges,
            received_unix_ms: now_unix_ms,
        };
        snapshot.validate()?;
        let snapshot = Arc::new(snapshot);
        self.snapshot = Some(snapshot.clone());
        self.changed.send_replace(());
        Ok(snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(time: u64) -> RobotUinRangesSnapshot {
        RobotUinRangesSnapshot {
            version: 17,
            received_unix_ms: time,
            ranges: vec![
                RobotUinRange {
                    min_uin: 0,
                    max_uin: 0,
                },
                RobotUinRange {
                    min_uin: 100,
                    max_uin: 200,
                },
                RobotUinRange {
                    min_uin: u32::MAX as u64 + 1,
                    max_uin: u64::MAX,
                },
            ],
        }
    }

    fn restore(state: &mut State, time: u64) {
        state
            .restore(
                RobotUinRangesCache {
                    account_uin: 42,
                    account_uid: "u_test".into(),
                    snapshot: snapshot(time),
                },
                42,
                "u_test",
            )
            .unwrap();
    }

    fn response(
        version: Option<u32>,
        min: Option<u64>,
        max: Option<u64>,
    ) -> pb::RobotUinRangeResponse {
        pb::RobotUinRangeResponse {
            robot_config: Some(pb::RobotUinRangeConfig {
                version,
                ranges: vec![pb::RobotUinRange {
                    min_uin: min,
                    max_uin: max,
                }],
            }),
        }
    }

    #[test]
    fn inclusive_endpoints_and_full_width_ranges_are_preserved() {
        let snapshot = snapshot(1);
        for uin in [0, 100, 150, 200, u32::MAX as u64 + 1, u64::MAX] {
            assert!(snapshot.is_robot_uin(uin));
        }
        for uin in [1, 99, 201, u32::MAX as u64] {
            assert!(!snapshot.is_robot_uin(uin));
        }
    }

    #[test]
    fn cache_age_uses_strict_native_millisecond_boundary_and_version() {
        let mut state = State::default();
        assert_eq!(state.request(1).unwrap().version, Some(0));
        restore(&mut state, 1000);
        assert!(state.request(1000 + MAX_CACHE_AGE_MS).is_none());
        let request = state.request(1001 + MAX_CACHE_AGE_MS).unwrap();
        assert_eq!(request.version, Some(17));
        assert_eq!(request.just_fetch_msg_config, Some(1));
        assert_eq!(request.r#type, Some(1));
        assert_eq!(request.aio_keyword_version, Some(0));
        assert!(state.request(999).is_some());
        restore(&mut state, 0);
        assert_eq!(
            state.request(MAX_CACHE_AGE_MS + 1).unwrap().version,
            Some(0)
        );
    }

    #[test]
    fn bad_cache_and_bad_responses_preserve_valid_version_and_ranges() {
        let mut state = State::default();
        restore(&mut state, 1000);
        let before = state.snapshot(42, "u_test").unwrap();
        let mut cache = state.cache(42, "u_test").unwrap();
        cache.snapshot.ranges.clear();
        assert!(state.restore(cache, 42, "u_test").is_err());
        let binding = state.begin(7, 42, "u_test", &CancellationToken::new());
        for response in [
            pb::RobotUinRangeResponse::default(),
            pb::RobotUinRangeResponse {
                robot_config: Some(pb::RobotUinRangeConfig {
                    version: Some(18),
                    ranges: Vec::new(),
                }),
            },
            response(None, Some(100), Some(200)),
            response(Some(18), None, Some(200)),
            response(Some(18), Some(200), Some(100)),
        ] {
            assert!(state.apply(&binding, response, 2000).is_err());
            assert!(Arc::ptr_eq(&before, &state.snapshot(42, "u_test").unwrap()));
        }
        let updated = state
            .apply(&binding, response(Some(0), Some(7), Some(9)), 2001)
            .unwrap();
        assert_eq!(updated.version, 0);
        assert!(updated.is_robot_uin(7));
        assert!(!updated.is_robot_uin(100));
    }

    #[test]
    fn cancelled_rebound_and_account_aba_scopes_cannot_publish() {
        let mut state = State::default();
        restore(&mut state, 1000);
        let cancel = CancellationToken::new();
        let first = state.begin(7, 42, "u_test", &cancel);
        cancel.cancel();
        assert!(matches!(
            state.apply(&first, response(Some(18), Some(7), Some(9)), 2000),
            Err(Error::Disconnected)
        ));
        let old = state.begin(7, 42, "u_test", &CancellationToken::new());
        let current = state.begin(8, 42, "u_test", &CancellationToken::new());
        assert!(matches!(
            state.apply(&old, response(Some(18), Some(7), Some(9)), 2000),
            Err(Error::Disconnected)
        ));
        state.begin(8, 99, "u_other", &CancellationToken::new());
        state.begin(8, 42, "u_test", &CancellationToken::new());
        assert!(matches!(
            state.apply(&current, response(Some(18), Some(7), Some(9)), 2000),
            Err(Error::Disconnected)
        ));
        assert!(state.snapshot(42, "u_test").is_none());
    }
}
