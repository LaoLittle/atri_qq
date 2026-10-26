use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use md5::{Digest, Md5};

pub const KEYCHAIN_SERVICE: &str = "com.tencent.o3token.xw";
pub const KEYCHAIN_ACCOUNT: &str = "com.tencent.o3token.xw.L2";
pub const DEFAULT_TTL_SECONDS: u64 = 14_400;

pub fn derive_xwid(raw_xwid: &[u8]) -> [u8; 12] {
    let digest = Md5::digest(raw_xwid);
    let mut output = [0; 12];
    STANDARD
        .encode_slice(&digest[..9], &mut output)
        .expect("nine input bytes encode to exactly twelve Base64 bytes");
    output
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct XwidGeneration {
    pub x: Bytes,
    pub f1: Bytes,
    pub f2: Bytes,
    pub v: Bytes,
    pub t: Bytes,
}

#[derive(Debug)]
pub struct XwidProviderCache {
    tuple: Option<XwidGeneration>,
    timestamp: u64,
    ttl_seconds: u64,
}

impl Default for XwidProviderCache {
    fn default() -> Self {
        Self::new(DEFAULT_TTL_SECONDS)
    }
}

impl XwidProviderCache {
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            tuple: None,
            timestamp: 0,
            ttl_seconds,
        }
    }

    pub fn cached_tuple(&self) -> Option<&XwidGeneration> {
        self.tuple.as_ref()
    }
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
    pub fn ttl_seconds(&self) -> u64 {
        self.ttl_seconds
    }

    pub fn is_valid_at(&self, now: u64) -> bool {
        self.tuple.as_ref().is_some_and(|tuple| !tuple.x.is_empty())
            && self.timestamp != 0
            && now.saturating_sub(self.timestamp) < self.ttl_seconds
    }

    pub fn publish_generation(&mut self, tuple: XwidGeneration, generated_at: u64) -> bool {
        if tuple.x.is_empty() {
            return false;
        }
        self.tuple = Some(tuple);
        self.timestamp = generated_at;
        true
    }

    pub fn get_or_generate<F>(&mut self, now: u64, generate: F) -> Option<&XwidGeneration>
    where
        F: FnOnce() -> Option<XwidGeneration>,
    {
        if !self.is_valid_at(now) {
            if let Some(tuple) = generate() {
                self.publish_generation(tuple, now);
            }
        }
        self.cached_tuple()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct XwidSnapshot {
    pub raw: Bytes,
    pub derived: Option<[u8; 12]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XwidGenerationMode {
    Queued,
    Synchronous,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XwidLookup {
    pub snapshot: XwidSnapshot,
    pub generation: Option<XwidGenerationMode>,
}

#[derive(Debug, Default)]
pub struct XwidManager {
    snapshot: XwidSnapshot,
    timestamp: u64,
    generating: bool,
    cache_attempted: bool,
    cache_loaded: bool,
}

impl XwidManager {
    pub fn snapshot(&self) -> XwidSnapshot {
        self.snapshot.clone()
    }
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
    pub fn is_generating(&self) -> bool {
        self.generating
    }
    pub fn cache_attempted(&self) -> bool {
        self.cache_attempted
    }
    pub fn cache_loaded(&self) -> bool {
        self.cache_loaded
    }

    pub fn needs_generation_at(&self, now: u64) -> bool {
        self.snapshot.raw.is_empty()
            || (self.timestamp != 0 && now.saturating_sub(self.timestamp) > DEFAULT_TTL_SECONDS)
    }

    pub fn lookup<F>(
        &mut self,
        now: u64,
        enabled: bool,
        synchronous_when_missing: bool,
        load_cache: F,
    ) -> XwidLookup
    where
        F: FnOnce() -> Option<Bytes>,
    {
        let mut generation = None;
        if enabled && !self.generating && self.needs_generation_at(now) {
            if !self.cache_attempted {
                self.cache_attempted = true;
                if let Some(raw) = load_cache().filter(|raw| !raw.is_empty()) {
                    self.publish_raw(raw, now);
                    self.cache_loaded = true;
                }
            }
            self.generating = true;
            generation = Some(
                if !self.cache_loaded && self.snapshot.raw.is_empty() && synchronous_when_missing {
                    XwidGenerationMode::Synchronous
                } else {
                    XwidGenerationMode::Queued
                },
            );
        }
        XwidLookup {
            snapshot: self.snapshot(),
            generation,
        }
    }

    pub fn finish_generation(&mut self, raw: Option<Bytes>, started_at: u64) -> bool {
        let published = match raw.filter(|raw| !raw.is_empty()) {
            Some(raw) => {
                self.publish_raw(raw, started_at);
                true
            }
            None => false,
        };
        self.generating = false;
        published
    }

    pub fn publish_legitimate_raw(&mut self, raw: Bytes, observed_at: u64) -> bool {
        if raw.is_empty() {
            return false;
        }
        self.publish_raw(raw, observed_at);
        true
    }

    fn publish_raw(&mut self, raw: Bytes, timestamp: u64) {
        self.snapshot.derived = Some(derive_xwid(&raw));
        self.snapshot.raw = raw;
        self.timestamp = timestamp;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple(raw: &'static [u8]) -> XwidGeneration {
        XwidGeneration {
            x: Bytes::from_static(raw),
            f1: Bytes::from_static(b"F1"),
            f2: Bytes::from_static(b"F2"),
            v: Bytes::from_static(b"V"),
            t: Bytes::from_static(b"T"),
        }
    }

    #[test]
    fn derivative_uses_first_nine_digest_bytes_and_standard_base64() {
        assert_eq!(&derive_xwid(b"abc"), b"kAFQmDzST7DW");
        assert_eq!(&derive_xwid(b""), b"1B2M2Y8AsgTp");
    }

    #[test]
    fn cache_boundaries_are_intentionally_different() {
        let mut provider = XwidProviderCache::default();
        provider.publish_generation(tuple(b"real"), 10);
        assert!(provider.is_valid_at(14_409));
        assert!(!provider.is_valid_at(14_410));
        let mut manager = XwidManager::default();
        manager.publish_legitimate_raw(Bytes::from_static(b"real"), 10);
        assert!(!manager.needs_generation_at(14_410));
        assert!(manager.needs_generation_at(14_411));
    }

    #[test]
    fn provider_failure_keeps_full_old_tuple_and_manager_sees_nonempty_success() {
        let mut provider = XwidProviderCache::default();
        let original = tuple(b"actual");
        provider.publish_generation(original.clone(), 10);
        let returned = provider
            .get_or_generate(20_000, || Some(XwidGeneration::default()))
            .unwrap();
        assert_eq!(returned, &original);
        let raw = returned.x.clone();
        assert_eq!(provider.timestamp(), 10);
        let mut manager = XwidManager::default();
        assert!(manager.finish_generation(Some(raw), 19_999));
        assert_eq!(manager.timestamp(), 19_999);
        assert!(!manager.finish_generation(None, 20_000));
        assert_eq!(manager.timestamp(), 19_999);
        assert_eq!(manager.snapshot().raw, original.x);
        assert!(!manager.is_generating());
    }

    #[test]
    fn successful_persistent_cache_load_still_queues_generation() {
        let mut manager = XwidManager::default();
        let lookup = manager.lookup(10, true, true, || Some(Bytes::from_static(b"saved-real-X")));
        assert_eq!(lookup.generation, Some(XwidGenerationMode::Queued));
        assert_eq!(lookup.snapshot.raw, Bytes::from_static(b"saved-real-X"));
        assert!(manager.cache_loaded());
        assert!(
            manager
                .lookup(11, true, true, || panic!("cache read twice"))
                .generation
                .is_none()
        );
        manager.finish_generation(None, 10);
        assert!(
            manager
                .lookup(14_410, true, true, || panic!("cache read twice"))
                .generation
                .is_none()
        );
        assert_eq!(
            manager
                .lookup(14_411, true, true, || panic!("cache read twice"))
                .generation,
            Some(XwidGenerationMode::Queued)
        );
    }

    #[test]
    fn missing_cache_allows_synchronous_generation_and_disabled_does_nothing() {
        let mut manager = XwidManager::default();
        assert!(
            manager
                .lookup(10, false, true, || panic!("disabled cache read"))
                .generation
                .is_none()
        );
        assert!(!manager.cache_attempted());
        assert_eq!(
            manager.lookup(10, true, true, || None).generation,
            Some(XwidGenerationMode::Synchronous)
        );
        assert!(manager.finish_generation(Some(Bytes::from_static(b"provider-X")), 10));
        assert_eq!(manager.snapshot().raw, Bytes::from_static(b"provider-X"));
    }
}
