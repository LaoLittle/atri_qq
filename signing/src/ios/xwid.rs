use crate::derive_xwid;
use bytes::Bytes;
use sha1::{Digest, Sha1};

pub use super::xwid_resource::ResourceSample;

pub const KEYCHAIN_SERVICE: &str = "com.tencent.o3token.xw";
pub const KEYCHAIN_ACCOUNT: &str = "com.tencent.o3token.xw.L2";
pub const DEFAULT_TTL_SECONDS: u64 = 14_400;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CandidateError {
    Length = 1,
    Digest = 2,
    Checksum = 3,
}

pub fn candidate_from_source(source: &[u8]) -> [u8; 44] {
    let mut candidate = [0; 44];
    let digest = Sha1::digest(c_string_bytes(source));
    hex::encode_to_slice(&digest[..16], &mut candidate[..32]).expect("sixteen-byte digest");
    let check = candidate_digest(&candidate[..32]);
    candidate[32..36].copy_from_slice(&check);
    candidate[36..].copy_from_slice(&candidate_checksum(&check));
    candidate
}

pub fn validate_candidate(candidate: &str) -> Result<(), CandidateError> {
    let prefix_end = if candidate.is_ascii() {
        if candidate.len() != 44 {
            return Err(CandidateError::Length);
        }
        32
    } else {
        if candidate.encode_utf16().count() != 44 {
            return Err(CandidateError::Length);
        }
        let mut units = 0;
        candidate
            .char_indices()
            .find_map(|(index, character)| {
                if units == 32 {
                    Some(index)
                } else {
                    units += character.len_utf16();
                    None
                }
            })
            .ok_or(CandidateError::Digest)?
    };
    let check = candidate_digest(candidate[..prefix_end].as_bytes());
    let tail = candidate[prefix_end..].as_bytes();
    if !tail.starts_with(&check) {
        return Err(CandidateError::Digest);
    }
    if tail[4..] != candidate_checksum(&check) {
        return Err(CandidateError::Checksum);
    }
    Ok(())
}

fn c_string_bytes(value: &[u8]) -> &[u8] {
    &value[..value
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(value.len())]
}

fn candidate_digest(prefix: &[u8]) -> [u8; 4] {
    let digest = Sha1::digest(c_string_bytes(prefix));
    let mut output = [0; 4];
    hex::encode_to_slice(&digest[..2], &mut output).expect("two-byte digest");
    output
}

fn candidate_checksum(check: &[u8; 4]) -> [u8; 8] {
    const ALPHABET: &[u8; 62] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    fn index(byte: u8) -> usize {
        usize::from(if byte.is_ascii_digit() {
            byte - b'0' + 52
        } else {
            byte - b'a'
        })
    }
    let mut output = [0; 8];
    hex::encode_to_slice((!crc32fast::hash(check)).to_be_bytes(), &mut output)
        .expect("four-byte checksum");
    for (position, byte) in output.iter_mut().enumerate() {
        *byte = ALPHABET[(index(*byte) + index(check[position % 4])) % ALPHABET.len()];
    }
    output
}

pub fn secure_material(material: &[u8; 36], unix_seconds: u64, random: &[u8; 5]) -> [u8; 76] {
    use std::num::Wrapping;

    let mut blocks = [0u8; 32];
    blocks[..8].copy_from_slice(b"02060020");
    blocks[8..12].copy_from_slice(&((unix_seconds as u32) ^ 0xde9dc120).to_le_bytes());
    for (output, pair) in blocks[12..30].iter_mut().zip(material.chunks_exact(2)) {
        *output = (Wrapping(nibble(pair[0])) * Wrapping(16) + Wrapping(nibble(pair[1]))).0;
    }
    blocks[30..].fill(2);
    encrypt_blocks(&mut blocks, random);
    publish(*b"B1", random, &blocks)
}

pub(super) fn encrypt_blocks(blocks: &mut [u8], random: &[u8; 5]) {
    let mut key = [0; 16];
    for positions in [[14, 4, 12, 8, 1], [0, 7, 4, 13, 10]] {
        key.fill(0);
        for (position, byte) in positions.into_iter().zip(random) {
            key[position] = *byte;
        }
        let cipher = super::xwid_cipher::Cipher::new(&key);
        for block in blocks.chunks_exact_mut(16) {
            cipher.encrypt(block.try_into().expect("exact block"));
        }
    }
}

pub(super) fn publish<const N: usize>(prefix: [u8; 2], random: &[u8; 5], blocks: &[u8]) -> [u8; N] {
    debug_assert_eq!(N, 2 + 2 * (random.len() + blocks.len()));
    let mut output = [0; N];
    output[..2].copy_from_slice(&prefix);
    for (destination, byte) in output[2..]
        .chunks_exact_mut(2)
        .zip(random.iter().chain(blocks))
    {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        destination[0] = HEX[usize::from(byte >> 4)];
        destination[1] = HEX[usize::from(byte & 15)];
    }
    output
}

pub(super) fn nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0xff,
    }
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

    #[test]
    fn original_candidates_match_resource_random_and_c_string_sources() {
        for (source, expected) in [
            (
                &b"00FFf8FF00FFf8FF00FFf8FF00FFf8FF00FFf8FF00FFf8FF00FF"[..],
                b"15538ae91c5862ea65de2523cd2c105e2f92Sj8SZg5T",
            ),
            (
                &b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"[..],
                b"dc0c61507543f8339b04fe27149ce98b7917b5Sa6bW6",
            ),
            (
                &b"0123456789abcdefghijklmnopqrstuv"[..],
                b"1de0f64996bc7ce4dc28c0593be0335d7707c2Z55XRZ",
            ),
            (
                &b"capture\0ignored"[..],
                b"fbc259d1f78c5cc26c64e0bfd6c19ff5aa0994X6afW8",
            ),
        ] {
            assert_eq!(&candidate_from_source(source), expected);
        }
    }

    #[test]
    fn original_validation_distinguishes_length_digest_and_checksum() {
        for (candidate, expected) in [
            ("15538ae91c5862ea65de2523cd2c105e2f92Sj8SZg5T", Ok(())),
            (
                "15538ae91c5862ea65de2523cd2c105e2f92Sj8SZg5",
                Err(CandidateError::Length),
            ),
            (
                "15538ae91c5862ea65de2523cd2c105e0f92Sj8SZg5T",
                Err(CandidateError::Digest),
            ),
            (
                "15538ae91c5862ea65de2523cd2c105e2f92Sj8SZg5A",
                Err(CandidateError::Checksum),
            ),
            (
                "15538ae91c5862ea65de2523cd2c105e2f92!j8SZg5T",
                Err(CandidateError::Checksum),
            ),
        ] {
            assert_eq!(validate_candidate(candidate), expected);
        }
    }

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
    fn original_outer_binary_and_published_prefix_match_selectors_one_and_two() {
        assert_eq!(
            &secure_material(&[b'0'; 36], 0, &[0, 1, 2, 3, 4]),
            b"B10001020304537544983D4D51ABEB726ED75A7ABA0653C9EA5C534B00FF3A448A7D42AA1574"
        );
    }

    #[test]
    fn original_mixed_case_hex_and_selectors_four_and_zero_match() {
        assert_eq!(
            &secure_material(
                b"0123456789abcdef0123456789abcdefABCD",
                1_700_000_000,
                &[239, 4, 0, 170, 90],
            ),
            b"B1EF0400AA5AE261F14316E28159C3DAA9618D4206B35D08313DA1E1764AE69C2836D493E05C"
        );
    }

    #[test]
    fn original_invalid_hex_arithmetic_and_time_truncation_match_selector_three() {
        let material = std::array::from_fn(|index| if index % 2 == 0 { b'g' } else { b'G' });
        assert_eq!(
            &secure_material(&material, 4_294_967_297, &[17, 3, 3, 34, 255]),
            b"B111030322FF472B49752D800B3309F919E1F5B1488F563541329359262EE472CB2A15EA1809"
        );
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
