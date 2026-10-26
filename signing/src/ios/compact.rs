use xxhash_rust::xxh32::xxh32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactConfig {
    pub word0: u64,
    pub word1: u64,
}

impl Default for CompactConfig {
    fn default() -> Self {
        Self { word0: 0, word1: 3 }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mt19937Snapshot {
    pub words: [u32; 624],
    pub index: u16,
}

impl Mt19937Snapshot {
    fn new(seed: u32) -> Self {
        let mut words = [0; 624];
        words[0] = seed;
        for i in 1..624 {
            words[i] = 1_812_433_253u32
                .wrapping_mul(words[i - 1] ^ (words[i - 1] >> 30))
                .wrapping_add(i as u32);
        }
        Self { words, index: 0 }
    }

    fn next_u32(&mut self) -> u32 {
        let i = usize::from(self.index);
        let next = (i + 1) % 624;
        let joined = (self.words[i] & 0x8000_0000) | (self.words[next] & 0x7fff_ffff);
        let mut value = self.words[(i + 397) % 624]
            ^ (joined >> 1)
            ^ if joined & 1 != 0 { 0x9908_b0df } else { 0 };
        self.words[i] = value;
        self.index = next as u16;
        value ^= value >> 11;
        value ^= (value << 7) & 0x9d2c_5680;
        value ^= (value << 15) & 0xefc6_0000;
        value ^ (value >> 18)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CompactSnapshot {
    pub engine: Option<Mt19937Snapshot>,
}

#[derive(Default)]
pub struct CompactState {
    state: CompactSnapshot,
}

pub trait CompactSource {
    type Error;
    fn steady_clock_nanos(&mut self) -> Result<i64, Self::Error>;
    fn system_clock_micros(&mut self) -> Result<i64, Self::Error>;
    fn random_device_word(&mut self) -> Result<Option<u32>, Self::Error>;
}

impl CompactState {
    pub const fn fresh_thread() -> Self {
        Self {
            state: CompactSnapshot { engine: None },
        }
    }

    pub fn restore(state: CompactSnapshot) -> Option<Self> {
        if state
            .engine
            .as_ref()
            .is_some_and(|engine| engine.index >= 624)
        {
            None
        } else {
            Some(Self { state })
        }
    }

    pub fn snapshot(&self) -> CompactSnapshot {
        self.state.clone()
    }

    pub fn sign<S: CompactSource>(
        &mut self,
        body: &[u8],
        config: CompactConfig,
        source: &mut S,
    ) -> Result<[u8; 28], S::Error> {
        let initial_clock = source.steady_clock_nanos()?;
        let system_scaled = source.system_clock_micros()? / 1000;
        let initial_seed = match source.random_device_word()? {
            Some(random) => random ^ system_scaled as u32,
            None => 0,
        };
        let elapsed = source.steady_clock_nanos()?.wrapping_sub(initial_clock);
        let seed = initial_seed ^ ((elapsed as f64) as i64 as u32);
        let selector = seed as u8;
        if self.state.engine.is_none() || selector == 0 {
            self.state.engine = Some(Mt19937Snapshot::new(seed));
        }
        let engine = self
            .state
            .engine
            .as_mut()
            .expect("initialized compact engine");
        let mut random = [0; 12];
        for chunk in random.chunks_exact_mut(4) {
            let value = if (1..15).contains(&selector) {
                engine.next_u32() ^ engine.next_u32()
            } else if (15..240).contains(&selector) {
                engine.next_u32() ^ 0xcccc_cccc
            } else {
                engine.next_u32()
            };
            chunk.copy_from_slice(&value.to_le_bytes());
        }
        Ok(assemble(body, config, &random))
    }
}

fn assemble(body: &[u8], config: CompactConfig, random: &[u8; 12]) -> [u8; 28] {
    let mut plaintext = [0u8; 19];
    plaintext[0] = 0x2a;
    let flags = config.word0;
    let protocol = config.word1;
    let header = ((protocol & 3)
        | (((protocol >> 8) & 1) << 2)
        | ((flags & 1) << 3)
        | (((flags >> 8) & 1) << 4)
        | (((flags >> 9) & 1) << 5)
        | (((flags >> 17) & 1) << 6)
        | (((flags >> 18) & 1) << 7)
        | (((flags >> 19) & 1) << 8)) as u16;
    plaintext[1..3].copy_from_slice(&header.to_le_bytes());
    let count = body.len().min(16);
    plaintext[3..3 + count].copy_from_slice(&body[..count]);
    for (byte, mask) in plaintext
        .iter_mut()
        .zip(super::salsa8::block::<19>(random, 0))
    {
        *byte ^= mask;
    }
    let mut output = [0u8; 28];
    output[..12].copy_from_slice(random);
    output[12] = random[0];
    const SELECTED: [usize; 11] = [0, 1, 2, 4, 5, 6, 8, 11, 16, 9, 7];
    for (dst, index) in output[13..24].iter_mut().zip(SELECTED) {
        *dst = plaintext[index];
    }
    let mut first_input = [0u8; 28];
    first_input[..4].copy_from_slice(&0x3d7a_ccd4u32.to_le_bytes());
    first_input[4..].copy_from_slice(&output[..24]);
    let first = xxh32(&first_input, 0);
    let mut second_input = [0xbe, 0xa6, 0x10, 0x57, 0, 0, 0, 0];
    second_input[4..].copy_from_slice(&first.to_le_bytes());
    output[24..].copy_from_slice(&xxh32(&second_input, 0x2795_37a4).to_le_bytes());
    output
}

#[cfg(test)]
fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("four-byte word"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    struct Seed(u32);
    impl CompactSource for Seed {
        type Error = Infallible;
        fn steady_clock_nanos(&mut self) -> Result<i64, Self::Error> {
            Ok(9876543210123)
        }
        fn system_clock_micros(&mut self) -> Result<i64, Self::Error> {
            Ok(1700000000123456)
        }
        fn random_device_word(&mut self) -> Result<Option<u32>, Self::Error> {
            Ok(Some(self.0 ^ (1700000000123456i64 / 1000) as u32))
        }
    }

    fn hex<const N: usize>(text: &str) -> [u8; N] {
        assert_eq!(text.len(), N * 2);
        std::array::from_fn(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
    }

    #[test]
    fn original_arm64_baseline_warm_threads_and_restore() {
        let body = hex::<16>("000102030405060708090a0b0c0d0e0f");
        let other = hex::<16>("ffeeddccbbaa99887766554433221100");
        let config = CompactConfig::default();
        let mut first = CompactState::fresh_thread();
        assert_eq!(
            first.sign(&body, config, &mut Seed(0x692ba460)).unwrap(),
            hex::<28>("6129b58d99f846a2ebd4e6c26150468e51d914cdbb71f53ae85518d6")
        );
        assert_eq!(first.state.engine.as_ref().unwrap().index, 3);
        let saved = first.snapshot();
        let second = first.sign(&other, config, &mut Seed(0xaecb1eed)).unwrap();
        assert_eq!(
            second,
            hex::<28>("1894c68cc92ad4216c1c68fd18d1fcf7855c97d8ed7a20b50009d828")
        );
        let mut restored = CompactState::restore(saved).unwrap();
        assert_eq!(
            restored
                .sign(&other, config, &mut Seed(0xaecb1eed))
                .unwrap(),
            second
        );
        let mut thread = CompactState::fresh_thread();
        assert_eq!(
            thread.sign(&body, config, &mut Seed(0x060cae6d)).unwrap(),
            hex::<28>("24a3a27c448106f004f78c3624d688654fb38c2b322a7d9068096a61")
        );
        assert_eq!(
            first.sign(&other, config, &mut Seed(0xfa5af156)).unwrap(),
            hex::<28>("c8058edcb4bea2f7bd82ac39c83d60f2799ae661ea6d2e212ee6365d")
        );
        assert_eq!(first.state.engine.as_ref().unwrap().index, 9);
    }

    #[test]
    fn original_arm64_selector_boundaries_and_reseed() {
        let vectors = [
            (
                0,
                3,
                "ac0a7f8c2faac49775a616b7acc111516ae299231c529b80ebd658fc",
            ),
            (
                1,
                9,
                "837f6f423824df506ed991b483663239147d5153312e3df2444da727",
            ),
            (
                14,
                15,
                "c68ff83ad6616312110660a8c6d4c129f882e789c37820df2ad597b8",
            ),
            (
                15,
                18,
                "147148c294567e3a4001008914dd19f16f31722dfebd3c5d70cb0eb4",
            ),
            (
                239,
                21,
                "f6f5e5ae0d8e84b62ab16206f634ceaf7bf4b848d9353a0acef07501",
            ),
            (
                240,
                24,
                "274aeacf57a86587aec8df7a276e4ee908cfd1ba23f92982bc89a02b",
            ),
            (
                255,
                27,
                "585e6b91518b8d64a5e6f3ec5863889f52de35ce2d9257463b5fc49e",
            ),
            (
                0,
                3,
                "ac0a7f8c2faac49775a616b7acc111516ae299231c529b80ebd658fc",
            ),
        ];
        let body = hex::<16>("000102030405060708090a0b0c0d0e0f");
        let mut state = CompactState::fresh_thread();
        for (seed, index, expected) in vectors {
            assert_eq!(
                state
                    .sign(&body, CompactConfig::default(), &mut Seed(seed))
                    .unwrap(),
                hex::<28>(expected)
            );
            assert_eq!(state.state.engine.as_ref().unwrap().index, index);
        }
    }

    #[test]
    fn original_arm64_configuration_bits() {
        let vectors = [
            (
                0,
                0,
                "ac0a7f8c2faac49775a616b7acc112516ae299231c529b8039841718",
            ),
            (
                0,
                1,
                "ac0a7f8c2faac49775a616b7acc113516ae299231c529b80bd3d3da5",
            ),
            (
                0,
                2,
                "ac0a7f8c2faac49775a616b7acc110516ae299231c529b8018fa16d0",
            ),
            (
                0,
                256,
                "ac0a7f8c2faac49775a616b7acc116516ae299231c529b8070c5b738",
            ),
            (
                1,
                3,
                "ac0a7f8c2faac49775a616b7acc119516ae299231c529b8052d3f1d8",
            ),
            (
                256,
                3,
                "ac0a7f8c2faac49775a616b7acc101516ae299231c529b80ed18fac0",
            ),
            (
                512,
                3,
                "ac0a7f8c2faac49775a616b7acc131516ae299231c529b80c131767a",
            ),
            (
                131072,
                3,
                "ac0a7f8c2faac49775a616b7acc151516ae299231c529b80274be628",
            ),
            (
                262144,
                3,
                "ac0a7f8c2faac49775a616b7acc191516ae299231c529b80363494fc",
            ),
            (
                524288,
                3,
                "ac0a7f8c2faac49775a616b7acc111506ae299231c529b8037d2fdf5",
            ),
        ];
        let body = hex::<16>("000102030405060708090a0b0c0d0e0f");
        let mut state = CompactState::fresh_thread();
        for (word0, word1, expected) in vectors {
            assert_eq!(
                state
                    .sign(&body, CompactConfig { word0, word1 }, &mut Seed(0))
                    .unwrap(),
                hex::<28>(expected)
            );
        }
    }

    #[test]
    fn original_arm64_incremental_mt_wrap_snapshot() {
        let mut state = CompactState::fresh_thread();
        let body = [0; 16];
        let mut last = [0; 28];
        for _ in 0..210 {
            last = state
                .sign(&body, CompactConfig::default(), &mut Seed(15))
                .unwrap();
        }
        assert_eq!(&last[..12], &hex::<12>("2257f76c038376f653eb31f7"));
        let engine = state.state.engine.as_ref().unwrap();
        let native = include_bytes!("../../tests/fixtures/ios/compact-mt-wrap-native.bin");
        for (i, value) in engine.words.iter().enumerate() {
            assert_eq!(*value, word(native, i * 4), "MT state word {i}");
        }
        assert_eq!(
            u64::from(engine.index),
            u64::from_le_bytes(native[2496..].try_into().unwrap())
        );
    }

    #[test]
    fn original_arm64_short_and_truncated_body() {
        let mut state = CompactState::fresh_thread();
        let config = CompactConfig::default();
        let expected = hex::<28>("ac0a7f8c2faac49775a616b7acc111516be09a26145f9d846cfbb504");
        assert_eq!(state.sign(&[], config, &mut Seed(0)).unwrap(), expected);
        assert_eq!(state.sign(&[1], config, &mut Seed(0)).unwrap(), expected);
        let long = hex::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        assert_eq!(
            state.sign(&long, config, &mut Seed(0)).unwrap(),
            hex::<28>("ac0a7f8c2faac49775a616b7acc111516ae299231c529b80ebd658fc")
        );
    }
}
