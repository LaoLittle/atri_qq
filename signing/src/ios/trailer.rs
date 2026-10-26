pub fn iv_and_trailer(seed: u32) -> ([u8; 16], [u8; 16]) {
    let first = seed.wrapping_mul(1_103_515_245).wrapping_add(1_103_527_590);
    let second = (first & 0x7fff_ffff)
        .wrapping_mul(1_103_515_245)
        .wrapping_add(12_345);
    let seeds = [first & 0x24ff_ffff, second & 0x24ff_ffff];
    let mut iv = [0u8; 16];
    iv[..4].copy_from_slice(&seeds[0].to_le_bytes());
    iv[4..8].copy_from_slice(&seeds[1].to_le_bytes());
    let mask = ((i32::from(iv[0] as i8) * i32::from(iv[4] as i8)) as u8) & 0x7f;
    for index in 0..8 {
        iv[8 + index] = iv[7 - index] ^ mask;
    }
    let mut trailer = [0u8; 16];
    for ((seed, modulus), output) in seeds
        .into_iter()
        .zip([0x6535_95dc_947f_c1fdu64, 0x74f3_c7b3_ac51_5ad9])
        .zip(trailer.chunks_exact_mut(8))
    {
        let mut message = [0u8; 7];
        message[0] = 0x5a;
        message[1..5].copy_from_slice(&seed.to_le_bytes());
        let checksum = crc16(&message[..5]);
        message[5..].copy_from_slice(&checksum.to_be_bytes());
        let mut integer = 0u128;
        for byte in message {
            integer = (integer << 8) | u128::from(byte);
        }
        output.copy_from_slice(&((integer * integer % u128::from(modulus)) as u64).to_be_bytes());
    }
    (iv, trailer)
}

fn crc16(bytes: &[u8]) -> u16 {
    let mut crc = 0xffffu16;
    for &byte in bytes {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            crc = (crc << 1) ^ if crc & 0x8000 != 0 { 0x1021 } else { 0 };
        }
    }
    crc
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SeedHelperSnapshot {
    pub counter: u32,
    pub tag: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SeedLocations {
    pub clock_sample: u64,
    pub random0: u64,
    pub random1: u64,
}

pub trait SeedSource {
    type Error;

    fn clock_nanoseconds(&mut self) -> Result<u64, Self::Error>;

    fn urandom_word(&mut self) -> Result<u32, Self::Error>;
}

pub struct SeedHelperState {
    state: SeedHelperSnapshot,
}

impl SeedHelperState {
    pub const fn fresh_process() -> Self {
        Self::restore(SeedHelperSnapshot { counter: 0, tag: 0 })
    }

    pub const fn restore(state: SeedHelperSnapshot) -> Self {
        Self { state }
    }

    pub const fn snapshot(&self) -> SeedHelperSnapshot {
        self.state
    }

    pub fn generate<S: SeedSource>(
        &mut self,
        source: &mut S,
        locations: SeedLocations,
    ) -> Result<u32, S::Error> {
        let t0 = source.clock_nanoseconds()?;
        self.state.tag = 3379;
        let t1 = source.clock_nanoseconds()?;
        if t0 != 0 && t0 != t1 {
            return Ok(((t0.wrapping_add(locations.clock_sample) as u32) & !8) | 32);
        }
        let random0 = source.urandom_word()?;
        let random1 = source.urandom_word()?;
        if random0 != 0 && random0 != random1 {
            return Ok(u64::from(random0)
                .wrapping_add(locations.clock_sample)
                .wrapping_add(locations.random0)
                .wrapping_add(locations.random1) as u32
                | 40);
        }
        let counter = self.state.counter;
        self.state.counter = counter.wrapping_add(2);
        let value = t0
            .max(0x2c01_2e6f)
            .wrapping_add(u64::from(random0))
            .wrapping_add(u64::from(counter) * 2 + 1)
            .wrapping_add(locations.clock_sample)
            .wrapping_add(locations.random1);
        Ok(((value ^ 0x2c01_2e6f) as u32) | 40)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_ios_constructor_vectors() {
        for (seed, iv, trailer) in [
            (
                0xca17_9929,
                [
                    0x1b, 0x33, 0x33, 0x04, 0xb8, 0x2c, 0x41, 0x20, 0x48, 0x29, 0x44, 0xd0, 0x6c,
                    0x5b, 0x5b, 0x73,
                ],
                [
                    0x2d, 0x8f, 0x92, 0xeb, 0xc2, 0x94, 0x6b, 0xe2, 0x1e, 0x88, 0x36, 0x9b, 0x8a,
                    0x13, 0xf1, 0xb8,
                ],
            ),
            (
                0x076f_9abb,
                [
                    0x45, 0x5a, 0x12, 0x04, 0x9a, 0xa5, 0xaf, 0x24, 0x26, 0xad, 0xa7, 0x98, 0x06,
                    0x10, 0x58, 0x47,
                ],
                [
                    0x41, 0xcf, 0xf8, 0xb6, 0x47, 0x4e, 0xe6, 0x8c, 0x4e, 0xeb, 0x20, 0x6c, 0xea,
                    0x18, 0x54, 0x60,
                ],
            ),
        ] {
            assert_eq!(iv_and_trailer(seed), (iv, trailer));
        }
        let (iv, trailer) = iv_and_trailer(0x4f0f_db2b);
        assert_eq!(&iv[..8], &[0xf5, 0xe9, 0x8f, 0x24, 0x8a, 0x73, 0x0d, 0x04]);
        assert_eq!(
            trailer,
            [
                0x52, 0x21, 0x2c, 0x41, 0x35, 0x19, 0x1e, 0xbd, 0x22, 0x08, 0x2b, 0xc6, 0x0e, 0x1d,
                0x83, 0x70
            ]
        );
    }

    struct Samples {
        clocks: std::array::IntoIter<u64, 2>,
        random: std::array::IntoIter<u32, 2>,
    }

    impl SeedSource for Samples {
        type Error = std::convert::Infallible;

        fn clock_nanoseconds(&mut self) -> Result<u64, Self::Error> {
            Ok(self
                .clocks
                .next()
                .expect("unexpected native clock consumption"))
        }

        fn urandom_word(&mut self) -> Result<u32, Self::Error> {
            Ok(self
                .random
                .next()
                .expect("unexpected native entropy consumption"))
        }
    }

    #[test]
    fn original_ios_seed_branches_and_retained_counter() {
        let locations = SeedLocations {
            clock_sample: 0x4000_ff8b0,
            random0: 0x4000_ff8b9,
            random1: 0x4000_ff8c2,
        };
        let mut state = SeedHelperState::fresh_process();
        for (clocks, random, expected, counter, remaining_random) in [
            (
                [0x1234_5678_1234, 0x1234_5678_1235],
                [0, 0],
                0x5688_0ae4,
                0,
                2,
            ),
            (
                [9_876_543_210_123; 2],
                [0xc9e9_c616, 0x35bf_992d],
                0xca19_b069,
                0,
                0,
            ),
            ([0, 1], [0x1234_5678, 0x8765_4321], 0x1264_40ab, 0, 0),
            ([0; 2], [0; 2], 0x0020_31ad, 2, 0),
            ([0; 2], [0; 2], 0x0020_31a9, 4, 0),
            ([0x1234_5678_9abc; 2], [0x1122_3344; 2], 0x4bbb_913c, 6, 0),
        ] {
            let mut source = Samples {
                clocks: clocks.into_iter(),
                random: random.into_iter(),
            };
            assert_eq!(state.generate(&mut source, locations).unwrap(), expected);
            assert_eq!(state.snapshot(), SeedHelperSnapshot { counter, tag: 3379 });
            assert_eq!(source.clocks.len(), 0);
            assert_eq!(source.random.len(), remaining_random);
        }
        let mut state = SeedHelperState::restore(SeedHelperSnapshot {
            counter: u32::MAX,
            tag: 0,
        });
        let mut source = Samples {
            clocks: [0; 2].into_iter(),
            random: [0; 2].into_iter(),
        };
        assert_eq!(state.generate(&mut source, locations).unwrap(), 0x0020_31af);
        assert_eq!(state.snapshot().counter, 1);
    }
}
