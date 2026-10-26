use std::{
    collections::HashMap,
    thread::{self, ThreadId},
};

use md5::{Digest, Md5};

use super::{
    body,
    compact::{CompactConfig, CompactSnapshot, CompactSource, CompactState},
    framing,
    payload::{self, Fields, Metadata},
    trailer::{self, SeedHelperSnapshot, SeedHelperState, SeedLocations, SeedSource},
};

pub trait Source: SeedSource + CompactSource<Error = <Self as SeedSource>::Error> {
    fn process_context(&mut self) -> Result<[u8; 16], <Self as SeedSource>::Error>;
    fn time_seconds(&mut self) -> Result<i64, <Self as SeedSource>::Error>;
    fn process_id(&mut self) -> Result<i32, <Self as SeedSource>::Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuxiliaryTransform {
    Unregistered,
    Md5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Primary,
    Compact,
    Disabled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signature {
    Primary([u8; 96]),
    Compact([u8; 28]),
    Disabled,
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Primary(bytes) => bytes,
            Self::Compact(bytes) => bytes,
            Self::Disabled => b"QQQQ",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub context: [u8; 16],
    pub initialized_at: i64,
    pub runtime: CompactConfig,
    pub record_word3: u8,
    pub metadata_counter: u8,
    pub cache_value: u16,
    pub status: [u8; 7],
    pub diagnostic_flags: [u8; 10],
    pub normalized_seed_offset: i32,
    pub auxiliary_transform: AuxiliaryTransform,
    pub seed_helper: SeedHelperSnapshot,
}

pub struct Request<'a> {
    pub digest: &'a [u8; 16],
    pub command: &'a [u8],
    pub device_token: &'a [u8],
    pub mode: Mode,
}

pub struct Signer {
    state: Snapshot,
    seeds: SeedHelperState,
    compact: HashMap<ThreadId, CompactState>,
}

impl Signer {
    pub fn new<S: Source>(source: &mut S) -> Result<Self, <S as SeedSource>::Error> {
        let initialized_at = source.time_seconds()?;
        let context = source.process_context()?;
        Ok(Self::restore(Snapshot {
            context,
            initialized_at,
            runtime: CompactConfig::default(),
            record_word3: 22,
            metadata_counter: 0xf0,
            cache_value: 0,
            status: [0; 7],
            diagnostic_flags: [0; 10],
            normalized_seed_offset: -1,
            auxiliary_transform: AuxiliaryTransform::Md5,
            seed_helper: SeedHelperState::fresh_process().snapshot(),
        }))
    }

    pub fn restore(state: Snapshot) -> Self {
        Self {
            seeds: SeedHelperState::restore(state.seed_helper),
            state,
            compact: HashMap::new(),
        }
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            seed_helper: self.seeds.snapshot(),
            ..self.state
        }
    }

    pub fn current_thread_snapshot(&self) -> CompactSnapshot {
        self.compact
            .get(&thread::current().id())
            .map_or_else(CompactSnapshot::default, CompactState::snapshot)
    }

    pub fn restore_current_thread(&mut self, snapshot: CompactSnapshot) -> bool {
        let Some(state) = CompactState::restore(snapshot) else {
            return false;
        };
        self.compact.insert(thread::current().id(), state);
        true
    }

    pub fn sign<S: Source>(
        &mut self,
        request: Request<'_>,
        source: &mut S,
        locations: Option<SeedLocations>,
    ) -> Result<Signature, <S as SeedSource>::Error> {
        match request.mode {
            Mode::Disabled => return Ok(Signature::Disabled),
            Mode::Compact => {
                return self
                    .compact
                    .entry(thread::current().id())
                    .or_insert_with(CompactState::fresh_thread)
                    .sign(request.digest, self.state.runtime, source)
                    .map(Signature::Compact);
            }
            Mode::Primary => {}
        }
        let anchors = [0u64; 3];
        let locations = locations.unwrap_or(SeedLocations {
            clock_sample: std::ptr::addr_of!(anchors[0]) as u64,
            random0: std::ptr::addr_of!(anchors[1]) as u64,
            random1: std::ptr::addr_of!(anchors[2]) as u64,
        });
        let body_seed = self.seeds.generate(source, locations)?;
        let packet = body::random_packet(body_seed);
        let normalized =
            (body_seed.swap_bytes() & !1).wrapping_add(self.state.normalized_seed_offset as u32);
        let mut message = [0; 20];
        message[..16].copy_from_slice(request.digest);
        message[16..].copy_from_slice(&normalized.to_le_bytes());
        let digest = body::hash(&body::derive_key(&packet), &message);
        let time = source.time_seconds()?;
        let pid = source.process_id()?;
        let random = body::random_word(time as u32);
        let auxiliary = if request.device_token.len() < 4 {
            0x8c
        } else {
            match self.state.auxiliary_transform {
                AuxiliaryTransform::Unregistered => 0,
                AuxiliaryTransform::Md5 => Md5::digest(request.device_token)[2],
            }
        };
        let mut flags = self.state.diagnostic_flags;
        for (byte, word) in flags[..8]
            .iter_mut()
            .zip(self.state.runtime.word0.to_le_bytes())
        {
            *byte ^= word;
        }
        for (byte, word) in flags[8..]
            .iter_mut()
            .zip(((self.state.runtime.word1 >> 8) as u16).to_le_bytes())
        {
            *byte ^= word;
        }
        let login_marker = is_login_command(request.command);
        let login_family = login_marker
            || request
                .command
                .eq_ignore_ascii_case(b"wtlogin.exchange_emp");
        if login_family {
            flags[9] |= 4;
        }
        let payload = payload::encode(&Fields {
            flags,
            record_word3: self.state.record_word3,
            body_digest: digest,
            metadata: Metadata {
                protocol: self.state.runtime.word1 as u8,
                login: login_marker,
                auxiliary,
                counter: self.state.metadata_counter,
                cache_value: self.state.cache_value,
                context: self.state.context,
                process_sample: sample_process_id(pid, random),
            },
            status: self.state.status,
            normalized_seed: normalized,
            random_packet: packet,
        });
        let trailer_seed = self.seeds.generate(source, locations)?;
        let (iv, trailer) = trailer::iv_and_trailer(trailer_seed);
        let clock = source.clock_nanoseconds()?;
        Ok(Signature::Primary(framing::encrypt(
            &payload, &iv, &trailer, clock,
        )))
    }
}

pub fn is_login_command(command: &[u8]) -> bool {
    [
        b"2088".as_slice(),
        b"810_9",
        b"2102",
        b"wtlogin.login",
        b"wtlogin.qrlogin",
        b"trpc.login.ecdh.EcdhService.SsoNTLoginTGTExchangeFastLogin",
        b"trpc.login.ecdh.EcdhService.SsoNTLoginAuthLogin",
        b"trpc.login.ecdh.EcdhService.SsoNTLoginPasswordLoginUnusualDevice",
        b"trpc.login.ecdh.EcdhService.SsoNTLoginEasyLoginUnusualDevice",
        b"trpc.login.ecdh.EcdhService.SsoNTLoginPasswordLoginNewDevice",
        b"trpc.login.ecdh.EcdhService.SsoNTLoginEasyLogin",
        b"trpc.login.ecdh.EcdhService.SsoNTLoginPasswordLogin",
    ]
    .into_iter()
    .any(|candidate| command.eq_ignore_ascii_case(candidate))
}

fn sample_process_id(pid: i32, random: u32) -> u8 {
    let mut digits = [0; 11];
    let mut position = digits.len();
    let mut value = pid.unsigned_abs();
    loop {
        position -= 1;
        digits[position] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    if pid < 0 {
        position -= 1;
        digits[position] = b'-';
    }
    let index = (u64::from(random) % (digits.len() - position) as u64) as usize;
    ((index as u8) << 4) | (digits[position + index] & 15)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::VecDeque, convert::Infallible};

    fn hex<const N: usize>(text: &str) -> [u8; N] {
        assert_eq!(text.len(), N * 2);
        std::array::from_fn(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
    }

    #[derive(Clone)]
    struct NativeResources(VecDeque<u32>);
    impl NativeResources {
        fn cold() -> Self {
            Self(
                [
                    0xa6ce_cc1b,
                    0x612e_7696,
                    0xc9e9_c616,
                    0x35bf_992d,
                    0x1807_2e8c,
                    0x7ce4_2c82,
                    0x0741_c7a8,
                    0xe4b0_6ce6,
                ]
                .into(),
            )
        }
    }
    impl SeedSource for NativeResources {
        type Error = Infallible;
        fn clock_nanoseconds(&mut self) -> Result<u64, Infallible> {
            Ok(9876543210123)
        }
        fn urandom_word(&mut self) -> Result<u32, Infallible> {
            Ok(self.0.pop_front().expect("unexpected entropy read"))
        }
    }
    impl CompactSource for NativeResources {
        type Error = Infallible;
        fn steady_clock_nanos(&mut self) -> Result<i64, Infallible> {
            Ok(9876543210123)
        }
        fn system_clock_micros(&mut self) -> Result<i64, Infallible> {
            Ok(1700000000123456)
        }
        fn random_device_word(&mut self) -> Result<Option<u32>, Infallible> {
            panic!("primary must not call compact RNG")
        }
    }
    impl Source for NativeResources {
        fn process_context(&mut self) -> Result<[u8; 16], Infallible> {
            Ok(hex("afd16c64d2d585a05518b73155c3b038"))
        }
        fn time_seconds(&mut self) -> Result<i64, Infallible> {
            Ok(1700000000)
        }
        fn process_id(&mut self) -> Result<i32, Infallible> {
            Ok(1234)
        }
    }

    const LOCATIONS: Option<SeedLocations> = Some(SeedLocations {
        clock_sample: 0x4000f4650,
        random0: 0x4000f4659,
        random1: 0x4000f4662,
    });
    const COLD: &str = "71329a817b05bfbd50b53618689212cb91914588475f19f84c30df2094dcbfb24851c5a730d7936be19467103e89d0b8698cf48bceff05354a43f9bf5aa41aa9f8540cc5fcd84d2b89aaf09dcf6fa8a1e69d0083daa2deb2a33733e00b89c3c9";

    #[test]
    fn native_login_flags_exchange_exclusion_and_sdk_token_transform() {
        let cases: [(&[u8], &[u8], &str); 4] = [
            (b"wtlogin.login.extra", b"", COLD),
            (
                b"wtlogin.LOGIN",
                b"",
                "d3840e2deab47f5e6aeb20254fddfd2e3b329815098db40c378edc6d0f2e673a5a9c7bd9ac101ffeaff3846d0c583b8897c6ca7f334caa081992b549a57385926151945c08d91a922570a11aa7fc9ccc03724fa4e7b4808840f78271a71d756b",
            ),
            (
                b"WTLOGIN.EXCHANGE_EMP",
                b"",
                "0aff58ad103a9252c2ba59f448ba175b3358393ad2d9b9024056b2071491c356b88ae64ddf3b6ce56b3d997ca9bbae509abb9f0e81bd5758e1aaab5cf341867ba8c42056dd2e331cf4c81054c70b88c7769828a336cdd1204c1a0c8b274b0eb2",
            ),
            (
                b"MessageSvc.PbSendMsg",
                b"abcd",
                "9ba5fa88cbfaffba85dabc7106266dfd206a0ecdc7badbce14c5db9757ae98fff58e7fc628029fe8e12c4c5fd22fa7c50b3ebc6a093e677e4d84c89922abfb7e7cb6faadd0c391ac9f349f28ceb8f867d0e2b4edb328b167a477cc5002e95423",
            ),
        ];
        let digest = std::array::from_fn(|i| i as u8);
        for (command, device_token, expected) in cases {
            let mut source = NativeResources::cold();
            let mut signer = Signer::new(&mut source).unwrap();
            let actual = signer
                .sign(
                    Request {
                        digest: &digest,
                        command,
                        device_token,
                        mode: Mode::Primary,
                    },
                    &mut source,
                    LOCATIONS,
                )
                .unwrap();
            assert_eq!(actual.as_ref(), hex::<96>(expected), "command {command:?}");
        }
    }

    #[test]
    fn native_warm_stream_survives_snapshot_restore() {
        let digest = std::array::from_fn(|i| i as u8);
        let request = || Request {
            digest: &digest,
            command: b"MessageSvc.PbSendMsg",
            device_token: b"",
            mode: Mode::Primary,
        };
        let mut source = NativeResources::cold();
        let mut signer = Signer::new(&mut source).unwrap();
        assert_eq!(
            signer
                .sign(request(), &mut source, LOCATIONS)
                .unwrap()
                .as_ref(),
            hex::<96>(COLD)
        );
        let mut restored = Signer::restore(signer.snapshot());
        let mut restored_source = source.clone();
        let expected = hex::<96>(
            "b21c0cfaaf01878e4e8d6fa6d349e570be43c891a7ab271d538e103cf0c5a37f0b1fe32f900e3f3db49d96e8b98cd7d9a4816d060fd3737b961a22e3f0bcd7dddf74f5786bc16f95c3c99f0ba0aca038312ab165e1216bc2c06c21c3101448d2",
        );
        assert_eq!(
            signer
                .sign(request(), &mut source, LOCATIONS)
                .unwrap()
                .as_ref(),
            expected
        );
        assert_eq!(
            restored
                .sign(request(), &mut restored_source, LOCATIONS)
                .unwrap()
                .as_ref(),
            expected
        );
        assert_eq!(signer.snapshot(), restored.snapshot());
    }
}
