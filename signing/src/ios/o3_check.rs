use aes::Aes128;
use ctr::cipher::{KeyIvInit, StreamCipher};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckMode {
    Sdk,
    NativeFallback,
}

impl CheckMode {
    pub fn encode(self, digest: &[u8; 32], counter: &[u8; 16]) -> [u8; 48] {
        let key: [u8; 16] = match self {
            Self::Sdk => [
                0xf7, 0x36, 0xe6, 0x44, 0x64, 0x03, 0x68, 0x8b, 0x6e, 0x5e, 0xba, 0xee, 0x6c, 0x0b,
                0x4e, 0xdc,
            ],
            Self::NativeFallback => [
                0x6e, 0x4a, 0xcc, 0xd4, 0x2a, 0xa2, 0x4b, 0xe7, 0xbb, 0x6b, 0x31, 0xf4, 0x8c, 0x1c,
                0xbd, 0xc8,
            ],
        };
        let mut output = [0; 48];
        output[..16].copy_from_slice(counter);
        output[16..].copy_from_slice(digest);
        ctr::Ctr128BE::<Aes128>::new((&key).into(), counter.into())
            .apply_keystream(&mut output[16..]);
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), N * 2);
        std::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
    }

    #[test]
    fn complete_native_wrapper_output() {
        let digest = decode("630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd");
        let expected = decode::<48>(
            "3139ddaed493ec17a93c2af89ac962ed722e247d34771d05e7ec9d7be6569852ec26f31827791dfe9efc683aa5189362",
        );
        let counter = expected[..16].try_into().unwrap();
        assert_eq!(CheckMode::Sdk.encode(&digest, counter), expected);
    }

    #[test]
    fn native_counter_carry_and_wrap() {
        for (mode, counter, expected) in [
            (
                CheckMode::Sdk,
                "000102030405060708090a0b0c0d0eff",
                "5c1d694d2f854d36faddb3d2c80034372514fc897140928dbb0dda95e351699d",
            ),
            (
                CheckMode::Sdk,
                "ffffffffffffffffffffffffffffffff",
                "15c197dcb38cb358b3c98d1152801576fefa249e25329ff8d92a7e40e7118cb1",
            ),
            (
                CheckMode::NativeFallback,
                "000102030405060708090a0b0c0d0eff",
                "61f40f9c31ec446a50f7ef4505f32bc15e3b07e653fba02901bbfd327208f0db",
            ),
            (
                CheckMode::NativeFallback,
                "ffffffffffffffffffffffffffffffff",
                "2a302bb9c6a11ac9989ca542b3506dff37b96729c71e3294f87c2578e253321a",
            ),
        ] {
            let encoded = mode.encode(&[0; 32], &decode(counter));
            assert_eq!(encoded[16..], decode::<32>(expected));
        }
    }
}
