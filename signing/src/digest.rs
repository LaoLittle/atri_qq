use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use md5::{Digest, Md5};
use rand_chacha::ChaCha12Rng;
use rand_core::{Rng, SeedableRng};
use rc4::{KeyInit, Rc4};

pub(crate) fn md5(input: &[u8]) -> [u8; 16] {
    md5_parts(&[input])
}

pub(crate) fn md5_parts(parts: &[&[u8]]) -> [u8; 16] {
    let mut digest = Md5::new();
    for &part in parts {
        digest.update(part);
    }
    digest.finalize().into()
}

pub fn derive_xwid(raw_xwid: &[u8]) -> [u8; 12] {
    let digest = md5(raw_xwid);
    let mut output = [0; 12];
    STANDARD
        .encode_slice(&digest[..9], &mut output)
        .expect("nine input bytes encode to exactly twelve Base64 bytes");
    output
}

pub(crate) fn prepare_sign(input_digest: &[u8; 16], clock_nanoseconds: i64) -> [u8; 21] {
    let microseconds = ((clock_nanoseconds % 1_000_000_000) / 1_000) as i32;
    let seed = (microseconds as u32).swap_bytes();
    let random_bytes = seed_bytes(seed);
    let key = derive_key(random_bytes);
    let mut padded_key = [0u8; 32];
    padded_key[..8].copy_from_slice(&key);
    let mut encrypted = [0u8; 20];
    encrypted[..16].copy_from_slice(input_digest);
    encrypted[16..].copy_from_slice(&seed.to_le_bytes());
    chacha20_xor(&padded_key, 0x14b7ba9329e934e3, &mut encrypted);
    for byte in &mut encrypted {
        *byte ^= 0x81;
    }
    let authentication = md5(&encrypted);
    let mut prefix = [0u8; 20];
    prefix[..2].copy_from_slice(&[0x0c, 0x15]);
    prefix[4..8].copy_from_slice(&random_bytes);
    prefix[8..12].copy_from_slice(&seed.to_le_bytes());
    prefix[12..].copy_from_slice(&authentication[..8]);
    let checksum = crc32(&prefix[4..]);
    prefix[2..4].copy_from_slice(&checksum.to_be_bytes()[..2]);
    let mut prepared = [0u8; 21];
    prepared[..5].copy_from_slice(&prefix[..5]);
    prepared[6..].copy_from_slice(&prefix[5..]);
    prepared
}

const SEED_ALPHABET: [u8; 50] = [
    0x22, 0x23, 0x24, 0x28, 0x29, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x46, 0x48, 0x52, 0x53, 0x54,
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x37, 0x38, 0x39, 0x3a, 0x3e, 0x41, 0x42, 0x43, 0x44, 0x45,
    0x45, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x2a, 0x6d, 0x6e, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
    0x79, 0x7a,
];

fn seed_bytes(seed: u32) -> [u8; 4] {
    let mut random = ChaCha12Rng::seed_from_u64(seed.into());
    let a = SEED_ALPHABET[((random.next_u32() >> 1) % 50) as usize].wrapping_add(72) ^ 17;
    let b = SEED_ALPHABET[((random.next_u32() >> 1) % 50) as usize].wrapping_add(72) ^ 17;
    [a, b, a.wrapping_add(38) ^ 32, b.wrapping_add(38) ^ 32]
}

pub(crate) fn seeded_random_word(seed: u32) -> u32 {
    ChaCha12Rng::seed_from_u64(seed.into()).next_u32() >> 1
}

fn derive_key(random_bytes: [u8; 4]) -> [u8; 8] {
    let mask = *b"&O9!";
    let mut key = *b"a$(e\0\0\0\0";
    for i in 0..4 {
        key[i + 4] = random_bytes[i] ^ mask[i];
    }
    key.rotate_right(2);
    rc4_self(key)
}

fn rc4_self(key: [u8; 8]) -> [u8; 8] {
    let mut cipher = Rc4::new_from_slice(&key).expect("RC4 key is eight bytes");
    let mut encrypted = key;
    cipher.apply_keystream(&mut encrypted);
    encrypted
}

fn chacha20_xor(key: &[u8; 32], nonce: u64, bytes: &mut [u8]) {
    let nonce = nonce.to_le_bytes();
    let mut cipher = chacha20::ChaCha20Legacy::new(key.into(), (&nonce).into());
    cipher.apply_keystream(bytes);
}

fn crc32(bytes: &[u8]) -> u32 {
    crc32fast::hash(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivative_uses_first_nine_digest_bytes_and_standard_base64() {
        assert_eq!(&derive_xwid(b"abc"), b"kAFQmDzST7DW");
        assert_eq!(&derive_xwid(b""), b"1B2M2Y8AsgTp");
    }
}
