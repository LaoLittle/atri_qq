use super::heartbeat::TaskMaterial;
use crate::{Error, Result, crypto};
use bytes::Bytes;
use md4::{Digest, Md4};
use rand::{TryRng, rngs::SysRng};
use sha2::block_api::compress256;
use sha3::Sha3_512;
use std::time::{SystemTime, UNIX_EPOCH};

const SEED_ALPHABET: &[u8; 16] = b"dkShcIAMWyoG5XPU";
const SEED_SOURCE: &[u8; 240] = b"dkShcIAMWyoG5XPUAIcXIdIkAAhyMhAccUIchAhhIochIhhkAkAcckIAcSMWhMAhhIAkcAA5IycchIAoAcAWAWhcAWcGISMSMycoIhhyMWhMIAMAhkcAIyIkIMhkIIAWcohcMAcMcychcMASMhccMAMoAGAMhIAGMcAPAhIAIMAhIShAcWASAMIyIAAPAccGMhhWcyAAAMAohchhAoAyAocPAIcyAGMyIShhMMhdAcIAAhIW";
const RUNTIME_ALPHABET: &[u8; 50] = b"!#$%&)+.0123456789:=>?@ABCDEFGKMNabcdefghijkopqrst";
const HEX: &[u8; 16] = b"0123456789abcdef";
const TABLE: [u8; 128] = decode_table();
const SUFFIX_SUMS: [u32; 128] = suffix_sums();
const MODIFIED_IV: [u32; 8] = [
    0x6a09a669, 0xba67ae87, 0x7b6bf372, 0xa56cf53a, 0x511e527f, 0x5b25688c, 0x1f73c9ab, 0x3bd0bd19,
];

const fn alphabet_index(byte: u8) -> u8 {
    let mut index = 0;
    while index < SEED_ALPHABET.len() {
        if SEED_ALPHABET[index] == byte {
            return index as u8;
        }
        index += 1;
    }
    panic!("invalid task11 source alphabet")
}

const fn decode_table() -> [u8; 128] {
    let mut table = [0; 128];
    let mut index = 0;
    while index < 16 {
        table[index] = SEED_ALPHABET[index];
        index += 1;
    }
    while index < 128 {
        let offset = 16 + (index - 16) * 2;
        table[index] =
            (alphabet_index(SEED_SOURCE[offset]) << 4) | alphabet_index(SEED_SOURCE[offset + 1]);
        index += 1;
    }
    table
}

const fn suffix_sums() -> [u32; 128] {
    let mut prefix = [0usize; 128];
    let mut index = 1;
    while index < TABLE.len() {
        let mut matched = prefix[index - 1];
        while matched > 0 && TABLE[index] != TABLE[matched] {
            matched = prefix[matched - 1];
        }
        if TABLE[index] == TABLE[matched] {
            matched += 1;
        }
        prefix[index] = matched;
        index += 1;
    }
    let mut suffix = [0; 128];
    let mut sum = 0;
    while index > 0 {
        index -= 1;
        sum += (prefix[index] + index) as u32;
        suffix[index] = sum;
    }
    suffix
}

fn failure(message: impl Into<String>) -> Error {
    Error::Crypto(message.into())
}

fn random_word(random: &mut impl TryRng) -> Result<u32> {
    let mut bytes = [0; 4];
    random
        .try_fill_bytes(&mut bytes)
        .map_err(|error| failure(format!("O3 task11 entropy: {error}")))?;
    Ok(u32::from_le_bytes(bytes))
}

fn random_below(random: &mut impl TryRng, limit: u32) -> Result<u32> {
    let threshold = limit.wrapping_neg() % limit;
    loop {
        let word = random_word(random)?;
        if word >= threshold {
            return Ok(word % limit);
        }
    }
}

#[derive(Default)]
pub(super) struct Generator {
    second: Option<u64>,
    draw: u32,
}

pub(super) struct Job {
    payload: Bytes,
    timestamp: u64,
    draw: u32,
    material: [u8; 255],
    material_length: u8,
    identifier: u32,
    runtime: [u8; 4],
    word: u32,
}

impl Generator {
    pub(super) fn prepare(&mut self, payload: Bytes, cache: &mut TaskMaterial) -> Result<Job> {
        self.prepare_at(payload, cache, SystemTime::now(), &mut SysRng)
    }

    fn prepare_at(
        &mut self,
        payload: Bytes,
        cache: &mut TaskMaterial,
        now: SystemTime,
        random: &mut impl TryRng,
    ) -> Result<Job> {
        if payload.is_empty() {
            return Err(failure("O3 task11 nonempty job requires a payload"));
        }
        let length = u64::try_from(payload.len())
            .map_err(|_| failure("O3 task11 payload length exceeds u64"))?;
        length
            .checked_add(64)
            .and_then(|length| length.checked_mul(8))
            .ok_or_else(|| failure("O3 task11 payload exceeds SHA256 length limit"))?;
        let material_length = u8::try_from(cache.material.len())
            .map_err(|_| failure("O3 task11 material exceeds 255 bytes"))?;
        let elapsed = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| failure("O3 task11 clock precedes Unix epoch"))?;
        let timestamp = u64::try_from(elapsed.as_millis())
            .map_err(|_| failure("O3 task11 millisecond timestamp exceeds u64"))?;
        if timestamp < 100 {
            return Err(failure(
                "O3 task11 timestamp requires at least three decimal digits",
            ));
        }
        let second = elapsed.as_secs();
        let draw = if self.second == Some(second) {
            self.draw
        } else {
            random_word(random)? & 0x7fff_ffff
        };
        let runtime = if cache.runtime[0] == 0 {
            let a = RUNTIME_ALPHABET[random_below(random, 50)? as usize];
            let b = RUNTIME_ALPHABET[random_below(random, 50)? as usize];
            let q = 1 + 2 * random_below(random, 4)? as u8;
            [a, b, a + q, b + 9 - q]
        } else {
            cache.runtime[..4].try_into().unwrap()
        };
        let mut material = [0; 255];
        material[..cache.material.len()].copy_from_slice(&cache.material);
        self.second = Some(second);
        self.draw = draw;
        cache.runtime[..4].copy_from_slice(&runtime);
        Ok(Job {
            payload,
            timestamp,
            draw,
            material,
            material_length,
            identifier: cache.identifier,
            runtime,
            word: cache.word,
        })
    }
}

fn seed(draw: u32) -> [u8; 10] {
    let start = (draw & 127) as usize;
    let value = SUFFIX_SUMS[start];
    let mut seed = [0; 10];
    for (index, byte) in seed[..4].iter_mut().enumerate() {
        *byte = HEX[((value >> ((3 - index) * 4)) & 15) as usize];
    }
    let mut n = 2u32;
    for _ in 0..draw % 5 + 1 {
        let candidate = n + u32::from(TABLE[start]);
        if candidate >= 256 {
            break;
        }
        n = candidate;
    }
    let x = f64::from(n - 1) / f64::from(n + 1);
    let mut sum = 0.0f64;
    let mut previous = 1.0;
    let mut k = 1;
    while previous > 1e-9 {
        let exponent = f64::from(2 * k - 1);
        let term = (2.0 * x.powf(exponent)) / exponent;
        sum += term;
        previous = term;
        k += 1;
    }
    let decimal = ((sum - sum.trunc()) * 1000.0).trunc() as u32;
    seed[4] = b'0' + (decimal / 100) as u8;
    seed[5] = b'0' + (decimal / 10 % 10) as u8;
    seed[6] = b'0' + (decimal % 10) as u8;
    seed[7] = HEX[(n >> 4) as usize];
    seed[8] = HEX[(n & 15) as usize];
    let mut checksum = seed[0];
    for byte in &seed[..9] {
        for _ in 0..8 {
            checksum = (checksum << 1) ^ if checksum & 0x80 != 0 { 0x83 } else { 0 };
        }
        checksum ^= byte;
    }
    seed[9] = SEED_ALPHABET[(checksum & 15) as usize];
    seed
}

fn lower_hex<const N: usize>(input: &[u8], output: &mut [u8; N]) {
    for (byte, pair) in input.iter().zip(output.chunks_exact_mut(2)) {
        pair[0] = HEX[(byte >> 4) as usize];
        pair[1] = HEX[(byte & 15) as usize];
    }
}

fn key(seed: &[u8; 10], timestamp: u64) -> [u8; 20] {
    let mut sorted = *seed;
    sorted.sort_unstable();
    let mut unique_length = 0;
    for index in 0..sorted.len() {
        if unique_length == 0 || sorted[index] != sorted[unique_length - 1] {
            sorted[unique_length] = sorted[index];
            unique_length += 1;
        }
    }
    let mut digest_hex = [0; 64];
    lower_hex(&crypto::sha256(seed), &mut digest_hex);
    let mut prefix = [0; 13];
    let milliseconds = timestamp % 1000;
    prefix[0] = b'0' + (milliseconds / 100) as u8;
    prefix[1] = b'0' + (milliseconds / 10 % 10) as u8;
    prefix[2] = b'0' + (milliseconds % 10) as u8;
    for (index, byte) in seed.iter().enumerate() {
        let rank = sorted[..unique_length]
            .iter()
            .position(|value| value == byte)
            .unwrap();
        prefix[index + 3] = digest_hex[10 * (rank / 5 + 1) + rank % 5 + 1];
    }
    let mut key = [0; 20];
    key[..13].copy_from_slice(&prefix);
    lower_hex(&crypto::sha256(&prefix), &mut digest_hex);
    key[13..].copy_from_slice(&digest_hex[9..16]);
    key
}

fn modified_sha256(parts: &[&[u8]]) -> Result<[u8; 32]> {
    let mut length = 0u64;
    for part in parts {
        length = length
            .checked_add(
                u64::try_from(part.len())
                    .map_err(|_| failure("O3 task11 hash length exceeds u64"))?,
            )
            .ok_or_else(|| failure("O3 task11 hash length overflow"))?;
    }
    let bit_length = length
        .checked_mul(8)
        .ok_or_else(|| failure("O3 task11 hash exceeds SHA256 length limit"))?;
    let mut state = MODIFIED_IV;
    let mut block = [0; 64];
    let mut used = 0;
    for mut part in parts.iter().copied() {
        if used != 0 {
            let taken = (64 - used).min(part.len());
            block[used..used + taken].copy_from_slice(&part[..taken]);
            used += taken;
            part = &part[taken..];
            if used == 64 {
                compress256(&mut state, std::slice::from_ref(&block));
                used = 0;
            }
        }
        let (blocks, remainder) = part.as_chunks::<64>();
        compress256(&mut state, blocks);
        if !remainder.is_empty() {
            block[..remainder.len()].copy_from_slice(remainder);
            used = remainder.len();
        }
    }
    block[used] = 0x80;
    block[used + 1..].fill(0);
    if used >= 56 {
        compress256(&mut state, std::slice::from_ref(&block));
        block.fill(0);
    }
    block[56..].copy_from_slice(&bit_length.to_be_bytes());
    compress256(&mut state, std::slice::from_ref(&block));
    let mut output = [0; 32];
    for (word, bytes) in state.iter().zip(output.chunks_exact_mut(4)) {
        bytes.copy_from_slice(&word.to_be_bytes());
    }
    Ok(output)
}

fn digest9(key: &[u8; 20], payload: &[u8]) -> Result<[u8; 32]> {
    let mut pad = [0x36; 64];
    for (byte, key) in pad.iter_mut().zip(key) {
        *byte ^= key;
    }
    let inner = modified_sha256(&[&pad, payload])?;
    for byte in &mut pad {
        *byte ^= 0x36 ^ 0x5c;
    }
    modified_sha256(&[&pad, &inner])
}

fn digest10(key: &[u8; 20], payload: &[u8]) -> [u8; 16] {
    let mut input = [0; 16];
    let prefix_length = payload.len().min(8);
    input[..prefix_length].copy_from_slice(&payload[..prefix_length]);
    input[8..].copy_from_slice(&key[..8]);
    let inner = Md4::digest(input);
    let mut outer = [0; 12];
    outer[..4].copy_from_slice(&(crc32fast::hash(key) ^ crc32fast::hash(payload)).to_be_bytes());
    outer[4..].copy_from_slice(&inner[..8]);
    crypto::md5(&outer)
}

fn digest11(material: &[u8], payload: &[u8]) -> [u8; 16] {
    let mut output = [0; 16];
    output[..8].copy_from_slice(&Sha3_512::digest(payload)[..8]);
    output[8..].copy_from_slice(&crypto::md5(material)[..8]);
    output
}

fn tlv(output: &mut Vec<u8>, tag: u16, value: &[u8]) {
    output.extend_from_slice(&tag.to_be_bytes());
    output.extend_from_slice(&(value.len() as u16).to_be_bytes());
    output.extend_from_slice(value);
}

impl Job {
    pub(super) fn execute(self) -> Result<Vec<u8>> {
        let seed = seed(self.draw);
        let key = key(&seed, self.timestamp);
        let digest9 = digest9(&key, &self.payload)?;
        let digest10 = digest10(&key, &self.payload);
        let material = &self.material[..usize::from(self.material_length)];
        let effective_id = if material.is_empty() {
            0
        } else {
            self.identifier
        };
        let effective_material = if material.is_empty() {
            &key[..]
        } else {
            material
        };
        let digest11 = digest11(effective_material, &self.payload);
        let mut output = Vec::with_capacity(215);
        output.extend_from_slice(b"heha\0\0\0\0\x04");
        output.extend_from_slice(&2u64.to_be_bytes());
        output.extend_from_slice(&0x0200_0018u32.to_be_bytes());
        output.extend_from_slice(&[0; 8]);
        output.extend_from_slice(&2u32.to_be_bytes());
        output.extend_from_slice(&166u32.to_be_bytes());
        tlv(&mut output, 6, &1u32.to_be_bytes());
        tlv(&mut output, 9, &digest9);
        tlv(&mut output, 7, &0x0200_0004u32.to_be_bytes());
        tlv(&mut output, 10, &digest10);
        tlv(&mut output, 8, &0x0200_0005u32.to_be_bytes());
        tlv(&mut output, 11, &digest11);
        tlv(&mut output, 4, &effective_id.to_be_bytes());
        tlv(&mut output, 5, &0x0200_0001u32.to_be_bytes());
        tlv(&mut output, 3, &0x0200_0001u32.to_be_bytes());
        tlv(&mut output, 2, &seed);
        tlv(&mut output, 1, &self.timestamp.to_be_bytes());
        tlv(&mut output, 12, &0x0200_0001u32.to_be_bytes());
        tlv(&mut output, 13, &0u32.to_be_bytes());
        let crc = crc32fast::hash(&output[29..]);
        output[25..29].copy_from_slice(&crc.to_be_bytes());
        output.extend_from_slice(&self.identifier.to_be_bytes());
        output.extend_from_slice(&self.runtime);
        output.extend_from_slice(&self.word.to_le_bytes());
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;
    use std::time::Duration;

    fn job(payload: &[u8], material: &[u8]) -> Job {
        let mut snapshot = [0; 255];
        snapshot[..material.len()].copy_from_slice(material);
        Job {
            payload: Bytes::copy_from_slice(payload),
            timestamp: 1_792_952_031_123,
            draw: 0,
            material: snapshot,
            material_length: material.len() as u8,
            identifier: 7,
            runtime: [0x21, 0x74, 0x28, 0x76],
            word: 1,
        }
    }

    fn tag(output: &[u8], wanted: u16) -> &[u8] {
        let mut offset = 37;
        while offset < 203 {
            let tag = u16::from_be_bytes(output[offset..offset + 2].try_into().unwrap());
            let length = usize::from(u16::from_be_bytes(
                output[offset + 2..offset + 4].try_into().unwrap(),
            ));
            offset += 4;
            let value = &output[offset..offset + length];
            if tag == wanted {
                return value;
            }
            offset += length;
        }
        panic!("missing task11 tag")
    }

    #[test]
    fn original_nonempty_frames_match_every_byte() {
        let material: [u8; 32] = std::array::from_fn(|index| index as u8);
        let payload: [u8; 129] = std::array::from_fn(|index| index as u8);
        for (payload, material, expected) in [
            (
                b"A".as_slice(),
                b"".as_slice(),
                "6865686100000000040000000000000002020000180000000062833d2900000002000000a6000600040000000100090020382260572bd177a427fd439b1501fea34dbd876a2e081c8c13e19b688474363f0007000402000004000a0010c1f9a95db830ef974aa1a3db3bec39e10008000402000005000b0010f5f0eaa9ca3fd0c476e38c577576d3040004000400000000000500040200000100030004020000010002000a3166633536323436366800010008000001a17444d793000c000402000001000d000400000000000000072174287601000000",
            ),
            (
                payload.as_slice(),
                material.as_slice(),
                "6865686100000000040000000000000002020000180000000021406b3d00000002000000a60006000400000001000900205fb54b607a2f4b1c881f54c153e7d3768ae40acaddcdd74dbf5b3ee47e77d0080007000402000004000a0010cf225658ffc16a58bd5aeaa93c4a71880008000402000005000b00104d8f28ea5211c66ab4ffcb23737cec310004000400000007000500040200000100030004020000010002000a3166633536323436366800010008000001a17444d793000c000402000001000d000400000000000000072174287601000000",
            ),
        ] {
            assert_eq!(
                job(payload, material).execute().unwrap(),
                hex::decode(expected).unwrap()
            );
        }
    }

    #[test]
    fn original_seed_boundaries_match() {
        for (draw, expected) in [
            (0, b"1fc562466h"),
            (1, b"1fc5375d8c"),
            (127, b"007f181b2c"),
            (128, b"1fc5308caU"),
            (2_147_483_647, b"007f181b2c"),
        ] {
            assert_eq!(&seed(draw), expected);
        }
    }

    #[test]
    fn payload_boundaries_and_embedded_nuls_are_hashed_in_full() {
        for length in [1, 8, 16, 55, 56, 64, 65, 129] {
            let first = vec![0; length];
            let mut second = first.clone();
            second[length - 1] = 0xff;
            let first = job(&first, b"material").execute().unwrap();
            let second = job(&second, b"material").execute().unwrap();
            assert_eq!(first.len(), 215);
            assert_eq!(second.len(), 215);
            for digest in [9, 10, 11] {
                assert_ne!(tag(&first, digest), tag(&second, digest));
            }
            assert_eq!(&tag(&first, 11)[8..], &tag(&second, 11)[8..]);
            for output in [&first, &second] {
                assert_eq!(
                    u32::from_be_bytes(output[25..29].try_into().unwrap()),
                    crc32fast::hash(&output[29..203]),
                );
            }
        }
    }

    #[test]
    fn material_fallback_keeps_actual_identifier_in_trailer() {
        let fallback = job(b"A", b"").execute().unwrap();
        let with_material = job(b"A", b"XY").execute().unwrap();
        assert_eq!(tag(&fallback, 4), 0u32.to_be_bytes());
        assert_eq!(tag(&with_material, 4), 7u32.to_be_bytes());
        assert_eq!(&fallback[203..207], &with_material[203..207]);
        assert_ne!(&tag(&fallback, 11)[8..], &tag(&with_material, 11)[8..]);
        for unchanged in [1, 2, 9, 10] {
            assert_eq!(tag(&fallback, unchanged), tag(&with_material, unchanged));
        }
    }

    #[test]
    fn prepared_job_owns_material_word_and_runtime_snapshot() {
        let mut generator = Generator::default();
        let mut random = ChaCha12Rng::seed_from_u64(11);
        let mut cache = TaskMaterial {
            identifier: 7,
            material: b"before".to_vec(),
            word: 0x0102_0304,
            runtime: [0x21, 0x74, 0x28, 0x76, 9, 8, 7, 6],
            ..TaskMaterial::default()
        };
        let now = UNIX_EPOCH + Duration::from_millis(1_792_952_031_123);
        let before = generator
            .prepare_at(Bytes::from_static(b"A"), &mut cache, now, &mut random)
            .unwrap();
        cache.identifier = 8;
        cache.material.fill(0xff);
        cache.word = 0x0506_0708;
        cache.runtime[..4].fill(0x44);
        let after = generator
            .prepare_at(Bytes::from_static(b"A"), &mut cache, now, &mut random)
            .unwrap();
        let before = before.execute().unwrap();
        let after = after.execute().unwrap();
        assert_eq!(tag(&before, 4), 7u32.to_be_bytes());
        assert_eq!(tag(&after, 4), 8u32.to_be_bytes());
        assert_eq!(
            &before[203..],
            &[0, 0, 0, 7, 0x21, 0x74, 0x28, 0x76, 4, 3, 2, 1]
        );
        assert_eq!(
            &after[203..],
            &[0, 0, 0, 8, 0x44, 0x44, 0x44, 0x44, 8, 7, 6, 5]
        );
        assert_ne!(&tag(&before, 11)[8..], &tag(&after, 11)[8..]);
        assert_eq!(tag(&before, 9), tag(&after, 9));
    }

    #[test]
    fn same_second_reuses_seed_and_runtime_without_consuming_entropy() {
        let mut generator = Generator::default();
        let mut random = ChaCha12Rng::seed_from_u64(11);
        let mut cache = TaskMaterial {
            runtime: [0, 0, 0, 0, 9, 8, 7, 6],
            ..TaskMaterial::default()
        };
        let now = UNIX_EPOCH + Duration::from_millis(1_792_952_031_123);
        let first = generator
            .prepare_at(Bytes::from_static(b"A"), &mut cache, now, &mut random)
            .unwrap();
        let runtime = cache.runtime;
        let mut untouched = random.clone();
        let second = generator
            .prepare_at(
                Bytes::from_static(b"A"),
                &mut cache,
                now + Duration::from_millis(1),
                &mut random,
            )
            .unwrap();
        assert_eq!(random.next_u64(), untouched.next_u64());
        assert_eq!(cache.runtime, runtime);
        assert_eq!(&runtime[4..], &[9, 8, 7, 6]);
        assert!(RUNTIME_ALPHABET.contains(&runtime[0]));
        assert!(RUNTIME_ALPHABET.contains(&runtime[1]));
        let q = runtime[2] - runtime[0];
        assert!([1, 3, 5, 7].contains(&q));
        assert_eq!(runtime[3] - runtime[1], 9 - q);
        let first = first.execute().unwrap();
        let second = second.execute().unwrap();
        assert_eq!(tag(&first, 2), tag(&second, 2));
        assert_ne!(tag(&first, 1), tag(&second, 1));
        assert_ne!(tag(&first, 9), tag(&second, 9));
        let next_draw = random_word(&mut untouched).unwrap() & 0x7fff_ffff;
        let third = generator
            .prepare_at(
                Bytes::from_static(b"A"),
                &mut cache,
                now + Duration::from_secs(1),
                &mut random,
            )
            .unwrap()
            .execute()
            .unwrap();
        assert_eq!(tag(&third, 2), seed(next_draw));
        assert_eq!(cache.runtime, runtime);
        assert_eq!(random.next_u64(), untouched.next_u64());
    }

    #[test]
    fn invalid_local_inputs_do_not_mutate_state_or_consume_entropy() {
        let mut generator = Generator::default();
        let mut random = ChaCha12Rng::seed_from_u64(11);
        let mut cache = TaskMaterial::default();
        let mut untouched = random.clone();
        for now in [
            UNIX_EPOCH - Duration::from_secs(1),
            UNIX_EPOCH,
            UNIX_EPOCH + Duration::from_millis(99),
        ] {
            assert!(
                generator
                    .prepare_at(Bytes::from_static(b"A"), &mut cache, now, &mut random)
                    .is_err()
            );
            assert_eq!(cache, TaskMaterial::default());
            assert!(generator.second.is_none());
        }
        let now = UNIX_EPOCH + Duration::from_millis(100);
        assert!(
            generator
                .prepare_at(Bytes::new(), &mut cache, now, &mut random)
                .is_err()
        );
        cache.material = vec![0; 256];
        assert!(
            generator
                .prepare_at(Bytes::from_static(b"A"), &mut cache, now, &mut random)
                .is_err()
        );
        assert!(generator.second.is_none());
        assert_eq!(random.next_u64(), untouched.next_u64());
    }
}
