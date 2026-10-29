use rand::RngExt;

use super::xwid::{candidate_from_source, encrypt_blocks, nibble, publish};

#[derive(Clone, PartialEq, Eq)]
pub struct ResourceSample {
    bytes: [u8; 52],
    observed: bool,
}

impl ResourceSample {
    pub fn from_inodes(inodes: &[Option<u64>; 26]) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut bytes = [b'F'; 52];
        let mut observed = false;
        for (index, inode) in inodes.iter().enumerate() {
            if let Some(inode) = inode {
                let value = (*inode % 249) as u8 ^ ((index * 3) % 251) as u8;
                bytes[index * 2] = HEX[usize::from(value >> 4)];
                bytes[index * 2 + 1] = HEX[usize::from(value & 15)];
                observed = true;
            }
        }
        Self { bytes, observed }
    }

    pub fn as_bytes(&self) -> &[u8; 52] {
        &self.bytes
    }

    pub fn has_observations(&self) -> bool {
        self.observed
    }

    pub fn candidate(&self, fallback: &[u8; 32]) -> [u8; 44] {
        candidate_from_source(if self.observed { &self.bytes } else { fallback })
    }

    pub fn secure(&self, unix_seconds: u64, random: &[u8; 5]) -> [u8; 108] {
        let mut blocks = [0; 48];
        blocks[..8].copy_from_slice(b"02060020");
        blocks[8..12].copy_from_slice(&((unix_seconds as u32) ^ 0xde9dc120).to_le_bytes());
        for (index, output) in blocks[12..38].iter_mut().enumerate() {
            let position = index * 2;
            let high = nibble(self.bytes[position]) ^ (position % 15) as u8;
            let low = nibble(self.bytes[position + 1]) ^ ((position + 1) % 15) as u8;
            *output = (high << 4) | low;
        }
        blocks[38..].fill(10);
        encrypt_blocks(&mut blocks, random);
        publish(*b"B4", random, &blocks)
    }

    pub fn random_source<R: rand::Rng + ?Sized>(random: &mut R) -> [u8; 32] {
        std::array::from_fn(|_| source_character(random.random_range(0u8..75)))
    }
}

fn source_character(value: u8) -> u8 {
    let byte = value + b'0';
    match byte {
        b':'..=b'@' => byte - 9,
        b'['..=b'`' => byte - 25,
        _ => byte,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_random_source_character_mapping_covers_all_75_inputs() {
        assert_eq!(
            std::array::from_fn::<_, 75, _>(|index| source_character(index as u8)),
            *b"01234567891234567ABCDEFGHIJKLMNOPQRSTUVWXYZBCDEFGabcdefghijklmnopqrstuvwxyz"
        );
    }

    #[test]
    fn original_inode_scalar_handles_modulo_index_and_full_u64_range() {
        for (index, inode, expected) in [
            (0, 0, *b"00"),
            (0, 248, *b"f8"),
            (1, 249, *b"03"),
            (25, u64::MAX, *b"82"),
            (7, 0x123456789abcdef0, *b"d5"),
        ] {
            let mut inodes = [None; 26];
            inodes[index] = Some(inode);
            let sample = ResourceSample::from_inodes(&inodes);
            assert_eq!(&sample.as_bytes()[index * 2..index * 2 + 2], &expected);
            assert!(sample.has_observations());
        }
    }

    #[test]
    fn unavailable_resource_uses_random_source_without_claiming_an_observation() {
        let sample = ResourceSample::from_inodes(&[None; 26]);
        assert!(!sample.has_observations());
        assert_eq!(
            &sample.candidate(b"0123456789abcdefghijklmnopqrstuv"),
            b"1de0f64996bc7ce4dc28c0593be0335d7707c2Z55XRZ"
        );
        let mut inodes = [None; 26];
        inodes[25] = Some(180);
        let sample = ResourceSample::from_inodes(&inodes);
        assert_eq!(&sample.as_bytes()[50..], b"ff");
        assert!(sample.has_observations());
        assert_eq!(
            sample.candidate(b"0123456789abcdefghijklmnopqrstuv"),
            sample.candidate(b"11111111111111111111111111111111")
        );
    }

    #[test]
    fn complete_original_resource_cipher_matches_full_52_character_inputs() {
        for (source, expected) in [
            (
                *b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                b"B4EF0400AA5AB585E54B8FD2150F9C962CDA5FED4BE7426976906580662CFC8DFF117AA3CEC7DFA54C9EF1BF46DA7E1191EA1CA749F1",
            ),
            (
                *b"0123456789abcdef0123456789abcdef0123456789abcdefABCD",
                b"B4EF0400AA5AE47CB5D213B36154A80D864BBC20D725E54584FE2E84FB4F579570D361D6592C3B152D41F562BF6A182C4305BA972A72",
            ),
        ] {
            let sample = ResourceSample { bytes: source, observed: false };
            assert_eq!(&sample.secure(1700000000, &[239, 4, 0, 170, 90]), expected);
        }
    }
}
