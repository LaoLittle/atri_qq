use crate::digest::seeded_random_word;

#[derive(Clone, Copy, Debug)]
pub enum EntropyRead {
    Unavailable,
    ShortRead([u8; 16]),
    Complete([u8; 16]),
}

#[derive(Clone, Copy, Debug)]
pub struct MetadataResources {
    pub checksum_seconds: u32,
    pub trailer_seconds: u32,
    pub entropy_read: EntropyRead,
}

#[derive(Clone, Debug, Default)]
pub struct MetadataState {
    mixed_identifier_cache: [u8; 16],
}

impl MetadataState {
    pub const fn new() -> Self {
        Self {
            mixed_identifier_cache: [0; 16],
        }
    }

    pub const fn with_cached_resource(cached_resource: [u8; 16]) -> Self {
        Self {
            mixed_identifier_cache: cached_resource,
        }
    }

    pub fn requires_entropy(&self) -> bool {
        self.mixed_identifier_cache.iter().all(|&byte| byte == 0)
    }

    pub fn cached_resource(&self) -> &[u8; 16] {
        &self.mixed_identifier_cache
    }

    pub fn encode(
        &mut self,
        prepared: &[u8; 21],
        counter: u16,
        machine_id: &[u8],
        uin: &[u8],
        resources: MetadataResources,
    ) -> [u8; 46] {
        let checksum_random = if machine_id.is_empty() {
            0
        } else {
            seeded_random_word(resources.checksum_seconds)
        };
        let trailer_random = if uin.len() < 3 {
            0
        } else if !machine_id.is_empty() && resources.checksum_seconds == resources.trailer_seconds
        {
            checksum_random
        } else {
            seeded_random_word(resources.trailer_seconds)
        };
        let checksum = machine_id_checksum(machine_id, checksum_random);
        let mixed_identifier = if self.mixed_identifier_cache.iter().any(|&byte| byte != 0) {
            self.mixed_identifier_cache
        } else {
            match resources.entropy_read {
                EntropyRead::Unavailable => [0; 16],
                EntropyRead::ShortRead(bytes) => bytes,
                EntropyRead::Complete(mut bytes) => {
                    for (index, &byte) in machine_id.iter().enumerate() {
                        bytes[index & 15] ^= byte;
                    }
                    for (index, &byte) in uin.iter().enumerate() {
                        bytes[index & 15] ^= byte;
                    }
                    self.mixed_identifier_cache = bytes;
                    bytes
                }
            }
        };
        let trailer = if uin.len() >= 3 {
            let index = trailer_random as usize % uin.len();
            (uin[index] << 4) | (index as u8 & 15)
        } else {
            0xee
        };
        let mut plaintext = [0; 46];
        plaintext[..19].copy_from_slice(&prepared[2..]);
        plaintext[19] = 6;
        plaintext[20..22].copy_from_slice(&counter.to_le_bytes());
        plaintext[22..24].copy_from_slice(&checksum.to_le_bytes());
        plaintext[28..44].copy_from_slice(&mixed_identifier);
        plaintext[44] = trailer;
        plaintext
    }
}

pub fn machine_id_checksum(machine_id: &[u8], random_word: u32) -> u16 {
    if machine_id.is_empty() {
        return 0x00ff;
    }
    let initial_index = random_word as usize % machine_id.len();
    let mut index = initial_index;
    for _ in 0..8 {
        if machine_id[index].is_ascii_alphanumeric() {
            break;
        }
        index = if initial_index == 0 {
            0
        } else {
            (index + 1) % initial_index
        };
    }
    let byte = i32::from(machine_id[index]);
    let value = if byte <= i32::from(b'9') {
        byte - i32::from(b'0')
    } else if byte <= i32::from(b'Z') {
        byte - i32::from(b'A') + 10
    } else {
        byte - i32::from(b'a') + 36
    };
    (((index as u32) << 8) | value as u32) as u16
}
