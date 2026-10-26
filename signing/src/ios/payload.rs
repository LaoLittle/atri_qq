#[inline]
pub(crate) fn index_mask(index: usize) -> u8 {
    let value = (index as u32).wrapping_mul(0x9e37_79b9);
    (value ^ (value >> 16)) as u8
}

pub(crate) fn scramble(bytes: &mut [u8]) {
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte ^= index_mask(index);
    }
}

pub fn header_hash(body: &[u8]) -> [u8; 4] {
    let mut hash = 0x4d45_c2ecu32;
    for &byte in body {
        hash = hash.wrapping_mul(33).wrapping_add(u32::from(byte));
    }
    hash ^= hash >> 16;
    hash = hash.wrapping_mul(0x85eb_ca6b);
    hash ^= hash >> 13;
    let mut encoded = hash.to_be_bytes();
    scramble(&mut encoded);
    encoded
}

pub fn checksum(payload: &[u8; 71]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for &byte in payload {
        hash = (hash ^ u32::from(byte))
            .wrapping_mul(0x9e37_79b1)
            .rotate_left(13);
    }
    hash ^ (hash >> 16)
}

pub fn complete(mut payload: [u8; 71]) -> [u8; 75] {
    let header = header_hash(&payload[8..]);
    payload[4..8].copy_from_slice(&header);
    let mut output = [0; 75];
    output[..71].copy_from_slice(&payload);
    output[71..].copy_from_slice(&checksum(&payload).to_le_bytes());
    output
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub protocol: u8,
    pub login: bool,
    pub auxiliary: u8,
    pub counter: u8,
    pub cache_value: u16,
    pub context: [u8; 16],
    pub process_sample: u8,
}

impl Metadata {
    pub fn encode(&self) -> [u8; 24] {
        let mut output = [0; 24];
        output[0] = self.protocol;
        output[1..3].copy_from_slice(&u16::from(self.login).to_be_bytes());
        output[3] = self.auxiliary;
        output[4] = self.counter;
        output[5..7].copy_from_slice(&self.cache_value.to_le_bytes());
        output[7..23].copy_from_slice(&self.context);
        output[23] = self.process_sample;
        let mut state = 0x4d94_2d27u32;
        for chunk in output.chunks_exact_mut(4) {
            state = state.wrapping_mul(0x1b87_3593);
            for (byte, mask) in chunk.iter_mut().zip((state ^ (state >> 15)).to_le_bytes()) {
                *byte ^= mask;
            }
        }
        output
    }
}

pub struct Fields {
    pub flags: [u8; 10],
    pub record_word3: u8,
    pub body_digest: u64,
    pub metadata: Metadata,
    pub status: [u8; 7],
    pub normalized_seed: u32,
    pub random_packet: [u8; 4],
}

pub fn encode(fields: &Fields) -> [u8; 75] {
    let mut flags = fields.flags;
    scramble(&mut flags);
    let mut digest = fields.body_digest.to_le_bytes();
    scramble(&mut digest);
    let mut seed_packet = [0; 8];
    seed_packet[..4].copy_from_slice(&fields.normalized_seed.to_le_bytes());
    seed_packet[4..].copy_from_slice(&fields.random_packet);
    scramble(&mut seed_packet);
    let mut status = fields.status;
    scramble(&mut status);
    let mut output = [0; 71];
    output[1] = 0x80;
    output[2..4].copy_from_slice(&flags[..2]);
    output[8] = 0x20;
    output[9] = 0x40;
    output[10..12].copy_from_slice(&flags[2..4]);
    output[12] = 2;
    output[13] = fields.record_word3 ^ index_mask(1);
    output[14] = 2;
    output[15..17].copy_from_slice(&flags[8..]);
    output[17..25].copy_from_slice(&digest);
    output[25] = 0x10;
    output[26..50].copy_from_slice(&fields.metadata.encode());
    output[50] = 0x90;
    output[51..58].copy_from_slice(&status);
    output[58] = 4;
    output[59..61].copy_from_slice(&flags[6..8]);
    output[61..65].copy_from_slice(&seed_packet[..4]);
    output[65..67].copy_from_slice(&flags[4..6]);
    output[67..71].copy_from_slice(&seed_packet[4..]);
    complete(output)
}
