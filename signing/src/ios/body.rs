use super::word_stream::Context;

pub fn derive_key(packet: &[u8; 4]) -> [u8; 8] {
    let mut mixed = 0u64;
    for counter in 0u32..64 {
        let mut value = 0xcafe_babeu64;
        for byte in packet
            .iter()
            .chain([0x16, 0xac, 0x23, 0x4b].iter())
            .chain(counter.to_le_bytes().iter())
        {
            value = ((value << 5) ^ (value >> 3) ^ u64::from(*byte))
                .wrapping_add(0x55aa_55aa_55aa_55aa);
        }
        mixed ^= value;
    }
    let mut key = mixed.to_le_bytes();
    for pair in 0..3 {
        key[2 * pair] = key[2 * pair + 2];
        key[2 * pair + 1] = key[2 * pair + 3];
        key[pair] ^= key[7 - pair];
    }
    key.rotate_right(2);
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = (*byte ^ (0x3f + index as u8)).rotate_left(3) ^ (index as u8).wrapping_mul(0x37);
    }
    key[4..].rotate_right(2);
    for (index, byte) in key[4..].iter_mut().enumerate() {
        *byte = (*byte ^ (0xb7 + index as u8)).rotate_left(3) ^ (index as u8).wrapping_mul(0x37);
    }
    key
}

pub fn random_word(seed: u32) -> u32 {
    let state = if seed == 0 { 123_459_876 } else { seed };
    (u64::from(state) * 16_807 % 2_147_483_647) as u32
}

pub fn random_packet(seed: u32) -> [u8; 4] {
    let mut state = seed;
    let first: [u8; 3] = std::array::from_fn(|_| {
        state = random_word(state);
        state as u8
    });
    state = seed.wrapping_add(500);
    let second: [u8; 3] = std::array::from_fn(|_| {
        state = random_word(state);
        state as u8
    });
    let mut checksum = 0u8;
    for byte in first {
        checksum ^= byte ^ 0xe7;
        for _ in 0..8 {
            checksum = (checksum << 1) ^ if checksum & 0x80 != 0 { 7 } else { 0 };
        }
    }
    [
        first[0],
        first[1],
        first[2],
        checksum.wrapping_add(u8::from(first == second)),
    ]
}

fn initialize(key: &[u8; 8]) -> Context {
    let k0 = u32::from_le_bytes(key[..4].try_into().expect("key word"));
    let k1 = u32::from_le_bytes(key[4..].try_into().expect("key word"));
    let s = [
        k0, k1, 0, 0, 0, 0, k0, k1, 0, 0, 0, 0, k0, k1, 0, 0, 0, 0, k0, k1, k0, k1, 0, 0, 0, 0, 0,
        0, 0, 0, k0, k1,
    ];
    let mut state = Context {
        s,
        high: 0,
        low: 0,
        setup_position: 0,
        saved_state: s,
        flag: 1,
        size_selector: 128,
    };
    state.inject_and_mix(&[
        0x3a, 0xe7, 0x5b, 0xc4, 0x89, 0x15, 0xf2, 0x6c, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    state
}

pub fn hash(key: &[u8; 8], input: &[u8]) -> u64 {
    let mut state = initialize(key);
    let mut value = 0xd724_bfb6_d0f8_c8d8u64;
    for &byte in input {
        let encrypted = byte ^ state.sample_byte();
        value = value.wrapping_mul(127).wrapping_add(u64::from(encrypted));
    }
    value ^= value >> 33;
    value = value.wrapping_mul(0xac58_456d_3ed2_e5b9);
    value ^= value >> 31;
    value ^ (value >> 32)
}
