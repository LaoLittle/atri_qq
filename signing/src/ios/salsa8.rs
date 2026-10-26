fn word(bytes: &[u8; 12], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("four-byte word"),
    )
}

fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[b] ^= x[a].wrapping_add(x[d]).rotate_left(7);
    x[c] ^= x[b].wrapping_add(x[a]).rotate_left(9);
    x[d] ^= x[c].wrapping_add(x[b]).rotate_left(13);
    x[a] ^= x[d].wrapping_add(x[c]).rotate_left(18);
}

pub(super) fn block<const N: usize>(key: &[u8; 12], counter: u64) -> [u8; N] {
    assert!(N <= 64);
    let initial = [
        0xc609_6c57,
        word(key, 3),
        word(key, 4),
        word(key, 1),
        word(key, 2),
        0x37a6_c743,
        word(key, 8),
        0x6ca4_44ef,
        counter as u32,
        (counter >> 32) as u32,
        0x694c_e16a,
        word(key, 0),
        word(key, 4),
        word(key, 3),
        word(key, 2),
        0xaf51_1ca1,
    ];
    let mut x = initial;
    for _ in 0..4 {
        for (a, b, c, d) in [
            (3, 2, 1, 0),
            (6, 5, 4, 7),
            (9, 8, 11, 10),
            (12, 15, 14, 13),
            (3, 7, 11, 15),
            (6, 10, 14, 2),
            (9, 13, 1, 5),
            (12, 0, 4, 8),
        ] {
            quarter_round(&mut x, a, b, c, d);
        }
    }
    let mut output = [0u8; N];
    for (i, chunk) in output.chunks_mut(4).enumerate() {
        let bytes = x[i].wrapping_add(initial[i]).to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    output
}

pub(super) fn apply_keystream(key: &[u8; 12], bytes: &mut [u8]) {
    for (counter, chunk) in bytes.chunks_mut(64).enumerate() {
        let mask = block::<64>(key, counter as u64);
        for (byte, mask) in chunk.iter_mut().zip(mask) {
            *byte ^= mask;
        }
    }
}
