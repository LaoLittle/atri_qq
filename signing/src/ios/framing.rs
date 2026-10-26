use super::whitebox;

pub fn encrypt(
    payload: &[u8; 75],
    iv: &[u8; 16],
    trailer: &[u8; 16],
    steady_nanos: u64,
) -> [u8; 96] {
    let mut output = [0; 96];
    output[..75].copy_from_slice(payload);
    let timestamp = ((steady_nanos / 1_000_000) % 1_000_000) as u32;
    output[75..78].copy_from_slice(&timestamp.to_le_bytes()[..3]);
    output[78..80].fill(5);
    let mut previous = *iv;
    for chunk in output[..80].chunks_exact_mut(16) {
        let mut block = [0; 16];
        for index in 0..16 {
            let transposed = 4 * (index & 3) + (index >> 2);
            block[transposed] = chunk[index] ^ previous[index];
        }
        whitebox::transform(&mut block);
        for index in 0..16 {
            let transposed = 4 * (index & 3) + (index >> 2);
            chunk[index] = block[transposed];
            previous[index] = chunk[index];
        }
    }
    output[80..].copy_from_slice(trailer);
    mix(&mut output);
    output
}

pub fn mix(output: &mut [u8; 96]) {
    let mut previous = 0;
    for offset in 0..48 {
        let left = 47 - offset;
        let right = 48 + offset;
        output[left] ^= previous;
        previous = output[left];
        output[right] ^= previous;
        previous = output[right];
    }
}
