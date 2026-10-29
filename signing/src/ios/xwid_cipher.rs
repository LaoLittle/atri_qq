const TABLES: &[u8; 1280] = include_bytes!("../../tables/ios/xwid-sbox.bin");

pub(super) struct Cipher {
    expanded: [u8; 176],
    substitution: &'static [u8],
}

impl Cipher {
    pub(super) fn new(key: &[u8; 16]) -> Self {
        let offset = usize::from(key[4] % 5) * 256;
        let substitution = &TABLES[offset..offset + 256];
        let mut expanded = [0; 176];
        expanded[..16].copy_from_slice(key);
        let mut round_constant = 1;
        for position in (16..176).step_by(4) {
            let mut word = [
                expanded[position - 4],
                expanded[position - 3],
                expanded[position - 2],
                expanded[position - 1],
            ];
            if position % 16 == 0 {
                word.rotate_left(1);
                for byte in &mut word {
                    *byte = substitution[usize::from(*byte)];
                }
                word[0] ^= round_constant;
                round_constant = xtime(round_constant);
            }
            for index in 0..4 {
                expanded[position + index] = expanded[position - 16 + index] ^ word[index];
            }
        }
        Self {
            expanded,
            substitution,
        }
    }

    pub(super) fn encrypt(&self, block: &mut [u8; 16]) {
        for (byte, key) in block.iter_mut().zip(&self.expanded[..16]) {
            *byte ^= key;
        }
        for round in 1..=10 {
            for byte in &mut *block {
                *byte = self.substitution[usize::from(*byte)];
            }
            let first = block[1];
            block[1] = block[5];
            block[5] = block[9];
            block[9] = block[13];
            block[13] = first;
            block.swap(2, 10);
            block.swap(6, 14);
            let last = block[15];
            block[15] = block[11];
            block[11] = block[7];
            block[7] = block[3];
            block[3] = last;
            if round != 10 {
                for column in block.chunks_exact_mut(4) {
                    let sum = column[0] ^ column[1] ^ column[2] ^ column[3];
                    let first = column[0];
                    column[0] ^= sum ^ xtime(column[0] ^ column[1]);
                    column[1] ^= sum ^ xtime(column[1] ^ column[2]);
                    column[2] ^= sum ^ xtime(column[2] ^ column[3]);
                    column[3] ^= sum ^ xtime(column[3] ^ first);
                }
            }
            for (byte, key) in block
                .iter_mut()
                .zip(&self.expanded[round * 16..(round + 1) * 16])
            {
                *byte ^= key;
            }
        }
    }
}

fn xtime(value: u8) -> u8 {
    (value << 1) ^ if value & 0x80 != 0 { 0x1b } else { 0 }
}
