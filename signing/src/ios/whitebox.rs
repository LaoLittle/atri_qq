const TABLES: &[u8; 0x124040] = include_bytes!("../../tables/ios/whitebox.bin");
const SHIFT_ROWS: [usize; 16] = [0, 1, 2, 3, 5, 6, 7, 4, 10, 11, 8, 9, 15, 12, 13, 14];

#[inline]
fn transpose(index: usize) -> usize {
    4 * (index & 3) + (index >> 2)
}

#[inline]
fn combine_into(left: &mut [u8; 16], right: &[u8; 16], offset: usize) {
    for index in 0..16 {
        let a = left[index];
        let b = right[index];
        let high = usize::from((a & 0xf0) | (b >> 4));
        let low = usize::from((a << 4) | (b & 0x0f));
        let base = offset + index * 0x200;
        left[index] = (TABLES[base + high] << 4) | (TABLES[base + 0x100 + low] & 0x0f);
    }
}

#[inline]
fn combine_word(left: u32, right: u32, offset: usize) -> u32 {
    let a = left.to_le_bytes();
    let b = right.to_le_bytes();
    u32::from_le_bytes(std::array::from_fn(|index| {
        let high = usize::from((a[index] & 0xf0) | (b[index] >> 4));
        let low = usize::from((a[index] << 4) | (b[index] & 0x0f));
        let base = offset + index * 0x200;
        (TABLES[base + high] << 4) | (TABLES[base + 0x100 + low] & 0x0f)
    }))
}

#[inline]
fn reduce_words(words: [u32; 4], offset: usize) -> [u8; 4] {
    let left = combine_word(words[0], words[1], offset);
    let right = combine_word(words[2], words[3], offset + 0x800);
    combine_word(left, right, offset + 0x1000).to_le_bytes()
}

#[inline]
fn word(offset: usize) -> u32 {
    u32::from_le_bytes(TABLES[offset..offset + 4].try_into().expect("table word"))
}

fn reduce(mut vectors: [[u8; 16]; 16], pairs: usize, tree: usize) -> [u8; 16] {
    for pair in 0..8 {
        let index = 2 * pair;
        let (left, right) = vectors.split_at_mut(index + 1);
        combine_into(&mut left[index], &right[0], pairs + pair * 0x2000);
    }
    let mut table_index = 0;
    for stride in [2, 4, 8] {
        for index in (0..16).step_by(2 * stride) {
            let (left, right) = vectors.split_at_mut(index + stride);
            combine_into(&mut left[index], &right[0], tree + table_index * 0x2000);
            table_index += 1;
        }
    }
    vectors[0]
}

fn encode_input(state: &[u8; 16]) -> [u8; 16] {
    let mut vectors = [[0; 16]; 16];
    for (index, vector) in vectors.iter_mut().enumerate() {
        let offset = 0xb4040 + index * 0x1000 + usize::from(state[transpose(index)]) * 16;
        vector.copy_from_slice(&TABLES[offset..offset + 16]);
    }
    reduce(vectors, 0x78040, 0x88040)
}

fn central_rounds(state: &mut [u8; 16]) {
    for round in 0..9 {
        let mut next = [0; 16];
        for column in 0..4 {
            let mut words = [0; 4];
            for (row, value) in words.iter_mut().enumerate() {
                let input = state[4 * row + (column + row) % 4];
                let offset =
                    0xd4040 + round * 0x4000 + (4 * column + row) * 0x400 + usize::from(input) * 4;
                *value = word(offset);
            }
            let merge = 0x40 + round * 0xc000 + column * 0x3000;
            let intermediate = reduce_words(words, merge);
            for (row, value) in words.iter_mut().enumerate() {
                let offset = 0xfc040
                    + round * 0x4000
                    + (4 * column + row) * 0x400
                    + usize::from(intermediate[row]) * 4;
                *value = word(offset);
            }
            let output = reduce_words(words, merge + 0x1800);
            for row in 0..4 {
                next[4 * row + column] = output[row];
            }
        }
        *state = next;
    }
}

fn decode_output(state: &[u8; 16]) -> [u8; 16] {
    let mut vectors = [[0; 16]; 16];
    for (index, vector) in vectors.iter_mut().enumerate() {
        let input = state[SHIFT_ROWS[transpose(index)]];
        let offset = 0xc4040 + index * 0x1000 + usize::from(input) * 16;
        vector.copy_from_slice(&TABLES[offset..offset + 16]);
    }
    let reduced = reduce(vectors, 0x96040, 0xa6040);
    std::array::from_fn(|index| reduced[transpose(index)])
}

pub fn transform(block: &mut [u8; 16]) {
    let mut state = encode_input(block);
    central_rounds(&mut state);
    *block = decode_output(&state);
}
