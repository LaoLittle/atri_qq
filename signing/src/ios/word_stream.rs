#[path = "word_stream_tables.rs"]
mod tables;

use tables::{A, B};

pub const NATIVE_CONTEXT_BYTES: usize = 0x114;
pub const BLOCK_BYTES: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context {
    pub s: [u32; 32],
    pub high: u32,
    pub low: u32,
    pub setup_position: u32,
    pub saved_state: [u32; 32],
    pub flag: u8,
    pub size_selector: u32,
}

impl Context {
    pub fn from_native_bytes(bytes: &[u8; NATIVE_CONTEXT_BYTES]) -> Self {
        Self {
            s: core::array::from_fn(|i| read_word(bytes, i * 4)),
            high: read_word(bytes, 0x80),
            low: read_word(bytes, 0x84),
            setup_position: read_word(bytes, 0x88),
            saved_state: core::array::from_fn(|i| read_word(bytes, 0x8c + i * 4)),
            flag: bytes[0x10c],
            size_selector: read_word(bytes, 0x110),
        }
    }

    pub fn write_native_bytes(&self, bytes: &mut [u8; NATIVE_CONTEXT_BYTES]) {
        for i in 0..32 {
            write_word(bytes, i * 4, self.s[i]);
            write_word(bytes, 0x8c + i * 4, self.saved_state[i]);
        }
        write_word(bytes, 0x80, self.high);
        write_word(bytes, 0x84, self.low);
        write_word(bytes, 0x88, self.setup_position);
        bytes[0x10c] = self.flag;
        write_word(bytes, 0x110, self.size_selector);
    }

    pub fn inject_and_mix(&mut self, iv: &[u8]) {
        let iv_bytes = if self.size_selector == 128 { 16 } else { 32 };
        assert!(
            iv.len() >= iv_bytes,
            "IV is shorter than the context selector requires"
        );

        if self.flag == 0 {
            self.s = self.saved_state;
        }
        if self.size_selector == 128 {
            for i in 0..4 {
                let v = read_word(iv, i * 4);
                self.s[8 + i] = v;
                self.s[20 + i] ^= v;
                self.s[28 + i] ^= v;
            }
            for i in 0..2 {
                let v = read_word(iv, (i + 2) * 4);
                self.s[4 + i] ^= v;
                self.s[12 + i] ^= v;
                self.s[24 + i] = v;
                let v = read_word(iv, i * 4);
                self.s[6 + i] ^= v;
                self.s[14 + i] ^= v;
                self.s[26 + i] = v;
            }
        } else {
            for i in 0..8 {
                let v = read_word(iv, i * 4);
                self.s[8 + i] ^= v;
                self.s[16 + i] ^= !v;
                self.s[24 + i] = v;
            }
        }

        let mut a = 0x2243_2775u32;
        let mut b = 0x3c56_9f6du32;
        for _ in 0..16 {
            let p = self.setup_position;
            let r = |k| self.s[index(p, k)];
            let u = r(1) ^ r(24) ^ r(28);
            let v = r(2) ^ r(26) ^ r(30);
            let q = u ^ r(3) ^ r(25) ^ r(29);
            let r = v ^ r(0) ^ r(27) ^ r(31);
            let z = a ^ b;
            let x = v.wrapping_add(q);
            let y = r.wrapping_add(a);
            let w = u.wrapping_add(z);
            let h = z ^ f1(x);
            let i = q ^ f2(y);
            let j = r ^ f3(w);
            let yy = y ^ f4(h);
            let ww = w ^ f5(i);
            let xx = x ^ f6(j);

            let new_p = p.wrapping_add(28);
            self.setup_position = new_p;
            b = xx.wrapping_add(h);
            self.s[index(p, 28)] = self.s[index(p, 16)] ^ ww ^ b;
            let t = yy.wrapping_add(i);
            self.s[index(new_p, 3)] = self.s[index(new_p, 22)] ^ t;
            self.s[index(new_p, 2)] = self.s[index(new_p, 21)] ^ xx ^ t;
            let k = ww.wrapping_add(j);
            self.s[index(new_p, 1)] = self.s[index(new_p, 23)] ^ k;
            a = k ^ yy;
        }
        self.high = a;
        self.low = b;
        self.flag = 0;
    }

    pub fn generate_blocks(&mut self, out: &mut [[u8; BLOCK_BYTES]]) {
        assert!(
            out.len() <= (u32::MAX / 16) as usize,
            "native output unit count overflows"
        );
        let high = self.high;
        let initial_low = self.low;
        for (block_index, block) in out.iter_mut().enumerate() {
            let base = initial_low.wrapping_add((block_index as u32).wrapping_mul(16));
            self.generate_block::<true>(base, high, block);
        }
        let new_low = initial_low.wrapping_add((out.len() as u32).wrapping_mul(16));
        if new_low < initial_low {
            self.high = high.wrapping_add(1);
        }
        self.low = new_low;
    }

    pub fn sample_byte(&mut self) -> u8 {
        let initial_low = self.low;
        let first = self.generate_block::<false>(initial_low, self.high, &mut []);
        self.low = initial_low.wrapping_add(16);
        if self.low < initial_low {
            self.high = self.high.wrapping_add(1);
        }
        first
    }

    fn generate_block<const FULL_OUTPUT: bool>(
        &mut self,
        base: u32,
        high: u32,
        output: &mut [u8],
    ) -> u8 {
        let mut first = 0;
        for (step, &(n, a, b, c, d)) in TAPS.iter().enumerate() {
            let av = self.s[a];
            let bv = self.s[b];
            let z = self.s[n] ^ high;
            let x = self.s[c] ^ av;
            let y = self.s[d] ^ bv;
            let t = self.s[n + 1] ^ z ^ base.wrapping_add(step as u32);
            let xx = x.wrapping_add(bv);
            let yy = y.wrapping_add(z);
            let ww = t.wrapping_add(av);
            let h = t ^ f1(xx);
            let i = x ^ f2(yy);
            let j = y ^ f3(ww);
            let y2 = yy ^ f4(h);
            let w2 = ww ^ f5(i);
            let x2 = xx ^ f6(j);
            let sum = y2.wrapping_add(i);
            let other = x2 ^ sum;
            if step < 14 {
                self.s[n] = sum;
                self.s[n + 1] = other;
            } else if step == 14 {
                self.s[3] = other;
            } else {
                self.s[1] = sum;
                self.s[2] = other;
            }
            if FULL_OUTPUT {
                write_word(output, step * 8, x2.wrapping_add(h) ^ w2);
                write_word(output, step * 8 + 4, w2.wrapping_add(j) ^ y2);
            } else if step == 0 {
                first = (x2.wrapping_add(h) ^ w2) as u8;
            }
        }
        first
    }
}

const TAPS: [(usize, usize, usize, usize, usize); 16] = [
    (30, 0, 16, 9, 19),
    (28, 28, 14, 7, 17),
    (26, 30, 12, 5, 15),
    (24, 24, 10, 3, 13),
    (22, 26, 8, 2, 11),
    (20, 22, 6, 31, 9),
    (18, 20, 4, 29, 7),
    (16, 14, 2, 27, 5),
    (14, 16, 0, 25, 3),
    (12, 18, 30, 23, 1),
    (10, 12, 28, 21, 31),
    (8, 10, 26, 19, 29),
    (6, 8, 24, 17, 27),
    (4, 6, 22, 15, 25),
    (2, 2, 20, 13, 23),
    (0, 4, 18, 11, 21),
];

#[inline]
fn index(position: u32, offset: u32) -> usize {
    (position.wrapping_add(offset) & 31) as usize
}

#[inline]
fn read_word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

#[inline]
fn write_word(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[inline]
fn f1(x: u32) -> u32 {
    let [b0, b1, b2, b3] = x.to_le_bytes();
    A[b0 as usize] ^ B[b1 as usize] ^ A[b2 as usize] ^ A[b3 as usize]
}

#[inline]
fn f2(x: u32) -> u32 {
    let [b0, b1, b2, b3] = x.to_le_bytes();
    A[b0 as usize] ^ A[b1 as usize] ^ B[b2 as usize] ^ A[b3 as usize]
}

#[inline]
fn f3(x: u32) -> u32 {
    let [b0, b1, b2, b3] = x.to_le_bytes();
    B[b0 as usize] ^ A[b1 as usize] ^ A[b2 as usize] ^ A[b3 as usize]
}

#[inline]
fn f4(x: u32) -> u32 {
    let [b0, b1, b2, b3] = x.to_le_bytes();
    B[b0 as usize] ^ B[b1 as usize] ^ A[b2 as usize] ^ B[b3 as usize]
}

#[inline]
fn f5(x: u32) -> u32 {
    let [b0, b1, b2, b3] = x.to_le_bytes();
    A[b0 as usize] ^ B[b1 as usize] ^ B[b2 as usize] ^ B[b3 as usize]
}

#[inline]
fn f6(x: u32) -> u32 {
    let [b0, b1, b2, b3] = x.to_le_bytes();
    B[b0 as usize] ^ A[b1 as usize] ^ B[b2 as usize] ^ B[b3 as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    const BEFORE_MIX: &str = concat!(
        "f93562cfbe6f95f900000000000000000000000000000000f93562cfbe6f95f900000000000000000000000000000000",
        "f93562cfbe6f95f900000000000000000000000000000000f93562cfbe6f95f9f93562cfbe6f95f90000000000000000",
        "000000000000000000000000000000000000000000000000f93562cfbe6f95f9000000000000000000000000f93562cf",
        "be6f95f900000000000000000000000000000000f93562cfbe6f95f900000000000000000000000000000000f93562cf",
        "be6f95f900000000000000000000000000000000f93562cfbe6f95f9f93562cfbe6f95f9000000000000000000000000",
        "0000000000000000000000000000000000000000f93562cfbe6f95f90100000080000000",
    );
    const AFTER_MIX: &str = concat!(
        "1bf8770b46bc2cb794e12ab7499c3228f132e5fb7fe6f39e59d7db05833c7147116e9dd1666086fa55c0f53cb1f2ba13",
        "d0a599ade1c9b6f0a77d6b5241d300c4e97f44e5807094788ea7b0ba7dbe85b5fa69954aad26baf5f76a6f2e765d2c29",
        "6e890cbfa143753bf2a717070c63dd49585275b809784e3fccb294638ede1db467b42b22719dd177c0010000f93562cf",
        "be6f95f900000000000000000000000000000000f93562cfbe6f95f900000000000000000000000000000000f93562cf",
        "be6f95f900000000000000000000000000000000f93562cfbe6f95f9f93562cfbe6f95f9000000000000000000000000",
        "0000000000000000000000000000000000000000f93562cfbe6f95f90000000080000000",
    );
    const IV: [u8; 16] = [
        0x3a, 0xe7, 0x5b, 0xc4, 0x89, 0x15, 0xf2, 0x6c, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    const OUTPUT_CALLS: [(&str, &str); 20] = [
        (
            concat!(
                "93a26ebb8c0eeae03c572052cba77165cc94e5e16d097a4b7f325dff12d031d937220a5921e4db7a4bc9945edcdd14e9",
                "848cd2771ed94fdf3cc921e0936b067f355612f0c8c277406e91e952068e7b800b10ca942be1276b4619254f29764313",
                "9308deea286d82c6180cb91fc857cfaac1e7187328a4fd3e6c2db4bdaf0f8aa5",
            ),
            concat!(
                "1bf8770b21c24ebc92f0c40a78e7198cbdf62574649bbae8fd08bc13cd3101800a6a6544c8e4a055e84481f12f26c394",
                "5694954c3a0bd300ae3b31fd537564f49ca32b8ceaed33ceff2a3a1e704bee1d238787e32174fe69020b02c2f58cd6f6",
                "0a7e2ed6c4255bda05b5f8d14750987e05023c91f5b24ecdb347f576dc58b11567b42b22819dd177c0010000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f900000000000000000000000000000000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f9f93562cfbe6f95f9000000000000000000000000",
                "0000000000000000000000000000000000000000f93562cfbe6f95f90000000080000000",
            ),
        ),
        (
            concat!(
                "d78936aa8d7eb91e2e8e5c200a50e88a4e01ff147cb2be9cd26bd3d6e66f452f138916dde091d45a8062f6a5b23dd211",
                "ebfdaa0292a5d0522ed95a87b29a64dc806517ce9f951899bc7b3df214f7f3992d8edd301cffc8176bd1fedcbadadff2",
                "e28729a7c62996addbd65b9d8f08a49cd9e80b1a0317d892f4ec80fa0ce975ee",
            ),
            concat!(
                "1bf8770be999f40708e8de89c0411239fc3fd603b6220f3c1fb3d0495b80aa7a36c04aec91a9d4cbf1898369a43e8035",
                "b9c09e7114bf7c10744338d7455d166f27a0af70ab42933c63d868f07d4516aa4d329d66a08fbbfb8732ba9fa4a06ae6",
                "ce836577dd33202444a36936b66152e9b37a02a16913fc81bdd49b4c1ced061267b42b22919dd177c0010000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f900000000000000000000000000000000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f9f93562cfbe6f95f9000000000000000000000000",
                "0000000000000000000000000000000000000000f93562cfbe6f95f90000000080000000",
            ),
        ),
        (
            concat!(
                "e4d91a80f2ef0a4b9d11cd76b9b115b5b19373fd0dcb1d520a6b52bff206791672a6b127a7544d17eca8fc1f1858677c",
                "4384eb50dd13bf786b82e0ea6eb15d940592d1daa0b7b538634fdfc9892e23889e65675cd619efce975668447bb30df3",
                "d58f240fba31fb6d0ae8beeac2f8a2d89890c5a7654737243b4c35eb7486eb5a",
            ),
            concat!(
                "1bf8770b1327b995f064afce78af441d89992201611fbddb30a16edb3e3a56f0fce9ec975329c6edf23abedbed33433d",
                "1ae4fcfd0170f6ba968be8d9a2fd14cdd61bcaf45067a3664e1028784f4606a5c0d38411c9f0660bc9b1ea84281c1e34",
                "5ac2ad9be83b4b18eeacebacd9695688438f5653d82034aa7f5fecddc605be5d67b42b22a19dd177c0010000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f900000000000000000000000000000000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f9f93562cfbe6f95f9000000000000000000000000",
                "0000000000000000000000000000000000000000f93562cfbe6f95f90000000080000000",
            ),
        ),
        (
            concat!(
                "434e186ebf8c0f74956887e23b35d1c4d7174a88ef7eee40a217d7cdc610f96e06c3944dbebb4a3bccfacddc1dc61198",
                "61c1eb3cf83c7b936713325388616641f77bb16a12bc66b5eaf4ce8fb8a3cbafdd7951c62687f4a9483e0c1bb7522b31",
                "bcd5b871f7de110ecb5f43a7b3fab2e4b7bfd5471cf0ef16137d739de5aef5b0",
            ),
            concat!(
                "1bf8770b5ebf111ca4ae376620d4a6d3a14b9352fca3cf1e0b185c75b13e21d7709270e290020010010b142bf77211cf",
                "73d4887951a694fe142b1c1e1b7553ad8f599bb7bac564f6eff517cabc7f116d6c258113b78199ddf53c6deb496e9d3b",
                "1781d9268f09f7e43391042febb44c688243e6d3996f0e2c7d797043013a187d67b42b22b19dd177c0010000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f900000000000000000000000000000000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f9f93562cfbe6f95f9000000000000000000000000",
                "0000000000000000000000000000000000000000f93562cfbe6f95f90000000080000000",
            ),
        ),
        (
            concat!(
                "67f82413e2b3b4b976f6ddd9a32d9761254e33116296fc4726d187d7aff805ce807f5cbad2a1e4273733eef60d875b17",
                "0a660b1d8d6a6af70e0caae8c4a6672c7ff8699dca0726999885e6add5f1a281e73836da32ee7b717d17db31832a9d63",
                "c0fec5d9c12f78cf4ea84f12d0e1ec217d265932d6ba0f9b49fc5522a79e727e",
            ),
            concat!(
                "1bf8770b7862ba34b637dd3672a718c8613f01652118340df240d6e27473182d33c8ca07fedd1c3b7921d3ac4073691e",
                "e4c67fbdf5addd18ed07f03e8b7ee36655b3245c28e0b625c9392ef478b08973137e565dfd2ddc1188572576a3cb7e2f",
                "f81ddbd093b19a5ff3c095d823e69d6909d763d326991679ae8a50edeb8ece7c67b42b22c19dd177c0010000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f900000000000000000000000000000000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f9f93562cfbe6f95f9000000000000000000000000",
                "0000000000000000000000000000000000000000f93562cfbe6f95f90000000080000000",
            ),
        ),
        (
            concat!(
                "36feaacbd615092faa0122a86e2db499dfbb6d5da58d80652a7c4299e1bc967687db3adbf50db378f7f24cf9b639a7b1",
                "2c973880a3044f740252350d2bae07d1a131700030350dd89c348d529183115789cd4a73c0916e20733c9cd68f5196cd",
                "a70abe69f8c6942ade5eee88173ce79610c9ad418159645ec3a7c5a6e122fc50",
            ),
            concat!(
                "1bf8770b12696029fd1c24abca400fd0b4c6bb0d9761756c0ee8d077af2f2100296d2c3df9ec8e5c2297109b92270a47",
                "bb75776c91391beece4e8683abd65f9ea339db836dfdbd389a1654ee5612c9319378149a7d446cdf9e02c70e463e43bb",
                "0115b488a5f78e0ae7fc7842f13f90f2d6182d39ec2801ba0d56ac66ff6ad71767b42b22d19dd177c0010000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f900000000000000000000000000000000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f9f93562cfbe6f95f9000000000000000000000000",
                "0000000000000000000000000000000000000000f93562cfbe6f95f90000000080000000",
            ),
        ),
        (
            concat!(
                "f9ae779bee0a5ac1e070122123ee1249fe12dce44880d8c37597b1163dfc4e906118fdd185b7be1068f4447c52e59d96",
                "f1a7657bb0abcbdb1db8954da5f41afd46916bb825cd273c66786ad22cdf32d88923eb58232c073e0cc6b00d90d93d85",
                "85063a3ed76837f4b9b4f07f9bb61f4a408dece4eea25ae5a32b6c81914961ec",
            ),
            concat!(
                "1bf8770b93da0e25e45e77b5fbc69be3bd3b0cf7aedd1e94e0f2157b6fcfa32b36ea5deea8e49974fc358e4c065b8561",
                "4ca3679e1a98c6716157e41122fa97e128cdc48e93c3518339fc6f2e43a162cc633c793cffc809ae6f7d8bc22afa95fd",
                "9836751c4332169303ad0227d5c9517236425b3029654600681b963c4db3b60567b42b22e19dd177c0010000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f900000000000000000000000000000000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f9f93562cfbe6f95f9000000000000000000000000",
                "0000000000000000000000000000000000000000f93562cfbe6f95f90000000080000000",
            ),
        ),
        (
            concat!(
                "1810b5a09a6ea5ee27610705e7667be3c1aab640673d9a15fb8653d69e8daa7eac85d45cd2e12e3cd7b24abcd2b200d8",
                "16711c3fd7dde03f887b473c82f43d5c1899dc6e5b6f671c4433372e03b16128aa71b5b24de22a88783f1e815604e308",
                "48a19e185120315074ebe3c6cab640f7468d545fcdf6df4601d3beb592ff917a",
            ),
            concat!(
                "1bf8770bcb8358624c2e47d7337277b8a682276f87ff520d1f279342d6f5b5c45500395ac82ceb7309466e91a022b060",
                "6285ac58dcdbfb6a026c37ce3161f6124210dcdf99f65cf4251ad7df666764df72c265ce4854b2575b55c26b4cc16e0e",
                "6ebe55ac6880318f353add97705d7d016f980f94538ecfd293c352b6ae66aee367b42b22f19dd177c0010000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f900000000000000000000000000000000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f9f93562cfbe6f95f9000000000000000000000000",
                "0000000000000000000000000000000000000000f93562cfbe6f95f90000000080000000",
            ),
        ),
        (
            concat!(
                "4f985687cb05a668fc8984dc9cb0c34260b40bfd20be3540e9f0a4b5ded96aa2aee0209fbd4d6c3a0fd5e3f436cee7a2",
                "c1f5899765639d7707fe5ff1d6064339b6baf79dcc8fec192abecef94edf75090c025867ed03412e285d074a5f2c8411",
                "3c6a712a6726d51e3eb3ffe299f7b9cc7b9c3e5c0b3458f5ae8d9e7b742e2b50",
            ),
            concat!(
                "1bf8770b9a249ff8e48e6584b762908c46bb9db74d0ee7dbe8767e53fdb36a8080900a0cab8ffddf73a0caf2b5c5d8c3",
                "3f4c72389779bde6b2eacd4c7f24afa0a3792fb6e401c29b6929176f6f654045d10d659c5e728393d79ef3bec3e1639b",
                "df750281da75206115faa52c3b4ceb29778d1f9a25e38e7858613f88e217206a67b42b22019ed177c0010000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f900000000000000000000000000000000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f9f93562cfbe6f95f9000000000000000000000000",
                "0000000000000000000000000000000000000000f93562cfbe6f95f90000000080000000",
            ),
        ),
        (
            concat!(
                "f69fad9b90073d99af4cdbb595452c69bf827f99bed7395c0c9686c45d0bb2d48d274748df41726a737187204b8e0f1d",
                "aef0fe437d0eb230eea65c620802fc0513a4f7b94360ed368dced7fdbe5c5cdbfff3d907af0356054665c5ccf8aae3fa",
                "341bf7630bc8648280cceb6664619865f987327e14fe85570e41b415500cadc1",
            ),
            concat!(
                "1bf8770bde0c43a136f226869481e773accdd6a90a36b887af1c5c18120b03503f7b4c735c4a80297d88a1c9dfd7a95c",
                "49cc80fbca87797318ff1a6b99a4dd4e96ba241a614c77c02361a807b67c874f2debe28c0230ed28b578c9b35dd54c5d",
                "74e0f262b8fe9222e988891fa90bac2a873df25fe350ee297ecaa132790e906c67b42b22119ed177c0010000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f900000000000000000000000000000000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f9f93562cfbe6f95f9000000000000000000000000",
                "0000000000000000000000000000000000000000f93562cfbe6f95f90000000080000000",
            ),
        ),
        (
            concat!(
                "be8b905ab42b29189bc844d671fd343bede7fb7bb5e7854fcf1774fe29ca9d4ce2315f24b83673309b1bceb6729008ef",
                "a67fbdb69268d4e1ef3d0fe955359f30513027dc79f6970f8c01a6a563468ef247aeed15485286e666e3dd2ead70eae8",
                "30a5831a3f137b9811e4f3e28bab57afe82469001596c0dfe4306179da01015f",
            ),
            concat!(
                "1bf8770bde10f829fa49d7fab2be3dc630801629909923dc0cfd4bdfe31c0553e678874670d35c0d0d2b492dde6a75cd",
                "538dc71241c7658286863a9ee694d03c5e5153bd6c2a59582dccf660393c297a481f7aef7b3ba4c94c803f01604ae602",
                "21847daab9ea94cb7d60010cd210324204830fae62f847e7ced851070784567767b42b22219ed177c0010000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f900000000000000000000000000000000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f9f93562cfbe6f95f9000000000000000000000000",
                "0000000000000000000000000000000000000000f93562cfbe6f95f90000000080000000",
            ),
        ),
        (
            concat!(
                "df5ddf737eb328fc32d8116685a5081f8da909c409835bce787ec6d6ac516c837bf3965bd12baa89a882869698c666f4",
                "18d334aa3be14679e07330bf523108ebccea514a3f9306e07b34c1b7d7e3bcaf8fa0cf42b177dc9357aa2f62bd0c2cd8",
                "10e808f3f52e90a21df154ea82e695aef9c7f0e672c03114c7930666fba3edca",
            ),
            concat!(
                "1bf8770bc0a13d6709d74d2f0c81e5684b505ef7d7d6fbbe2a3c8a0241f82b260c5045938f0f1943d127b5545719953e",
                "17c03ea3c1e4b1ac90c40ac4b0104c69920c2faf4fa147b7c71ff8a124ef952b62bc8ac641463118cb391827a806571c",
                "9a6634f2bce3f1e6138e568799612265e6f42bd10932891c7b2e4503e92310e867b42b22319ed177c0010000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f900000000000000000000000000000000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f9f93562cfbe6f95f9000000000000000000000000",
                "0000000000000000000000000000000000000000f93562cfbe6f95f90000000080000000",
            ),
        ),
        (
            concat!(
                "872382b9eaf89d36aa78180200a1567aa65a135d57bdd4fdc5028e350e74a9d2656f244aeeb88e23faa9220706550520",
                "2609539bf7a7a3ff357a7a07b4d8e36f47d7eb89ce9e14bd6aee8c9ad17e7c970a9a70dec08f7fef79d135b9ba5ba036",
                "230c876f9c3983e6c53d10e0cb1db7c28d7f698e64462f0c2468a341bcd56e28",
            ),
            concat!(
                "1bf8770b1e99a6d915f135b50ab60bdd742c8dc0d9b1c45c2a612cc505cfa4b2b37cabb20a8dd2a624289362207637b4",
                "767e02b89424acb4e2f8f2bacefb7c3ca60f4898d806f7302b351bc289d06840cead932037565ce0771849cc130ad9cf",
                "cd951e4c0d2501ca3a41330163987611dc78ee57a5893eb111e1e4cf5f0442f567b42b22419ed177c0010000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f900000000000000000000000000000000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f9f93562cfbe6f95f9000000000000000000000000",
                "0000000000000000000000000000000000000000f93562cfbe6f95f90000000080000000",
            ),
        ),
        (
            concat!(
                "6336f37ba547a799637d605ea1bcb8fc2420a9318a2c2cf3e7fcdaf9190451cea379afad570a5cb10b541df4b2e8002c",
                "d6e672ab4ba1a7364816473e8e56b0e636ef4f5c8135dbe81f372ecc302147cb7d7116ed5b5cfbd4fbae05e82b1388f5",
                "508296f62cfd0c3be5fdb147cb2c5d788888c1fe4013c1e8ccb9fc7ffcf81972",
            ),
            concat!(
                "1bf8770b3ae28fe4d29a9b47870d1c252cb8d33d0d21f07d9ef9f51d4f55d0873e0fc05a07b46efa4975fd6c878a1dcf",
                "ebc572117c25ef84782d11f38d8c0f017738c051a9e8ce603c692c5d1012c91112ebeaa64c1bb775f36c216a0050c68f",
                "e3bd28624a7df50b2f78930174bf5e36d7d8877035eeb0db1fb0b2ed6a5f430767b42b22519ed177c0010000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f900000000000000000000000000000000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f9f93562cfbe6f95f9000000000000000000000000",
                "0000000000000000000000000000000000000000f93562cfbe6f95f90000000080000000",
            ),
        ),
        (
            concat!(
                "8e319e770ce21f9697c1e7e9268fb252cf023281edcecc3e61670fb7c8d31c93b9274f405f6e90a0e5674c62926c3390",
                "9cd2d827e05a305973521430c6750ef83d41be41ea0794aa829ec77f08e7513f6de321ccdf2d52691a46ab60c218ec0b",
                "ddd822303a88248cf0f7acfb5484a6e59ee116ef163ae42b057c07fd4671eaba",
            ),
            concat!(
                "1bf8770b6c0be711e47b742248d618bd642f08ed790f56f4c766b67aa4095cd5930a16fb4f131d7d5adc17511923685a",
                "3e35e300e49acef63c1366942d9f634a5ae7725bedc0ff81b065b529091f009567388f16b83d3617a4fc8d389a5815b1",
                "234ff92f78debccc2d62ae1f6fcc231d56bea5712d939da87ff8cd402cd4c65967b42b22619ed177c0010000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f900000000000000000000000000000000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f9f93562cfbe6f95f9000000000000000000000000",
                "0000000000000000000000000000000000000000f93562cfbe6f95f90000000080000000",
            ),
        ),
        (
            concat!(
                "90e8aeb8d65f27ba4ee80215f13354cfba2cc35ad974714f4fd087fa2927bbb96a61be2628dc7abfe88fcb80bb417906",
                "320514c7573c83bf2589dad5b0f04b3def2a94522fc777957402a0ed9247ce61ac20169fd57f4b1580a4476d668dcb84",
                "759d0ebe3728f0812a899c5f7fea6b9e71ce84115643e442c79417f12443d554",
            ),
            concat!(
                "1bf8770b4680576ebe45f1df590995534f7d5af9b734eb165f065738a615e8c85ffa78e63758e8c36c929b73de3c8932",
                "16aac5199fbe9e1c0ef004a954f8d202e7bf31a638834df82c5abc76858055eceb33b6aab28ea50abb30efc224f224ac",
                "d1f4c9148e1845faafc906d6a5ee80ab7c5603162a8700c01f28a7748934970c67b42b22719ed177c0010000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f900000000000000000000000000000000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f9f93562cfbe6f95f9000000000000000000000000",
                "0000000000000000000000000000000000000000f93562cfbe6f95f90000000080000000",
            ),
        ),
        (
            concat!(
                "bc35b935eec36b7457b7195ba616b65ec7fb628746fef6965a104f7212d6f92e4e15600cbf78dd19cb9e58ae95bcc27a",
                "8c8c578ea3a4a7f5c5285d87058a2ecb54baf579b6b087cad6d1f4fc7ed4892a47e0c2a995c911a2e6a50f265d5420df",
                "252dace540c33709ead487998a2f0d0c1f4ed55570f1a59d9f058fc879aed9a0",
            ),
            concat!(
                "1bf8770b7cfff7864135346cefacece70c9edd215b868386181b8b05e491daf2937d2ec32c616eff1296a2b096e07173",
                "0cbef4a09ca86188170ec505e024fcb518779190517da311bd716bad5b56122b6e55af94723064436d6372110d870622",
                "16723e48e40be3e8b0cce767604edc4395056b0bcd5e1c278439ced41f3e1c6967b42b22819ed177c0010000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f900000000000000000000000000000000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f9f93562cfbe6f95f9000000000000000000000000",
                "0000000000000000000000000000000000000000f93562cfbe6f95f90000000080000000",
            ),
        ),
        (
            concat!(
                "adeac0a08907a177f667c6b2d8e6c528b7ce6915958face1995dc7e5ebda42745fa15f05b8abf449abea422010e8e508",
                "9ca09bddd9bc4bbd06eaac9e36a68bee42471271d3fff146a2a203b3aa2181696127bea250d335d67effaa60947aec28",
                "87ae7d4a9f3936d961ca97c7f57ee7f97c9a2716755b20a059989ee0e08eae7c",
            ),
            concat!(
                "1bf8770ba2ee8952ab0787bb18f6c6525baabb89529b11310e01f8b70ef567cb67fbd992a0ab83290ca62048ae525ef7",
                "2ce12307a5d5f20cb218f293bea095b8fec0f407becd76838f0076dd91a5eda54d33a78a6bb2bffe1bb374d0a3b53b11",
                "7aad32300bc43ec0ef7931c545ca5ebf8077741d0a11f75aa00767bfed1df92067b42b22919ed177c0010000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f900000000000000000000000000000000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f9f93562cfbe6f95f9000000000000000000000000",
                "0000000000000000000000000000000000000000f93562cfbe6f95f90000000080000000",
            ),
        ),
        (
            concat!(
                "c58813170bf807511a65a2c23f0c4ce5e6460a7ade55d21098f3160b8118405057534ee03036b2c8e1fbc42d02e8a5e1",
                "337533ee58c7d193d771a0442fa45b24d788b1476f3129e59e0cd2ffa7f20d47338e3c1a48b3fc1695218154d9383674",
                "7267d0baec00b0df59d525f2b2c08052eb5bc5c54ae42ef16fe04045696f97cf",
            ),
            concat!(
                "1bf8770b4604f0f1f52e6ea89153d2d0fdca7f09a774d8aa9997267436dff1aa20d3a59da535a147e9750e7dd3bd64e9",
                "7614490cb725af7ce002ce9baac52e48167d3639ec99b5265e7890525393f8c68a82a04b0c28b79e8fc66e9d7468e095",
                "8fd9a02fb7ec1a1d2474fdfa068e09ef98440123a82575265b9c4a34464d59c167b42b22a19ed177c0010000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f900000000000000000000000000000000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f9f93562cfbe6f95f9000000000000000000000000",
                "0000000000000000000000000000000000000000f93562cfbe6f95f90000000080000000",
            ),
        ),
        (
            concat!(
                "63999cd77af781fc97a4a06810a20b997db13ebd6a2bec9f3502bde0d61d283dc63e0666130c3a2c40ebd118b8fde784",
                "324a0e18b6d023a5f8f8ff97723034e82b0472a4da23366be0d82c597c26d08017b3512b134d3f1f476aeffebd408d55",
                "695b25fe700fd46003ccbfa5736b30d9e4bf3aef812eceb2368f3c65c6de7770",
            ),
            concat!(
                "1bf8770bbfc282d05686d9d44b46e956f343fb653d8b15754e82c68bdc549d6e1f0a6868d1fc8124b3b14ab876bc75aa",
                "fbf35d74c1db9f8883c0aba1330f44d645b58beb52e4922da98f3d4e9ff327d680c68c1f25a3ac52ac7603fd91dec626",
                "2bf3d407c08e3515402a5bfbef59b92f6bdb206d7cecd097435509bc01faa0c667b42b22b19ed177c0010000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f900000000000000000000000000000000f93562cf",
                "be6f95f900000000000000000000000000000000f93562cfbe6f95f9f93562cfbe6f95f9000000000000000000000000",
                "0000000000000000000000000000000000000000f93562cfbe6f95f90000000080000000",
            ),
        ),
    ];

    fn decode<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), N * 2);
        let mut bytes = [0; N];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        bytes
    }

    fn before_mix() -> Context {
        Context::from_native_bytes(&decode(BEFORE_MIX))
    }

    fn after_mix() -> Context {
        Context::from_native_bytes(&decode(AFTER_MIX))
    }

    #[test]
    fn native_setup_and_twenty_successive_output_calls() {
        let mut context = before_mix();
        context.inject_and_mix(&IV);
        assert_eq!(context, after_mix());
        let unchanged_word_zero = context.s[0];
        let mut blocks = [[0; BLOCK_BYTES]; 1];
        for (call, &(expected_output, expected_context)) in OUTPUT_CALLS.iter().enumerate() {
            context.generate_blocks(&mut blocks);
            assert_eq!(
                blocks[0],
                decode::<BLOCK_BYTES>(expected_output),
                "output call {call}"
            );
            assert_eq!(
                context,
                Context::from_native_bytes(&decode(expected_context)),
                "context call {call}"
            );
            assert_eq!(context.s[0], unchanged_word_zero);
        }
    }

    #[test]
    fn twenty_block_batch_matches_native_calls_without_counter_wrap() {
        let mut context = after_mix();
        let mut blocks = [[0; BLOCK_BYTES]; 20];
        context.generate_blocks(&mut blocks);
        for (block, &(expected_output, _)) in blocks.iter().zip(OUTPUT_CALLS.iter()) {
            assert_eq!(*block, decode::<BLOCK_BYTES>(expected_output));
        }
        assert_eq!(
            context,
            Context::from_native_bytes(&decode(OUTPUT_CALLS[19].1))
        );
    }

    #[test]
    fn zero_flag_restores_saved_state_and_nonzero_flag_keeps_current_state() {
        let mut restored = before_mix();
        restored.s.fill(0xdead_beef);
        restored.flag = 0;
        restored.inject_and_mix(&IV);
        assert_eq!(restored, after_mix());

        let mut kept = before_mix();
        kept.saved_state.fill(0xdead_beef);
        kept.flag = 0xff;
        let saved = kept.saved_state;
        kept.inject_and_mix(&IV);
        let mut expected = after_mix();
        expected.saved_state = saved;
        assert_eq!(kept, expected);
    }

    #[test]
    fn setup_position_wraps_without_masking_its_stored_value() {
        let mut context = before_mix();
        context.setup_position = 0xffff_ffe0;
        context.inject_and_mix(&IV);
        let mut expected = after_mix();
        expected.setup_position = 0x1a0;
        assert_eq!(context, expected);
    }

    #[test]
    fn counter_carry_is_deferred_until_the_end_of_the_call() {
        let mut context = after_mix();
        context.high = u32::MAX;
        context.low = 0xffff_fff8;
        let mut per_block = context.clone();
        let mut blocks = [[0; BLOCK_BYTES]; 3];
        context.generate_blocks(&mut blocks);
        for block in &blocks {
            per_block.high = u32::MAX;
            let mut single = [[0; BLOCK_BYTES]; 1];
            per_block.generate_blocks(&mut single);
            assert_eq!(*block, single[0]);
        }
        per_block.high = 0;
        assert_eq!(context.high, 0);
        assert_eq!(context.low, 0x28);
        assert_eq!(context, per_block);
    }

    #[test]
    fn empty_output_preserves_all_fields() {
        let mut context = after_mix();
        context.low = u32::MAX;
        let expected = context.clone();
        context.generate_blocks(&mut []);
        assert_eq!(context, expected);
    }

    #[test]
    fn native_context_round_trip_preserves_padding() {
        let mut bytes: [u8; NATIVE_CONTEXT_BYTES] = decode(BEFORE_MIX);
        bytes[0x10d..0x110].copy_from_slice(&[0x12, 0x34, 0x56]);
        let context = Context::from_native_bytes(&bytes);
        let mut encoded = [0xa5; NATIVE_CONTEXT_BYTES];
        encoded[0x10d..0x110].copy_from_slice(&[0x12, 0x34, 0x56]);
        context.write_native_bytes(&mut encoded);
        assert_eq!(encoded, bytes);
    }

    #[test]
    fn full_width_iv_injection_matches_independently_prepared_short_path() {
        let words: [u32; 8] = [
            0x0123_4567,
            0x89ab_cdef,
            0xfedc_ba98,
            0x7654_3210,
            0xffff_ffff,
            0x8000_0001,
            0x0000_0000,
            0x1357_9bdf,
        ];
        let short_words = [words[2], words[3], words[0], words[1]];
        let mut full_iv = [0; 32];
        let mut short_iv = [0; 16];
        for (i, word) in words.iter().enumerate() {
            full_iv[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        for (i, word) in short_words.iter().enumerate() {
            short_iv[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        let mut full = before_mix();
        full.size_selector = 256;
        for i in 0..4 {
            full.s[8 + i] = words[i] ^ short_words[i];
        }
        let mut short = full.clone();
        for i in 0..8 {
            short.s[8 + i] ^= words[i];
            short.s[16 + i] ^= !words[i];
            short.s[24 + i] = words[i];
        }
        for i in 0..4 {
            short.s[20 + i] ^= short_words[i];
            short.s[28 + i] ^= short_words[i];
        }
        for i in 0..2 {
            short.s[4 + i] ^= short_words[2 + i];
            short.s[12 + i] ^= short_words[2 + i];
            short.s[6 + i] ^= short_words[i];
            short.s[14 + i] ^= short_words[i];
        }
        short.size_selector = 128;
        short.inject_and_mix(&short_iv);
        full.inject_and_mix(&full_iv);
        short.size_selector = 256;
        assert_eq!(full, short);
    }
}
