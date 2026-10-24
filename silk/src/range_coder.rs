pub const MAX_ARITHM_BYTES: usize = 1024;

pub const RANGE_CODER_CDF_OUT_OF_RANGE: i32 = -2;
pub const RANGE_CODER_NORMALIZATION_FAILED: i32 = -3;
pub const RANGE_CODER_ZERO_INTERVAL_WIDTH: i32 = -4;
pub const RANGE_CODER_DECODER_CHECK_FAILED: i32 = -5;
pub const RANGE_CODER_READ_BEYOND_BUFFER: i32 = -6;
pub const RANGE_CODER_ILLEGAL_SAMPLING_RATE: i32 = -7;
pub const RANGE_CODER_DEC_PAYLOAD_TOO_LONG: i32 = -8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeCoderState {
    pub buffer_length: usize,
    pub buffer_ix: usize,
    pub base_q32: u32,
    pub range_q16: u32,
    pub error: i32,
    // Four bytes of zero lookahead permit normalization at the maximum packet size.
    pub buffer: [u8; MAX_ARITHM_BYTES + 4],
}

impl Default for RangeCoderState {
    fn default() -> Self {
        Self {
            buffer_length: MAX_ARITHM_BYTES,
            buffer_ix: 0,
            base_q32: 0,
            range_q16: 0x0000_FFFF,
            error: 0,
            buffer: [0; MAX_ARITHM_BYTES + 4],
        }
    }
}

impl RangeCoderState {
    pub fn dec_init(&mut self, input: &[u8]) {
        if input.len() > MAX_ARITHM_BYTES {
            self.error = RANGE_CODER_DEC_PAYLOAD_TOO_LONG;
            return;
        }
        self.buffer.fill(0);
        self.buffer[..input.len()].copy_from_slice(input);
        self.buffer_length = input.len();
        self.buffer_ix = 0;
        self.base_q32 = ((self.buffer[0] as u32) << 24)
            | ((self.buffer[1] as u32) << 16)
            | ((self.buffer[2] as u32) << 8)
            | (self.buffer[3] as u32);
        self.range_q16 = 0x0000_FFFF;
        self.error = 0;
    }

    pub fn decode_symbol(&mut self, cdf: &[u16], mut prob_ix: usize) -> usize {
        if self.error != 0 {
            return 0;
        }
        if prob_ix >= cdf.len() {
            self.error = RANGE_CODER_CDF_OUT_OF_RANGE;
            return 0;
        }

        let mut high_q16 = cdf[prob_ix] as u32;
        let mut base_tmp = self.range_q16.wrapping_mul(high_q16);
        let low_q16: u32;
        if base_tmp > self.base_q32 {
            loop {
                if prob_ix == 0 {
                    self.error = RANGE_CODER_CDF_OUT_OF_RANGE;
                    return 0;
                }
                prob_ix -= 1;
                let low = cdf[prob_ix] as u32;
                base_tmp = self.range_q16.wrapping_mul(low);
                if base_tmp <= self.base_q32 {
                    low_q16 = low;
                    break;
                }
                high_q16 = low;
                if high_q16 == 0 {
                    self.error = RANGE_CODER_CDF_OUT_OF_RANGE;
                    return 0;
                }
            }
        } else {
            let mut low = high_q16;
            loop {
                prob_ix += 1;
                if prob_ix >= cdf.len() {
                    self.error = RANGE_CODER_CDF_OUT_OF_RANGE;
                    return 0;
                }
                high_q16 = cdf[prob_ix] as u32;
                base_tmp = self.range_q16.wrapping_mul(high_q16);
                if base_tmp > self.base_q32 {
                    prob_ix -= 1;
                    low_q16 = low;
                    break;
                }
                low = high_q16;
                if high_q16 == 0xFFFF {
                    self.error = RANGE_CODER_CDF_OUT_OF_RANGE;
                    return 0;
                }
            }
        }

        self.base_q32 = self
            .base_q32
            .wrapping_sub(self.range_q16.wrapping_mul(low_q16));
        let range_q32 = self.range_q16.wrapping_mul(high_q16.wrapping_sub(low_q16));

        if (range_q32 & 0xFF00_0000) != 0 {
            self.range_q16 = range_q32 >> 16;
        } else {
            if (range_q32 & 0xFFFF_0000) != 0 {
                self.range_q16 = range_q32 >> 8;
                if (self.base_q32 >> 24) != 0 {
                    self.error = RANGE_CODER_NORMALIZATION_FAILED;
                    return 0;
                }
            } else {
                self.range_q16 = range_q32;
                if (self.base_q32 >> 16) != 0 {
                    self.error = RANGE_CODER_NORMALIZATION_FAILED;
                    return 0;
                }
                self.base_q32 = self.base_q32.wrapping_shl(8);
                if self.buffer_ix < self.buffer_length {
                    self.base_q32 |= self.buffer[4 + self.buffer_ix] as u32;
                    self.buffer_ix += 1;
                }
            }
            self.base_q32 = self.base_q32.wrapping_shl(8);
            if self.buffer_ix < self.buffer_length {
                self.base_q32 |= self.buffer[4 + self.buffer_ix] as u32;
                self.buffer_ix += 1;
            }
        }

        if self.range_q16 == 0 {
            self.error = RANGE_CODER_ZERO_INTERVAL_WIDTH;
            return 0;
        }
        prob_ix
    }

    pub fn get_length_bits_and_bytes(&self) -> (usize, usize) {
        let nbits = (self.buffer_ix << 3)
            + ((self.range_q16.wrapping_sub(1)).leading_zeros() as usize)
            - 14;
        let nbytes = (nbits + 7) >> 3;
        (nbits, nbytes)
    }

    pub fn check_after_decoding(&mut self) {
        let (bits_in_stream, nbytes) = self.get_length_bits_and_bytes();
        if nbytes == 0 || nbytes > self.buffer_length {
            self.error = RANGE_CODER_DECODER_CHECK_FAILED;
            return;
        }
        if (bits_in_stream & 7) != 0 {
            let mask = 0xFFu8 >> (bits_in_stream & 7);
            if (self.buffer[nbytes - 1] & mask) != mask {
                self.error = RANGE_CODER_DECODER_CHECK_FAILED;
            }
        }
    }
}
