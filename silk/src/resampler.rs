use crate::math::{rshift_round, sat16, smlawb, smulbb, smulwb};
use crate::resampler_tables::RESAMPLER_FRAC_FIR_144;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResamplerError {
    OutputTooSmall,
    UnsupportedRatio,
    InvalidSampleRate,
}

const DOWN2_0: i16 = 9872;
const DOWN2_1: i16 = -25727; // 39809 - 65536
const UP2_LQ_0: i16 = 8102;
const UP2_LQ_1: i16 = -28753; // 36783 - 65536
const UP2_HQ_0: [i16; 2] = [4280, -31809];
const UP2_HQ_1: [i16; 2] = [16295, -11521];
const UP2_HQ_NOTCH: [i16; 4] = [7864, -3604, 13107, 28508];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Up2State {
    s: [i32; 2],
}

impl Up2State {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn process(&mut self, input: &[i16], output: &mut [i16]) -> Result<usize, ResamplerError> {
        let needed = input.len().saturating_mul(2);
        if output.len() < needed {
            return Err(ResamplerError::OutputTooSmall);
        }

        for (k, &sample) in input.iter().enumerate() {
            let in32 = (sample as i32) << 10;

            let y0 = in32.wrapping_sub(self.s[0]);
            let x0 = smulwb(y0, UP2_LQ_0 as i32);
            let out0 = self.s[0].wrapping_add(x0);
            self.s[0] = in32.wrapping_add(x0);
            output[2 * k] = sat16(rshift_round(out0, 10));

            let y1 = in32.wrapping_sub(self.s[1]);
            let x1 = smlawb(y1, y1, UP2_LQ_1 as i32);
            let out1 = self.s[1].wrapping_add(x1);
            self.s[1] = in32.wrapping_add(x1);
            output[2 * k + 1] = sat16(rshift_round(out1, 10));
        }
        Ok(needed)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Down2State {
    s: [i32; 2],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResamplerMode {
    Copy,
    Up2,
    Down2,
    DownFir34,
    DownFir23,
    DownFir13,
    UpIirFir,
}

const RESAMPLER_DOWN_ORDER_FIR: usize = 12;

const COEFS_3_4: [i16; 20] = [
    -18249, -12532, -97, 284, -495, 309, 10268, 20317, -94, 156, -48, -720, 5984, 18278, -45, -4,
    237, -847, 2540, 14662,
];
const COEFS_2_3: [i16; 14] = [
    -11891, -12486, 20, 211, -657, 688, 8423, 15911, -44, 197, -152, -653, 3855, 13015,
];
const COEFS_1_3: [i16; 8] = [16643, -14000, -331, 19, 581, 1421, 2290, 2845];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FractionalDownKind {
    R3Over4,
    R2Over3,
    R1Over3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FractionalDownResampler {
    kind: FractionalDownKind,
    s_iir: [i32; 2],
    s_fir: [i32; RESAMPLER_DOWN_ORDER_FIR],
    inv_ratio_q16: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UpIirFirResampler {
    use_hq_up2: bool,
    up2_lq: Up2State,
    up2_hq_state: [i32; 6],
    fir_state: [i16; 6],
    inv_ratio_q16: u32,
}

impl UpIirFirResampler {
    fn new(in_hz: u32, out_hz: u32) -> Self {
        let num = (in_hz as u64) << 17;
        let inv_ratio_q16 = num.div_ceil(out_hz as u64) as u32;
        Self {
            use_hq_up2: in_hz <= 24_000,
            up2_lq: Up2State::new(),
            up2_hq_state: [0; 6],
            fir_state: [0; 6],
            inv_ratio_q16,
        }
    }

    fn output_len_for_input(&self, in_len: usize) -> usize {
        if in_len == 0 {
            return 0;
        }
        let max_index = (in_len as u64) << 17;
        let step = self.inv_ratio_q16 as u64;
        (((max_index - 1) / step) + 1) as usize
    }

    fn up2_hq_process(
        &mut self,
        input: &[i16],
        output: &mut [i16],
    ) -> Result<usize, ResamplerError> {
        let needed = input.len().saturating_mul(2);
        if output.len() < needed {
            return Err(ResamplerError::OutputTooSmall);
        }
        for (k, &s) in input.iter().enumerate() {
            let in32 = (s as i32) << 10;

            let mut y = in32.wrapping_sub(self.up2_hq_state[0]);
            let mut x = smulwb(y, UP2_HQ_0[0] as i32);
            let mut out32_1 = self.up2_hq_state[0].wrapping_add(x);
            self.up2_hq_state[0] = in32.wrapping_add(x);

            y = out32_1.wrapping_sub(self.up2_hq_state[1]);
            x = smlawb(y, y, UP2_HQ_0[1] as i32);
            let mut out32_2 = self.up2_hq_state[1].wrapping_add(x);
            self.up2_hq_state[1] = out32_1.wrapping_add(x);

            out32_2 = smlawb(out32_2, self.up2_hq_state[5], UP2_HQ_NOTCH[2] as i32);
            out32_2 = smlawb(out32_2, self.up2_hq_state[4], UP2_HQ_NOTCH[1] as i32);
            out32_1 = smlawb(out32_2, self.up2_hq_state[4], UP2_HQ_NOTCH[0] as i32);
            self.up2_hq_state[5] = out32_2.wrapping_sub(self.up2_hq_state[5]);
            output[2 * k] = sat16((smlawb(256, out32_1, UP2_HQ_NOTCH[3] as i32)) >> 9);

            y = in32.wrapping_sub(self.up2_hq_state[2]);
            x = smulwb(y, UP2_HQ_1[0] as i32);
            out32_1 = self.up2_hq_state[2].wrapping_add(x);
            self.up2_hq_state[2] = in32.wrapping_add(x);

            y = out32_1.wrapping_sub(self.up2_hq_state[3]);
            x = smlawb(y, y, UP2_HQ_1[1] as i32);
            out32_2 = self.up2_hq_state[3].wrapping_add(x);
            self.up2_hq_state[3] = out32_1.wrapping_add(x);

            out32_2 = smlawb(out32_2, self.up2_hq_state[4], UP2_HQ_NOTCH[2] as i32);
            out32_2 = smlawb(out32_2, self.up2_hq_state[5], UP2_HQ_NOTCH[1] as i32);
            out32_1 = smlawb(out32_2, self.up2_hq_state[5], UP2_HQ_NOTCH[0] as i32);
            self.up2_hq_state[4] = out32_2.wrapping_sub(self.up2_hq_state[4]);
            output[2 * k + 1] = sat16((smlawb(256, out32_1, UP2_HQ_NOTCH[3] as i32)) >> 9);
        }
        Ok(needed)
    }

    fn process(&mut self, input: &[i16], output: &mut [i16]) -> Result<usize, ResamplerError> {
        let needed = self.output_len_for_input(input.len());
        if output.len() < needed {
            return Err(ResamplerError::OutputTooSmall);
        }
        if input.is_empty() {
            return Ok(0);
        }

        let mut up = vec![0i16; input.len().saturating_mul(2)];
        let up_n = if self.use_hq_up2 {
            self.up2_hq_process(input, &mut up)?
        } else {
            self.up2_lq.process(input, &mut up)?
        };

        let mut buf = vec![0i16; 6 + up_n];
        buf[..6].copy_from_slice(&self.fir_state);
        buf[6..6 + up_n].copy_from_slice(&up[..up_n]);

        let mut produced = 0usize;
        let max_index_q16 = (input.len() as u32) << 17;
        let mut index_q16 = 0u32;
        while index_q16 < max_index_q16 {
            let table_index = smulwb((index_q16 & 0xFFFF) as i32, 144) as usize;
            let b = (index_q16 >> 16) as usize;
            let p = &buf[b..b + 6];
            let c0 = RESAMPLER_FRAC_FIR_144[table_index];
            let c1 = RESAMPLER_FRAC_FIR_144[143 - table_index];
            let mut res_q15 = smulbb(p[0] as i32, c0[0] as i32);
            res_q15 += smulbb(p[1] as i32, c0[1] as i32);
            res_q15 += smulbb(p[2] as i32, c0[2] as i32);
            res_q15 += smulbb(p[3] as i32, c1[2] as i32);
            res_q15 += smulbb(p[4] as i32, c1[1] as i32);
            res_q15 += smulbb(p[5] as i32, c1[0] as i32);
            output[produced] = sat16(rshift_round(res_q15, 15));
            produced += 1;
            index_q16 = index_q16.wrapping_add(self.inv_ratio_q16);
        }

        self.fir_state.copy_from_slice(&buf[up_n..up_n + 6]);
        Ok(produced)
    }
}

impl FractionalDownResampler {
    fn new(kind: FractionalDownKind, in_hz: u32, out_hz: u32) -> Self {
        let inv_ratio_q16 = ((in_hz as u64) << 16).div_ceil(out_hz as u64);
        Self {
            kind,
            s_iir: [0; 2],
            s_fir: [0; RESAMPLER_DOWN_ORDER_FIR],
            inv_ratio_q16: inv_ratio_q16 as u32,
        }
    }
    fn coeffs(&self) -> (&'static [i16], u32, &'static [i16]) {
        match self.kind {
            FractionalDownKind::R3Over4 => (&COEFS_3_4[0..2], 3, &COEFS_3_4[2..]),
            FractionalDownKind::R2Over3 => (&COEFS_2_3[0..2], 2, &COEFS_2_3[2..]),
            FractionalDownKind::R1Over3 => (&COEFS_1_3[0..2], 1, &COEFS_1_3[2..]),
        }
    }

    fn output_len_for_input(&self, in_len: usize) -> usize {
        if in_len == 0 {
            return 0;
        }
        let max_index = (in_len as u64) << 16;
        let step = self.inv_ratio_q16 as u64;
        (((max_index - 1) / step) + 1) as usize
    }

    fn process(&mut self, input: &[i16], output: &mut [i16]) -> Result<usize, ResamplerError> {
        let needed = self.output_len_for_input(input.len());
        if output.len() < needed {
            return Err(ResamplerError::OutputTooSmall);
        }
        if input.is_empty() {
            return Ok(0);
        }

        let (ar, fir_fracs, fir_coefs) = self.coeffs();
        let mut buf2 = vec![0i32; RESAMPLER_DOWN_ORDER_FIR + input.len()];
        buf2[..RESAMPLER_DOWN_ORDER_FIR].copy_from_slice(&self.s_fir);

        for (k, &sample) in input.iter().enumerate() {
            let mut out32 = self.s_iir[0].wrapping_add((sample as i32) << 8);
            buf2[RESAMPLER_DOWN_ORDER_FIR + k] = out32;
            out32 = out32.wrapping_shl(2);
            self.s_iir[0] = smlawb(self.s_iir[1], out32, ar[0] as i32);
            self.s_iir[1] = smulwb(out32, ar[1] as i32);
        }

        let mut produced = 0usize;
        let mut index_q16: u32 = 0;
        let max_index_q16: u32 = (input.len() as u32) << 16;
        while index_q16 < max_index_q16 {
            let base = (index_q16 >> 16) as usize;
            let b = &buf2[base..base + RESAMPLER_DOWN_ORDER_FIR];

            let res_q6 = if fir_fracs == 1 {
                let c = fir_coefs;
                let mut r = smulwb(b[0].wrapping_add(b[11]), c[0] as i32);
                r = smlawb(r, b[1].wrapping_add(b[10]), c[1] as i32);
                r = smlawb(r, b[2].wrapping_add(b[9]), c[2] as i32);
                r = smlawb(r, b[3].wrapping_add(b[8]), c[3] as i32);
                r = smlawb(r, b[4].wrapping_add(b[7]), c[4] as i32);
                smlawb(r, b[5].wrapping_add(b[6]), c[5] as i32)
            } else {
                let frac = index_q16 & 0xFFFF;
                let interpol_ind = ((frac as u64 * fir_fracs as u64) >> 16) as usize;
                let stride = RESAMPLER_DOWN_ORDER_FIR / 2;
                let p0 = &fir_coefs[stride * interpol_ind..stride * (interpol_ind + 1)];
                let p1_ind = (fir_fracs as usize - 1) - interpol_ind;
                let p1 = &fir_coefs[stride * p1_ind..stride * (p1_ind + 1)];

                let mut r = smulwb(b[0], p0[0] as i32);
                r = smlawb(r, b[1], p0[1] as i32);
                r = smlawb(r, b[2], p0[2] as i32);
                r = smlawb(r, b[3], p0[3] as i32);
                r = smlawb(r, b[4], p0[4] as i32);
                r = smlawb(r, b[5], p0[5] as i32);
                r = smlawb(r, b[11], p1[0] as i32);
                r = smlawb(r, b[10], p1[1] as i32);
                r = smlawb(r, b[9], p1[2] as i32);
                r = smlawb(r, b[8], p1[3] as i32);
                r = smlawb(r, b[7], p1[4] as i32);
                smlawb(r, b[6], p1[5] as i32)
            };

            output[produced] = sat16(rshift_round(res_q6, 6));
            produced += 1;
            index_q16 = index_q16.wrapping_add(self.inv_ratio_q16);
        }

        self.s_fir
            .copy_from_slice(&buf2[input.len()..input.len() + RESAMPLER_DOWN_ORDER_FIR]);
        Ok(produced)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleResampler {
    in_hz: u32,
    out_hz: u32,
    up2: Up2State,
    down2: Down2State,
    fractional_down: Option<FractionalDownResampler>,
    up_iir_fir: Option<UpIirFirResampler>,
}

impl SimpleResampler {
    pub fn new(in_hz: u32, out_hz: u32) -> Result<Self, ResamplerError> {
        if !(8_000..=48_000).contains(&in_hz) || !(8_000..=48_000).contains(&out_hz) {
            return Err(ResamplerError::InvalidSampleRate);
        }
        let s = Self {
            in_hz,
            out_hz,
            up2: Up2State::new(),
            down2: Down2State::new(),
            fractional_down: None,
            up_iir_fir: None,
        };
        let mode = s.mode()?;
        let mut s = s;
        s.fractional_down = match mode {
            ResamplerMode::DownFir34 => Some(FractionalDownResampler::new(
                FractionalDownKind::R3Over4,
                in_hz,
                out_hz,
            )),
            ResamplerMode::DownFir23 => Some(FractionalDownResampler::new(
                FractionalDownKind::R2Over3,
                in_hz,
                out_hz,
            )),
            ResamplerMode::DownFir13 => Some(FractionalDownResampler::new(
                FractionalDownKind::R1Over3,
                in_hz,
                out_hz,
            )),
            _ => None,
        };
        s.up_iir_fir = match mode {
            ResamplerMode::UpIirFir => Some(UpIirFirResampler::new(in_hz, out_hz)),
            _ => None,
        };
        Ok(s)
    }

    fn mode(&self) -> Result<ResamplerMode, ResamplerError> {
        if self.in_hz == self.out_hz {
            Ok(ResamplerMode::Copy)
        } else if self.out_hz == self.in_hz.saturating_mul(2) {
            Ok(ResamplerMode::Up2)
        } else if self.in_hz == self.out_hz.saturating_mul(2) {
            Ok(ResamplerMode::Down2)
        } else if self.out_hz.saturating_mul(4) == self.in_hz.saturating_mul(3) {
            Ok(ResamplerMode::DownFir34)
        } else if self.out_hz.saturating_mul(3) == self.in_hz.saturating_mul(2) {
            Ok(ResamplerMode::DownFir23)
        } else if self.out_hz.saturating_mul(3) == self.in_hz {
            Ok(ResamplerMode::DownFir13)
        } else if self.out_hz > self.in_hz {
            Ok(ResamplerMode::UpIirFir)
        } else {
            Err(ResamplerError::UnsupportedRatio)
        }
    }

    pub fn output_len_for_input(&self, in_len: usize) -> Result<usize, ResamplerError> {
        match self.mode()? {
            ResamplerMode::Copy => Ok(in_len),
            ResamplerMode::Up2 => Ok(in_len.saturating_mul(2)),
            ResamplerMode::Down2 => Ok(in_len / 2),
            ResamplerMode::DownFir34 | ResamplerMode::DownFir23 | ResamplerMode::DownFir13 => self
                .fractional_down
                .as_ref()
                .map(|fd| fd.output_len_for_input(in_len))
                .ok_or(ResamplerError::UnsupportedRatio),
            ResamplerMode::UpIirFir => self
                .up_iir_fir
                .as_ref()
                .map(|uf| uf.output_len_for_input(in_len))
                .ok_or(ResamplerError::UnsupportedRatio),
        }
    }

    pub fn process(&mut self, input: &[i16], output: &mut [i16]) -> Result<usize, ResamplerError> {
        match self.mode()? {
            ResamplerMode::Copy => {
                if output.len() < input.len() {
                    return Err(ResamplerError::OutputTooSmall);
                }
                output[..input.len()].copy_from_slice(input);
                Ok(input.len())
            }
            ResamplerMode::Up2 => self.up2.process(input, output),
            ResamplerMode::Down2 => self.down2.process(input, output),
            ResamplerMode::DownFir34 | ResamplerMode::DownFir23 | ResamplerMode::DownFir13 => self
                .fractional_down
                .as_mut()
                .ok_or(ResamplerError::UnsupportedRatio)?
                .process(input, output),
            ResamplerMode::UpIirFir => self
                .up_iir_fir
                .as_mut()
                .ok_or(ResamplerError::UnsupportedRatio)?
                .process(input, output),
        }
    }
}

impl Down2State {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn process(&mut self, input: &[i16], output: &mut [i16]) -> Result<usize, ResamplerError> {
        let out_len = input.len() / 2;
        if output.len() < out_len {
            return Err(ResamplerError::OutputTooSmall);
        }

        for k in 0..out_len {
            let in0 = (input[2 * k] as i32) << 10;
            let y0 = in0.wrapping_sub(self.s[0]);
            let x0 = smlawb(y0, y0, DOWN2_1 as i32);
            let mut out32 = self.s[0].wrapping_add(x0);
            self.s[0] = in0.wrapping_add(x0);

            let in1 = (input[2 * k + 1] as i32) << 10;
            let y1 = in1.wrapping_sub(self.s[1]);
            let x1 = smulwb(y1, DOWN2_0 as i32);
            out32 = out32.wrapping_add(self.s[1]);
            out32 = out32.wrapping_add(x1);
            self.s[1] = in1.wrapping_add(x1);

            output[k] = sat16(rshift_round(out32, 11));
        }
        Ok(out_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_signal(len: usize) -> Vec<i16> {
        let mut x = Vec::with_capacity(len);
        let mut acc: i32 = 1;
        for _ in 0..len {
            acc = acc.wrapping_mul(1103515245).wrapping_add(12345);
            x.push((acc >> 16) as i16);
        }
        x
    }

    #[test]
    fn up2_output_len_matches() {
        let x = test_signal(97);
        let mut out = vec![0i16; x.len() * 2];
        let mut st = Up2State::new();
        let n = st.process(&x, &mut out).unwrap();
        assert_eq!(n, x.len() * 2);
    }

    #[test]
    fn down2_output_len_matches() {
        let x = test_signal(98);
        let mut out = vec![0i16; x.len() / 2];
        let mut st = Down2State::new();
        let n = st.process(&x, &mut out).unwrap();
        assert_eq!(n, x.len() / 2);
    }

    #[test]
    fn up2_stateful_chunking_matches_full() {
        let x = test_signal(128);
        let mut full_state = Up2State::new();
        let mut full = vec![0i16; x.len() * 2];
        full_state.process(&x, &mut full).unwrap();

        let mut chunk_state = Up2State::new();
        let mut chunked = vec![0i16; x.len() * 2];
        let (a, b) = x.split_at(37);
        let n0 = chunk_state.process(a, &mut chunked[..a.len() * 2]).unwrap();
        let n1 = chunk_state.process(b, &mut chunked[n0..]).unwrap();
        assert_eq!(n0 + n1, chunked.len());
        assert_eq!(full, chunked);
    }

    #[test]
    fn down2_stateful_chunking_matches_full() {
        let x = test_signal(128);
        let mut full_state = Down2State::new();
        let mut full = vec![0i16; x.len() / 2];
        full_state.process(&x, &mut full).unwrap();

        let mut chunk_state = Down2State::new();
        let mut chunked = vec![0i16; x.len() / 2];
        let (a, b) = x.split_at(48);
        let n0 = chunk_state.process(a, &mut chunked[..a.len() / 2]).unwrap();
        let n1 = chunk_state.process(b, &mut chunked[n0..]).unwrap();
        assert_eq!(n0 + n1, chunked.len());
        assert_eq!(full, chunked);
    }

    #[test]
    fn simple_resampler_copy() {
        let x = test_signal(19);
        let mut out = vec![0i16; x.len()];
        let mut rs = SimpleResampler::new(16_000, 16_000).unwrap();
        let n = rs.process(&x, &mut out).unwrap();
        assert_eq!(n, x.len());
        assert_eq!(x, out);
    }

    #[test]
    fn simple_resampler_up2() {
        let x = test_signal(23);
        let mut out = vec![0i16; 46];
        let mut rs = SimpleResampler::new(16_000, 32_000).unwrap();
        let n = rs.process(&x, &mut out).unwrap();
        assert_eq!(n, 46);
    }

    #[test]
    fn simple_resampler_down2() {
        let x = test_signal(24);
        let mut out = vec![0i16; 12];
        let mut rs = SimpleResampler::new(24_000, 12_000).unwrap();
        let n = rs.process(&x, &mut out).unwrap();
        assert_eq!(n, 12);
    }

    #[test]
    fn simple_resampler_rejects_invalid_rate() {
        let err = SimpleResampler::new(16_000, 96_000).unwrap_err();
        assert_eq!(err, ResamplerError::InvalidSampleRate);
    }

    #[test]
    fn simple_resampler_up_3_over_2_via_up2_down34() {
        let x = test_signal(80);
        let mut rs = SimpleResampler::new(16_000, 24_000).unwrap();
        let need = rs.output_len_for_input(x.len()).unwrap();
        let mut out = vec![0i16; need];
        let n = rs.process(&x, &mut out).unwrap();
        assert_eq!(n, need);
        assert_eq!(n, 120);
    }

    #[test]
    fn simple_resampler_down_3_over_4() {
        let x = test_signal(80);
        let mut rs = SimpleResampler::new(16_000, 12_000).unwrap();
        let need = rs.output_len_for_input(x.len()).unwrap();
        let mut out = vec![0i16; need];
        let n = rs.process(&x, &mut out).unwrap();
        assert_eq!(n, need);
        assert_eq!(n, 60);
    }

    #[test]
    fn simple_resampler_down_2_over_3() {
        let x = test_signal(90);
        let mut rs = SimpleResampler::new(24_000, 16_000).unwrap();
        let need = rs.output_len_for_input(x.len()).unwrap();
        let mut out = vec![0i16; need];
        let n = rs.process(&x, &mut out).unwrap();
        assert_eq!(n, need);
        assert_eq!(n, 60);
    }

    #[test]
    fn simple_resampler_down_1_over_3() {
        let x = test_signal(90);
        let mut rs = SimpleResampler::new(24_000, 8_000).unwrap();
        let need = rs.output_len_for_input(x.len()).unwrap();
        let mut out = vec![0i16; need];
        let n = rs.process(&x, &mut out).unwrap();
        assert_eq!(n, need);
        assert_eq!(n, 30);
    }

    #[test]
    fn fractional_down_stateful_chunking_matches_full() {
        let x = test_signal(120);
        let mut full_rs = SimpleResampler::new(24_000, 16_000).unwrap();
        let full_need = full_rs.output_len_for_input(x.len()).unwrap();
        let mut full = vec![0i16; full_need];
        let full_n = full_rs.process(&x, &mut full).unwrap();

        let mut chunk_rs = SimpleResampler::new(24_000, 16_000).unwrap();
        let mut chunk = vec![0i16; full_need];
        let (a, b) = x.split_at(45);
        let need_a = chunk_rs.output_len_for_input(a.len()).unwrap();
        let n0 = chunk_rs.process(a, &mut chunk[..need_a]).unwrap();
        let n1 = chunk_rs.process(b, &mut chunk[n0..]).unwrap();

        assert_eq!(full_n, n0 + n1);
        assert_eq!(full, chunk);
    }
}
