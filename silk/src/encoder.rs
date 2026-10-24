use crate::gains::gains_dequant;
use crate::nlsf::{NlsfCbKind, nlsf_msvq_decode};
use crate::nlsf2a::nlsf2a_stable;
use crate::{
    SilkError, range_encoder::RangeEncoder, tables_control::*, tables_nlsf::*, tables_nlsf_vec::*,
    tables_pulses::*,
};

/// Stateful mono SILK_V3 encoder using 20 ms packets.
/// Bitrate is a VBR target; difficult frames may exceed it to bound quantization noise.
pub struct Encoder {
    sample_rate: u32,
    bitrate: u32,
    history: Vec<f64>,
    quantizer: Quantizer,
}
impl Encoder {
    pub fn new(sample_rate: u32, bitrate: u32) -> Result<Self, SilkError> {
        if !matches!(sample_rate, 8000 | 12000 | 16000 | 24000) {
            return Err(SilkError::InvalidSampleRate);
        }
        Ok(Self {
            sample_rate,
            bitrate: bitrate.clamp(8000, 64000),
            history: vec![0.; 16],
            quantizer: Quantizer {
                history: [0; 16],
                inverse_gain: 65536,
            },
        })
    }
    pub fn encode_frame(&mut self, pcm: &[i16]) -> Result<Vec<u8>, SilkError> {
        let length = self.sample_rate as usize / 50;
        if pcm.len() != length {
            return Err(SilkError::InvalidPcm);
        }
        let order = if self.sample_rate == 8000 { 10 } else { 16 };
        let target = analyze(pcm, &self.history, order);
        let indices = quantize_nlsf(&target, order);
        let kind = if order == 10 {
            NlsfCbKind::Cb1_10
        } else {
            NlsfCbKind::Cb1_16
        };
        let nlsf = nlsf_msvq_decode(kind, &indices);
        let mut lpc = vec![0i16; order];
        nlsf2a_stable(&mut lpc, &nlsf);
        let budget = (self.bitrate / 400).max(32) as usize;
        let mut best = None;
        let mut fallback: Option<(Vec<u8>, Vec<f64>, Quantizer)> = None;
        let (mut low, mut high) = (0i32, 40i32);
        while low <= high {
            let gain_index = ((low + high) / 2) as usize;
            let (pulses, history, state) = quantize(pcm, &lpc, &self.quantizer, gain_index);
            match packet(self.sample_rate, &indices, gain_index, &pulses) {
                Ok(bytes) if bytes.len() <= budget => {
                    best = Some((bytes, history, state));
                    high = gain_index as i32 - 1;
                }
                Ok(bytes) => {
                    if fallback
                        .as_ref()
                        .is_none_or(|(previous, _, _)| bytes.len() < previous.len())
                    {
                        fallback = Some((bytes, history, state));
                    }
                    low = gain_index as i32 + 1;
                }
                Err(SilkError::InvalidPacket) => low = gain_index as i32 + 1,
                Err(error) => return Err(error),
            }
        }
        let (bytes, history, state) = match best {
            Some(best) => best,
            None => fallback.ok_or(SilkError::InvalidPacket)?,
        };
        self.history = history;
        self.quantizer = state;
        Ok(bytes)
    }
}

/// Encode signed little-endian mono PCM16, padding the final 20 ms frame with silence.
pub fn encode_silk(
    pcm: &[u8],
    sample_rate: u32,
    bitrate: u32,
    tencent: bool,
) -> Result<Vec<u8>, SilkError> {
    if !pcm.len().is_multiple_of(2) || pcm.is_empty() {
        return Err(SilkError::InvalidPcm);
    }
    let mut encoder = Encoder::new(sample_rate, bitrate)?;
    if pcm.len() / 2 > sample_rate as usize * 600 {
        return Err(SilkError::TooLong);
    }
    let length = sample_rate as usize / 50;
    let mut out = Vec::new();
    if tencent {
        out.push(2);
    }
    out.extend_from_slice(b"#!SILK_V3");
    for chunk in pcm.chunks(length * 2) {
        let mut frame = vec![0i16; length];
        for (sample, bytes) in frame.iter_mut().zip(chunk.as_chunks::<2>().0.iter()) {
            *sample = i16::from_le_bytes([bytes[0], bytes[1]]);
        }
        let packet = encoder.encode_frame(&frame)?;
        out.extend_from_slice(&(packet.len() as i16).to_le_bytes());
        out.extend(packet);
    }
    Ok(out)
}

fn analyze(pcm: &[i16], history: &[f64], order: usize) -> Vec<i16> {
    let mut signal = history.iter().rev().copied().collect::<Vec<_>>();
    signal.extend(pcm.iter().map(|&sample| sample as f64));
    let mut r = vec![0.; order + 1];
    for lag in 0..=order {
        r[lag] = (order..signal.len())
            .map(|i| signal[i] * signal[i - lag])
            .sum();
    }
    r[0] = r[0] * 1.0001 + 1.;
    let mut a = vec![0.; order];
    let mut error = r[0];
    for i in 0..order {
        let reflection =
            ((r[i + 1] - (0..i).map(|j| a[j] * r[i - j]).sum::<f64>()) / error).clamp(-0.97, 0.97);
        let previous = a.clone();
        for j in 0..i {
            a[j] = previous[j] - reflection * previous[i - j - 1];
        }
        a[i] = reflection;
        error *= 1. - reflection * reflection;
    }
    for (i, value) in a.iter_mut().enumerate() {
        *value *= 0.98f64.powi(i as i32 + 1);
    }
    crate::analysis::lpc_to_nlsf(&a)
}

fn quantize_nlsf(target: &[i16], order: usize) -> Vec<usize> {
    let (counts, vectors): (&[usize], &[i16]) = if order == 10 {
        (&NLSF_CB1_10_STAGE_NVEC, &NLSF_CB1_10_Q15)
    } else {
        (&NLSF_CB1_16_STAGE_NVEC, &NLSF_CB1_16_Q15)
    };
    let mut beam = vec![(
        target.iter().map(|&x| x as f64).collect::<Vec<_>>(),
        Vec::new(),
        0.,
    )];
    let mut base = 0;
    for &count in counts {
        let mut next = Vec::new();
        for (residual, path, _) in &beam {
            for index in 0..count {
                let vector = &vectors[(base + index) * order..(base + index + 1) * order];
                let residual: Vec<_> = residual
                    .iter()
                    .zip(vector)
                    .map(|(a, &b)| a - b as f64)
                    .collect();
                let score = residual.iter().map(|x| x * x).sum::<f64>();
                let mut path = path.clone();
                path.push(index);
                next.push((residual, path, score));
            }
        }
        next.sort_by(|a, b| a.2.total_cmp(&b.2));
        next.truncate(8);
        beam = next;
        base += count;
    }
    beam.remove(0).1
}

#[derive(Clone)]
struct Quantizer {
    history: [i32; 16],
    inverse_gain: i32,
}
fn quantize(
    pcm: &[i16],
    lpc: &[i16],
    previous: &Quantizer,
    gain_index: usize,
) -> (Vec<i32>, Vec<f64>, Quantizer) {
    use crate::math::{inverse32_varq, rshift_round, sat16, smulww};
    use opus_rs::silk::macros::{silk_smlawb, silk_smulwb};
    let mut gain_q16 = [0; 4];
    gains_dequant(&mut gain_q16, &[gain_index as i32, 4, 4, 4], &mut 0, false);
    let gain = gain_q16[0] as f64 / 65536.;
    let mut state = previous.clone();
    let inverse_gain = inverse32_varq(gain_q16[0].max(1), 32).min(i16::MAX as i32);
    if inverse_gain != state.inverse_gain {
        let adjustment = crate::decode_core::div32_varq(inverse_gain, state.inverse_gain, 16);
        for sample in &mut state.history {
            *sample = smulww(adjustment, *sample);
        }
    }
    state.inverse_gain = inverse_gain;
    let mut seed = 0u32;
    let mut pulses = Vec::with_capacity(pcm.len());
    let mut history = previous.history.iter().map(|_| 0.).collect::<Vec<_>>();
    for &sample in pcm {
        let mut predicted = silk_smulwb(state.history[0], lpc[0] as i32);
        for (&history, &coefficient) in state.history[1..].iter().zip(&lpc[1..]) {
            predicted = silk_smlawb(predicted, history, coefficient as i32);
        }
        seed = 907633515u32.wrapping_add(seed.wrapping_mul(196314165));
        let sign = if (seed as i32) < 0 { -1 } else { 1 };
        let q = ((((sample as f64 / gain * 1024. - predicted as f64) * sign as f64) - 100.) / 1024.)
            .round()
            .clamp(-127., 127.) as i32;
        let reconstructed = predicted.wrapping_add(sign * (q * 1024 + 100));
        state.history.rotate_right(1);
        state.history[0] = reconstructed.saturating_mul(16);
        history.rotate_right(1);
        history[0] = sat16(rshift_round(smulww(reconstructed, gain_q16[0]), 10)) as f64;
        pulses.push(q);
        seed = seed.wrapping_add(q as u32);
    }
    (pulses, history, state)
}

fn packet(
    sample_rate: u32,
    nlsf: &[usize],
    gain: usize,
    pulses: &[i32],
) -> Result<Vec<u8>, SilkError> {
    let mut rc = RangeEncoder::new();
    let rate = match sample_rate {
        8000 => 0,
        12000 => 1,
        16000 => 2,
        _ => 3,
    };
    rc.symbol(rate, &SAMPLING_RATES_CDF)?;
    rc.symbol(2, &TYPE_OFFSET_CDF)?;
    rc.symbol(gain, &GAIN_CDF[1])?;
    for _ in 0..3 {
        rc.symbol(4, &DELTA_GAIN_CDF)?;
    }
    let (cdf, starts): (&[u16], &[usize]) = if sample_rate == 8000 {
        (&NLSF_CB1_10_CDF, &NLSF_CB1_10_START_IX)
    } else {
        (&NLSF_CB1_16_CDF, &NLSF_CB1_16_START_IX)
    };
    for (stage, &index) in nlsf.iter().enumerate() {
        rc.symbol(index, &cdf[starts[stage]..])?;
    }
    rc.symbol(4, &NLSF_INTERPOLATION_FACTOR_CDF)?;
    rc.symbol(0, &SEED_CDF)?;
    encode_pulses(&mut rc, pulses)?;
    rc.symbol(1, &VADFLAG_CDF)?;
    rc.symbol(0, &FRAME_TERMINATION_CDF)?;
    rc.finish()
}

fn encode_pulses(rc: &mut RangeEncoder, pulses: &[i32]) -> Result<(), SilkError> {
    let mut blocks = Vec::new();
    for chunk in pulses.as_chunks::<16>().0 {
        let absolute: Vec<_> = chunk.iter().map(|x| x.unsigned_abs()).collect();
        let mut scaled = absolute.clone();
        let mut shifts = 0;
        loop {
            let valid = [2, 4, 8, 16]
                .iter()
                .zip([6, 8, 12, 18])
                .all(|(&width, maximum)| {
                    scaled
                        .chunks_exact(width)
                        .all(|values| values.iter().sum::<u32>() <= maximum)
                });
            if valid {
                break;
            }
            shifts += 1;
            for value in &mut scaled {
                *value >>= 1;
            }
        }
        blocks.push((absolute, scaled, shifts));
    }
    let rate = (0..9)
        .min_by(|&a, &b| {
            let cost = |rate: usize| {
                blocks
                    .iter()
                    .map(|(_, scaled, shifts)| {
                        let symbol = if *shifts > 0 {
                            19
                        } else {
                            scaled.iter().sum::<u32>() as usize
                        };
                        let cdf = &PULSES_PER_BLOCK_CDF[rate];
                        -((cdf[symbol + 1] - cdf[symbol]) as f64 / 65535.).log2()
                    })
                    .sum::<f64>()
                    - ((RATE_LEVELS_CDF[1][rate + 1] - RATE_LEVELS_CDF[1][rate]) as f64 / 65535.)
                        .log2()
            };
            cost(a).total_cmp(&cost(b))
        })
        .unwrap();
    rc.symbol(rate, &RATE_LEVELS_CDF[1])?;
    for (_, scaled, shifts) in &blocks {
        let sum = scaled.iter().sum::<u32>() as usize;
        if *shifts > 0 {
            rc.symbol(19, &PULSES_PER_BLOCK_CDF[rate])?;
            for _ in 1..*shifts {
                rc.symbol(19, &PULSES_PER_BLOCK_CDF[9])?;
            }
            rc.symbol(sum, &PULSES_PER_BLOCK_CDF[9])?;
        } else {
            rc.symbol(sum, &PULSES_PER_BLOCK_CDF[rate])?;
        }
    }
    for (_, scaled, _) in &blocks {
        shell(rc, scaled, 3)?;
    }
    for (absolute, _, shifts) in &blocks {
        for &value in absolute {
            for bit in (0..*shifts).rev() {
                rc.symbol(((value >> bit) & 1) as usize, &LSB_CDF)?;
            }
        }
    }
    let cdf = [0, SIGN_CDF[18 + rate], 65535];
    for &pulse in pulses {
        if pulse != 0 {
            rc.symbol(usize::from(pulse > 0), &cdf)?;
        }
    }
    Ok(())
}
fn shell(rc: &mut RangeEncoder, values: &[u32], level: usize) -> Result<(), SilkError> {
    let total = values.iter().sum::<u32>() as usize;
    if total == 0 {
        return Ok(());
    }
    let half = values.len() / 2;
    let left = values[..half].iter().sum::<u32>() as usize;
    let table: &[u16] = match level {
        0 => &SHELL_CODE_TABLE0,
        1 => &SHELL_CODE_TABLE1,
        2 => &SHELL_CODE_TABLE2,
        _ => &SHELL_CODE_TABLE3,
    };
    rc.symbol(left, &table[SHELL_CODE_TABLE_OFFSETS[total] as usize..])?;
    if level > 0 {
        shell(rc, &values[..half], level - 1)?;
        shell(rc, &values[half..], level - 1)?;
    }
    Ok(())
}
