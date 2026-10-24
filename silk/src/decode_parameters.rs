use crate::decoder::{DecoderControl, DecoderState, NB_SUBFR};
use crate::gains::gains_dequant;
use crate::nlsf::{NlsfCbKind, nlsf_msvq_decode};
use crate::nlsf2a::{bwexpander, nlsf2a_stable};
use crate::pitch::decode_pitch;
use crate::pulses_codec::decode_pulses;
use crate::range_coder::{RANGE_CODER_ILLEGAL_SAMPLING_RATE, RANGE_CODER_READ_BEYOND_BUFFER};
use crate::tables_control::{
    DELTA_GAIN_CDF, DELTA_GAIN_CDF_OFFSET, FRAME_TERMINATION_CDF, FRAME_TERMINATION_OFFSET,
    GAIN_CDF, GAIN_CDF_OFFSET, LTP_SCALES_TABLE_Q14, NLSF_INTERPOLATION_FACTOR_CDF,
    NLSF_INTERPOLATION_FACTOR_OFFSET, SAMPLING_RATES_CDF, SAMPLING_RATES_OFFSET,
    SAMPLING_RATES_TABLE, SEED_CDF, SEED_OFFSET, TYPE_OFFSET_CDF, TYPE_OFFSET_CDF_OFFSET,
    TYPE_OFFSET_JOINT_CDF, VADFLAG_CDF, VADFLAG_OFFSET,
};
use crate::tables_ltp::{
    LTP_GAIN_CDF_0, LTP_GAIN_CDF_1, LTP_GAIN_CDF_2, LTP_GAIN_CDF_OFFSETS, LTP_GAIN_VQ_0_Q14,
    LTP_GAIN_VQ_1_Q14, LTP_GAIN_VQ_2_Q14, LTP_PER_INDEX_CDF, LTP_PER_INDEX_CDF_OFFSET,
};
use crate::tables_nlsf::{
    NLSF_CB0_10_CDF, NLSF_CB0_10_MIDDLE_IX, NLSF_CB0_10_START_IX, NLSF_CB0_16_CDF,
    NLSF_CB0_16_MIDDLE_IX, NLSF_CB0_16_START_IX, NLSF_CB1_10_CDF, NLSF_CB1_10_MIDDLE_IX,
    NLSF_CB1_10_START_IX, NLSF_CB1_16_CDF, NLSF_CB1_16_MIDDLE_IX, NLSF_CB1_16_START_IX,
};
use crate::tables_pitch_lag::{
    PITCH_CONTOUR_CDF, PITCH_CONTOUR_CDF_OFFSET, PITCH_CONTOUR_NB_CDF, PITCH_CONTOUR_NB_CDF_OFFSET,
    PITCH_LAG_MB_CDF, PITCH_LAG_MB_CDF_OFFSET, PITCH_LAG_NB_CDF, PITCH_LAG_NB_CDF_OFFSET,
    PITCH_LAG_SWB_CDF, PITCH_LAG_SWB_CDF_OFFSET, PITCH_LAG_WB_CDF, PITCH_LAG_WB_CDF_OFFSET,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedHeader {
    pub fs_khz: i32,
    pub sigtype: i32,
    pub quant_offset_type: i32,
    pub gains_indices: [i32; NB_SUBFR],
    pub seed: i32,
    pub vad_flag: i32,
    pub frame_termination: i32,
}

#[allow(dead_code)]
pub struct DecodeParametersOutput {
    pub header: DecodedHeader,
    pub q: Vec<i32>,
    pub type_ix: usize,
    pub nlsf_indices: Vec<usize>,
    pub nlsf_interp_coef_q2: usize,
    pub lag_index: Option<usize>,
    pub contour_index: Option<usize>,
    pub per_index: Option<usize>,
    pub ltp_gain_indices: [usize; NB_SUBFR],
    pub ltp_scale_index: Option<usize>,
}

fn interp_nlsf_q15(dst: &mut [i32], prev: &[i32], cur: &[i32], coef_q2: i32) {
    for i in 0..dst.len() {
        dst[i] = prev[i] + ((coef_q2 * (cur[i] - prev[i])) >> 2);
    }
}

fn decode_nlsf_path(
    dec: &mut DecoderState,
    cdf: &[u16],
    start_ix: &[usize],
    middle_ix: &[usize],
) -> Vec<usize> {
    let mut out = vec![0usize; start_ix.len()];
    for s in 0..start_ix.len() {
        let start = start_ix[s];
        let end = if s + 1 < start_ix.len() {
            start_ix[s + 1]
        } else {
            cdf.len()
        };
        if start >= end || end > cdf.len() || end - start < 2 {
            dec.src.error = RANGE_CODER_READ_BEYOND_BUFFER;
            return out;
        }
        let stage_cdf = &cdf[start..end];
        let prob = middle_ix[s].min(stage_cdf.len() - 2);
        out[s] = dec.src.decode_symbol(stage_cdf, prob);
    }
    out
}

fn select_nlsf_tables(
    sigtype: i32,
    lpc_order: usize,
) -> (&'static [u16], &'static [usize], &'static [usize]) {
    match (sigtype, lpc_order) {
        (0, 10) => (
            &NLSF_CB0_10_CDF,
            &NLSF_CB0_10_START_IX,
            &NLSF_CB0_10_MIDDLE_IX,
        ),
        (1, 10) => (
            &NLSF_CB1_10_CDF,
            &NLSF_CB1_10_START_IX,
            &NLSF_CB1_10_MIDDLE_IX,
        ),
        (0, _) => (
            &NLSF_CB0_16_CDF,
            &NLSF_CB0_16_START_IX,
            &NLSF_CB0_16_MIDDLE_IX,
        ),
        _ => (
            &NLSF_CB1_16_CDF,
            &NLSF_CB1_16_START_IX,
            &NLSF_CB1_16_MIDDLE_IX,
        ),
    }
}

pub fn decode_parameters(
    dec: &mut DecoderState,
    ctrl: &mut DecoderControl,
    full_decoding: bool,
) -> DecodeParametersOutput {
    if dec.n_frames_decoded == 0 {
        let ix = dec
            .src
            .decode_symbol(&SAMPLING_RATES_CDF, SAMPLING_RATES_OFFSET);
        if ix >= SAMPLING_RATES_TABLE.len() {
            dec.src.error = RANGE_CODER_ILLEGAL_SAMPLING_RATE;
            return DecodeParametersOutput {
                header: DecodedHeader {
                    fs_khz: dec.fs_khz,
                    sigtype: ctrl.sigtype,
                    quant_offset_type: ctrl.quant_offset_type,
                    gains_indices: [0; NB_SUBFR],
                    seed: ctrl.seed,
                    vad_flag: dec.vad_flag,
                    frame_termination: dec.frame_termination,
                },
                q: vec![0; dec.frame_length],
                type_ix: 0,
                nlsf_indices: Vec::new(),
                nlsf_interp_coef_q2: 4,
                lag_index: None,
                contour_index: None,
                per_index: None,
                ltp_gain_indices: [0; NB_SUBFR],
                ltp_scale_index: None,
            };
        }
        dec.set_fs(SAMPLING_RATES_TABLE[ix]);
    }

    let type_ix = if dec.n_frames_decoded == 0 {
        dec.src
            .decode_symbol(&TYPE_OFFSET_CDF, TYPE_OFFSET_CDF_OFFSET) as i32
    } else {
        dec.src.decode_symbol(
            &TYPE_OFFSET_JOINT_CDF[dec.type_offset_prev as usize],
            TYPE_OFFSET_CDF_OFFSET,
        ) as i32
    };
    ctrl.sigtype = type_ix >> 1;
    ctrl.quant_offset_type = type_ix & 1;
    dec.type_offset_prev = type_ix;

    let mut gains_indices = [0i32; NB_SUBFR];
    gains_indices[0] = if dec.n_frames_decoded == 0 {
        dec.src
            .decode_symbol(&GAIN_CDF[ctrl.sigtype as usize], GAIN_CDF_OFFSET) as i32
    } else {
        dec.src
            .decode_symbol(&DELTA_GAIN_CDF, DELTA_GAIN_CDF_OFFSET) as i32
    };
    for g in gains_indices.iter_mut().skip(1) {
        *g = dec
            .src
            .decode_symbol(&DELTA_GAIN_CDF, DELTA_GAIN_CDF_OFFSET) as i32;
    }
    gains_dequant(
        &mut ctrl.gains_q16,
        &gains_indices,
        &mut dec.last_gain_index,
        dec.n_frames_decoded != 0,
    );

    let (nlsf_cdf, nlsf_start_ix, nlsf_mid_ix) = select_nlsf_tables(ctrl.sigtype, dec.lpc_order);
    let nlsf_indices = decode_nlsf_path(dec, nlsf_cdf, nlsf_start_ix, nlsf_mid_ix);
    let nlsf_kind = match (ctrl.sigtype, dec.lpc_order) {
        (0, 10) => NlsfCbKind::Cb0_10,
        (1, 10) => NlsfCbKind::Cb1_10,
        (0, _) => NlsfCbKind::Cb0_16,
        _ => NlsfCbKind::Cb1_16,
    };
    let p_nlsf_q15 = nlsf_msvq_decode(nlsf_kind, &nlsf_indices);

    let nlsf_interp_raw = dec.src.decode_symbol(
        &NLSF_INTERPOLATION_FACTOR_CDF,
        NLSF_INTERPOLATION_FACTOR_OFFSET,
    ) as i32;
    ctrl.nlsf_interp_coef_q2 = nlsf_interp_raw;
    if dec.first_frame_after_reset == 1 {
        ctrl.nlsf_interp_coef_q2 = 4;
    }
    if full_decoding {
        let mut a1 = vec![0i16; dec.lpc_order];
        nlsf2a_stable(&mut a1, &p_nlsf_q15[..dec.lpc_order]);
        ctrl.pred_coef_q12[1][..dec.lpc_order].copy_from_slice(&a1);
        if ctrl.nlsf_interp_coef_q2 < 4 {
            let mut p0 = vec![0i32; dec.lpc_order];
            interp_nlsf_q15(
                &mut p0,
                &dec.prev_nlsf_q15[..dec.lpc_order],
                &p_nlsf_q15[..dec.lpc_order],
                ctrl.nlsf_interp_coef_q2,
            );
            let mut a0 = vec![0i16; dec.lpc_order];
            nlsf2a_stable(&mut a0, &p0);
            ctrl.pred_coef_q12[0][..dec.lpc_order].copy_from_slice(&a0);
        } else {
            let tmp = ctrl.pred_coef_q12[1][..dec.lpc_order].to_vec();
            ctrl.pred_coef_q12[0][..dec.lpc_order].copy_from_slice(&tmp);
        }

        if dec.loss_cnt > 0 {
            bwexpander(&mut ctrl.pred_coef_q12[0][..dec.lpc_order], 63_570);
            bwexpander(&mut ctrl.pred_coef_q12[1][..dec.lpc_order], 63_570);
        }
    }

    for (i, &v) in p_nlsf_q15.iter().enumerate().take(dec.lpc_order) {
        dec.prev_nlsf_q15[i] = v;
    }

    let mut lag_index = None;
    let mut contour_index = None;
    let mut per_index = None;
    let mut ltp_gain_indices = [0usize; NB_SUBFR];
    let mut ltp_scale_index = None;
    if ctrl.sigtype == 0 {
        let lag_idx = match dec.fs_khz {
            8 => dec
                .src
                .decode_symbol(&PITCH_LAG_NB_CDF, PITCH_LAG_NB_CDF_OFFSET),
            12 => dec
                .src
                .decode_symbol(&PITCH_LAG_MB_CDF, PITCH_LAG_MB_CDF_OFFSET),
            16 => dec
                .src
                .decode_symbol(&PITCH_LAG_WB_CDF, PITCH_LAG_WB_CDF_OFFSET),
            _ => dec
                .src
                .decode_symbol(&PITCH_LAG_SWB_CDF, PITCH_LAG_SWB_CDF_OFFSET),
        };
        lag_index = Some(lag_idx);
        let contour_idx = if dec.fs_khz == 8 {
            dec.src
                .decode_symbol(&PITCH_CONTOUR_NB_CDF, PITCH_CONTOUR_NB_CDF_OFFSET)
        } else {
            dec.src
                .decode_symbol(&PITCH_CONTOUR_CDF, PITCH_CONTOUR_CDF_OFFSET)
        };
        contour_index = Some(contour_idx);
        ctrl.pitch_l = decode_pitch(lag_idx as i32, contour_idx, dec.fs_khz);

        ctrl.per_index =
            dec.src
                .decode_symbol(&LTP_PER_INDEX_CDF, LTP_PER_INDEX_CDF_OFFSET) as i32;
        per_index = Some(ctrl.per_index as usize);
        let cdf = match ctrl.per_index {
            0 => &LTP_GAIN_CDF_0[..],
            1 => &LTP_GAIN_CDF_1[..],
            _ => &LTP_GAIN_CDF_2[..],
        };
        let cdf_offset = LTP_GAIN_CDF_OFFSETS[ctrl.per_index as usize];
        for (k, ltp_gain_ix) in ltp_gain_indices.iter_mut().enumerate().take(NB_SUBFR) {
            let ix = dec.src.decode_symbol(cdf, cdf_offset);
            *ltp_gain_ix = ix;
            let base = k * 5;
            let vq = match ctrl.per_index {
                0 => &LTP_GAIN_VQ_0_Q14[..],
                1 => &LTP_GAIN_VQ_1_Q14[..],
                _ => &LTP_GAIN_VQ_2_Q14[..],
            };
            let vq_base = ix * 5;
            if vq_base + 5 <= vq.len() {
                ctrl.ltp_coef_q14[base..base + 5].copy_from_slice(&vq[vq_base..vq_base + 5]);
            } else {
                dec.src.error = RANGE_CODER_READ_BEYOND_BUFFER;
                ctrl.ltp_coef_q14[base..base + 5].fill(0);
            }
        }
        let ix = dec.src.decode_symbol(
            &crate::tables_control::LTP_SCALE_CDF,
            crate::tables_control::LTP_SCALE_OFFSET,
        );
        ltp_scale_index = Some(ix);
        ctrl.ltp_scale_q14 = LTP_SCALES_TABLE_Q14[ix] as i32;
    } else {
        ctrl.pitch_l.fill(0);
        ctrl.ltp_coef_q14.fill(0);
        ctrl.per_index = 0;
        ctrl.ltp_scale_q14 = 0;
    }

    ctrl.seed = dec.src.decode_symbol(&SEED_CDF, SEED_OFFSET) as i32;
    let (q, rate_level_index) = decode_pulses(
        &mut dec.src,
        ctrl.sigtype as usize,
        ctrl.quant_offset_type as usize,
        dec.frame_length,
    );
    ctrl.rate_level_index = rate_level_index as i32;
    dec.vad_flag = dec.src.decode_symbol(&VADFLAG_CDF, VADFLAG_OFFSET) as i32;
    dec.frame_termination =
        dec.src
            .decode_symbol(&FRAME_TERMINATION_CDF, FRAME_TERMINATION_OFFSET) as i32;

    // An entropy error is reported by the caller; do not derive a bit length
    // from a failed (possibly zero-width) range coder.
    if dec.src.error == 0 {
        let (_bits, nbytes_used) = dec.src.get_length_bits_and_bytes();
        dec.n_bytes_left = dec.src.buffer_length as i32 - nbytes_used as i32;
        if dec.n_bytes_left < 0 {
            dec.src.error = RANGE_CODER_READ_BEYOND_BUFFER;
        }
        if dec.n_bytes_left == 0 {
            dec.src.check_after_decoding();
        }
    }
    let header = DecodedHeader {
        fs_khz: dec.fs_khz,
        sigtype: ctrl.sigtype,
        quant_offset_type: ctrl.quant_offset_type,
        gains_indices,
        seed: ctrl.seed,
        vad_flag: dec.vad_flag,
        frame_termination: dec.frame_termination,
    };
    DecodeParametersOutput {
        header,
        q,
        type_ix: type_ix as usize,
        nlsf_indices,
        nlsf_interp_coef_q2: nlsf_interp_raw as usize,
        lag_index,
        contour_index,
        per_index,
        ltp_gain_indices,
        ltp_scale_index,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder::DecoderState;

    #[test]
    fn decode_parameters_reads_some_symbols() {
        let mut dec = DecoderState::default();
        let payload = vec![0xFFu8; 64];
        dec.src.dec_init(&payload);
        dec.n_frames_decoded = 0;
        let mut ctrl = DecoderControl::default();
        let _ = decode_parameters(&mut dec, &mut ctrl, false);
        assert!(dec.frame_length > 0);
    }
}
