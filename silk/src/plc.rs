use crate::decoder::{
    DecoderControl, DecoderState, LTP_ORDER, MAX_FRAME_LENGTH, MAX_LPC_ORDER, NB_SUBFR,
};
use crate::math::{clz32, rshift_round, sat16, silk_rand, smlawb, smulbb, smulwb, smulww};
use crate::nlsf2a::{bwexpander, lpc_inverse_pred_gain};

const SIG_TYPE_VOICED: i32 = 0;
const SIG_TYPE_UNVOICED: i32 = 1;

const BWE_COEF_Q16: i32 = 64_880;
const V_PITCH_GAIN_START_MIN_Q14: i32 = 11_469;
const V_PITCH_GAIN_START_MAX_Q14: i32 = 15_565;
const MAX_PITCH_LAG_MS: i32 = 18;
const RAND_BUF_SIZE: usize = 128;
const RAND_BUF_MASK: usize = RAND_BUF_SIZE - 1;
const LOG2_INV_LPC_GAIN_HIGH_THRES: i32 = 3;
const LOG2_INV_LPC_GAIN_LOW_THRES: i32 = 8;
const PITCH_DRIFT_FAC_Q16: i32 = 655;

const HARM_ATT_Q15: [i16; 2] = [32_440, 31_130];
const PLC_RAND_ATTENUATE_V_Q15: [i16; 2] = [31_130, 26_214];
const PLC_RAND_ATTENUATE_UV_Q15: [i16; 2] = [32_440, 29_491];

#[inline]
fn ror32(a32: i32, rot: i32) -> i32 {
    let x = a32 as u32;
    if rot <= 0 {
        x.rotate_left((-rot) as u32) as i32
    } else {
        x.rotate_right(rot as u32) as i32
    }
}

#[inline]
fn clz_frac(input: i32) -> (i32, i32) {
    let lz = clz32(input);
    let frac_q7 = ror32(input, 24 - lz) & 0x7f;
    (lz, frac_q7)
}

#[inline]
fn sqrt_approx(x: i32) -> i32 {
    if x <= 0 {
        return 0;
    }
    let (lz, frac_q7) = clz_frac(x);
    let mut y = if (lz & 1) != 0 { 32_768 } else { 46_214 };
    y >>= lz >> 1;
    smlawb(y, y, smulbb(213, frac_q7))
}

fn sum_sqr_shift_i16(x: &[i16]) -> (i32, i32) {
    let mut shft = 0i32;
    let mut nrg = 0i32;
    for &v in x {
        let sq = (v as i32).wrapping_mul(v as i32);
        nrg = nrg.wrapping_add(sq >> shft);
        if nrg < 0 {
            nrg = ((nrg as u32) >> 2) as i32;
            shft += 2;
        }
    }
    if (nrg & 0xC000_0000u32 as i32) != 0 {
        nrg = ((nrg as u32) >> 2) as i32;
        shft += 2;
    }
    (nrg, shft)
}

pub fn plc_reset(dec: &mut DecoderState) {
    dec.s_plc.pitch_l_q8 = (dec.frame_length as i32) >> 1;
}

pub fn plc(
    dec: &mut DecoderState,
    ctrl: &mut DecoderControl,
    signal: &mut [i16],
    length: usize,
    lost: bool,
) {
    if dec.fs_khz != dec.s_plc.fs_khz {
        plc_reset(dec);
        dec.s_plc.fs_khz = dec.fs_khz;
    }
    if lost {
        plc_conceal(dec, ctrl, signal, length);
        dec.loss_cnt += 1;
    } else {
        plc_update(dec, ctrl, signal, length);
    }
}

pub fn plc_update(
    dec: &mut DecoderState,
    ctrl: &mut DecoderControl,
    _signal: &mut [i16],
    _length: usize,
) {
    dec.prev_sigtype = ctrl.sigtype;
    let mut ltp_gain_q14 = 0i32;

    if ctrl.sigtype == SIG_TYPE_VOICED {
        let mut j = 0usize;
        while (j * dec.subfr_length) < ctrl.pitch_l[NB_SUBFR - 1] as usize {
            let sf = NB_SUBFR - 1 - j;
            let mut temp_gain_q14 = 0i32;
            for i in 0..LTP_ORDER {
                temp_gain_q14 += ctrl.ltp_coef_q14[sf * LTP_ORDER + i] as i32;
            }
            if temp_gain_q14 > ltp_gain_q14 {
                ltp_gain_q14 = temp_gain_q14;
                for i in 0..LTP_ORDER {
                    dec.s_plc.ltp_coef_q14[i] = ctrl.ltp_coef_q14[sf * LTP_ORDER + i];
                }
                dec.s_plc.pitch_l_q8 = ctrl.pitch_l[sf] << 8;
            }
            j += 1;
            if j >= NB_SUBFR {
                break;
            }
        }

        dec.s_plc.ltp_coef_q14.fill(0);
        dec.s_plc.ltp_coef_q14[LTP_ORDER / 2] = ltp_gain_q14 as i16;

        if ltp_gain_q14 < V_PITCH_GAIN_START_MIN_Q14 {
            let scale_q10 = (V_PITCH_GAIN_START_MIN_Q14 << 10) / ltp_gain_q14.max(1);
            for i in 0..LTP_ORDER {
                dec.s_plc.ltp_coef_q14[i] =
                    ((smulbb(dec.s_plc.ltp_coef_q14[i] as i32, scale_q10)) >> 10) as i16;
            }
        } else if ltp_gain_q14 > V_PITCH_GAIN_START_MAX_Q14 {
            let scale_q14 = (V_PITCH_GAIN_START_MAX_Q14 << 14) / ltp_gain_q14.max(1);
            for i in 0..LTP_ORDER {
                dec.s_plc.ltp_coef_q14[i] =
                    ((smulbb(dec.s_plc.ltp_coef_q14[i] as i32, scale_q14)) >> 14) as i16;
            }
        }
    } else {
        dec.s_plc.pitch_l_q8 = (dec.fs_khz * 18) << 8;
        dec.s_plc.ltp_coef_q14.fill(0);
    }

    dec.s_plc.prev_lpc_q12[..dec.lpc_order]
        .copy_from_slice(&ctrl.pred_coef_q12[1][..dec.lpc_order]);
    dec.s_plc.prev_ltp_scale_q14 = ctrl.ltp_scale_q14 as i16;
    dec.s_plc.prev_gain_q16.copy_from_slice(&ctrl.gains_q16);
}

pub fn plc_conceal(
    dec: &mut DecoderState,
    ctrl: &mut DecoderControl,
    signal: &mut [i16],
    _length: usize,
) {
    let frame_length = dec.frame_length;
    let subfr_length = dec.subfr_length;
    let lpc_order = dec.lpc_order;

    for i in 0..frame_length {
        dec.s_ltp_q16[i] = dec.s_ltp_q16[frame_length + i];
    }

    bwexpander(&mut dec.s_plc.prev_lpc_q12[..lpc_order], BWE_COEF_Q16);

    let mut exc_buf = [0i16; MAX_FRAME_LENGTH];
    let mut off = 0usize;
    for k in (NB_SUBFR >> 1)..NB_SUBFR {
        for i in 0..subfr_length {
            let e = smulww(
                dec.exc_q10[i + k * subfr_length],
                dec.s_plc.prev_gain_q16[k],
            );
            exc_buf[off + i] = (e >> 10) as i16;
        }
        off += subfr_length;
    }

    let (energy1, shift1) = sum_sqr_shift_i16(&exc_buf[..subfr_length]);
    let (energy2, shift2) = sum_sqr_shift_i16(&exc_buf[subfr_length..(2 * subfr_length)]);
    let rand_base = if (energy1 >> shift2) < (energy2 >> shift1) {
        (3 * subfr_length).saturating_sub(RAND_BUF_SIZE)
    } else {
        frame_length.saturating_sub(RAND_BUF_SIZE)
    };

    let mut rand_scale_q14 = dec.s_plc.rand_scale_q14 as i32;
    let mut harm_gain_q15 = HARM_ATT_Q15[(dec.loss_cnt as usize).min(1)] as i32;
    let mut rand_gain_q15 = if dec.prev_sigtype == SIG_TYPE_VOICED {
        PLC_RAND_ATTENUATE_V_Q15[(dec.loss_cnt as usize).min(1)] as i32
    } else {
        PLC_RAND_ATTENUATE_UV_Q15[(dec.loss_cnt as usize).min(1)] as i32
    };

    if dec.loss_cnt == 0 {
        rand_scale_q14 = 1 << 14;
        if dec.prev_sigtype == SIG_TYPE_VOICED {
            for i in 0..LTP_ORDER {
                rand_scale_q14 -= dec.s_plc.ltp_coef_q14[i] as i32;
            }
            rand_scale_q14 = rand_scale_q14.max(3277);
            rand_scale_q14 = (smulbb(rand_scale_q14, dec.s_plc.prev_ltp_scale_q14 as i32)) >> 14;
        }
        if dec.prev_sigtype == SIG_TYPE_UNVOICED {
            let (_, inv_gain_q30) = lpc_inverse_pred_gain(&dec.s_plc.prev_lpc_q12[..lpc_order]);
            let mut down_scale_q30 = ((1 << 30) >> LOG2_INV_LPC_GAIN_HIGH_THRES).min(inv_gain_q30);
            down_scale_q30 = ((1 << 30) >> LOG2_INV_LPC_GAIN_LOW_THRES).max(down_scale_q30);
            down_scale_q30 <<= LOG2_INV_LPC_GAIN_HIGH_THRES;
            rand_gain_q15 = smulwb(down_scale_q30, rand_gain_q15) >> 14;
        }
    }

    let mut rand_seed = dec.s_plc.rand_seed;
    let mut lag = rshift_round(dec.s_plc.pitch_l_q8, 8);
    let mut s_ltp_buf_idx = frame_length as i32;
    let mut sig_q10 = [0i32; MAX_FRAME_LENGTH];

    for k in 0..NB_SUBFR {
        let start_pred = (s_ltp_buf_idx - lag + (LTP_ORDER / 2) as i32) as usize;
        for i in 0..subfr_length {
            let pred_idx = start_pred + i;
            rand_seed = silk_rand(rand_seed);
            let idx = ((rand_seed >> 25) as usize) & RAND_BUF_MASK;

            let mut ltp_pred_q14 =
                smulwb(dec.s_ltp_q16[pred_idx], dec.s_plc.ltp_coef_q14[0] as i32);
            ltp_pred_q14 = smlawb(
                ltp_pred_q14,
                dec.s_ltp_q16[pred_idx - 1],
                dec.s_plc.ltp_coef_q14[1] as i32,
            );
            ltp_pred_q14 = smlawb(
                ltp_pred_q14,
                dec.s_ltp_q16[pred_idx - 2],
                dec.s_plc.ltp_coef_q14[2] as i32,
            );
            ltp_pred_q14 = smlawb(
                ltp_pred_q14,
                dec.s_ltp_q16[pred_idx - 3],
                dec.s_plc.ltp_coef_q14[3] as i32,
            );
            ltp_pred_q14 = smlawb(
                ltp_pred_q14,
                dec.s_ltp_q16[pred_idx - 4],
                dec.s_plc.ltp_coef_q14[4] as i32,
            );

            let rand_sample = dec.exc_q10[rand_base + idx];
            let mut lpc_exc_q10 = smulwb(rand_sample, rand_scale_q14) << 2;
            lpc_exc_q10 = lpc_exc_q10.wrapping_add(rshift_round(ltp_pred_q14, 4));

            dec.s_ltp_q16[s_ltp_buf_idx as usize] = lpc_exc_q10 << 6;
            s_ltp_buf_idx += 1;
            sig_q10[k * subfr_length + i] = lpc_exc_q10;
        }

        for j in 0..LTP_ORDER {
            dec.s_plc.ltp_coef_q14[j] =
                ((smulbb(harm_gain_q15, dec.s_plc.ltp_coef_q14[j] as i32)) >> 15) as i16;
        }
        rand_scale_q14 = (smulbb(rand_scale_q14, rand_gain_q15)) >> 15;
        dec.s_plc.pitch_l_q8 += smulwb(dec.s_plc.pitch_l_q8, PITCH_DRIFT_FAC_Q16);
        let max_pitch = (MAX_PITCH_LAG_MS * dec.fs_khz) << 8;
        dec.s_plc.pitch_l_q8 = dec.s_plc.pitch_l_q8.min(max_pitch);
        lag = rshift_round(dec.s_plc.pitch_l_q8, 8);
        harm_gain_q15 = harm_gain_q15.max(0);
    }

    let a_q12_tmp = dec.s_plc.prev_lpc_q12;
    for k in 0..NB_SUBFR {
        for i in 0..subfr_length {
            let mut lpc_pred_q10 = 0i32;
            for (j, &a_q12) in a_q12_tmp.iter().take(lpc_order).enumerate() {
                lpc_pred_q10 = smlawb(
                    lpc_pred_q10,
                    dec.s_lpc_q14[MAX_LPC_ORDER + i - j - 1],
                    a_q12 as i32,
                );
            }
            let idx = k * subfr_length + i;
            sig_q10[idx] = sig_q10[idx].wrapping_add(lpc_pred_q10);
            dec.s_lpc_q14[MAX_LPC_ORDER + i] = sig_q10[idx] << 4;
        }
        let src = dec.s_lpc_q14[subfr_length..subfr_length + MAX_LPC_ORDER].to_vec();
        dec.s_lpc_q14[..MAX_LPC_ORDER].copy_from_slice(&src);
    }

    for i in 0..frame_length {
        let v = rshift_round(
            smulww(sig_q10[i], dec.s_plc.prev_gain_q16[NB_SUBFR - 1]),
            10,
        );
        signal[i] = sat16(v);
    }

    dec.s_plc.rand_seed = rand_seed;
    dec.s_plc.rand_scale_q14 = rand_scale_q14 as i16;
    ctrl.pitch_l.fill(lag);
}

pub fn plc_glue_frames(
    dec: &mut DecoderState,
    _ctrl: &mut DecoderControl,
    signal: &mut [i16],
    length: usize,
) {
    if dec.loss_cnt > 0 {
        let (nrg, sh) = sum_sqr_shift_i16(&signal[..length]);
        dec.s_plc.conc_energy = nrg;
        dec.s_plc.conc_energy_shift = sh;
        dec.s_plc.last_frame_lost = 1;
    } else {
        if dec.s_plc.last_frame_lost != 0 {
            let (mut energy, energy_shift) = sum_sqr_shift_i16(&signal[..length]);
            if energy_shift > dec.s_plc.conc_energy_shift {
                dec.s_plc.conc_energy >>= energy_shift - dec.s_plc.conc_energy_shift;
            } else if energy_shift < dec.s_plc.conc_energy_shift {
                energy >>= dec.s_plc.conc_energy_shift - energy_shift;
            }
            if energy > dec.s_plc.conc_energy {
                let mut conc_energy = dec.s_plc.conc_energy;
                let lz = clz32(conc_energy) - 1;
                conc_energy <<= lz.max(0);
                energy >>= (24 - lz).max(0);

                let frac_q24 = conc_energy / energy.max(1);
                let mut gain_q12 = sqrt_approx(frac_q24);
                let slope_q12 = ((1 << 12) - gain_q12) / (length as i32).max(1);

                for s in signal.iter_mut().take(length) {
                    *s = ((gain_q12 * *s as i32) >> 12) as i16;
                    gain_q12 += slope_q12;
                    gain_q12 = gain_q12.min(1 << 12);
                }
            }
        }
        dec.s_plc.last_frame_lost = 0;
    }
}
