use crate::decoder::{CNG_BUF_MASK_MAX, DecoderControl, DecoderState, NB_SUBFR};
use crate::math::{rshift_round, sat16, silk_rand, smlawb, smlawt, smulwb, smulww};
use crate::nlsf2a::nlsf2a_stable;

const NO_VOICE_ACTIVITY: i32 = 0;
const CNG_GAIN_SMTH_Q16: i32 = 4634;
const CNG_NLSF_SMTH_Q16: i32 = 16_348;

#[inline]
fn add_sat32(a: i32, b: i32) -> i32 {
    a.saturating_add(b)
}

#[inline]
fn lshift_sat32(a: i32, shift: i32) -> i32 {
    if shift <= 0 {
        a >> (-shift)
    } else {
        a.checked_shl(shift as u32)
            .unwrap_or(if a < 0 { i32::MIN } else { i32::MAX })
    }
}

fn lpc_synthesis_filter(
    in_sig: &[i16],
    a_q12: &[i16],
    gain_q26: i32,
    state: &mut [i32],
    out: &mut [i16],
    order: usize,
) {
    let order_half = order >> 1;
    for k in 0..in_sig.len() {
        let mut sa = state[order - 1];
        let mut out32_q10 = 0i32;
        for j in 0..(order_half - 1) {
            let idx = (j << 1) + 1;
            let sb = state[order - 1 - idx];
            state[order - 1 - idx] = sa;
            out32_q10 = smlawb(out32_q10, sa, a_q12[j << 1] as i32);
            out32_q10 = smlawt(out32_q10, sb, a_q12[(j << 1) + 1] as i32);
            sa = state[order - 2 - idx];
            state[order - 2 - idx] = sb;
        }
        let sb = state[0];
        state[0] = sa;
        out32_q10 = smlawb(out32_q10, sa, a_q12[order - 2] as i32);
        out32_q10 = smlawt(out32_q10, sb, a_q12[order - 1] as i32);
        out32_q10 = add_sat32(out32_q10, smulwb(gain_q26, in_sig[k] as i32));
        let out32 = rshift_round(out32_q10, 10);
        out[k] = sat16(out32);
        state[order - 1] = lshift_sat32(out32_q10, 4);
    }
}

fn cng_exc(residual: &mut [i16], exc_buf_q10: &[i32], gain_q16: i32, rand_seed: &mut i32) {
    let length = residual.len();
    let mut exc_mask = CNG_BUF_MASK_MAX;
    while exc_mask > length {
        exc_mask >>= 1;
    }

    let mut seed = *rand_seed;
    for r in residual.iter_mut() {
        seed = silk_rand(seed);
        let idx = ((seed >> 24) as usize) & exc_mask;
        *r = sat16(rshift_round(smulww(exc_buf_q10[idx], gain_q16), 10));
    }
    *rand_seed = seed;
}

pub fn cng_reset(dec: &mut DecoderState) {
    let nlsf_step_q15 = (i16::MAX as i32) / (dec.lpc_order as i32 + 1);
    let mut nlsf_acc_q15 = 0i32;
    for i in 0..dec.lpc_order {
        nlsf_acc_q15 += nlsf_step_q15;
        dec.s_cng.cng_smth_nlsf_q15[i] = nlsf_acc_q15;
    }
    dec.s_cng.cng_smth_gain_q16 = 0;
    dec.s_cng.rand_seed = 3_176_576;
}

pub fn cng(dec: &mut DecoderState, ctrl: &mut DecoderControl, signal: &mut [i16], length: usize) {
    if dec.fs_khz != dec.s_cng.fs_khz {
        cng_reset(dec);
        dec.s_cng.fs_khz = dec.fs_khz;
    }

    if dec.loss_cnt == 0 && dec.vad_flag == NO_VOICE_ACTIVITY {
        for i in 0..dec.lpc_order {
            dec.s_cng.cng_smth_nlsf_q15[i] += smulwb(
                dec.prev_nlsf_q15[i] - dec.s_cng.cng_smth_nlsf_q15[i],
                CNG_NLSF_SMTH_Q16,
            );
        }

        let mut max_gain_q16 = 0i32;
        let mut subfr = 0usize;
        for i in 0..NB_SUBFR {
            if ctrl.gains_q16[i] > max_gain_q16 {
                max_gain_q16 = ctrl.gains_q16[i];
                subfr = i;
            }
        }

        let sf = dec.subfr_length;
        let move_len = (NB_SUBFR - 1) * sf;
        for i in (0..move_len).rev() {
            dec.s_cng.cng_exc_buf_q10[sf + i] = dec.s_cng.cng_exc_buf_q10[i];
        }
        for i in 0..sf {
            dec.s_cng.cng_exc_buf_q10[i] = dec.exc_q10[subfr * sf + i];
        }

        for i in 0..NB_SUBFR {
            dec.s_cng.cng_smth_gain_q16 += smulwb(
                ctrl.gains_q16[i] - dec.s_cng.cng_smth_gain_q16,
                CNG_GAIN_SMTH_Q16,
            );
        }
    }

    if dec.loss_cnt != 0 {
        let mut cng_sig = vec![0i16; length];
        cng_exc(
            &mut cng_sig,
            &dec.s_cng.cng_exc_buf_q10,
            dec.s_cng.cng_smth_gain_q16,
            &mut dec.s_cng.rand_seed,
        );

        let mut lpc_buf = vec![0i16; dec.lpc_order];
        nlsf2a_stable(&mut lpc_buf, &dec.s_cng.cng_smth_nlsf_q15[..dec.lpc_order]);

        let gain_q26 = 1 << 26;
        let cng_in = cng_sig.clone();
        lpc_synthesis_filter(
            &cng_in,
            &lpc_buf,
            gain_q26,
            &mut dec.s_cng.cng_synth_state[..dec.lpc_order],
            &mut cng_sig,
            dec.lpc_order,
        );

        for i in 0..length {
            signal[i] = sat16(signal[i] as i32 + cng_sig[i] as i32);
        }
    } else {
        dec.s_cng.cng_synth_state[..dec.lpc_order].fill(0);
    }
}
