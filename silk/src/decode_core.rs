use crate::decoder::{DecoderControl, DecoderState, MAX_FRAME_LENGTH, MAX_LPC_ORDER, NB_SUBFR};
use crate::math::{
    inverse32_varq, rshift_round, sat16, shift_with_lshift, silk_rand, smlawb, smulwb, smulww,
};
use crate::tables_control::QUANTIZATION_OFFSETS_Q10;

const LTP_ORDER: usize = 5;
const SIG_TYPE_VOICED: i32 = 0;
const SIG_TYPE_UNVOICED: i32 = 1;

#[inline]
pub(crate) fn div32_varq(a32: i32, b32: i32, qres: i32) -> i32 {
    if b32 == 0 || qres < 0 {
        return 0;
    }
    let a_headrm = a32.unsigned_abs().leading_zeros() as i32 - 1;
    let mut a32_nrm = a32 << a_headrm;
    let b_headrm = b32.unsigned_abs().leading_zeros() as i32 - 1;
    let b32_nrm = b32 << b_headrm;
    let b32_inv = (i32::MAX >> 2) / (b32_nrm >> 16);
    let mut result = smulwb(a32_nrm, b32_inv);
    a32_nrm = a32_nrm.wrapping_sub(((((b32_nrm as i64) * (result as i64)) >> 32) as i32) << 3);
    result = smlawb(result, a32_nrm, b32_inv);
    let lshift = 29 + a_headrm - b_headrm - qres;
    shift_with_lshift(result, lshift)
}

fn ma_prediction(in_sig: &[i16], b_q12: &[i16], s: &mut [i32], out: &mut [i16], order: usize) {
    for k in 0..in_sig.len() {
        let in16 = in_sig[k] as i32;
        let out32 = (in16 << 12).wrapping_sub(s[0]);
        out[k] = sat16(rshift_round(out32, 12));

        for d in 0..order - 1 {
            s[d] = s[d + 1].wrapping_add(in16.wrapping_mul(b_q12[d] as i32));
        }
        s[order - 1] = in16.wrapping_mul(b_q12[order - 1] as i32);
    }
}

fn decode_short_term_prediction(
    vec_q10: &mut [i32],
    pres_q10: &[i32],
    s_lpc_q14: &mut [i32],
    a_q12_tmp: &[i16],
    lpc_order: usize,
) {
    for i in 0..pres_q10.len() {
        let mut lpc_pred_q10 = smulwb(s_lpc_q14[MAX_LPC_ORDER + i - 1], a_q12_tmp[0] as i32);
        for j in 1..lpc_order {
            lpc_pred_q10 = smlawb(
                lpc_pred_q10,
                s_lpc_q14[MAX_LPC_ORDER + i - j - 1],
                a_q12_tmp[j] as i32,
            );
        }
        vec_q10[i] = pres_q10[i].wrapping_add(lpc_pred_q10);
        let v = vec_q10[i];
        s_lpc_q14[MAX_LPC_ORDER + i] = if v == (v << 4) >> 4 {
            v << 4
        } else if v > 0 {
            i32::MAX
        } else {
            i32::MIN
        };
    }
}

pub fn decode_core(dec: &mut DecoderState, ctrl: &mut DecoderControl, q: &[i32]) -> Vec<i16> {
    let frame_length = dec.frame_length;
    let subfr_length = dec.subfr_length;
    let lpc_order = dec.lpc_order;

    let offset_q10 =
        QUANTIZATION_OFFSETS_Q10[ctrl.sigtype as usize][ctrl.quant_offset_type as usize] as i32;
    let nlsf_interpolation_flag = if ctrl.nlsf_interp_coef_q2 < 4 { 1 } else { 0 };

    let mut rand_seed = ctrl.seed;
    for (i, &q_i) in q.iter().enumerate().take(frame_length) {
        rand_seed = silk_rand(rand_seed);
        let dither = rand_seed >> 31;
        let mut e = (q_i << 10).wrapping_add(offset_q10);
        e = (e ^ dither).wrapping_sub(dither);
        dec.exc_q10[i] = e;
        rand_seed = rand_seed.wrapping_add(q_i);
    }

    let mut pexc_off = 0usize;
    let mut pres_off = 0usize;
    let mut pxq_off = frame_length;
    let mut s_ltp_buf_idx = frame_length;
    let mut s_ltp = [0i16; MAX_FRAME_LENGTH];

    for k in 0..NB_SUBFR {
        let a_q12 = &ctrl.pred_coef_q12[k >> 1];
        let mut a_q12_tmp = [0i16; MAX_LPC_ORDER];
        a_q12_tmp[..lpc_order].copy_from_slice(&a_q12[..lpc_order]);
        let mut b_q14 = [0i16; LTP_ORDER];
        b_q14.copy_from_slice(&ctrl.ltp_coef_q14[k * LTP_ORDER..(k + 1) * LTP_ORDER]);
        let gain_q16 = ctrl.gains_q16[k];
        let mut sigtype = ctrl.sigtype;

        let mut inv_gain_q16 = inverse32_varq(gain_q16.max(1), 32);
        inv_gain_q16 = inv_gain_q16.min(i16::MAX as i32);

        let mut gain_adj_q16 = 1 << 16;
        if inv_gain_q16 != dec.prev_inv_gain_q16 {
            gain_adj_q16 = div32_varq(inv_gain_q16, dec.prev_inv_gain_q16, 16);
        }

        if dec.loss_cnt > 0
            && dec.prev_sigtype == SIG_TYPE_VOICED
            && ctrl.sigtype == SIG_TYPE_UNVOICED
            && k < (NB_SUBFR >> 1)
        {
            b_q14.fill(0);
            b_q14[LTP_ORDER / 2] = 1 << 12;
            sigtype = SIG_TYPE_VOICED;
            ctrl.pitch_l[k] = dec.lag_prev;
        }

        if sigtype == SIG_TYPE_VOICED {
            let lag = ctrl.pitch_l[k] as usize;
            if (k & (3 - (nlsf_interpolation_flag << 1) as usize)) == 0 {
                let start_idx =
                    frame_length as i32 - lag as i32 - lpc_order as i32 - (LTP_ORDER / 2) as i32;
                debug_assert!(start_idx >= 0);
                let start_idx = start_idx.max(0) as usize;
                debug_assert!(start_idx <= frame_length - lpc_order);
                let mut filt_state = [0i32; MAX_LPC_ORDER];
                let in_start = start_idx + k * (frame_length >> 2);
                let pred_len = frame_length - start_idx;
                let in_end = in_start + pred_len;
                let in_slice = &dec.out_buf[in_start..in_end];
                let mut out_tmp = vec![0i16; frame_length - start_idx];
                ma_prediction(
                    in_slice,
                    &a_q12_tmp[..lpc_order],
                    &mut filt_state[..lpc_order],
                    &mut out_tmp,
                    lpc_order,
                );
                s_ltp[start_idx..frame_length]
                    .copy_from_slice(&out_tmp[..frame_length - start_idx]);

                let mut inv_gain_q32 = inv_gain_q16 << 16;
                if k == 0 {
                    inv_gain_q32 = smulwb(inv_gain_q32, ctrl.ltp_scale_q14) << 2;
                }
                for i in 0..(lag + LTP_ORDER / 2) {
                    dec.s_ltp_q16[s_ltp_buf_idx - i - 1] =
                        smulwb(inv_gain_q32, s_ltp[frame_length - i - 1] as i32);
                }
            } else if gain_adj_q16 != (1 << 16) {
                for i in 0..(lag + LTP_ORDER / 2) {
                    dec.s_ltp_q16[s_ltp_buf_idx - i - 1] =
                        smulww(gain_adj_q16, dec.s_ltp_q16[s_ltp_buf_idx - i - 1]);
                }
            }
        }

        for i in 0..MAX_LPC_ORDER {
            dec.s_lpc_q14[i] = smulww(gain_adj_q16, dec.s_lpc_q14[i]);
        }
        dec.prev_inv_gain_q16 = inv_gain_q16;

        if sigtype == SIG_TYPE_VOICED {
            let lag = ctrl.pitch_l[k] as usize;
            let start_pred = s_ltp_buf_idx - lag + (LTP_ORDER / 2);
            for i in 0..subfr_length {
                let pred_idx = start_pred + i;
                let p = |off: usize| -> i32 { dec.s_ltp_q16[pred_idx - off] };
                let mut ltp_pred_q14 = smulwb(p(0), b_q14[0] as i32);
                ltp_pred_q14 = smlawb(ltp_pred_q14, p(1), b_q14[1] as i32);
                ltp_pred_q14 = smlawb(ltp_pred_q14, p(2), b_q14[2] as i32);
                ltp_pred_q14 = smlawb(ltp_pred_q14, p(3), b_q14[3] as i32);
                ltp_pred_q14 = smlawb(ltp_pred_q14, p(4), b_q14[4] as i32);

                dec.res_q10[pres_off + i] =
                    dec.exc_q10[pexc_off + i].wrapping_add(rshift_round(ltp_pred_q14, 4));
                dec.s_ltp_q16[s_ltp_buf_idx] = dec.res_q10[pres_off + i] << 6;
                s_ltp_buf_idx += 1;
            }
        } else {
            for i in 0..subfr_length {
                dec.res_q10[pres_off + i] = dec.exc_q10[pexc_off + i];
            }
        }

        let mut vec_q10 = vec![0i32; subfr_length];
        decode_short_term_prediction(
            &mut vec_q10,
            &dec.res_q10[pres_off..pres_off + subfr_length],
            &mut dec.s_lpc_q14,
            &a_q12_tmp[..lpc_order],
            lpc_order,
        );

        for (i, v) in vec_q10.iter().enumerate() {
            dec.out_buf[pxq_off + i] = sat16(rshift_round(smulww(*v, gain_q16), 10));
        }

        let src = dec.s_lpc_q14[subfr_length..subfr_length + MAX_LPC_ORDER].to_vec();
        dec.s_lpc_q14[..MAX_LPC_ORDER].copy_from_slice(&src);
        pexc_off += subfr_length;
        pres_off += subfr_length;
        pxq_off += subfr_length;
    }

    dec.out_buf[frame_length..frame_length + frame_length].to_vec()
}
