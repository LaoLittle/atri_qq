use crate::math::{clz32, inverse32_varq, rshift_round, rshift_round64, smulww};
const LSF_COS_TAB_FIX_Q12: [i32; 129] = [
    8192, 8190, 8182, 8170, 8152, 8130, 8104, 8072, 8034, 7994, 7946, 7896, 7840, 7778, 7714, 7644,
    7568, 7490, 7406, 7318, 7226, 7128, 7026, 6922, 6812, 6698, 6580, 6458, 6332, 6204, 6070, 5934,
    5792, 5648, 5502, 5352, 5198, 5040, 4880, 4718, 4552, 4382, 4212, 4038, 3862, 3684, 3502, 3320,
    3136, 2948, 2760, 2570, 2378, 2186, 1990, 1794, 1598, 1400, 1202, 1002, 802, 602, 402, 202, 0,
    -202, -402, -602, -802, -1002, -1202, -1400, -1598, -1794, -1990, -2186, -2378, -2570, -2760,
    -2948, -3136, -3320, -3502, -3684, -3862, -4038, -4212, -4382, -4552, -4718, -4880, -5040,
    -5198, -5352, -5502, -5648, -5792, -5934, -6070, -6204, -6332, -6458, -6580, -6698, -6812,
    -6922, -7026, -7128, -7226, -7318, -7406, -7490, -7568, -7644, -7714, -7778, -7840, -7896,
    -7946, -7994, -8034, -8072, -8104, -8130, -8152, -8170, -8182, -8190, -8192,
];

#[inline]
fn smmul(a32: i32, b32: i32) -> i32 {
    (((a32 as i64) * (b32 as i64)) >> 32) as i32
}

fn bwexpander_32(ar: &mut [i32], chirp_q16: i32) {
    if ar.is_empty() {
        return;
    }
    let mut tmp = chirp_q16;
    let n = ar.len();
    for v in ar.iter_mut().take(n.saturating_sub(1)) {
        *v = smulww(*v, tmp);
        tmp = smulww(chirp_q16, tmp);
    }
    let last = n - 1;
    ar[last] = smulww(ar[last], tmp);
}

fn nlsf2a_find_poly(out: &mut [i32], c_lsf_q20: &[i32], dd: usize) {
    out[0] = 1 << 20;
    out[1] = -c_lsf_q20[0];
    for k in 1..dd {
        let ftmp = c_lsf_q20[2 * k];
        out[k + 1] = (out[k - 1] << 1) - rshift_round64((ftmp as i64) * (out[k] as i64), 20) as i32;
        for n in (2..=k).rev() {
            out[n] += out[n - 2] - rshift_round64((ftmp as i64) * (out[n - 1] as i64), 20) as i32;
        }
        out[1] -= ftmp;
    }
}

pub fn nlsf2a(a_q12: &mut [i16], nlsf_q15: &[i32], d: usize) {
    let mut cos_lsf_q20 = vec![0i32; d];
    for k in 0..d {
        let f_int = (nlsf_q15[k] >> 8).clamp(0, 127) as usize;
        let f_frac = nlsf_q15[k] - ((f_int as i32) << 8);
        let cos_val = LSF_COS_TAB_FIX_Q12[f_int];
        let delta = LSF_COS_TAB_FIX_Q12[f_int + 1] - cos_val;
        cos_lsf_q20[k] = (cos_val << 8) + delta * f_frac;
    }

    let dd = d >> 1;
    let mut p = vec![0i32; dd + 1];
    let mut q = vec![0i32; dd + 1];
    nlsf2a_find_poly(&mut p, &cos_lsf_q20, dd);
    nlsf2a_find_poly(&mut q, &cos_lsf_q20[1..], dd);

    let mut a_int32 = vec![0i32; d];
    for k in 0..dd {
        let ptmp = p[k + 1] + p[k];
        let qtmp = q[k + 1] - q[k];
        a_int32[k] = -rshift_round(ptmp + qtmp, 9);
        a_int32[d - k - 1] = rshift_round(qtmp - ptmp, 9);
    }

    for _ in 0..10 {
        let mut maxabs = 0i32;
        let mut idx = 0usize;
        for (k, &v) in a_int32.iter().enumerate() {
            let av = v.abs();
            if av > maxabs {
                maxabs = av;
                idx = k;
            }
        }
        if maxabs <= i16::MAX as i32 {
            break;
        }
        let maxabs = maxabs.min(98_369);
        let denom = (((maxabs as i64) * ((idx + 1) as i64)) >> 2).max(1) as i32;
        let sc_q16 = 65_470 - (((65_470 >> 2) * (maxabs - i16::MAX as i32)) / denom);
        bwexpander_32(&mut a_int32, sc_q16);
    }

    for (i, a) in a_q12.iter_mut().enumerate().take(d) {
        *a = a_int32[i].clamp(i16::MIN as i32, i16::MAX as i32) as i16;
    }
}

pub fn bwexpander(ar: &mut [i16], chirp_q16: i32) {
    if ar.is_empty() {
        return;
    }
    let chirp_minus_one_q16 = chirp_q16 - 65_536;
    let mut c = chirp_q16;
    for i in 0..ar.len().saturating_sub(1) {
        ar[i] = rshift_round(c * ar[i] as i32, 16) as i16;
        c += rshift_round(c * chirp_minus_one_q16, 16);
    }
    let last = ar.len() - 1;
    ar[last] = rshift_round(c * ar[last] as i32, 16) as i16;
}

pub fn lpc_inverse_pred_gain(a_q12: &[i16]) -> (bool, i32) {
    const QA: i32 = 16;
    const A_LIMIT: i32 = 65_520; // FIX_CONST(0.99975, 16)
    let order = a_q12.len();
    let mut a0 = vec![0i32; order];
    let mut a1 = vec![0i32; order];
    let mut use_a0 = (order & 1) == 0;
    for (k, &v) in a_q12.iter().enumerate() {
        if use_a0 {
            a0[k] = (v as i32) << (QA - 12);
        } else {
            a1[k] = (v as i32) << (QA - 12);
        }
    }

    let mut inv_gain_q30 = 1 << 30;
    for k in (1..order).rev() {
        let a_new = if use_a0 { &a0 } else { &a1 };
        let ak = a_new[k];
        if !(-A_LIMIT..=A_LIMIT).contains(&ak) {
            return (true, inv_gain_q30);
        }
        let rc_q31 = -(ak << (31 - QA));
        let rc_mult1_q30 = (i32::MAX >> 1) - smmul(rc_q31, rc_q31);
        let rc_mult2_q16 = inverse32_varq(rc_mult1_q30, 46);
        inv_gain_q30 = smmul(inv_gain_q30, rc_mult1_q30) << 2;

        let (a_old, a_new_mut) = if use_a0 {
            (&a0, &mut a1)
        } else {
            (&a1, &mut a0)
        };
        let headrm = clz32(rc_mult2_q16) - 1;
        let rc_m = rc_mult2_q16 << headrm;
        for n in 0..k {
            let tmp = a_old[n] - (smmul(a_old[k - n - 1], rc_q31) << 1);
            a_new_mut[n] = smmul(tmp, rc_m) << (16 - headrm);
        }
        use_a0 = !use_a0;
    }
    let a_new = if use_a0 { &a0 } else { &a1 };
    if a_new[0] > A_LIMIT || a_new[0] < -A_LIMIT {
        return (true, inv_gain_q30);
    }
    let rc_q31 = -(a_new[0] << (31 - QA));
    let rc_mult1_q30 = (i32::MAX >> 1) - smmul(rc_q31, rc_q31);
    inv_gain_q30 = smmul(inv_gain_q30, rc_mult1_q30) << 2;
    (false, inv_gain_q30)
}

pub fn nlsf2a_stable(a_q12: &mut [i16], nlsf_q15: &[i32]) {
    nlsf2a(a_q12, nlsf_q15, a_q12.len());
    for i in 0..16 {
        let (unstable, _) = lpc_inverse_pred_gain(a_q12);
        if !unstable {
            return;
        }
        bwexpander(a_q12, 65_536 - (10 + i) * i);
    }
    a_q12.fill(0);
}
