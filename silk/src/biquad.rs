use crate::math::{rshift_round, sat16, smulwb};

#[inline]
fn smlabb(a32: i32, b32: i32, c32: i32) -> i32 {
    a32.wrapping_add((b32 as i16 as i32).wrapping_mul(c32 as i16 as i32))
}

pub fn biquad(
    in_sig: &[i16],
    b_q13: &[i16; 3],
    a_q13: &[i16; 2],
    state: &mut [i32; 2],
    out: &mut [i16],
) {
    let n = in_sig.len().min(out.len());
    let mut s0 = state[0];
    let mut s1 = state[1];
    let a0_neg = -(a_q13[0] as i32);
    let a1_neg = -(a_q13[1] as i32);

    for k in 0..n {
        let in16 = in_sig[k] as i32;
        let out32 = smlabb(s0, in16, b_q13[0] as i32);

        s0 = smlabb(s1, in16, b_q13[1] as i32);
        s0 = s0.wrapping_add(smulwb(out32, a0_neg) << 3);

        s1 = (smulwb(out32, a1_neg) << 3).wrapping_add((in16 as i16 as i32) * (b_q13[2] as i32));

        out[k] = sat16(rshift_round(out32, 13) + 1);
    }

    state[0] = s0;
    state[1] = s1;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn biquad_smoke() {
        let input = [100i16, -50, 25, -12, 6, -3];
        let b = [8000i16, -16000, 8000];
        let a = [-16127i16, 7940];
        let mut st = [0i32; 2];
        let mut out = [0i16; 6];
        biquad(&input, &b, &a, &mut st, &mut out);
        assert_eq!(out.len(), input.len());
    }
}
