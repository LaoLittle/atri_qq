#[inline]
fn skp_mul(a: i32, b: i32) -> i32 {
    a.wrapping_mul(b)
}

#[inline]
fn skp_smlawb(a: i32, b: i32, c: i32) -> i32 {
    let c16 = c as i16 as i32;
    let hi = (b >> 16).wrapping_mul(c16);
    let lo = ((b & 0x0000_FFFF).wrapping_mul(c16)) >> 16;
    a.wrapping_add(hi.wrapping_add(lo))
}

pub fn silk_log2lin(in_log_q7: i32) -> i32 {
    if in_log_q7 < 0 {
        return 0;
    }
    if in_log_q7 >= (31 << 7) {
        return i32::MAX;
    }

    let mut out = 1i32 << (in_log_q7 >> 7);
    let frac_q7 = in_log_q7 & 0x7f;
    let poly = skp_smlawb(frac_q7, skp_mul(frac_q7, 128 - frac_q7), -174);
    if in_log_q7 < 2048 {
        out = (out.wrapping_add(skp_mul(out, poly))) >> 7;
    } else {
        out = out.wrapping_add((out >> 7).wrapping_mul(poly));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log2lin_bounds() {
        assert_eq!(silk_log2lin(-1), 0);
        assert_eq!(silk_log2lin(0), 0);
        assert_eq!(silk_log2lin(31 << 7), i32::MAX);
    }
}
