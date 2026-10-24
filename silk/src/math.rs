#[inline]
pub(crate) fn smulbb(a32: i32, b32: i32) -> i32 {
    (a32 as i16 as i32).wrapping_mul(b32 as i16 as i32)
}

#[inline]
pub(crate) fn smulwb(a32: i32, b32: i32) -> i32 {
    let b16 = b32 as i16 as i32;
    let hi = (a32 >> 16).wrapping_mul(b16);
    let lo = ((a32 & 0x0000_FFFF).wrapping_mul(b16)) >> 16;
    hi.wrapping_add(lo)
}

#[inline]
pub(crate) fn smlawb(a32: i32, b32: i32, c32: i32) -> i32 {
    a32.wrapping_add(smulwb(b32, c32))
}

#[inline]
pub(crate) fn smlawt(a32: i32, b32: i32, c32: i32) -> i32 {
    let c16 = c32 as i16 as i32;
    let lo = (b32.wrapping_mul(c16)) + ((b32.wrapping_mul(c16)) >> 15);
    (a32.wrapping_add(lo)) >> 16
}

#[inline]
pub(crate) fn rshift_round(a: i32, shift: i32) -> i32 {
    if shift == 1 {
        (a >> 1) + (a & 1)
    } else {
        ((a >> (shift - 1)) + 1) >> 1
    }
}

#[inline]
pub(crate) fn rshift_round64(a: i64, shift: i32) -> i64 {
    if shift == 1 {
        (a >> 1) + (a & 1)
    } else {
        ((a >> (shift - 1)) + 1) >> 1
    }
}

#[inline]
pub(crate) fn smulww(a32: i32, b32: i32) -> i32 {
    let rb = rshift_round(b32, 16);
    smulwb(a32, b32).wrapping_add(a32.wrapping_mul(rb))
}

#[inline]
pub(crate) fn sat16(v: i32) -> i16 {
    v.clamp(i16::MIN as i32, i16::MAX as i32) as i16
}

#[inline]
pub(crate) fn silk_rand(seed: i32) -> i32 {
    seed.wrapping_mul(196_314_165).wrapping_add(907_633_515)
}

#[inline]
pub(crate) fn clz32(x: i32) -> i32 {
    (x as u32).leading_zeros() as i32
}

#[inline]
pub(crate) fn shift_with_lshift(result: i32, lshift: i32) -> i32 {
    if lshift <= 0 {
        result
            .checked_shl((-lshift) as u32)
            .unwrap_or(if result < 0 { i32::MIN } else { i32::MAX })
    } else if lshift < 32 {
        result >> lshift
    } else {
        0
    }
}

#[inline]
pub(crate) fn inverse32_varq(b32: i32, qres: i32) -> i32 {
    if b32 == 0 || b32 == i32::MIN || qres <= 0 {
        return 0;
    }
    let b_headrm = clz32(b32.abs()) - 1;
    let b32_nrm = b32 << b_headrm;
    let b32_inv = (i32::MAX >> 2) / (b32_nrm >> 16);
    let mut result = b32_inv << 16;
    let err_q32 = (-smulwb(b32_nrm, b32_inv)) << 3;
    result = result.wrapping_add(smulww(err_q32, b32_inv));
    let lshift = 61 - b_headrm - qres;
    shift_with_lshift(result, lshift)
}
