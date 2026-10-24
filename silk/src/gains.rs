use crate::fixed::silk_log2lin;
use crate::math::smulwb;

pub const NB_SUBFR: usize = 4;
const MIN_QGAIN_DB: i32 = 6;
const MAX_QGAIN_DB: i32 = 86;
const N_LEVELS_QGAIN: i32 = 64;
const MIN_DELTA_GAIN_QUANT: i32 = -4;

const OFFSET: i32 = ((MIN_QGAIN_DB * 128) / 6) + 16 * 128;
const INV_SCALE_Q16: i32 =
    (65536 * (((MAX_QGAIN_DB - MIN_QGAIN_DB) * 128) / 6)) / (N_LEVELS_QGAIN - 1);

pub fn gains_dequant(
    gain_q16: &mut [i32; NB_SUBFR],
    ind: &[i32; NB_SUBFR],
    prev_ind: &mut i32,
    conditional: bool,
) {
    for k in 0..NB_SUBFR {
        if k == 0 && !conditional {
            *prev_ind = ind[k];
        } else {
            *prev_ind += ind[k] + MIN_DELTA_GAIN_QUANT;
        }
        gain_q16[k] = silk_log2lin((smulwb(INV_SCALE_Q16, *prev_ind) + OFFSET).min(3967));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dequant_smoke() {
        let ind = [10, 11, 12, 13];
        let mut prev = 5;
        let mut out = [0i32; NB_SUBFR];
        gains_dequant(&mut out, &ind, &mut prev, false);
        assert!(out.iter().all(|&v| v >= 0));
    }
}
