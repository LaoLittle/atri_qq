pub const PITCH_EST_NB_SUBFR: usize = 4;
pub const PITCH_EST_MIN_LAG_MS: i32 = 2;

pub const CB_LAGS_STAGE2: [[i16; 11]; PITCH_EST_NB_SUBFR] = [
    [0, 2, -1, -1, -1, 0, 0, 1, 1, 0, 1],
    [0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0],
    [0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0],
    [0, -1, 2, 1, 0, 1, 1, 0, 0, -1, -1],
];

pub const CB_LAGS_STAGE3: [[i16; 34]; PITCH_EST_NB_SUBFR] = [
    [
        -9, -7, -6, -5, -5, -4, -4, -3, -3, -2, -2, -2, -1, -1, -1, 0, 0, 0, 1, 1, 0, 1, 2, 2, 2,
        3, 3, 4, 4, 5, 6, 5, 6, 8,
    ],
    [
        -3, -2, -2, -2, -1, -1, -1, -1, -1, 0, 0, -1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1,
        2, 1, 2, 2, 2, 2, 3,
    ],
    [
        3, 3, 2, 2, 2, 2, 1, 2, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, -1, 0, 0, -1, -1, -1,
        -1, -1, -2, -2, -2,
    ],
    [
        9, 8, 6, 5, 6, 5, 4, 4, 3, 3, 2, 2, 2, 1, 0, 1, 1, 0, 0, 0, -1, -1, -1, -2, -2, -2, -3, -3,
        -4, -4, -5, -5, -6, -7,
    ],
];

pub fn decode_pitch(
    lag_index: i32,
    contour_index: usize,
    fs_khz: i32,
) -> [i32; PITCH_EST_NB_SUBFR] {
    let min_lag = PITCH_EST_MIN_LAG_MS * fs_khz;
    let lag = min_lag + lag_index;
    let mut out = [0i32; PITCH_EST_NB_SUBFR];
    if fs_khz == 8 {
        for i in 0..PITCH_EST_NB_SUBFR {
            out[i] = lag + CB_LAGS_STAGE2[i][contour_index] as i32;
        }
    } else {
        for i in 0..PITCH_EST_NB_SUBFR {
            out[i] = lag + CB_LAGS_STAGE3[i][contour_index] as i32;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_pitch_shape() {
        let l = decode_pitch(10, 0, 8);
        assert_eq!(l.len(), 4);
        let l2 = decode_pitch(10, 0, 16);
        assert_eq!(l2.len(), 4);
    }
}
