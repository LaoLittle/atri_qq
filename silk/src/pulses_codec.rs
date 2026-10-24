use crate::range_coder::RangeCoderState;
use crate::shell_coder::shell_decode_frame_16;
use crate::tables_control::SIGN_CDF;
use crate::tables_pulses::{
    LSB_CDF, MAX_NB_SHELL_BLOCKS, MAX_PULSES, N_RATE_LEVELS, PULSES_PER_BLOCK_CDF,
    PULSES_PER_BLOCK_CDF_OFFSET, RATE_LEVELS_CDF, RATE_LEVELS_CDF_OFFSET, SHELL_CODEC_FRAME_LENGTH,
};

fn dec_map(a: i32) -> i32 {
    (a << 1) - 1
}

pub fn decode_signs(
    rc: &mut RangeCoderState,
    q_abs: &mut [i32],
    sigtype: usize,
    quant_offset_type: usize,
    rate_level_index: usize,
) {
    let i = (N_RATE_LEVELS - 1) * ((sigtype << 1) + quant_offset_type) + rate_level_index;
    let cdf = [0u16, SIGN_CDF[i], 65535u16];
    for v in q_abs.iter_mut() {
        if *v > 0 {
            let data = rc.decode_symbol(&cdf, 1) as i32;
            *v *= dec_map(data);
        }
    }
}

pub fn decode_pulses(
    rc: &mut RangeCoderState,
    sigtype: usize,
    quant_offset_type: usize,
    frame_length: usize,
) -> (Vec<i32>, usize) {
    let rate_level_index = rc.decode_symbol(&RATE_LEVELS_CDF[sigtype], RATE_LEVELS_CDF_OFFSET);
    let iter = frame_length / SHELL_CODEC_FRAME_LENGTH;
    let mut q = vec![0i32; frame_length];
    let mut sum_pulses = [0i32; MAX_NB_SHELL_BLOCKS];
    let mut n_lshifts = [0usize; MAX_NB_SHELL_BLOCKS];

    let cdf_ptr = &PULSES_PER_BLOCK_CDF[rate_level_index];
    for i in 0..iter {
        n_lshifts[i] = 0;
        sum_pulses[i] = rc.decode_symbol(cdf_ptr, PULSES_PER_BLOCK_CDF_OFFSET) as i32;
        while sum_pulses[i] as usize == (MAX_PULSES + 1) {
            n_lshifts[i] += 1;
            if n_lshifts[i] > 8 {
                rc.error = crate::range_coder::RANGE_CODER_CDF_OUT_OF_RANGE;
                return (q, rate_level_index);
            }
            sum_pulses[i] = rc.decode_symbol(
                &PULSES_PER_BLOCK_CDF[N_RATE_LEVELS - 1],
                PULSES_PER_BLOCK_CDF_OFFSET,
            ) as i32;
        }
    }

    for (i, &sum_pulse) in sum_pulses.iter().enumerate().take(iter) {
        let base = i * SHELL_CODEC_FRAME_LENGTH;
        if sum_pulse > 0 {
            let blk = shell_decode_frame_16(rc, sum_pulse);
            q[base..(base + SHELL_CODEC_FRAME_LENGTH)]
                .copy_from_slice(&blk[..SHELL_CODEC_FRAME_LENGTH]);
        }
    }

    for (i, &n_lshift) in n_lshifts.iter().enumerate().take(iter) {
        if n_lshift > 0 {
            let base = i * SHELL_CODEC_FRAME_LENGTH;
            for k in 0..SHELL_CODEC_FRAME_LENGTH {
                let mut abs_q = q[base + k];
                for _ in 0..n_lshift {
                    abs_q <<= 1;
                    let bit = rc.decode_symbol(&LSB_CDF, 1) as i32;
                    abs_q += bit;
                }
                q[base + k] = abs_q;
            }
        }
    }

    decode_signs(rc, &mut q, sigtype, quant_offset_type, rate_level_index);
    (q, rate_level_index)
}
