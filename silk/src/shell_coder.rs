use crate::range_coder::RangeCoderState;
use crate::tables_pulses::{
    SHELL_CODE_TABLE_OFFSETS, SHELL_CODE_TABLE0, SHELL_CODE_TABLE1, SHELL_CODE_TABLE2,
    SHELL_CODE_TABLE3, SHELL_CODEC_FRAME_LENGTH,
};

fn decode_split(src: &mut RangeCoderState, p: i32, shell_table: &[u16]) -> (i32, i32) {
    if p > 0 {
        let cdf_middle = (p >> 1) as usize;
        let Some(&off) = SHELL_CODE_TABLE_OFFSETS.get(p as usize) else {
            src.error = crate::range_coder::RANGE_CODER_CDF_OUT_OF_RANGE;
            return (0, 0);
        };
        let off = off as usize;
        if off + p as usize + 2 > shell_table.len() {
            src.error = crate::range_coder::RANGE_CODER_CDF_OUT_OF_RANGE;
            return (0, 0);
        }
        let p_child1 = src.decode_symbol(&shell_table[off..], cdf_middle) as i32;
        let p_child2 = p - p_child1;
        (p_child1, p_child2)
    } else {
        (0, 0)
    }
}

pub fn shell_decode_frame_16(
    src: &mut RangeCoderState,
    pulses4: i32,
) -> [i32; SHELL_CODEC_FRAME_LENGTH] {
    let mut pulses0 = [0i32; SHELL_CODEC_FRAME_LENGTH];
    let mut p1 = [0i32; 8];
    let mut p2 = [0i32; 4];
    let mut p3 = [0i32; 2];

    (p3[0], p3[1]) = decode_split(src, pulses4, &SHELL_CODE_TABLE3);
    (p2[0], p2[1]) = decode_split(src, p3[0], &SHELL_CODE_TABLE2);
    (p1[0], p1[1]) = decode_split(src, p2[0], &SHELL_CODE_TABLE1);
    (pulses0[0], pulses0[1]) = decode_split(src, p1[0], &SHELL_CODE_TABLE0);
    (pulses0[2], pulses0[3]) = decode_split(src, p1[1], &SHELL_CODE_TABLE0);
    (p1[2], p1[3]) = decode_split(src, p2[1], &SHELL_CODE_TABLE1);
    (pulses0[4], pulses0[5]) = decode_split(src, p1[2], &SHELL_CODE_TABLE0);
    (pulses0[6], pulses0[7]) = decode_split(src, p1[3], &SHELL_CODE_TABLE0);
    (p2[2], p2[3]) = decode_split(src, p3[1], &SHELL_CODE_TABLE2);
    (p1[4], p1[5]) = decode_split(src, p2[2], &SHELL_CODE_TABLE1);
    (pulses0[8], pulses0[9]) = decode_split(src, p1[4], &SHELL_CODE_TABLE0);
    (pulses0[10], pulses0[11]) = decode_split(src, p1[5], &SHELL_CODE_TABLE0);
    (p1[6], p1[7]) = decode_split(src, p2[3], &SHELL_CODE_TABLE1);
    (pulses0[12], pulses0[13]) = decode_split(src, p1[6], &SHELL_CODE_TABLE0);
    (pulses0[14], pulses0[15]) = decode_split(src, p1[7], &SHELL_CODE_TABLE0);
    pulses0
}
