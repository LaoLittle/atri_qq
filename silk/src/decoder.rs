use crate::range_coder::RangeCoderState;
use crate::tables_control::{
    DEC_A_HP_8, DEC_A_HP_12, DEC_A_HP_16, DEC_A_HP_24, DEC_B_HP_8, DEC_B_HP_12, DEC_B_HP_16,
    DEC_B_HP_24,
};

pub const DEC_HP_ORDER: usize = 2;
pub const FRAME_LENGTH_MS: i32 = 20;
pub const MAX_FRAME_LENGTH: usize = 480;
pub const NB_SUBFR: usize = 4;
pub const MAX_LPC_ORDER: usize = 16;
pub const MIN_LPC_ORDER: usize = 10;
pub const LTP_ORDER: usize = 5;
pub const CNG_BUF_MASK_MAX: usize = 255;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlcState {
    pub pitch_l_q8: i32,
    pub ltp_coef_q14: [i16; LTP_ORDER],
    pub prev_lpc_q12: [i16; MAX_LPC_ORDER],
    pub last_frame_lost: i32,
    pub rand_seed: i32,
    pub rand_scale_q14: i16,
    pub conc_energy: i32,
    pub conc_energy_shift: i32,
    pub prev_ltp_scale_q14: i16,
    pub prev_gain_q16: [i32; NB_SUBFR],
    pub fs_khz: i32,
}

impl Default for PlcState {
    fn default() -> Self {
        Self {
            pitch_l_q8: 0,
            ltp_coef_q14: [0; LTP_ORDER],
            prev_lpc_q12: [0; MAX_LPC_ORDER],
            last_frame_lost: 0,
            rand_seed: 0,
            rand_scale_q14: 0,
            conc_energy: 0,
            conc_energy_shift: 0,
            prev_ltp_scale_q14: 0,
            prev_gain_q16: [0; NB_SUBFR],
            fs_khz: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CngState {
    pub cng_exc_buf_q10: [i32; MAX_FRAME_LENGTH],
    pub cng_smth_nlsf_q15: [i32; MAX_LPC_ORDER],
    pub cng_synth_state: [i32; MAX_LPC_ORDER],
    pub cng_smth_gain_q16: i32,
    pub rand_seed: i32,
    pub fs_khz: i32,
}

impl Default for CngState {
    fn default() -> Self {
        Self {
            cng_exc_buf_q10: [0; MAX_FRAME_LENGTH],
            cng_smth_nlsf_q15: [0; MAX_LPC_ORDER],
            cng_synth_state: [0; MAX_LPC_ORDER],
            cng_smth_gain_q16: 0,
            rand_seed: 3_176_576,
            fs_khz: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecoderControl {
    pub pitch_l: [i32; NB_SUBFR],
    pub gains_q16: [i32; NB_SUBFR],
    pub seed: i32,
    pub pred_coef_q12: [[i16; MAX_LPC_ORDER]; 2],
    pub ltp_coef_q14: [i16; LTP_ORDER * NB_SUBFR],
    pub ltp_scale_q14: i32,
    pub per_index: i32,
    pub rate_level_index: i32,
    pub quant_offset_type: i32,
    pub sigtype: i32,
    pub nlsf_interp_coef_q2: i32,
}

impl Default for DecoderControl {
    fn default() -> Self {
        Self {
            pitch_l: [0; NB_SUBFR],
            gains_q16: [0; NB_SUBFR],
            seed: 0,
            pred_coef_q12: [[0; MAX_LPC_ORDER]; 2],
            ltp_coef_q14: [0; LTP_ORDER * NB_SUBFR],
            ltp_scale_q14: 0,
            per_index: 0,
            rate_level_index: 0,
            quant_offset_type: 0,
            sigtype: 0,
            nlsf_interp_coef_q2: 4,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecoderState {
    pub src: RangeCoderState,
    pub s_ltp_q16: [i32; 2 * MAX_FRAME_LENGTH],
    pub s_lpc_q14: [i32; (MAX_FRAME_LENGTH / NB_SUBFR) + MAX_LPC_ORDER],
    pub exc_q10: [i32; MAX_FRAME_LENGTH],
    pub res_q10: [i32; MAX_FRAME_LENGTH],
    pub out_buf: [i16; 2 * MAX_FRAME_LENGTH],
    pub lag_prev: i32,
    pub prev_inv_gain_q16: i32,
    pub last_gain_index: i32,
    pub type_offset_prev: i32,
    pub hp_state: [i32; DEC_HP_ORDER],
    pub hp_a: [i16; 2],
    pub hp_b: [i16; 3],
    pub fs_khz: i32,
    pub prev_api_sample_rate: i32,
    pub frame_length: usize,
    pub subfr_length: usize,
    pub lpc_order: usize,
    pub prev_nlsf_q15: [i32; MAX_LPC_ORDER],
    pub first_frame_after_reset: i32,
    pub n_bytes_left: i32,
    pub n_frames_decoded: i32,
    pub n_frames_in_packet: i32,
    pub more_internal_decoder_frames: i32,
    pub frame_termination: i32,
    pub vad_flag: i32,
    pub no_fec_counter: i32,
    pub inband_fec_offset: i32,
    pub loss_cnt: i32,
    pub prev_sigtype: i32,
    pub s_plc: PlcState,
    pub s_cng: CngState,
}

impl Default for DecoderState {
    fn default() -> Self {
        let mut s = Self {
            src: RangeCoderState::default(),
            s_ltp_q16: [0; 2 * MAX_FRAME_LENGTH],
            s_lpc_q14: [0; (MAX_FRAME_LENGTH / NB_SUBFR) + MAX_LPC_ORDER],
            exc_q10: [0; MAX_FRAME_LENGTH],
            res_q10: [0; MAX_FRAME_LENGTH],
            out_buf: [0; 2 * MAX_FRAME_LENGTH],
            lag_prev: 100,
            prev_inv_gain_q16: 65_536,
            last_gain_index: 1,
            type_offset_prev: 0,
            hp_state: [0; DEC_HP_ORDER],
            hp_a: DEC_A_HP_24,
            hp_b: DEC_B_HP_24,
            fs_khz: 0,
            prev_api_sample_rate: 0,
            frame_length: 0,
            subfr_length: 0,
            lpc_order: MAX_LPC_ORDER,
            prev_nlsf_q15: [0; MAX_LPC_ORDER],
            first_frame_after_reset: 1,
            n_bytes_left: 0,
            n_frames_decoded: 0,
            n_frames_in_packet: 0,
            more_internal_decoder_frames: 0,
            frame_termination: 0,
            vad_flag: 0,
            no_fec_counter: 0,
            inband_fec_offset: 0,
            loss_cnt: 0,
            prev_sigtype: 0,
            s_plc: PlcState::default(),
            s_cng: CngState::default(),
        };
        s.set_fs(24);
        s
    }
}

impl DecoderState {
    pub fn set_fs(&mut self, fs_khz: i32) {
        if self.fs_khz != fs_khz {
            self.fs_khz = fs_khz;
            self.frame_length = (FRAME_LENGTH_MS * fs_khz) as usize;
            self.subfr_length = (FRAME_LENGTH_MS / NB_SUBFR as i32 * fs_khz) as usize;
            self.lpc_order = if fs_khz == 8 {
                MIN_LPC_ORDER
            } else {
                MAX_LPC_ORDER
            };

            self.s_lpc_q14.fill(0);
            self.out_buf.fill(0);
            self.prev_nlsf_q15.fill(0);
            self.lag_prev = 100;
            self.last_gain_index = 1;
            self.prev_sigtype = 0;
            self.first_frame_after_reset = 1;

            match fs_khz {
                24 => {
                    self.hp_a = DEC_A_HP_24;
                    self.hp_b = DEC_B_HP_24;
                }
                16 => {
                    self.hp_a = DEC_A_HP_16;
                    self.hp_b = DEC_B_HP_16;
                }
                12 => {
                    self.hp_a = DEC_A_HP_12;
                    self.hp_b = DEC_B_HP_12;
                }
                8 => {
                    self.hp_a = DEC_A_HP_8;
                    self.hp_b = DEC_B_HP_8;
                }
                _ => {}
            }
        }
        assert!(self.frame_length > 0 && self.frame_length <= MAX_FRAME_LENGTH);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_fs_switches_orders() {
        let mut s = DecoderState::default();
        s.set_fs(8);
        assert_eq!(s.lpc_order, MIN_LPC_ORDER);
        assert_eq!(s.frame_length, 160);
        s.set_fs(16);
        assert_eq!(s.lpc_order, MAX_LPC_ORDER);
        assert_eq!(s.frame_length, 320);
    }
}
