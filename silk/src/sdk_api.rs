use crate::biquad::biquad;
use crate::cng::cng;
use crate::decode_core::decode_core;
use crate::decode_parameters::decode_parameters;
use crate::decoder::{DecoderControl, DecoderState, NB_SUBFR};
use crate::plc::{plc, plc_glue_frames};
use crate::range_coder::{MAX_ARITHM_BYTES, RANGE_CODER_DEC_PAYLOAD_TOO_LONG};
use crate::resampler::SimpleResampler;
use std::io::{self, Read};
use std::time::Duration;
use thiserror::Error;

const DEC_INVALID_SAMPLING_FREQUENCY: i32 = -10;
const DEC_PAYLOAD_TOO_LARGE: i32 = -11;
const DEC_PAYLOAD_ERROR: i32 = -12;

#[derive(Clone, Copy, Debug, Default)]
struct DecControl {
    api_sample_rate: i32,
    frame_size: i32,
    frames_per_packet: i32,
    more_internal_decoder_frames: i32,
    in_band_fec_offset: i32,
}

const MORE_FRAMES: i32 = 1;
const LAST_FRAME: i32 = 0;
const LBRR_VER1: i32 = 2;
const LBRR_VER2: i32 = 3;
const NO_LBRR_THRES: i32 = 10;

#[derive(Default)]
pub struct SilkDecoder {
    pub state: DecoderState,
    resampler: Option<SimpleResampler>,
    resampler_in_hz: u32,
    resampler_out_hz: u32,
}

impl SilkDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    fn map_rc_error(err: i32) -> i32 {
        if err == RANGE_CODER_DEC_PAYLOAD_TOO_LONG {
            DEC_PAYLOAD_TOO_LARGE
        } else {
            DEC_PAYLOAD_ERROR
        }
    }

    fn on_payload_error(
        &mut self,
        action: &mut i32,
        used_bytes: &mut usize,
        ret: &mut i32,
        restore_fs_khz: Option<i32>,
    ) {
        self.state.n_bytes_left = 0;
        *action = 1;
        if let Some(fs_khz) = restore_fs_khz {
            self.state.set_fs(fs_khz);
        }
        *used_bytes = self.state.src.buffer_length;
        *ret = Self::map_rc_error(self.state.src.error);
    }

    fn update_fec_state(&mut self) {
        if self.state.vad_flag != 1 {
            return;
        }

        match self.state.frame_termination {
            LAST_FRAME => {
                self.state.no_fec_counter += 1;
                if self.state.no_fec_counter > NO_LBRR_THRES {
                    self.state.inband_fec_offset = 0;
                }
            }
            LBRR_VER1 => {
                self.state.inband_fec_offset = 1;
                self.state.no_fec_counter = 0;
            }
            LBRR_VER2 => {
                self.state.inband_fec_offset = 2;
                self.state.no_fec_counter = 0;
            }
            _ => {}
        }
    }

    fn maybe_resample(&mut self, input: &[i16], api_hz: i32) -> Result<Vec<i16>, i32> {
        let in_hz = (self.state.fs_khz * 1000) as u32;
        let out_hz = api_hz as u32;
        if in_hz == out_hz {
            return Ok(input.to_vec());
        }
        if self.resampler.is_none()
            || self.resampler_in_hz != in_hz
            || self.resampler_out_hz != out_hz
        {
            self.resampler = Some(
                SimpleResampler::new(in_hz, out_hz).map_err(|_| DEC_INVALID_SAMPLING_FREQUENCY)?,
            );
            self.resampler_in_hz = in_hz;
            self.resampler_out_hz = out_hz;
        }
        let rs = self
            .resampler
            .as_mut()
            .ok_or(DEC_INVALID_SAMPLING_FREQUENCY)?;
        let out_len = rs
            .output_len_for_input(input.len())
            .map_err(|_| DEC_INVALID_SAMPLING_FREQUENCY)?;
        let mut out = vec![0i16; out_len];
        let n = rs
            .process(input, &mut out)
            .map_err(|_| DEC_INVALID_SAMPLING_FREQUENCY)?;
        out.truncate(n);
        Ok(out)
    }

    fn decode_frame(
        &mut self,
        dec_control: &mut DecControl,
        lost_flag: i32,
        in_data: &[u8],
        produce_pcm: bool,
    ) -> Result<Vec<i16>, i32> {
        if self.state.more_internal_decoder_frames == 0 {
            self.state.n_frames_decoded = 0;
        }

        let mut action = if lost_flag != 0 { 1 } else { 0 };
        let mut ret = 0i32;
        if self.state.more_internal_decoder_frames == 0
            && action == 0
            && in_data.len() > MAX_ARITHM_BYTES
        {
            action = 1;
            ret = DEC_PAYLOAD_TOO_LARGE;
        }

        let prev_fs_khz = self.state.fs_khz;
        let mut ctrl = DecoderControl::default();
        let mut used_bytes = 0usize;
        let mut internal_pcm = Vec::new();

        if action == 0 {
            let fs_khz_old = self.state.fs_khz;
            if self.state.n_frames_decoded == 0 {
                self.state.src.dec_init(in_data);
            }

            if self.state.src.error != 0 {
                self.on_payload_error(&mut action, &mut used_bytes, &mut ret, None);
            } else {
                let out = decode_parameters(&mut self.state, &mut ctrl, produce_pcm);
                if self.state.src.error != 0 {
                    self.on_payload_error(&mut action, &mut used_bytes, &mut ret, Some(fs_khz_old));
                } else {
                    used_bytes = self
                        .state
                        .src
                        .buffer_length
                        .saturating_sub(self.state.n_bytes_left as usize);
                    self.state.n_frames_decoded += 1;
                    if (self.state.frame_termination == MORE_FRAMES
                        && (self.state.n_bytes_left <= 0 || self.state.n_frames_decoded >= 5))
                        || (self.state.frame_termination == LAST_FRAME
                            && self.state.n_bytes_left != 0)
                    {
                        return Err(DEC_PAYLOAD_ERROR);
                    }
                    if produce_pcm {
                        internal_pcm = decode_core(&mut self.state, &mut ctrl, &out.q);
                        let l = self.state.frame_length;
                        plc(&mut self.state, &mut ctrl, &mut internal_pcm[..l], l, false);
                        self.state.loss_cnt = 0;
                        self.state.prev_sigtype = ctrl.sigtype;
                        self.state.lag_prev = ctrl.pitch_l[NB_SUBFR - 1];
                    }
                    self.state.first_frame_after_reset = 0;
                }
            }
        }

        if action == 1 && ret != 0 {
            return Err(ret);
        }
        if produce_pcm {
            let l = self.state.frame_length;
            if action == 1 {
                if internal_pcm.len() < l {
                    internal_pcm.resize(l, 0);
                }
                plc(&mut self.state, &mut ctrl, &mut internal_pcm[..l], l, true);
            }

            self.state.out_buf[..l].copy_from_slice(&internal_pcm[..l]);
            plc_glue_frames(&mut self.state, &mut ctrl, &mut internal_pcm[..l], l);
            cng(&mut self.state, &mut ctrl, &mut internal_pcm[..l], l);

            let hp_in = internal_pcm[..l].to_vec();
            biquad(
                &hp_in,
                &self.state.hp_b,
                &self.state.hp_a,
                &mut self.state.hp_state,
                &mut internal_pcm[..l],
            );
            internal_pcm.truncate(l);
        }

        if used_bytes != 0 {
            if self.state.n_bytes_left > 0
                && self.state.frame_termination == MORE_FRAMES
                && self.state.n_frames_decoded < 5
            {
                self.state.more_internal_decoder_frames = 1;
            } else {
                self.state.more_internal_decoder_frames = 0;
                self.state.n_frames_in_packet = self.state.n_frames_decoded;
                self.update_fec_state();
            }
        }

        if !(8_000..=48_000).contains(&dec_control.api_sample_rate) {
            return Err(DEC_INVALID_SAMPLING_FREQUENCY);
        }
        let pcm = if produce_pcm {
            self.maybe_resample(&internal_pcm, dec_control.api_sample_rate)?
        } else {
            Vec::new()
        };
        self.state.prev_api_sample_rate = dec_control.api_sample_rate;
        if prev_fs_khz != self.state.fs_khz {
            self.resampler = None;
        }

        dec_control.frame_size = dec_control.api_sample_rate / 50;
        dec_control.frames_per_packet = self.state.n_frames_in_packet.max(1);
        dec_control.more_internal_decoder_frames = self.state.more_internal_decoder_frames;
        dec_control.in_band_fec_offset = self.state.inband_fec_offset;

        if ret != 0 { Err(ret) } else { Ok(pcm) }
    }
}

#[derive(Debug, Error)]
pub enum SilkError {
    #[error("不支持的 SILK 采样率")]
    InvalidSampleRate,
    #[error("SILK 数据不完整或无效")]
    InvalidPacket,
    #[error("PCM 数据不完整")]
    InvalidPcm,
    #[error("音频过长")]
    TooLong,
    #[error("SILK 解码失败: {0}")]
    Decode(i32),
    #[error("SILK 输入读取失败: {0}")]
    Io(#[from] io::Error),
}

/// Decode standard or Tencent SILK_V3 packets to mono PCM16 samples.
pub fn decode_silk(input: &[u8], sample_rate: u32) -> Result<Vec<i16>, SilkError> {
    if !matches!(
        sample_rate,
        8000 | 12000 | 16000 | 24000 | 32000 | 44100 | 48000
    ) {
        return Err(SilkError::InvalidSampleRate);
    }
    let mut packets = SilkPackets::new(input)?;
    let mut decoder = SilkDecoder::new();
    let mut control = DecControl {
        api_sample_rate: sample_rate as i32,
        frames_per_packet: 1,
        ..Default::default()
    };
    let mut output = Vec::new();
    let mut packet = [0; MAX_ARITHM_BYTES];
    while let Some(length) = packets.next(&mut packet)? {
        let packet = &packet[..length];
        loop {
            let pcm = decoder
                .decode_frame(&mut control, 0, packet, true)
                .map_err(SilkError::Decode)?;
            if output.len() + pcm.len() > sample_rate as usize * 600 {
                return Err(SilkError::TooLong);
            }
            output.extend(pcm);
            if control.more_internal_decoder_frames == 0 {
                break;
            }
        }
    }
    if output.is_empty() {
        return Err(SilkError::InvalidPacket);
    }
    Ok(output)
}

/// Validate standard or Tencent SILK_V3 audio and return its exact encoded duration.
///
/// Reads at most one 1024-byte packet at a time and counts its internal 20 ms frames
/// with the same entropy decoder used by [`decode_silk`], without synthesizing,
/// resampling or retaining PCM. An optional signed `-1` terminator must end the input.
/// Partial packet lengths, invalid codec data and empty recordings are rejected.
pub fn inspect_silk(input: impl Read) -> Result<Duration, SilkError> {
    let mut packets = SilkPackets::new(input)?;
    let mut decoder = SilkDecoder::new();
    let mut control = DecControl {
        api_sample_rate: 24_000,
        ..Default::default()
    };
    let mut packet = [0; MAX_ARITHM_BYTES];
    let mut frames = 0u64;
    while let Some(length) = packets.next(&mut packet)? {
        loop {
            decoder
                .decode_frame(&mut control, 0, &packet[..length], false)
                .map_err(SilkError::Decode)?;
            frames = frames.checked_add(1).ok_or(SilkError::TooLong)?;
            if control.more_internal_decoder_frames == 0 {
                break;
            }
        }
    }
    if frames == 0 {
        return Err(SilkError::InvalidPacket);
    }
    let millis = frames.checked_mul(20).ok_or(SilkError::TooLong)?;
    Ok(Duration::from_millis(millis))
}

/// Shared native SILK container framing for decoding and duration inspection.
struct SilkPackets<R> {
    input: R,
    ended: bool,
}

impl<R: Read> SilkPackets<R> {
    fn new(mut input: R) -> Result<Self, SilkError> {
        let mut header = [0; 9];
        read_required(&mut input, &mut header[..1])?;
        if header[0] == 2 {
            read_required(&mut input, &mut header)?;
        } else {
            read_required(&mut input, &mut header[1..])?;
        }
        if &header != b"#!SILK_V3" {
            return Err(SilkError::InvalidPacket);
        }
        Ok(Self {
            input,
            ended: false,
        })
    }

    fn next(&mut self, packet: &mut [u8; MAX_ARITHM_BYTES]) -> Result<Option<usize>, SilkError> {
        if self.ended {
            return Ok(None);
        }
        let Some(first) = read_optional_byte(&mut self.input)? else {
            self.ended = true;
            return Ok(None);
        };
        let mut word = [first, 0];
        read_required(&mut self.input, &mut word[1..])?;
        let length = i16::from_le_bytes(word);
        if length == -1 {
            if read_optional_byte(&mut self.input)?.is_some() {
                return Err(SilkError::InvalidPacket);
            }
            self.ended = true;
            return Ok(None);
        }
        if !(1..=MAX_ARITHM_BYTES as i16).contains(&length) {
            return Err(SilkError::InvalidPacket);
        }
        let length = length as usize;
        read_required(&mut self.input, &mut packet[..length])?;
        Ok(Some(length))
    }
}

fn read_optional_byte(input: &mut impl Read) -> Result<Option<u8>, SilkError> {
    let mut byte = [0];
    match input.read_exact(&mut byte) {
        Ok(()) => Ok(Some(byte[0])),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn read_required(input: &mut impl Read, bytes: &mut [u8]) -> Result<(), SilkError> {
    input.read_exact(bytes).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            SilkError::InvalidPacket
        } else {
            error.into()
        }
    })
}
