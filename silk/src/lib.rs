#![forbid(unsafe_code)]

mod biquad;
mod cng;
mod decode_core;
mod decode_parameters;
mod decoder;
mod fixed;
mod gains;
mod math;
mod nlsf;
mod nlsf2a;
mod pitch;
mod plc;
mod pulses_codec;
mod range_coder;
mod resampler;
mod resampler_tables;
mod sdk_api;
mod shell_coder;
mod tables_control;
mod tables_ltp;
mod tables_nlsf;
mod tables_nlsf_vec;
mod tables_pitch_lag;
mod tables_pulses;

mod analysis;
mod encoder;
mod range_encoder;
pub use encoder::{Encoder, encode_silk};
pub use sdk_api::{SilkError, decode_silk, inspect_silk};
