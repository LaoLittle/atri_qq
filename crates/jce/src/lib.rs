//! Internal Tars/JCE codec, adapted from <https://github.com/LaoLittle/rust-jce>
//! at commit `37363944a2003ea1fc0848464eed90b7c13d9adc` (MIT OR Apache-2.0).
//! Local adaptations check untrusted lengths and struct boundaries, bound nesting,
//! accept compressed integers, and fix encoded lengths. Unknown fields are skipped
//! without allocating. Derived fields default when absent; `#[jce(required)]`
//! requires presence, and combines with the upstream `#[jce(tag = "3")]` syntax.
//! `JceType::write_len` excludes the field header; `JceStruct::encoded_len` includes
//! all field headers but not an enclosing struct start/end pair.
//!
//! Decoding is limited to 64 nested containers/structures on each thread.
//! Owned values allocate in proportion to consumed input, never advertised lengths
//! without first checking the available bytes.

use crate::error::{DecodeResult, EncodeError, EncodeResult};

pub mod bytes;
pub mod de;
pub mod error;
mod ser;
pub mod types;
pub mod value;

use ::bytes::{Buf, BufMut};
pub use jce_derive::JceStruct;

pub trait JceStruct: Sized {
    fn encode_raw<B: BufMut>(&self, buf: &mut B);

    fn encode<B: BufMut>(&self, mut buf: B) -> EncodeResult<()> {
        if self.encoded_len() > buf.remaining_mut() {
            return Err(EncodeError);
        }

        self.encode_raw(&mut buf);
        Ok(())
    }

    fn encoded_len(&self) -> usize;

    fn decode_raw<B: Buf>(buf: &mut B, to_end: bool) -> DecodeResult<Self>;

    fn decode<B: Buf>(mut buf: B) -> DecodeResult<Self> {
        Self::decode_raw(&mut buf, true)
    }
}
