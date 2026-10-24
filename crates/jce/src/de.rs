use crate::error::{DecodeError, DecodeResult};
use crate::types::{self, JceHeader, JceType};
use bytes::Buf;
use std::cell::Cell;

thread_local! {
    static DEPTH: Cell<usize> = const { Cell::new(0) };
}

/// Maximum nested containers/structures accepted by the decoder.
pub const MAX_DEPTH: usize = 64;

/// Recursion guard shared by typed decoding, dynamic values and unknown fields.
#[doc(hidden)]
pub struct DepthGuard(std::marker::PhantomData<std::rc::Rc<()>>);

impl Drop for DepthGuard {
    fn drop(&mut self) {
        DEPTH.with(|depth| depth.set(depth.get() - 1));
    }
}

#[doc(hidden)]
pub fn enter_depth() -> DecodeResult<DepthGuard> {
    DEPTH.with(|depth| {
        if depth.get() >= MAX_DEPTH {
            return Err(DecodeError::DepthLimit);
        }
        depth.set(depth.get() + 1);
        Ok(DepthGuard(std::marker::PhantomData))
    })
}

#[inline]
pub(crate) fn check_buf<B: Buf>(buf: &B, min: usize) -> DecodeResult<()> {
    if buf.remaining() < min {
        return Err(DecodeError::Eof);
    }
    Ok(())
}

#[inline]
pub(crate) fn check_buf_zero<B: Buf>(buf: &B) -> DecodeResult<()> {
    check_buf(buf, 1)
}

pub fn read_header<B: Buf>(buf: &mut B) -> DecodeResult<JceHeader> {
    check_buf_zero(buf)?;
    let head = buf.get_u8();
    let val_type = head & 0xF;
    let mut tag = head >> 4;
    if tag == 0xF {
        check_buf_zero(buf)?;
        tag = buf.get_u8();
    }
    if val_type > types::SINGLE_LIST {
        return Err(DecodeError::InvalidType);
    }
    Ok(JceHeader { val_type, tag })
}

/// Container lengths are signed Tars int32 fields with tag zero.
pub(crate) fn read_len<B: Buf>(buf: &mut B) -> DecodeResult<usize> {
    let header = read_header(buf)?;
    if header.tag() != 0 {
        return Err(DecodeError::InvalidLength);
    }
    let len = i32::read(buf, header.value_type(), "container", "length")?;
    usize::try_from(len).map_err(|_| DecodeError::InvalidLength)
}

pub(crate) fn check_count<B: Buf>(buf: &B, count: usize, fields: usize) -> DecodeResult<()> {
    // Every element has at least a one-byte header. Avoid count multiplication overflow.
    if count > buf.remaining() / fields {
        return Err(DecodeError::Eof);
    }
    Ok(())
}

pub(crate) fn read_bytes_len<B: Buf>(buf: &mut B, t: u8) -> DecodeResult<usize> {
    let len = match t {
        types::SHORT_BYTES => {
            check_buf(buf, 1)?;
            buf.get_u8() as usize
        }
        types::LONG_BYTES => {
            check_buf(buf, 4)?;
            let len = buf.get_u32();
            if len > i32::MAX as u32 {
                return Err(DecodeError::InvalidLength);
            }
            len as usize
        }
        types::SINGLE_LIST => {
            let elem = read_header(buf)?;
            if elem.tag() != 0 || elem.value_type() != types::BYTE {
                return Err(DecodeError::InvalidType);
            }
            read_len(buf)?
        }
        _ => return Err(DecodeError::InvalidType),
    };
    check_buf(buf, len)?;
    Ok(len)
}
