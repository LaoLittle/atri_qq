use crate::types;
use crate::types::JceHeader;
use bytes::BufMut;

pub fn write_header<B: BufMut>(buf: &mut B, JceHeader { val_type, tag }: JceHeader) {
    if tag < 0xF {
        buf.put_u8((tag << 4) | val_type)
    } else {
        buf.put_u8(val_type | 0xF0);
        buf.put_u8(tag);
    }
}

pub fn write_empty<B: BufMut>(buf: &mut B, tag: u8) {
    write_header(
        buf,
        JceHeader {
            val_type: types::EMPTY,
            tag,
        },
    );
}

pub fn write_type<B: BufMut>(buf: &mut B, t: u8) {
    buf.put_u8(t);
}

pub fn write_len<B: BufMut>(buf: &mut B, len: usize) {
    // Tars lengths are signed; 128 must be SHORT, not a negative BYTE.
    if len <= i8::MAX as usize {
        buf.put_u8(types::BYTE);
        buf.put_u8(len as u8);
    } else if len <= i16::MAX as usize {
        buf.put_u8(types::SHORT);
        buf.put_u16(len as u16);
    } else if len <= i32::MAX as usize {
        buf.put_u8(types::INT);
        buf.put_u32(len as u32);
    } else {
        buf.put_u8(types::LONG);
        buf.put_u64(len as u64);
    }
}

pub fn len_bytes(len: usize) -> usize {
    if len <= i8::MAX as usize {
        1
    } else if len <= i16::MAX as usize {
        2
    } else if len <= i32::MAX as usize {
        4
    } else {
        8
    }
}
