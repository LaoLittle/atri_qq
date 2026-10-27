use crate::de::{check_buf, read_len};
use crate::error::{DecodeError, DecodeResult};
use crate::ser::write_empty;
use bytes::{Buf, BufMut};
use std::fmt::{Display, Formatter};

pub const BYTE: u8 = 0; // i8 / u8
pub const SHORT: u8 = 1; // i16 / u16
pub const INT: u8 = 2; // i32 / u32
pub const LONG: u8 = 3; // i64 / u64
pub const FLOAT: u8 = 4; // f32
pub const DOUBLE: u8 = 5; // f64
pub const SHORT_BYTES: u8 = 6;
pub const LONG_BYTES: u8 = 7;
pub const MAP: u8 = 8; // Map<*Any, *Any>
pub const LIST: u8 = 9; // Vec<*Any>
pub const STRUCT_START: u8 = 10;
pub const STRUCT_END: u8 = 11;
pub const EMPTY: u8 = 12; // Option<*Any>
pub const SINGLE_LIST: u8 = 13; // Vec<u8>(?)

fn check_type(
    current: u8,
    expected: u8,
    struct_name: &'static str,
    field: &'static str,
) -> DecodeResult<()> {
    if current == expected {
        Ok(())
    } else {
        Err(DecodeError::IncorrectType {
            struct_name,
            field,
            val_type: current,
        })
    }
}

#[derive(Debug)]
pub struct JceHeader {
    pub(crate) val_type: u8,
    pub(crate) tag: u8,
}

impl JceHeader {
    #[inline]
    pub fn value_type(&self) -> u8 {
        self.val_type
    }

    #[inline]
    pub fn tag(&self) -> u8 {
        self.tag
    }
}

#[derive(Debug)]
pub enum Type {
    Byte,
    Short,
    Int,
    Long,
    Float,
    Double,
    Bytes,
    Map,
    List,
    Struct,
    Empty,
    SingleList,
}

impl Display for Type {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Type {
    pub fn from_u8(t: u8) -> Option<Self> {
        let t = match t {
            BYTE => Self::Byte,
            SHORT => Self::Short,
            INT => Self::Int,
            LONG => Self::Long,
            FLOAT => Self::Float,
            DOUBLE => Self::Double,
            SHORT_BYTES | LONG_BYTES => Self::Bytes,
            MAP => Self::Map,
            LIST => Self::List,
            STRUCT_START => Self::Struct,
            EMPTY => Self::Empty,
            SINGLE_LIST => Self::SingleList,
            _ => return None,
        };

        Some(t)
    }
}

pub trait JceType: Sized {
    fn read<B: Buf>(
        buf: &mut B,
        t: u8,
        struct_name: &'static str,
        field: &'static str,
    ) -> DecodeResult<Self>;

    fn write<B: BufMut>(&self, buf: &mut B, tag: u8);

    fn write_len(&self) -> usize;
}

impl<T: JceType> JceType for Option<T> {
    fn read<B: Buf>(
        buf: &mut B,
        t: u8,
        struct_name: &'static str,
        field: &'static str,
    ) -> DecodeResult<Self> {
        Ok(if t != EMPTY {
            Some(T::read(buf, t, struct_name, field)?)
        } else {
            None
        })
    }

    fn write<B: BufMut>(&self, buf: &mut B, tag: u8) {
        if let Some(t) = self {
            t.write(buf, tag);
        } else {
            write_empty(buf, tag);
        }
    }

    fn write_len(&self) -> usize {
        match self {
            Some(t) => t.write_len(),
            None => 0,
        }
    }
}

macro_rules! integer_type {
    ($type:ident, $jce_type:ident, $read:ident, $write:ident) => {
        impl JceType for $type {
            fn read<B: Buf>(
                buf: &mut B,
                t: u8,
                struct_name: &'static str,
                field: &'static str,
            ) -> DecodeResult<Self> {
                if t == EMPTY {
                    return Ok(0);
                }
                // Signed wire integers are sign-extended when widened. Exact-width
                // unsigned reads retain the upstream bit-pattern API.
                if t == $jce_type {
                    check_buf(buf, std::mem::size_of::<Self>())?;
                    return Ok(buf.$read());
                }
                let value = match t {
                    BYTE if BYTE < $jce_type => {
                        check_buf(buf, 1)?;
                        buf.get_i8() as i64
                    }
                    SHORT if SHORT < $jce_type => {
                        check_buf(buf, 2)?;
                        buf.get_i16() as i64
                    }
                    INT if INT < $jce_type => {
                        check_buf(buf, 4)?;
                        buf.get_i32() as i64
                    }
                    _ => {
                        return Err(DecodeError::IncorrectType {
                            struct_name,
                            field,
                            val_type: t,
                        })
                    }
                };
                Self::try_from(value).map_err(|_| DecodeError::InvalidLength)
            }

            fn write<B: BufMut>(&self, buf: &mut B, tag: u8) {
                crate::ser::write_header(
                    buf,
                    JceHeader {
                        val_type: $jce_type,
                        tag,
                    },
                );
                buf.$write(*self);
            }

            fn write_len(&self) -> usize {
                std::mem::size_of::<Self>()
            }
        }
    };
}

integer_type!(i8, BYTE, get_i8, put_i8);
integer_type!(u8, BYTE, get_u8, put_u8);
integer_type!(i16, SHORT, get_i16, put_i16);
integer_type!(u16, SHORT, get_u16, put_u16);
integer_type!(i32, INT, get_i32, put_i32);
integer_type!(u32, INT, get_u32, put_u32);
integer_type!(i64, LONG, get_i64, put_i64);
integer_type!(u64, LONG, get_u64, put_u64);

macro_rules! float_type {
    ($type:ident, $jce_type:ident, $read:ident, $write:ident) => {
        impl JceType for $type {
            fn read<B: Buf>(
                buf: &mut B,
                t: u8,
                struct_name: &'static str,
                field: &'static str,
            ) -> DecodeResult<Self> {
                if t == EMPTY {
                    return Ok(0.0);
                }
                check_type(t, $jce_type, struct_name, field)?;
                check_buf(buf, std::mem::size_of::<Self>())?;
                Ok(buf.$read())
            }
            fn write<B: BufMut>(&self, buf: &mut B, tag: u8) {
                crate::ser::write_header(
                    buf,
                    JceHeader {
                        val_type: $jce_type,
                        tag,
                    },
                );
                buf.$write(*self);
            }
            fn write_len(&self) -> usize {
                std::mem::size_of::<Self>()
            }
        }
    };
}

float_type!(f32, FLOAT, get_f32, put_f32);
float_type!(f64, DOUBLE, get_f64, put_f64);

macro_rules! type_array {
    (
        $(
        $type:ident,
        $jce_type:ident,
        $read:ident,
        $write:ident $(,)?
        );* $(;)?
    ) => {
        mod arrays {
            $(
            impl $crate::types::JceType for Vec<$type> {
                fn read<B: ::bytes::Buf>(
                    buf: &mut B,
                    t: u8,
                    struct_name: &'static str,
                    field: &'static str,
                ) -> $crate::error::DecodeResult<Self> {
                    $crate::types::check_type(t, $crate::types::LIST, struct_name, field)?;

                    let len = $crate::de::read_len(buf)?;
                    $crate::de::check_count(buf, len, 1)?;
                    let _depth = $crate::de::enter_depth()?;
                    let mut v = Vec::new();

                    for _ in 0..len {
                        let t = $crate::types::read_type(buf)?;
                        v.push(<$type as $crate::types::JceType>::read(buf, t, struct_name, field)?);
                    }

                    Ok(v)
                }

                fn write<B: ::bytes::BufMut>(&self, buf: &mut B, tag: u8) {
                    $crate::ser::write_header(
                        buf,
                        $crate::types::JceHeader {
                            val_type: $crate::types::LIST,
                            tag,
                        }
                    );

                    $crate::ser::write_len(buf, self.len());

                    for val in self {
                        <$type as $crate::types::JceType>::write(val, buf, 0);
                    }
                }

                fn write_len(&self) -> usize {
                    let len = self.len();
                    $crate::ser::len_bytes(len)
                    + len // each header
                    + len * ::std::mem::size_of::<$type>()
                    + 1 // len type
                }
            }
            )*
        }
    };
}

type_array! {
    i8,
    BYTE,
    get_i8,
    put_i8;
    i16,
    SHORT,
    get_i16,
    put_i16;
    u16,
    SHORT,
    get_u16,
    put_u16;
    i32,
    INT,
    get_i32,
    put_i32;
    u32,
    INT,
    get_u32,
    put_u32;
    i64,
    LONG,
    get_i64,
    put_i64;
    u64,
    LONG,
    get_u64,
    put_u64;
    f32,
    FLOAT,
    get_f32,
    put_f32;
    f64,
    DOUBLE,
    get_f64,
    put_f64
}

mod bool {
    use crate::error::DecodeResult;
    use crate::types::JceType;
    use bytes::{Buf, BufMut};

    impl JceType for bool {
        fn read<B: Buf>(
            buf: &mut B,
            t: u8,
            struct_name: &'static str,
            field: &'static str,
        ) -> DecodeResult<Self> {
            Ok(<u8 as JceType>::read(buf, t, struct_name, field)? != 0)
        }

        fn write<B: BufMut>(&self, buf: &mut B, tag: u8) {
            (*self as u8).write(buf, tag);
        }

        fn write_len(&self) -> usize {
            std::mem::size_of::<bool>()
        }
    }
}

mod byte_array {
    use crate::de::read_len;
    use crate::error::{DecodeError, DecodeResult};
    use crate::ser::write_header;
    use crate::types::{read_type, JceHeader, JceType};
    use bytes::{Buf, BufMut};

    fn read_bytes_len<B: Buf>(
        buf: &mut B,
        t: u8,
        struct_name: &'static str,
        field: &'static str,
    ) -> DecodeResult<usize> {
        match t {
            super::SHORT_BYTES | super::LONG_BYTES | super::SINGLE_LIST => {
                crate::de::read_bytes_len(buf, t)
            }
            _ => Err(DecodeError::IncorrectType {
                struct_name,
                field,
                val_type: t,
            }),
        }
    }

    fn read_slice<B: Buf>(buf: &mut B, value: &mut [u8], len: usize) -> DecodeResult<()> {
        if buf.remaining() < len {
            return Err(DecodeError::Eof);
        }

        buf.copy_to_slice(&mut value[..len]);

        Ok(())
    }

    pub fn write_slice<B: BufMut>(buf: &mut B, value: &[u8], tag: u8) {
        let len = value.len();
        if let Ok(len) = u8::try_from(len) {
            write_header(
                buf,
                JceHeader {
                    val_type: super::SHORT_BYTES,
                    tag,
                },
            );

            buf.put_u8(len);
        } else if let Ok(len) = u32::try_from(len) {
            write_header(
                buf,
                JceHeader {
                    val_type: super::LONG_BYTES,
                    tag,
                },
            );

            buf.put_u32(len);
        } else {
            panic!("bytes too long");
        }

        buf.put_slice(value);
    }

    pub fn slice_encoded_len(slice: &[u8]) -> usize {
        let bytes_len = if slice.len() <= u8::MAX as usize {
            1
        } else {
            4
        };

        bytes_len + slice.len()
    }

    impl JceType for Vec<u8> {
        fn read<B: Buf>(
            buf: &mut B,
            t: u8,
            struct_name: &'static str,
            field: &'static str,
        ) -> DecodeResult<Vec<u8>> {
            if t == super::LIST {
                let len = read_len(buf)?;

                crate::de::check_count(buf, len, 1)?;
                let mut v = Vec::new();

                for _ in 0..len {
                    let t = read_type(buf)?;
                    v.push(<u8 as JceType>::read(buf, t, struct_name, field)?);
                }

                return Ok(v);
            }

            let len = read_bytes_len(buf, t, struct_name, field)?;

            let mut v = vec![0u8; len];
            read_slice(buf, &mut v, len)?;

            Ok(v)
        }

        fn write<B: BufMut>(&self, buf: &mut B, tag: u8) {
            write_slice(buf, self, tag);
        }

        fn write_len(&self) -> usize {
            slice_encoded_len(self)
        }
    }

    impl JceType for bytes::Bytes {
        fn read<B: Buf>(
            buf: &mut B,
            t: u8,
            struct_name: &'static str,
            field: &'static str,
        ) -> DecodeResult<Self> {
            if t == super::LIST {
                return <Vec<u8> as JceType>::read(buf, t, struct_name, field)
                    .map(bytes::Bytes::from);
            }
            let len = read_bytes_len(buf, t, struct_name, field)?;
            Ok(buf.copy_to_bytes(len))
        }

        fn write<B: BufMut>(&self, buf: &mut B, tag: u8) {
            write_slice(buf, self, tag);
        }

        fn write_len(&self) -> usize {
            slice_encoded_len(self)
        }
    }

    impl<const N: usize> JceType for [u8; N] {
        fn read<B: Buf>(
            buf: &mut B,
            t: u8,
            struct_name: &'static str,
            field: &'static str,
        ) -> DecodeResult<Self> {
            let len = read_bytes_len(buf, t, struct_name, field)?;

            if len != N {
                return Err(DecodeError::InvalidLength);
            }

            let mut arr = [0u8; N];
            read_slice(buf, &mut arr, N)?;

            Ok(arr)
        }

        fn write<B: BufMut>(&self, buf: &mut B, tag: u8) {
            write_slice(buf, self, tag);
        }

        fn write_len(&self) -> usize {
            slice_encoded_len(self)
        }
    }
}

mod string {
    use crate::error::DecodeResult;
    use crate::types::JceType;
    use bytes::{Buf, BufMut};

    impl JceType for String {
        fn read<B: Buf>(
            buf: &mut B,
            t: u8,
            struct_name: &'static str,
            field: &'static str,
        ) -> DecodeResult<Self> {
            let vec = <Vec<u8> as JceType>::read(buf, t, struct_name, field)?;
            Ok(String::from_utf8(vec)?)
        }

        fn write<B: BufMut>(&self, buf: &mut B, tag: u8) {
            super::byte_array::write_slice(buf, self.as_bytes(), tag);
        }

        fn write_len(&self) -> usize {
            super::byte_array::slice_encoded_len(self.as_bytes())
        }
    }
}

mod map {
    use crate::de::read_len;
    use crate::error::DecodeResult;
    use crate::ser::{write_header, write_len};
    use crate::types::{read_tagged_type, JceHeader, JceType};
    use bytes::{Buf, BufMut};
    use std::collections::HashMap;
    use std::hash::Hash;

    const TAG_KEY: u8 = 0;
    const TAG_VAL: u8 = 1;

    impl<K, V> JceType for HashMap<K, V>
    where
        K: JceType,
        K: Eq + Hash,
        V: JceType,
    {
        fn read<B: Buf>(
            buf: &mut B,
            t: u8,
            struct_name: &'static str,
            field: &'static str,
        ) -> DecodeResult<Self> {
            super::check_type(t, super::MAP, struct_name, field)?;

            let len = read_len(buf)?;
            crate::de::check_count(buf, len, 2)?;
            let _depth = crate::de::enter_depth()?;

            let mut map = Self::new();

            for _ in 0..len {
                let kt = read_tagged_type(buf, TAG_KEY)?;
                let k = K::read(buf, kt, struct_name, field)?;
                let vt = read_tagged_type(buf, TAG_VAL)?;
                let v = V::read(buf, vt, struct_name, field)?;

                map.insert(k, v);
            }

            Ok(map)
        }

        fn write<B: BufMut>(&self, buf: &mut B, tag: u8) {
            write_header(
                buf,
                JceHeader {
                    val_type: super::MAP,
                    tag,
                },
            );

            let len = self.len();
            write_len(buf, len);

            for (k, v) in self {
                k.write(buf, TAG_KEY);
                v.write(buf, TAG_VAL);
            }
        }

        fn write_len(&self) -> usize {
            crate::ser::len_bytes(self.len())
                + 1
                + self
                    .iter()
                    .map(|(k, v)| 2 + k.write_len() + v.write_len())
                    .sum::<usize>()
        }
    }
}

mod jce_struct {
    use crate::error::DecodeResult;
    use crate::ser::{write_header, write_type};
    use crate::types::{JceHeader, JceType};
    use crate::JceStruct;
    use bytes::{Buf, BufMut};

    impl<T: JceStruct> JceType for T {
        fn read<B: Buf>(
            buf: &mut B,
            t: u8,
            struct_name: &'static str,
            field: &'static str,
        ) -> DecodeResult<Self> {
            super::check_type(t, super::STRUCT_START, struct_name, field)?;

            Self::decode_raw(buf, false)
        }

        fn write<B: BufMut>(&self, buf: &mut B, tag: u8) {
            write_header(
                buf,
                JceHeader {
                    val_type: super::STRUCT_START,
                    tag,
                },
            );
            self.encode_raw(buf);
            write_type(buf, super::STRUCT_END);
        }

        fn write_len(&self) -> usize {
            <Self as JceStruct>::encoded_len(self) + 1
        }
    }

    impl<T: JceStruct> JceType for Vec<T> {
        fn read<B: Buf>(
            buf: &mut B,
            t: u8,
            struct_name: &'static str,
            field: &'static str,
        ) -> DecodeResult<Self> {
            super::check_type(t, super::LIST, struct_name, field)?;
            let count = crate::de::read_len(buf)?;
            crate::de::check_count(buf, count, 2)?;
            let _depth = crate::de::enter_depth()?;
            let mut values = Vec::new();
            for _ in 0..count {
                let kind = super::read_tagged_type(buf, 0)?;
                values.push(T::read(buf, kind, struct_name, field)?);
            }
            Ok(values)
        }

        fn write<B: BufMut>(&self, buf: &mut B, tag: u8) {
            write_header(
                buf,
                JceHeader {
                    val_type: super::LIST,
                    tag,
                },
            );
            crate::ser::write_len(buf, self.len());
            for value in self {
                value.write(buf, 0);
            }
        }

        fn write_len(&self) -> usize {
            crate::ser::len_bytes(self.len())
                + 1
                + self
                    .iter()
                    .map(|value| 1 + value.write_len())
                    .sum::<usize>()
        }
    }
}

fn read_type<B: Buf>(buf: &mut B) -> DecodeResult<u8> {
    read_tagged_type(buf, 0)
}

pub(crate) fn read_tagged_type<B: Buf>(buf: &mut B, tag: u8) -> DecodeResult<u8> {
    let header = crate::de::read_header(buf)?;
    if header.tag() != tag {
        return Err(DecodeError::InvalidType);
    }
    Ok(header.value_type())
}

/// Skip one field payload without materializing it, including complete nested structs.
/// The caller has already consumed its header. A standalone struct end is invalid.
pub fn skip_field<B: Buf>(buf: &mut B, t: u8) -> DecodeResult<()> {
    let width = match t {
        BYTE => 1,
        SHORT => 2,
        INT | FLOAT => 4,
        LONG | DOUBLE => 8,
        EMPTY => 0,
        SHORT_BYTES | LONG_BYTES | SINGLE_LIST => {
            let len = crate::de::read_bytes_len(buf, t)?;
            buf.advance(len);
            return Ok(());
        }
        STRUCT_START => {
            let _depth = crate::de::enter_depth()?;
            loop {
                let header = crate::de::read_header(buf)?;
                if header.value_type() == STRUCT_END {
                    if header.tag() != 0 {
                        return Err(DecodeError::InvalidType);
                    }
                    return Ok(());
                }
                skip_field(buf, header.value_type())?;
            }
        }
        MAP | LIST => {
            let _depth = crate::de::enter_depth()?;
            let len = read_len(buf)?;
            let fields = if t == MAP { 2 } else { 1 };
            crate::de::check_count(buf, len, fields)?;
            for _ in 0..len {
                for tag in 0..fields {
                    let t = read_tagged_type(buf, tag as u8)?;
                    skip_field(buf, t)?;
                }
            }
            return Ok(());
        }
        _ => return Err(DecodeError::InvalidType),
    };
    check_buf(buf, width)?;
    buf.advance(width);
    Ok(())
}
