use crate::de::{read_header, read_len};
use crate::error::{DecodeError, DecodeResult};
use crate::types;
use bytes::{Buf, Bytes};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

#[derive(Debug)]
pub enum Value {
    Byte(i8),
    Short(i16),
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    Bytes(Bytes),
    Struct(HashMap<u8, Value>),
    Map(HashMap<String, Value>),
    List(Vec<Value>),
    Empty,
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Byte(a), Value::Byte(b)) => a == b,
            (Value::Short(a), Value::Short(b)) => a == b,
            (Value::Int(a), Value::Int(b)) => a == b,
            (Value::Long(a), Value::Long(b)) => a == b,
            (Value::Float(a), Value::Float(b)) => a == b,
            (Value::Double(a), Value::Double(b)) => a == b,
            (Value::Bytes(a), Value::Bytes(b)) => a == b,
            (Value::Struct(a), Value::Struct(b)) => a == b,
            (Value::Map(a), Value::Map(b)) => a == b,
            (Value::List(a), Value::List(b)) => a == b,
            (Value::Empty, Value::Empty) => true,
            _ => false,
        }
    }
}

impl Eq for Value {}

impl Hash for Value {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Value::Byte(b) => b.hash(state),
            Value::Short(s) => s.hash(state),
            Value::Int(i) => i.hash(state),
            Value::Long(l) => l.hash(state),
            Value::Float(f) => {
                state.write_u8(b'f');
                state.write_u32(f.to_bits());
            }
            Value::Double(d) => {
                state.write_u8(b'd');
                state.write_u64(d.to_bits());
            }
            Value::Bytes(b) => b.hash(state),
            Value::Struct(s) => {
                state.write_usize(s.len());
                state.write_u8(b's');

                for (k, v) in s.iter() {
                    state.write_u8(*k);
                    v.hash(state);
                }
            }
            Value::Map(m) => {
                state.write_usize(m.len());
                state.write_u8(b'm');

                for (k, v) in m.iter() {
                    k.hash(state);
                    v.hash(state);
                }
            }
            Value::List(v) => {
                for val in v {
                    val.hash(state);
                }
            }
            Value::Empty => state.write(b"empty"),
        }
    }
}

fn read_value<B: Buf>(buf: &mut B, t: u8) -> DecodeResult<Value> {
    use crate::de::{check_count, enter_depth, read_bytes_len};
    use crate::types::JceType;

    let val = match t {
        types::BYTE => Value::Byte(i8::read(buf, t, "Value", "byte")?),
        types::SHORT => Value::Short(i16::read(buf, t, "Value", "short")?),
        types::INT => Value::Int(i32::read(buf, t, "Value", "int")?),
        types::LONG => Value::Long(i64::read(buf, t, "Value", "long")?),
        types::FLOAT => Value::Float(f32::read(buf, t, "Value", "float")?),
        types::DOUBLE => Value::Double(f64::read(buf, t, "Value", "double")?),
        types::SHORT_BYTES | types::LONG_BYTES | types::SINGLE_LIST => {
            let len = read_bytes_len(buf, t)?;
            Value::Bytes(buf.copy_to_bytes(len))
        }
        types::STRUCT_START => {
            let _depth = enter_depth()?;
            let mut fields = HashMap::new();
            loop {
                let header = read_header(buf)?;
                if header.value_type() == types::STRUCT_END {
                    if header.tag() != 0 {
                        return Err(DecodeError::InvalidType);
                    }
                    break;
                }
                fields.insert(header.tag(), read_value(buf, header.value_type())?);
            }
            Value::Struct(fields)
        }
        types::MAP => {
            let _depth = enter_depth()?;
            let len = read_len(buf)?;
            check_count(buf, len, 2)?;
            let mut map = HashMap::new();
            for _ in 0..len {
                let key_type = types::read_tagged_type(buf, 0)?;
                let key = read_value(buf, key_type)?;
                let value_type = types::read_tagged_type(buf, 1)?;
                let value = read_value(buf, value_type)?;
                let key = if let Value::Bytes(bytes) = key {
                    std::str::from_utf8(&bytes)?.to_owned()
                } else {
                    return Err(DecodeError::InvalidType);
                };
                map.insert(key, value);
            }
            Value::Map(map)
        }
        types::LIST => {
            let _depth = enter_depth()?;
            let len = read_len(buf)?;
            check_count(buf, len, 1)?;
            let mut list = Vec::new();
            for _ in 0..len {
                let t = types::read_tagged_type(buf, 0)?;
                list.push(read_value(buf, t)?);
            }
            Value::List(list)
        }
        types::EMPTY => Value::Empty,
        _ => return Err(DecodeError::InvalidType),
    };
    Ok(val)
}

pub fn read_elem<B: Buf>(buf: &mut B) -> DecodeResult<Value> {
    let header = read_header(buf)?;
    read_value(buf, header.value_type())
}

pub fn read_to_hashmap<B: Buf>(mut buf: B) -> DecodeResult<HashMap<u8, Value>> {
    let mut map = HashMap::new();
    while buf.remaining() > 0 {
        let header = read_header(&mut buf)?;
        let value = read_value(&mut buf, header.value_type())?;
        map.insert(header.tag(), value);
    }
    Ok(map)
}
