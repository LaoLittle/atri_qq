use bytes::{Buf, Bytes};
use jce::error::DecodeError;
use jce::types::{self, JceType};
use jce::value::{read_elem, read_to_hashmap, Value};
use jce::JceStruct;
use std::collections::HashMap;

fn payload<T: JceType>(kind: u8, bytes: &[u8]) -> Result<T, DecodeError> {
    let mut input = bytes;
    let value = T::read(&mut input, kind, "test", "value")?;
    assert_eq!(input.remaining(), 0);
    Ok(value)
}

#[test]
fn signed_compressed_integers_preserve_values_and_reject_widened_wire_types() {
    assert_eq!(payload::<i64>(types::EMPTY, &[]).unwrap(), 0);
    for value in [i8::MIN, -1, 0, i8::MAX] {
        assert_eq!(
            payload::<i16>(types::BYTE, &value.to_be_bytes()).unwrap(),
            i16::from(value)
        );
        assert_eq!(
            payload::<i32>(types::BYTE, &value.to_be_bytes()).unwrap(),
            i32::from(value)
        );
        assert_eq!(
            payload::<i64>(types::BYTE, &value.to_be_bytes()).unwrap(),
            i64::from(value)
        );
    }
    for value in [i16::MIN, -129, 128, i16::MAX] {
        assert_eq!(
            payload::<i32>(types::SHORT, &value.to_be_bytes()).unwrap(),
            i32::from(value)
        );
        assert_eq!(
            payload::<i64>(types::SHORT, &value.to_be_bytes()).unwrap(),
            i64::from(value)
        );
    }
    for value in [i32::MIN, -32_769, 32_768, i32::MAX] {
        assert_eq!(
            payload::<i64>(types::INT, &value.to_be_bytes()).unwrap(),
            i64::from(value)
        );
    }
    for value in [i64::MIN, i64::MAX] {
        assert_eq!(
            payload::<i64>(types::LONG, &value.to_be_bytes()).unwrap(),
            value
        );
    }
    assert!(i8::read(&mut &[0, 1][..], types::SHORT, "test", "value").is_err());
    assert!(i32::read(&mut &[0; 8][..], types::LONG, "test", "value").is_err());
    assert!(i64::read(&mut &[0; 8][..], types::DOUBLE, "test", "value").is_err());
    assert!(u32::read(&mut &[0xff][..], types::BYTE, "test", "value").is_err());
    assert_eq!(payload::<u8>(types::BYTE, &[0xff]).unwrap(), 255);
    assert_eq!(payload::<u16>(types::SHORT, &[0xff, 0xff]).unwrap(), 65535);
    assert_eq!(payload::<u32>(types::SHORT, &[0x7f, 0xff]).unwrap(), 32767);
    assert_eq!(payload::<bool>(types::EMPTY, &[]).unwrap(), false);
}

#[derive(Debug, PartialEq, JceStruct)]
struct Envelope {
    #[jce(tag = "1", required)]
    kind: i64,
    #[jce(tag = "3", required)]
    data: HashMap<String, HashMap<String, Bytes>>,
    #[jce(tag = "255", required)]
    tail: i32,
}

#[test]
fn tars_compressed_integer_nested_map_and_opaque_simple_list() {
    // Independently specified Tars wire data, not produced by this encoder.
    let wire = [
        0x10, 1, 0x38, 0, 1, 6, 4, b'p', b'u', b's', b'h', 0x18, 0, 1, 6, 4, b'b', b'o', b'd',
        b'y', 0x1d, 0xf0, 0, 0, 3, 0xff, 0, 0x0e, 0xf2, 255, 0, 0, 0x23, 0x29,
    ];
    let expected = Envelope {
        kind: 1,
        data: HashMap::from([(
            "push".into(),
            HashMap::from([("body".into(), Bytes::from_static(&[0xff, 0, 0x0e]))]),
        )]),
        tail: 9001,
    };
    for end in 0..wire.len() {
        assert!(
            Envelope::decode(&wire[..end]).is_err(),
            "accepted prefix {end}"
        );
    }
    assert_eq!(Envelope::decode(&wire[..]).unwrap(), expected);
    let mut encoded = Vec::new();
    expected.encode(&mut encoded).unwrap();
    assert_eq!(encoded.len(), expected.encoded_len());
    assert_eq!(Envelope::decode(&encoded[..]).unwrap(), expected);
    let dynamic = read_to_hashmap(&wire[..]).unwrap();
    let Value::Map(outer) = &dynamic[&3] else {
        panic!("expected map")
    };
    let Value::Map(inner) = &outer["push"] else {
        panic!("expected nested map")
    };
    assert_eq!(
        inner["body"],
        Value::Bytes(Bytes::from_static(&[0xff, 0, 0x0e]))
    );
}

#[derive(Debug, JceStruct)]
struct Tail {
    #[jce(tag = "2", required)]
    tail: i32,
}

#[test]
fn unknown_structs_and_containers_are_consumed_through_their_end() {
    let wire = [
        0x1a, // unknown struct tag1
        0xf6, 200, 4, 0xff, 0, 0x0e, 0x80, // opaque, not UTF-8
        0x09, 0, 2, 0x0a, 0x0c, 0x0b, 0x0d, 0, 0, 2, 0xff, 0x80,
        0x0b, // end unknown struct, not end Tail
        0x20, 7,
    ];
    assert_eq!(Tail::decode(&wire[..]).unwrap().tail, 7);
    let mut rest = &wire[1..];
    types::skip_field(&mut rest, types::STRUCT_START).unwrap();
    assert_eq!(rest, &[0x20, 7]);
}

#[test]
fn truncated_scalars_headers_and_malicious_container_lengths_return_errors() {
    for (kind, width) in [(0, 1), (1, 2), (2, 4), (3, 8), (4, 4), (5, 8)] {
        let mut wire = vec![kind];
        wire.resize(width + 1, 0);
        for end in 0..wire.len() {
            assert!(read_elem(&mut &wire[..end]).is_err());
            if end > 0 {
                assert!(types::skip_field(&mut &wire[1..end], kind).is_err());
            }
        }
        assert_eq!(
            read_elem(&mut &wire[..]).unwrap(),
            match kind {
                0 => Value::Byte(0),
                1 => Value::Short(0),
                2 => Value::Int(0),
                3 => Value::Long(0),
                4 => Value::Float(0.0),
                _ => Value::Double(0.0),
            }
        );
    }
    let malformed: &[&[u8]] = &[
        &[0x0e],
        &[0x0f],
        &[0xf0],
        &[0x0b],
        &[6, 4, b'x'],
        &[7, 0xff, 0xff, 0xff, 0xff],
        &[13, 0, 0, 4, 1],
        &[13, 1, 12],
        &[13, 0x10, 12],
        &[8, 0, 0xff],
        &[9, 0, 0xff],
        &[8, 1, 0xff, 0xff],
        &[9, 2, 0xff, 0xff, 0xff, 0xff],
        &[13, 0, 3, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        &[9, 0, 1, 0x0b],
        &[8, 2, 0x7f, 0xff, 0xff, 0xff],
        &[9, 2, 0x7f, 0xff, 0xff, 0xff],
        &[8, 0, 1, 12, 12],
        &[9, 0, 1, 0x1c],
        &[9, 0x10, 0],
        &[10, 12],
        &[10, 0x1b],
    ];
    for wire in malformed {
        let mut dynamic_input = *wire;
        assert!(
            read_elem(&mut dynamic_input).is_err(),
            "accepted dynamic value {wire:x?}"
        );
        let mut input = *wire;
        if let Ok(header) = jce::de::read_header(&mut input) {
            assert!(
                types::skip_field(&mut input, header.value_type()).is_err(),
                "accepted skip {wire:x?}"
            );
        }
    }
    for wire in [
        &[6, 4, b'x'][..],
        &[7, 0xff, 0xff, 0xff, 0xff],
        &[13, 0, 0, 4, 1],
        &[9, 0, 0xff],
    ] {
        let mut input = wire;
        let header = jce::de::read_header(&mut input).unwrap();
        assert!(Bytes::read(&mut input, header.value_type(), "test", "bytes").is_err());
    }
    for wire in [&[8, 0, 0xff][..], &[8, 2, 0x7f, 0xff, 0xff, 0xff]] {
        let mut input = &wire[1..];
        assert!(HashMap::<String, Bytes>::read(&mut input, types::MAP, "test", "map").is_err());
    }
}

#[derive(Debug, PartialEq, JceStruct)]
struct Defaults {
    number: i32,
    data: Bytes,
}

#[derive(Debug, JceStruct)]
struct Nested {
    inner: Defaults,
}

#[derive(Debug, JceStruct)]
struct Empty {}

#[test]
fn absent_defaults_required_presence_and_struct_end_boundaries() {
    assert_eq!(Defaults::decode(&[][..]).unwrap(), Defaults::default());
    assert_eq!(Defaults::decode(&[12][..]).unwrap().number, 0);
    assert!(matches!(
        Tail::decode(&[][..]),
        Err(DecodeError::MissingField { field: "tail", .. })
    ));
    assert_eq!(Tail::decode(&[0x2c][..]).unwrap().tail, 0);
    assert!(Nested::decode(&[10][..]).is_err());
    assert!(Nested::decode(&[10, 12][..]).is_err());
    assert!(Defaults::decode(&[0x0b][..]).is_err());
    assert!(Nested::decode(&[10, 0x1b][..]).is_err());
    assert_eq!(
        Nested::decode(&[10, 0x0b][..]).unwrap().inner,
        Defaults::default()
    );
    let mut encoded = Vec::new();
    Empty::default().encode(&mut encoded).unwrap();
    assert_eq!(encoded, Vec::<u8>::new());
    assert_eq!(Empty::default().encoded_len(), 0);
    assert_eq!(
        read_elem(&mut &[8, 12][..]).unwrap(),
        Value::Map(HashMap::new())
    );
    assert_eq!(
        read_elem(&mut &[9, 12][..]).unwrap(),
        Value::List(Vec::new())
    );
    assert_eq!(
        read_elem(&mut &[13, 0, 12][..]).unwrap(),
        Value::Bytes(Bytes::new())
    );
}

#[derive(Debug, JceStruct)]
struct Recursive {
    children: HashMap<String, Recursive>,
}

#[test]
fn excessive_nesting_fails_for_dynamic_typed_and_unknown_fields() {
    let mut deep = vec![0x0a; 129];
    deep.push(12);
    deep.extend(std::iter::repeat_n(0x0b, 129));
    assert!(matches!(
        read_elem(&mut &deep[..]),
        Err(DecodeError::DepthLimit)
    ));
    assert!(matches!(
        types::skip_field(&mut &deep[1..], types::STRUCT_START),
        Err(DecodeError::DepthLimit)
    ));
    deep[0] = 0x1a;
    deep.extend_from_slice(&[0x20, 7]);
    assert!(matches!(
        Tail::decode(&deep[..]),
        Err(DecodeError::DepthLimit)
    ));

    let mut typed = Vec::new();
    for _ in 0..129 {
        typed.extend_from_slice(&[8, 0, 1, 6, 0, 0x1a]);
    }
    typed.extend_from_slice(&[8, 12]);
    typed.extend(std::iter::repeat_n(0x0b, 129));
    assert!(matches!(
        Recursive::decode(&typed[..]),
        Err(DecodeError::DepthLimit)
    ));
    // Errors must release the recursion guard, not poison later requests.
    assert_eq!(Tail::decode(&[0x20, 7][..]).unwrap().tail, 7);
    assert_eq!(
        read_elem(&mut &[0x0a, 12, 0x0b][..]).unwrap(),
        Value::Struct(HashMap::from([(0, Value::Empty)]))
    );
    let mut shallow = vec![0x0a; 16];
    shallow.push(12);
    shallow.extend(std::iter::repeat_n(0x0b, 16));
    let mut remainder = &shallow[1..];
    types::skip_field(&mut remainder, types::STRUCT_START).unwrap();
    assert_eq!(remainder, &[]);
    let mut value = read_elem(&mut &shallow[..]).unwrap();
    for _ in 0..16 {
        let Value::Struct(mut fields) = value else {
            panic!("expected nested struct")
        };
        assert_eq!(fields.len(), 1);
        value = fields.remove(&0).unwrap();
    }
    assert_eq!(value, Value::Empty);
}

#[test]
fn byte_decoding_handles_noncontiguous_bufs_and_keeps_bytes_storage_shared() {
    let mut segmented = (&[3, b'a'][..]).chain(&[b'b', b'c'][..]);
    assert_eq!(
        Bytes::read(&mut segmented, types::SHORT_BYTES, "test", "bytes")
            .unwrap()
            .as_ref(),
        b"abc"
    );
    let mut segmented = (&[3, b'a'][..]).chain(&[b'b', b'c'][..]);
    assert_eq!(
        Vec::<u8>::read(&mut segmented, types::SHORT_BYTES, "test", "bytes").unwrap(),
        b"abc"
    );
    let mut segmented = (&[3, b'a'][..]).chain(&[b'b', b'c'][..]);
    assert_eq!(
        <[u8; 3]>::read(&mut segmented, types::SHORT_BYTES, "test", "bytes").unwrap(),
        *b"abc"
    );
    let mut source = Bytes::from_static(&[3, b'a', b'b', b'c']);
    let expected_ptr = source.as_ptr().wrapping_add(1);
    let decoded = Bytes::read(&mut source, types::SHORT_BYTES, "test", "bytes").unwrap();
    assert_eq!(decoded.as_ptr(), expected_ptr);
    assert_eq!(decoded.as_ref(), b"abc");
}

#[derive(Debug, PartialEq, JceStruct)]
struct Lengths {
    bytes: Bytes,
    numbers: Vec<i32>,
    values: HashMap<String, Bytes>,
    #[jce(tag = "255")]
    absent: Option<i64>,
}

#[test]
fn encoded_lengths_cover_signed_count_widths_byte_widths_and_variable_maps() {
    for len in [0, 127, 128, 255, 256, 32767, 32768] {
        let value = Lengths {
            bytes: Bytes::from(vec![b'x'; len]),
            numbers: vec![1234; len],
            values: HashMap::from([
                ("short".into(), Bytes::new()),
                ("different length".into(), Bytes::from_static(b"payload")),
            ]),
            absent: None,
        };
        let mut encoded = Vec::new();
        value.encode(&mut encoded).unwrap();
        assert_eq!(encoded.len(), value.encoded_len(), "length {len}");
        assert_eq!(Lengths::decode(&encoded[..]).unwrap(), value);
        let mut exact = vec![0; value.encoded_len()];
        value.encode(&mut exact[..]).unwrap();
        assert_eq!(exact, encoded);
        let mut short = vec![0; value.encoded_len() - 1];
        assert!(value.encode(&mut short[..]).is_err());
    }
    let empty = Lengths::default();
    let mut encoded = Vec::new();
    empty.encode(&mut encoded).unwrap();
    assert_eq!(empty.encoded_len(), encoded.len());
    assert_eq!(Lengths::decode(&encoded[..]).unwrap(), empty);
}
