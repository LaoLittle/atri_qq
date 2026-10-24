include!(concat!(env!("OUT_DIR"), "/signature.rs"));

pub(crate) fn encoded_bytes_len(bytes: &[u8]) -> usize {
    if bytes.is_empty() {
        0
    } else {
        1 + prost::encoding::encoded_len_varint(bytes.len() as u64) + bytes.len()
    }
}

pub(crate) fn append_bytes_field(output: &mut Vec<u8>, field: u32, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    prost::encoding::encode_key(field, prost::encoding::WireType::LengthDelimited, output);
    prost::encoding::encode_varint(bytes.len() as u64, output);
    output.extend_from_slice(bytes);
}
