use crate::{
    Error, Result, crypto,
    models::*,
    proto::{self, auth, sso},
};
use ::signing as signing_engine;
use bytes::{Buf, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

pub const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;

pub(crate) fn malformed(message: impl Into<String>) -> Error {
    Error::Malformed(message.into())
}

pub(crate) fn encode_push_ack(body: Bytes) -> Result<Option<Bytes>> {
    use prost::Message;
    let source: auth::PushAckSource = proto::decode(body)?;
    if source.required != Some(1) {
        return Ok(None);
    }
    if source.descriptors.is_empty() {
        return Err(malformed(
            "MsgPush requests an acknowledgment without a descriptor",
        ));
    }
    Ok(Some(
        auth::PushAckRequest {
            descriptors: source.descriptors,
        }
        .encode_to_vec()
        .into(),
    ))
}

pub(crate) mod config_push {
    use super::*;
    use bytes::BufMut;
    use jce::{JceStruct, types::JceType};
    use std::collections::HashMap;

    // Tars byte buffers use SIMPLE_LIST, not JCE string fields.
    #[derive(Default)]
    struct TarsBytes(Bytes);

    impl JceType for TarsBytes {
        fn read<B: Buf>(
            buf: &mut B,
            value_type: u8,
            struct_name: &'static str,
            field: &'static str,
        ) -> jce::error::DecodeResult<Self> {
            Bytes::read(buf, value_type, struct_name, field).map(Self)
        }

        fn write<B: BufMut>(&self, buf: &mut B, tag: u8) {
            if tag < 15 {
                buf.put_u8((tag << 4) | jce::types::SINGLE_LIST);
            } else {
                buf.put_u8(0xf0 | jce::types::SINGLE_LIST);
                buf.put_u8(tag);
            }
            buf.put_u8(jce::types::BYTE);
            match self.0.len() {
                0 => buf.put_u8(jce::types::EMPTY),
                len @ 1..=127 => (len as i8).write(buf, 0),
                len @ 128..=32767 => (len as i16).write(buf, 0),
                len => i32::try_from(len)
                    .expect("Tars buffer length exceeds i32")
                    .write(buf, 0),
            }
            buf.put_slice(&self.0);
        }

        fn write_len(&self) -> usize {
            let count_len = match self.0.len() {
                0 => 1,
                1..=127 => 2,
                128..=32767 => 3,
                _ => 5,
            };
            1 + count_len + self.0.len()
        }
    }

    // The same Tars envelopes as ricq's RequestPacket/RequestDataVersion2.
    #[derive(JceStruct)]
    struct Packet {
        #[jce(tag = "1", required)]
        version: i16,
        #[jce(tag = "2")]
        packet_type: u8,
        #[jce(tag = "3")]
        message_type: i32,
        #[jce(tag = "4")]
        request_id: i32,
        #[jce(tag = "5", required)]
        servant: String,
        #[jce(tag = "6", required)]
        function: String,
        #[jce(tag = "7", required)]
        buffer: TarsBytes,
        #[jce(tag = "8")]
        timeout: i32,
        #[jce(tag = "9")]
        context: HashMap<String, String>,
        #[jce(tag = "10")]
        status: HashMap<String, String>,
    }

    #[derive(JceStruct)]
    struct Data {
        #[jce(tag = "0", required)]
        entries: HashMap<String, HashMap<String, TarsBytes>>,
    }

    #[derive(JceStruct)]
    struct PushRequest {
        #[jce(tag = "1", required)]
        kind: i32,
        #[jce(tag = "2")]
        configuration: TarsBytes,
        #[jce(tag = "3")]
        sequence: RequestSequence,
    }

    // Option<i64> treats EMPTY as None, but it represents a present zero
    // sequence here. Track absence separately for conditionally required tag 3.
    #[derive(Default)]
    struct RequestSequence(Option<i64>);

    impl JceType for RequestSequence {
        fn read<B: Buf>(
            buf: &mut B,
            value_type: u8,
            struct_name: &'static str,
            field: &'static str,
        ) -> jce::error::DecodeResult<Self> {
            i64::read(buf, value_type, struct_name, field).map(|value| Self(Some(value)))
        }

        fn write<B: BufMut>(&self, buf: &mut B, tag: u8) {
            self.0.unwrap_or_default().write(buf, tag);
        }

        fn write_len(&self) -> usize {
            self.0.unwrap_or_default().write_len()
        }
    }

    #[derive(JceStruct)]
    struct PushResponse {
        #[jce(tag = "1")]
        kind: i32,
        #[jce(tag = "2")]
        sequence: i64,
        #[jce(tag = "3")]
        configuration: TarsBytes,
    }

    fn encode(value: &impl JceStruct) -> Bytes {
        let mut buf = BytesMut::with_capacity(value.encoded_len());
        value.encode_raw(&mut buf);
        buf.freeze()
    }

    fn wrap(value: &impl JceStruct) -> Bytes {
        let mut buf = BytesMut::with_capacity(value.encoded_len() + 2);
        value.write(&mut buf, 0);
        buf.freeze()
    }

    fn invalid(error: impl std::fmt::Display) -> Error {
        malformed(format!("Invalid JCE envelope: {error}"))
    }

    fn unpack(
        body: Bytes,
        servant: &str,
        function: &str,
        entry: &str,
        entry_type: &str,
    ) -> Result<(Packet, Bytes)> {
        if body.len() > MAX_FRAME_SIZE {
            return Err(malformed("JCE request exceeds limit"));
        }
        let mut packet = Packet::decode(body).map_err(invalid)?;
        if packet.version != 2 || packet.servant != servant || packet.function != function {
            return Err(malformed("Unsupported JCE request envelope"));
        }
        let mut data = Data::decode(std::mem::take(&mut packet.buffer.0)).map_err(invalid)?;
        let body = data.entries.remove(entry)
            .and_then(|mut entries| entries.remove(entry_type))
            .ok_or_else(|| malformed("Missing JCE request body"))?.0;
        if body.first() != Some(&0x0a) || body.last() != Some(&0x0b) {
            return Err(malformed("Invalid JCE request struct"));
        }
        let inner = body.slice(1..body.len() - 1);
        Ok((packet, inner))
    }

    pub(crate) fn payload(
        body: Bytes,
        servant: &str,
        function: &str,
        entry: &str,
        entry_type: &str,
    ) -> Result<Bytes> {
        unpack(body, servant, function, entry, entry_type).map(|(_, body)| body)
    }

    #[cfg(test)]
    pub(crate) fn payload_fixture(
        servant: &str,
        function: &str,
        entry: &str,
        entry_type: &str,
        body: Bytes,
    ) -> Bytes {
        let mut wrapped = BytesMut::with_capacity(body.len() + 2);
        wrapped.put_u8(0x0a);
        wrapped.put_slice(&body);
        wrapped.put_u8(0x0b);
        encode(&Packet {
            version: 2,
            servant: servant.into(),
            function: function.into(),
            buffer: TarsBytes(encode(&Data {
                entries: HashMap::from([(
                    entry.into(),
                    HashMap::from([(entry_type.into(), TarsBytes(wrapped.freeze()))]),
                )]),
            })),
            ..Default::default()
        })
    }

    pub(crate) struct DecodedPush {
        pub kind: i32,
        pub sequence: Option<i64>,
        pub configuration: Bytes,
        pub acknowledgment: Option<Bytes>,
    }

    pub(crate) fn decode(body: Bytes) -> Result<DecodedPush> {
        let (mut packet, request) = unpack(
            body,
            "QQService.ConfigPushSvc.MainServant",
            "PushReq",
            "PushReq",
            "ConfigPush.PushReq",
        )?;
        let request = PushRequest::decode(request).map_err(invalid)?;
        if request.kind != 1 {
            return Ok(DecodedPush {
                kind: request.kind,
                sequence: request.sequence.0,
                configuration: request.configuration.0,
                acknowledgment: None,
            });
        }
        let sequence = request
            .sequence
            .0
            .ok_or_else(|| malformed("Missing ConfigPush request sequence"))?;
        let wrapped = wrap(&PushResponse {
            kind: request.kind,
            sequence,
            configuration: TarsBytes::default(),
        });
        packet.function = "PushRes".into();
        packet.buffer = TarsBytes(encode(&Data {
            entries: HashMap::from([(
                "PushResp".into(),
                HashMap::from([("ConfigPush.PushResp".into(), TarsBytes(wrapped))]),
            )]),
        }));
        Ok(DecodedPush {
            kind: request.kind,
            sequence: Some(sequence),
            configuration: request.configuration.0,
            acknowledgment: Some(encode(&packet)),
        })
    }

    #[cfg(test)]
    pub(super) fn response(body: Bytes) -> Result<Option<Bytes>> {
        decode(body).map(|push| push.acknowledgment)
    }

    #[cfg(test)]
    pub(crate) fn request_fixture(kind: i32, sequence: i64) -> Bytes {
        packet_fixture(
            wrap(&PushRequest {
                kind,
                sequence: RequestSequence(Some(sequence)),
                configuration: TarsBytes::default(),
            }),
            0,
        )
    }

    #[cfg(test)]
    fn packet_fixture(wrapped: Bytes, request_id: i32) -> Bytes {
        encode(&Packet {
            version: 2,
            request_id,
            servant: "QQService.ConfigPushSvc.MainServant".into(),
            function: "PushReq".into(),
            buffer: TarsBytes(encode(&Data {
                entries: HashMap::from([(
                    "PushReq".into(),
                    HashMap::from([("ConfigPush.PushReq".into(), TarsBytes(wrapped))]),
                )]),
            })),
            ..Default::default()
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn unpack_response(encoded: Bytes) -> (Packet, Bytes) {
            let packet = Packet::decode(encoded).unwrap();
            let mut data = Data::decode(packet.buffer.0.clone()).unwrap();
            let wrapped = data
                .entries
                .remove("PushResp")
                .unwrap()
                .remove("ConfigPush.PushResp")
                .unwrap()
                .0;
            (packet, wrapped)
        }

        #[test]
        fn type_one_configuration_response_echoes_inner_sequence_only() {
            let sequence = 0x0102_0304_0506_0708;
            let encoded = response(request_fixture(1, sequence)).unwrap().unwrap();
            let (packet, wrapped) = unpack_response(encoded);
            assert_eq!(packet.version, 2);
            assert_eq!(packet.function, "PushRes");
            assert_eq!(packet.request_id, 0);
            assert_eq!(wrapped.first(), Some(&0x0a));
            assert_eq!(wrapped.last(), Some(&0x0b));
            let reply = PushResponse::decode(wrapped.slice(1..wrapped.len() - 1)).unwrap();
            assert_eq!(reply.kind, 1);
            assert_eq!(reply.sequence, sequence);
            assert!(reply.configuration.0.is_empty());
        }

        #[test]
        fn compact_tars_fixture_preserves_envelope_and_ack_wire_types() {
            // Independently encoded Tars: compact version/request-id/kind/sequence,
            // omitted default packet fields, and a SIMPLE_LIST configuration.
            let fixture = Bytes::from_static(
                b"\x10\x02\x40\x2a\x56\x23QQService.ConfigPushSvc.MainServant\
                  \x66\x07PushReq\x7d\x00\x00\x34\
                  \x08\x00\x01\x06\x07PushReq\x18\x00\x01\
                  \x06\x12ConfigPush.PushReq\x1d\x00\x00\x0d\
                  \x0a\x10\x01\x2d\x00\x00\x03\x01\x02\x03\x30\x11\x0b",
            );
            let encoded = response(fixture).unwrap().unwrap();
            let (packet, wrapped) = unpack_response(encoded);
            assert_eq!(packet.request_id, 42);
            assert_eq!(packet.servant, "QQService.ConfigPushSvc.MainServant");
            assert_eq!(packet.function, "PushRes");
            // Full-width response integers are valid Tars; configuration remains
            // an empty byte list, not a string or an echoed configuration.
            assert_eq!(
                wrapped.as_ref(),
                b"\x0a\x12\x00\x00\x00\x01\x23\x00\x00\x00\x00\x00\x00\x00\x11\x3d\x00\x0c\x0b",
            );
        }

        #[test]
        fn compact_signed_and_zero_sequences_are_not_missing() {
            for (request, expected) in [
                (b"\x0a\x10\x01\x3c\x0b".as_slice(), 0),
                (b"\x0a\x10\x01\x30\xef\x0b".as_slice(), -17),
                (b"\x0a\x10\x01\x31\x01\x00\x0b".as_slice(), 256),
                (b"\x0a\x10\x01\x32\x00\x01\x00\x00\x0b".as_slice(), 65536),
            ] {
                let encoded = response(packet_fixture(Bytes::from_static(request), 42))
                    .unwrap()
                    .unwrap();
                let (_, wrapped) = unpack_response(encoded);
                let reply = PushResponse::decode(wrapped.slice(1..wrapped.len() - 1)).unwrap();
                assert_eq!(reply.sequence, expected);
            }
        }

        #[test]
        fn malformed_configuration_is_not_acknowledged() {
            assert!(response(Bytes::from_static(b"not a Tars request")).is_err());
            assert!(response(request_fixture(2, 17)).unwrap().is_none());
            assert!(
                response(packet_fixture(Bytes::from_static(b"\x0a\x10\x02\x0b"), 0))
                    .unwrap()
                    .is_none()
            );
            assert!(response(packet_fixture(Bytes::from_static(b"\x0a\x10\x01\x0b"), 0)).is_err());
            assert!(response(packet_fixture(Bytes::from_static(b"\x0a\x30\x11\x0b"), 0)).is_err());
            let fixture = request_fixture(1, 17);
            for end in 0..fixture.len() {
                let _ = response(fixture.slice(..end));
            }
        }
    }
}

pub(crate) struct Reader {
    data: Bytes,
}
impl Reader {
    pub fn new(data: impl Into<Bytes>) -> Self {
        Self { data: data.into() }
    }
    pub fn remaining(&self) -> usize {
        self.data.len()
    }
    pub fn bytes(&mut self, n: usize) -> Result<Bytes> {
        if n > self.data.len() {
            return Err(malformed("Truncated binary field"));
        }
        Ok(self.data.split_to(n))
    }
    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.bytes(n).map(|_| ())
    }
    pub fn rest(&mut self) -> Bytes {
        self.data.split_to(self.data.len())
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        Ok(self.bytes(2)?.get_u16())
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(self.bytes(4)?.get_u32())
    }
    pub fn i32(&mut self) -> Result<i32> {
        Ok(self.u32()? as i32)
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(self.bytes(8)?.get_u64())
    }
    pub fn pref(&mut self, width: usize, inclusive: bool) -> Result<Bytes> {
        let length = match width {
            1 => self.u8()? as usize,
            2 => self.u16()? as usize,
            4 => self.u32()? as usize,
            _ => return Err(malformed("Invalid length prefix width")),
        };
        let n = if inclusive {
            length
                .checked_sub(width)
                .ok_or_else(|| malformed("Length prefix underflow"))?
        } else {
            length
        };
        self.bytes(n)
    }
    pub fn p32(&mut self) -> Result<Bytes> {
        self.pref(4, true)
    }
    pub fn p16(&mut self) -> Result<Bytes> {
        self.pref(2, false)
    }
}
#[derive(Default)]
pub(crate) struct Writer {
    pub data: Vec<u8>,
}
impl Writer {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn u8(&mut self, v: u8) {
        self.data.push(v)
    }
    pub fn u16(&mut self, v: u16) {
        self.data.extend_from_slice(&v.to_be_bytes())
    }
    pub fn u32(&mut self, v: u32) {
        self.data.extend_from_slice(&v.to_be_bytes())
    }
    pub fn i32(&mut self, v: i32) {
        self.u32(v as u32)
    }
    pub fn u64(&mut self, v: u64) {
        self.data.extend_from_slice(&v.to_be_bytes())
    }
    pub fn bytes(&mut self, b: impl AsRef<[u8]>) {
        self.data.extend_from_slice(b.as_ref())
    }
    pub fn zeros(&mut self, n: usize) {
        self.data.resize(self.data.len() + n, 0)
    }
    pub fn pref(&mut self, b: impl AsRef<[u8]>, width: usize, inclusive: bool) -> Result<()> {
        let b = b.as_ref();
        let n = b
            .len()
            .checked_add(if inclusive { width } else { 0 })
            .ok_or_else(|| malformed("Length overflow"))?;
        match width {
            1 => self.u8(u8::try_from(n).map_err(|_| malformed("u8 length overflow"))?),
            2 => self.u16(u16::try_from(n).map_err(|_| malformed("u16 length overflow"))?),
            4 => self.u32(u32::try_from(n).map_err(|_| malformed("u32 length overflow"))?),
            _ => return Err(malformed("Invalid length prefix width")),
        };
        self.bytes(b);
        Ok(())
    }
    pub fn p32(&mut self, b: impl AsRef<[u8]>) -> Result<()> {
        self.pref(b, 4, true)
    }
    pub fn p16(&mut self, b: impl AsRef<[u8]>) -> Result<()> {
        self.pref(b, 2, false)
    }
}

#[derive(Default)]
pub struct SsoFrameCodec;
impl Decoder for SsoFrameCodec {
    type Item = Bytes;
    type Error = std::io::Error;
    fn decode(&mut self, src: &mut BytesMut) -> std::io::Result<Option<Bytes>> {
        if src.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes(src[..4].try_into().unwrap()) as usize;
        if !(4..=MAX_FRAME_SIZE).contains(&len) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid SSO frame length",
            ));
        }
        if src.len() < len {
            return Ok(None);
        }
        Ok(Some(src.split_to(len).freeze()))
    }
}
impl Encoder<Bytes> for SsoFrameCodec {
    type Error = std::io::Error;
    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> std::io::Result<()> {
        if item.len() < 4
            || item.len() > MAX_FRAME_SIZE
            || u32::from_be_bytes(item[..4].try_into().unwrap()) as usize != item.len()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid outgoing SSO frame",
            ));
        }
        dst.extend_from_slice(&item);
        Ok(())
    }
}

pub(crate) fn encode_sso(
    command: &str,
    sequence: i32,
    body: Bytes,
    kind: RequestType,
    encryption: Encryption,
    state: &SessionState,
    signature: Option<signing_engine::SecureInfo>,
) -> Result<Bytes> {
    use prost::Message;
    if body.len() > MAX_FRAME_SIZE - 4096 || command.len() > 1024 * 1024 {
        return Err(malformed("SSO request exceeds limit"));
    }
    let store = &state.keystore;
    let mut head = Writer::new();
    match kind {
        RequestType::D2 => {
            head.i32(sequence);
            head.u32(state.profile.sub_app_id);
            head.u32(2052);
            head.u8(2);
            head.zeros(11);
            head.p32(&store.a2)?;
            head.p32(command)?;
            head.p32([])?;
            head.p32(hex::encode(&store.guid))?;
            head.p32([])?;
            head.pref(&state.profile.version, 2, true)?;
        }
        RequestType::Simple => {
            head.p32(command)?;
            head.p32([])?;
        }
    }
    let reserve = sso::Reserved {
        trace_parent: Some(format!(
            "01-{}-{}-01",
            hex::encode(random_bytes(16)),
            hex::encode(random_bytes(8))
        )),
        uid: Some(store.uid.clone()),
        secure_info: signature.map(|s| sso::SecureInfo {
            sign: Some(Bytes::copy_from_slice(s.sign.as_ref())),
            token: Some(s.token.into()),
            extra: Some(s.extra.into()),
        }),
        ..Default::default()
    };
    head.p32(reserve.encode_to_vec())?;
    let mut payload = Writer::new();
    payload.p32(head.data)?;
    payload.p32(body)?;
    let encrypted = match encryption {
        Encryption::None => payload.data,
        Encryption::D2 => crypto::tea_encrypt(&payload.data, &store.d2_key)?,
        Encryption::Empty => crypto::tea_encrypt(&payload.data, &[0; 16])?,
    };
    let mut envelope = Writer::new();
    envelope.u32(kind as u32);
    envelope.u8(encryption as u8);
    match kind {
        RequestType::D2 => envelope.p32(if encryption == Encryption::D2 {
            store.d2.as_slice()
        } else {
            &[]
        })?,
        RequestType::Simple => envelope.i32(sequence),
    }
    envelope.u8(0);
    envelope.p32(store.uin.to_string())?;
    envelope.bytes(encrypted);
    if envelope.data.len() > MAX_FRAME_SIZE - 4 {
        return Err(malformed("SSO frame exceeds limit"));
    }
    let mut frame = Writer::new();
    frame.p32(envelope.data)?;
    Ok(frame.data.into())
}
pub(crate) fn decode_sso(frame: Bytes, keys: &[&[u8]]) -> Result<(IncomingPacket, String)> {
    let length = frame.len();
    if length > MAX_FRAME_SIZE {
        return Err(malformed("SSO frame exceeds limit"));
    }
    let mut r = Reader::new(frame);
    if r.u32()? as usize != length {
        return Err(malformed("SSO frame length mismatch"));
    }
    let _ = r.u32()?;
    let auth = r.u8()?;
    let _ = r.u8()?;
    let _ = r.p32()?;
    let encrypted = r.rest();
    let clear = match auth {
        0 => encrypted,
        2 => crypto::tea_decrypt(&encrypted, &[0; 16])?.into(),
        1 => {
            let mut decrypted = None;
            for key in keys {
                if let Ok(value) = crypto::tea_decrypt(&encrypted, key) {
                    decrypted = Some(value);
                    break;
                }
            }
            decrypted
                .ok_or_else(|| Error::Authentication("No valid D2 reply key".into()))?
                .into()
        }
        _ => return Err(malformed("Unknown SSO encryption flag")),
    };
    let mut r = Reader::new(clear);
    let header = r.p32()?;
    let body = r.p32()?;
    let mut h = Reader::new(header);
    let sequence = h.i32()?;
    let return_code = h.i32()?;
    let extra = text(h.p32()?)?;
    let command = text(h.p32()?)?;
    let message_cookie = h.p32()?;
    let compression = h.i32()?;
    let server_reserve = h.p32()?;
    let header = SsoResponseHeader {
        message_cookie,
        server_reserve,
        extensions: h.rest(),
    };
    let body = match compression {
        0 | 4 => body,
        1 => bounded_zlib(&body, MAX_FRAME_SIZE)?.into(),
        _ => {
            return Err(Error::Unsupported(format!(
                "SSO compression flag {compression}"
            )));
        }
    };
    Ok((
        IncomingPacket {
            sequence,
            command,
            body,
            return_code,
            header,
        },
        extra,
    ))
}
fn text(b: Bytes) -> Result<String> {
    String::from_utf8(b.to_vec()).map_err(|_| malformed("Invalid SSO UTF-8"))
}
pub fn bounded_zlib(input: &[u8], limit: usize) -> Result<Vec<u8>> {
    use flate2::{Decompress, FlushDecompress, Status};
    let mut decoder = Decompress::new(true);
    let mut out = Vec::new();
    let mut offset = 0;
    loop {
        let mut chunk = [0u8; 8192];
        let before_in = decoder.total_in();
        let before_out = decoder.total_out();
        let status = decoder
            .decompress(&input[offset..], &mut chunk, FlushDecompress::None)
            .map_err(|e| malformed(format!("Invalid zlib: {e}")))?;
        let consumed = (decoder.total_in() - before_in) as usize;
        let produced = (decoder.total_out() - before_out) as usize;
        offset += consumed;
        if produced > limit.saturating_sub(out.len()) {
            return Err(malformed("Decompressed SSO body exceeds limit"));
        }
        out.extend_from_slice(&chunk[..produced]);
        if status == Status::StreamEnd {
            if offset != input.len() {
                return Err(malformed("Trailing bytes after zlib stream"));
            }
            return Ok(out);
        }
        if consumed == 0 && produced == 0 {
            return Err(malformed("Truncated zlib stream"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn push_ack_echoes_only_requested_opaque_server_descriptors() {
        use prost::Message;
        // Synthetic descriptors contain unknown fields and non-UTF8 bytes.
        let descriptors = vec![Bytes::from_static(&[0x0a, 2, 0xff, 0x80, 0xf8, 7, 1])];
        let source = auth::PushAckSource {
            required: Some(1),
            descriptors: descriptors.clone(),
        };
        let ack = encode_push_ack(source.encode_to_vec().into())
            .unwrap()
            .unwrap();
        let decoded: auth::PushAckRequest = proto::decode(ack).unwrap();
        assert_eq!(decoded.descriptors, descriptors);
        for required in [None, Some(0), Some(2)] {
            let source = auth::PushAckSource {
                required,
                descriptors: descriptors.clone(),
            };
            assert!(
                encode_push_ack(source.encode_to_vec().into())
                    .unwrap()
                    .is_none()
            );
        }
        assert!(
            encode_push_ack(
                auth::PushAckSource {
                    required: Some(1),
                    descriptors: Vec::new(),
                }
                .encode_to_vec()
                .into()
            )
            .is_err()
        );
    }
    fn response_header(command: &[u8], compression: i32) -> Vec<u8> {
        let mut h = Writer::new();
        h.i32(73);
        h.i32(0);
        h.p32("detail").unwrap();
        h.p32(command).unwrap();
        h.p32([0xff, 0, 0x80]).unwrap();
        h.i32(compression);
        h.p32([0x08, 0x01, 0xf8, 0x07, 0x02]).unwrap();
        h.data
    }
    fn response_payload(payload: &[u8], auth: u8) -> Bytes {
        let encrypted = match auth {
            0 => payload.to_vec(),
            2 => crypto::tea_encrypt(payload, &[0; 16]).unwrap(),
            _ => panic!("unsupported fixture encryption"),
        };
        let mut envelope = Writer::new();
        envelope.u32(12);
        envelope.u8(auth);
        envelope.u8(0);
        envelope.p32("0").unwrap();
        envelope.bytes(encrypted);
        let mut frame = Writer::new();
        frame.p32(envelope.data).unwrap();
        frame.data.into()
    }
    fn response_frame(header: &[u8], body: &[u8], auth: u8) -> Bytes {
        let mut payload = Writer::new();
        payload.p32(header).unwrap();
        payload.p32(body).unwrap();
        response_payload(&payload.data, auth)
    }
    #[test]
    fn desktop_extended_responses_preserve_bounded_unknown_header_data() {
        use std::io::Write;
        let body = b"\x08\x01\x12\x03\xff\x00\x80";
        let extensions = [0, 0, 0, 0, 0xff, 0x80, 7];
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(body).unwrap();
        let compressed = z.finish().unwrap();
        for command in [
            "wtlogin.trans_emp",
            "trpc.login.ecdh.EcdhService.SsoKeyExchange",
            "unknown.service",
        ] {
            for auth in [0, 2] {
                for compression in [0, 1, 4] {
                    let mut h = response_header(command.as_bytes(), compression);
                    h.extend_from_slice(&extensions);
                    let encoded_body = if compression == 1 {
                        compressed.as_slice()
                    } else {
                        body.as_slice()
                    };
                    let (packet, extra) =
                        decode_sso(response_frame(&h, encoded_body, auth), &[]).unwrap();
                    assert_eq!(packet.sequence, 73);
                    assert_eq!(packet.return_code, 0);
                    assert_eq!(packet.command, command);
                    assert_eq!(extra, "detail");
                    assert_eq!(&packet.body[..], body);
                    assert_eq!(&packet.header.message_cookie[..], &[0xff, 0, 0x80]);
                    assert_eq!(
                        &packet.header.server_reserve[..],
                        &[0x08, 0x01, 0xf8, 0x07, 0x02]
                    );
                    assert_eq!(&packet.header.extensions[..], &extensions);
                }
            }
        }
        let (packet, _) =
            decode_sso(response_frame(&response_header(b"plain", 0), body, 0), &[]).unwrap();
        assert!(packet.header.extensions.is_empty());
    }
    #[test]
    fn enclosing_suffix_is_excluded_from_raw_and_compressed_service_bodies() {
        use std::io::Write;
        let body = b"service payload";
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(body).unwrap();
        let compressed = encoder.finish().unwrap();
        for compression in [0, 1, 4] {
            for auth in [0, 2] {
                let mut payload = Writer::new();
                payload
                    .p32(response_header(b"example.reply", compression))
                    .unwrap();
                payload
                    .p32(if compression == 1 {
                        compressed.as_slice()
                    } else {
                        body.as_slice()
                    })
                    .unwrap();
                payload.bytes([0xff, 0, 0x80, 0, 0, 0, 4]);
                let (packet, _) = decode_sso(response_payload(&payload.data, auth), &[]).unwrap();
                assert_eq!(packet.body.as_ref(), body);
                assert!(packet.header.extensions.is_empty());
            }
        }
    }
    #[test]
    fn extended_header_support_keeps_mandatory_field_boundaries_strict() {
        let header = response_header(b"command", 0);
        // Every prefix truncation, including inside the declared reserve, is malformed.
        for end in 0..header.len() {
            assert!(
                decode_sso(response_frame(&header[..end], b"body", 0), &[]).is_err(),
                "header truncated at {end}"
            );
        }
        let reserve_prefix = header.len() - 9;
        for length in [0u32, 3, 10, u32::MAX] {
            let mut h = header.clone();
            h[reserve_prefix..reserve_prefix + 4].copy_from_slice(&length.to_be_bytes());
            assert!(
                decode_sso(response_frame(&h, b"body", 0), &[]).is_err(),
                "reserve length {length}"
            );
        }
        let mut invalid_utf8 = response_header(&[0xff], 0);
        invalid_utf8.extend_from_slice(&[0xff]);
        assert!(decode_sso(response_frame(&invalid_utf8, b"body", 0), &[]).is_err());
    }
    #[test]
    fn extended_headers_do_not_relax_outer_payload_lengths() {
        let mut header = response_header(b"command", 0);
        header.extend_from_slice(&[0xff, 0, 1]);
        let mut payload = Writer::new();
        payload.p32(&header).unwrap();
        payload.p32(b"body").unwrap();
        for length in [0u32, 3, u32::MAX] {
            let mut bad_header = payload.data.clone();
            bad_header[..4].copy_from_slice(&length.to_be_bytes());
            assert!(decode_sso(response_payload(&bad_header, 0), &[]).is_err());
            let mut bad_body = payload.data.clone();
            let offset = 4 + header.len();
            bad_body[offset..offset + 4].copy_from_slice(&length.to_be_bytes());
            assert!(decode_sso(response_payload(&bad_body, 0), &[]).is_err());
        }
        let truncated = &payload.data[..payload.data.len() - 1];
        assert!(decode_sso(response_payload(truncated, 0), &[]).is_err());
        let mut bad_frame = response_payload(&payload.data, 0).to_vec();
        let length = (bad_frame.len() + 1) as u32;
        bad_frame[..4].copy_from_slice(&length.to_be_bytes());
        assert!(decode_sso(bad_frame.into(), &[]).is_err());
    }
    #[test]
    fn frame_prefix_cannot_underflow_or_allocate_unbounded() {
        let mut c = SsoFrameCodec;
        for n in [0u32, 3, MAX_FRAME_SIZE as u32 + 1, u32::MAX] {
            let mut b = BytesMut::from(n.to_be_bytes().as_slice());
            assert!(c.decode(&mut b).is_err())
        }
        let mut b = BytesMut::from(&b"\0\0\0\x08abc"[..]);
        assert!(c.decode(&mut b).unwrap().is_none());
        b.extend_from_slice(b"d");
        assert_eq!(c.decode(&mut b).unwrap().unwrap().len(), 8);
    }
    #[test]
    fn zlib_limit_truncation_and_trailing_are_checked() {
        use std::io::Write;
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(&[42; 10000]).unwrap();
        let mut z = z.finish().unwrap();
        assert_eq!(bounded_zlib(&z, 10000).unwrap().len(), 10000);
        assert!(bounded_zlib(&z, 9999).is_err());
        assert!(bounded_zlib(&z[..z.len() - 1], 10000).is_err());
        z.push(0);
        assert!(bounded_zlib(&z, 10000).is_err());
    }
    #[test]
    fn binary_prefix_underflow_is_rejected() {
        let mut r = Reader::new(Bytes::from_static(&[0, 0, 0, 3]));
        assert!(r.p32().is_err());
    }
}
