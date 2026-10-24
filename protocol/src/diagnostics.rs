use crate::{Error, Result, models::IncomingPacket, proto};
use bytes::Bytes;
use prost::{Message, Name};
use prost_reflect::{DynamicMessage, Value};

pub(crate) async fn send_http(builder: reqwest::RequestBuilder) -> Result<reqwest::Response> {
    let (client, request) = builder.build_split();
    let request = request?;
    tracing::debug!(target: "atri_qq_protocol::packet_trace", direction = "send", transport = "http", method = %request.method(), url = %request.url(), headers = ?request.headers(), body_hex = %hex::encode(request.body().and_then(|body| body.as_bytes()).unwrap_or_default()), "QQ HTTP request");
    let response = client.execute(request).await?;
    tracing::debug!(target: "atri_qq_protocol::packet_trace", direction = "receive", transport = "http", url = %response.url(), status = response.status().as_u16(), headers = ?response.headers(), "QQ HTTP response");
    Ok(response)
}

pub(crate) fn trace_http_chunk(response: &reqwest::Response, offset: usize, chunk: &[u8]) {
    tracing::debug!(target: "atri_qq_protocol::packet_trace", direction = "receive", transport = "http", url = %response.url(), offset, length = chunk.len(), body_hex = %hex::encode(chunk), "QQ HTTP body");
}

pub(crate) fn decode_response<M: Message + Default + Name + std::fmt::Debug>(
    command: &str,
    raw: Bytes,
) -> Result<M> {
    let decoded = match proto::decode::<M>(raw.clone()) {
        Ok(decoded) => decoded,
        Err(error) => {
            log_raw_error(command, &raw, &error);
            return Err(error);
        }
    };
    if let Some(descriptor) = proto::descriptor_pool().get_message_by_name(&M::full_name())
        && let Ok(dynamic) = DynamicMessage::decode(descriptor, raw.clone())
        && let Some((field, code)) = response_status(&dynamic, "")
    {
        tracing::error!(target: "atri_qq_protocol::packet",
            command, response_type = %M::full_name(), status_field = field, code,
            packet = %format!("{decoded:#?}"), raw_length = raw.len(), raw_hex = %hex::encode(&raw),
            "QQ server error response");
    }
    Ok(decoded)
}

pub(crate) fn log_transport_error(packet: &IncomingPacket, extra: &str, frame: &[u8]) {
    tracing::error!(target: "atri_qq_protocol::packet",
        command = packet.command, sequence = packet.sequence, code = packet.return_code,
        message = extra, packet = %format!("{packet:#?}"),
        raw_length = frame.len(), raw_hex = %hex::encode(frame), body_hex = %hex::encode(&packet.body),
        "QQ SSO server error");
}

pub(crate) fn log_raw_error(command: &str, raw: &[u8], error: &Error) {
    tracing::error!(target: "atri_qq_protocol::packet", command, error = ?error,
        raw_length = raw.len(), raw_hex = %hex::encode(raw), "QQ response error");
}

fn response_status(message: &DynamicMessage, prefix: &str) -> Option<(String, i64)> {
    for (field, value) in message.fields() {
        let path = if prefix.is_empty() {
            field.name().to_owned()
        } else {
            format!("{prefix}.{}", field.name())
        };
        if matches!(
            field.name(),
            "code" | "result" | "result_code" | "ret_code" | "error_code" | "return_code"
        ) {
            let code = match value {
                Value::I32(code) => Some(*code as i64),
                Value::I64(code) => Some(*code),
                Value::U32(code) => Some(*code as i32 as i64),
                Value::U64(code) => Some(*code as i32 as i64),
                _ => None,
            };
            if let Some(code) = code.filter(|code| *code != 0) {
                return Some((path, code));
            }
        }
        if let Some(status) = nested_status(value, &path) {
            return Some(status);
        }
    }
    None
}
fn nested_status(value: &Value, path: &str) -> Option<(String, i64)> {
    match value {
        Value::Message(message) => response_status(message, path),
        Value::List(values) => values
            .iter()
            .enumerate()
            .find_map(|(index, value)| nested_status(value, &format!("{path}[{index}]"))),
        Value::Map(values) => values.values().find_map(|value| nested_status(value, path)),
        _ => None,
    }
}
