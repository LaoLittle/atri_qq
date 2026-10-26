use crate::{Error, Result, models::SessionState, proto};
use ::signing::token::{DeviceProperties, TokenError};
use prost::Message;

mod channel;
mod crypto;
pub(crate) use channel::Channel;

mod heartbeat;
mod task11;
pub(crate) use heartbeat::{Heartbeat, Work};

#[derive(Default)]
pub(crate) struct Session {
    pub channel: Channel,
    pub heartbeat: Heartbeat,
    pub scope: Option<(u64, u64)>,
    pub transport_generation: Option<u64>,
}

pub(crate) fn unix_seconds() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| Error::Crypto("O3 wall clock precedes Unix epoch".into()))
}

pub const REPORT_COMMAND: &str = "trpc.o3.report.Report.SsoReport";
pub const ESTABLISH_COMMAND: &str = "trpc.o3.ecdh_access.EcdhAccess.SsoEstablishShareKey";
pub const ACCESS_COMMAND: &str = "trpc.o3.ecdh_access.EcdhAccess.SsoSecureAccess";
const SDK_VERSION: &str = "0.0.20";
const REPORT_ID: &str = "0df00071646";

pub const CANONICAL_REPORT_MODULE_PATHS: &[&str] = &[
    "/opt/QQ/resources/app/app_launcher/index.js",
    "/opt/QQ/resources/app/app_launcher/launcher.js",
    "/opt/QQ/resources/app/application.asar/165.background.js",
    "/opt/QQ/resources/app/application.asar/288.background.js",
    "/opt/QQ/resources/app/application.asar/357.background.js",
    "/opt/QQ/resources/app/application.asar/544.background.js",
    "/opt/QQ/resources/app/application.asar/790.background.js",
    "/opt/QQ/resources/app/application.asar/86.background.js",
    "/opt/QQ/resources/app/application.asar/app_launcher/index.js",
    "/opt/QQ/resources/app/application.asar/app_launcher/launcher.js",
    "/opt/QQ/resources/app/application.asar/background.js",
    "/opt/QQ/resources/app/application.asar/node-plugin.background.js",
];

/// Bound trusted caller-supplied inventory without inspecting the host or
/// normalizing, sorting or dropping entries from the caller's complete snapshot.
pub fn validate_report_module_paths(paths: &[String]) -> Result<()> {
    let bytes = paths
        .iter()
        .try_fold(0usize, |total, path| total.checked_add(path.len()));
    if paths.len() > 4096
        || bytes.is_none_or(|bytes| bytes > 1024 * 1024)
        || paths
            .iter()
            .any(|path| path.is_empty() || path.as_bytes().contains(&0))
    {
        return Err(Error::Malformed(
            "O3 report module inventory exceeds resource bounds or contains empty/NUL paths".into(),
        ));
    }
    Ok(())
}

pub fn generate_application_uuid() -> String {
    let mut bytes = rand::random::<[u8; 16]>();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let mut value = String::with_capacity(36);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (index, byte) in bytes.into_iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            value.push('-');
        }
        value.push(HEX[(byte >> 4) as usize] as char);
        value.push(HEX[(byte & 15) as usize] as char);
    }
    value
}

fn normalize_local_text(mut value: Vec<u8>, padding: &[u8]) -> Vec<u8> {
    if let (Some(first), Some(last)) = (
        value.iter().position(|byte| !padding.contains(byte)),
        value.iter().rposition(|byte| !padding.contains(byte)),
    ) && last > first
    {
        if first != 0 {
            value.copy_within(first..=last, 0);
        }
        value.truncate(last - first + 1);
    }
    value
}

fn property_file_text(mut value: Vec<u8>) -> Vec<u8> {
    let mut read = 0;
    let mut written = 0;
    while read < value.len() {
        let limit = (read + 127).min(value.len());
        let end = value[read..limit]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(limit, |offset| read + offset + 1);
        let visible = value[read..end]
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(end - read);
        if written != read {
            value.copy_within(read..read + visible, written);
        }
        written += visible;
        read = end;
    }
    value.truncate(written);
    normalize_local_text(value, b"\n\r\t ")
}

fn read_property_file(path: &str) -> Option<Vec<u8>> {
    std::fs::read(path)
        .ok()
        .map(property_file_text)
        .filter(|value| !value.is_empty())
}

fn memory_total_text(mut source: &[u8]) -> Option<Vec<u8>> {
    while !source.is_empty() {
        let limit = source.len().min(127);
        let end = source[..limit]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(limit, |offset| offset + 1);
        let chunk = &source[..end];
        source = &source[end..];
        let chunk = &chunk[..chunk
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(chunk.len())];
        let Some(key) = chunk.windows(9).position(|window| window == b"MemTotal:") else {
            continue;
        };
        let colon = key + 8;
        let Some(unit) = chunk[key..].windows(2).position(|window| window == b"kB") else {
            continue;
        };
        let unit = key + unit;
        if colon != 0 && unit > colon {
            return Some(normalize_local_text(
                chunk[colon + 1..=unit].to_vec(),
                b"\n\r\t ",
            ));
        }
    }
    None
}

fn boot_time_text(source: &[u8], now: i64) -> Option<Vec<u8>> {
    let source = source.strip_suffix(b" ").unwrap_or(source);
    let mut fields = source.split(|byte| *byte == b' ');
    let uptime = fields.next()?.trim_ascii_start();
    fields.next()?;
    if fields.next().is_some() {
        return None;
    }
    let sign = usize::from(matches!(uptime.first(), Some(b'+' | b'-')));
    let digits = uptime[sign..]
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if digits == 0 {
        return None;
    }
    let seconds = std::str::from_utf8(&uptime[..sign + digits])
        .ok()?
        .parse::<i64>()
        .ok()?;
    now.checked_sub(seconds)
        .map(|seconds| seconds.to_string().into_bytes())
}

pub(crate) fn validate_local_identity(machine_id: &str) -> Result<()> {
    if machine_id.is_empty() || machine_id.as_bytes().contains(&0) {
        return Err(Error::Malformed(
            "O3 requires a nonempty, NUL-free configured machine_id".into(),
        ));
    }
    Ok(())
}

pub fn local_device_properties(
    machine_id: &str,
    application_uuid: &str,
) -> Result<DeviceProperties> {
    validate_local_identity(machine_id)?;
    let mut system_machine_id = read_property_file("/etc/machine-id");
    let mut boot_id = read_property_file("/proc/sys/kernel/random/boot_id");
    let mut boot_time = read_property_file("/proc/uptime").and_then(|source| {
        boot_time_text(&source, i64::try_from(unix_seconds().ok()?).ok()?)
    });
    let mut kernel_version = read_property_file("/proc/sys/kernel/version");
    let mut system_uuid = read_property_file("/etc/uuid");
    let mut memory_total = std::fs::read("/proc/meminfo")
        .ok()
        .and_then(|source| memory_total_text(&source));
    let mut hostname = hostname::get()
        .ok()
        .map(|value| normalize_local_text(value.into_encoded_bytes(), b"\r\n"))
        .filter(|value| !value.is_empty());
    Ok((0..=41)
        .map(|id| {
            let value = match id {
                0 => b"5".to_vec(),
                5 => memory_total.take().unwrap_or_else(|| b"-1".to_vec()),
                16 => machine_id.as_bytes().to_vec(),
                24 if !application_uuid.is_empty() => application_uuid.as_bytes().to_vec(),
                25 => system_machine_id.take().unwrap_or_else(|| b"-1".to_vec()),
                26 => boot_id.take().unwrap_or_else(|| b"-1".to_vec()),
                27 => boot_time.take().unwrap_or_else(|| b"-1".to_vec()),
                28 => kernel_version.take().unwrap_or_else(|| b"-1".to_vec()),
                30 => system_uuid.take().unwrap_or_else(|| b"-1".to_vec()),
                41 => hostname.take().unwrap_or_else(|| b"-1".to_vec()),
                _ => b"-1".to_vec(),
            };
            (id, value)
        })
        .collect())
}

/// Validate resource bounds, not the truth or server acceptability of observations.
/// Unknown and negative IDs remain supported for trusted external collectors.
pub fn validate_properties(properties: &DeviceProperties) -> std::result::Result<(), TokenError> {
    let bytes = properties
        .values()
        .try_fold(0usize, |total, value| total.checked_add(value.len()));
    if properties.len() > 4096 || bytes.is_none_or(|bytes| bytes > 1024 * 1024) {
        return Err(TokenError::Resource {
            operation: "collect_properties",
            message: "O3 device properties exceed the local resource limit".into(),
        });
    }
    Ok(())
}

fn telemetry(values: Vec<String>) -> Vec<u8> {
    proto::o3::TelemetryReport {
        report_id: REPORT_ID.into(),
        data: vec![proto::o3::TelemetryValues { values }],
    }
    .encode_to_vec()
}

pub fn empty_token_telemetry(state: &SessionState) -> Vec<u8> {
    telemetry(vec![
        state.profile.qua.clone(),
        SDK_VERSION.into(),
        "emptyToken".into(),
    ])
}

pub fn verify_file_telemetry(state: &SessionState, module_paths: Option<&[String]>) -> Vec<u8> {
    telemetry(vec![
        state.profile.qua.clone(),
        SDK_VERSION.into(),
        "verify_file".into(),
        concat!(r#"{"/opt/QQ/resources/app/application.json":"0"}"#, "\n",).into(),
        match module_paths {
            Some(paths) => serde_json::to_string(paths),
            None => serde_json::to_string(CANONICAL_REPORT_MODULE_PATHS),
        }
        .expect("serializing module path strings cannot fail"),
        "3".into(),
        state.machine_id.clone(),
        "/opt/bin/qq".into(),
    ])
}

pub fn complete_telemetry(response: &::signing::token::ReportResponse) -> Result<()> {
    if !response.transport_succeeded {
        return Err(Error::Server {
            code: response.error_code as i32,
            message: "O3 telemetry transport failed".into(),
        });
    }
    if !response.bytes.is_empty() {
        return Err(Error::Malformed(
            "Unexpected nonempty O3 telemetry response".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod property_tests {
    use super::*;

    #[test]
    fn file_text_preserves_native_chunk_and_degenerate_padding_semantics() {
        assert_eq!(
            property_file_text(b" \r\nabc\0discard\nnext\n".to_vec()),
            b"abcnext"
        );
        assert_eq!(property_file_text(b" x ".to_vec()), b" x ");
        assert_eq!(property_file_text(b" \r\n\t".to_vec()), b" \r\n\t");
        let mut source = vec![b'a'; 127];
        source[1] = 0;
        source.extend_from_slice(b"tail\n");
        assert_eq!(property_file_text(source), b"atail");
    }

    #[test]
    fn memory_total_keeps_native_unit_boundary_and_first_valid_chunk() {
        assert_eq!(
            memory_total_text(b"noise\nMemTotal:       123456 kB\nMemFree: 10 kB\n").unwrap(),
            b"123456 k"
        );
        assert_eq!(
            memory_total_text(b"prefix MemTotal: 42 kB\n").unwrap(),
            b"42 k"
        );
        assert!(memory_total_text(b"MemTotal: 42 MB\n").is_none());
        assert!(memory_total_text(b"MemTotal:\0 42 kB\n").is_none());
        let mut split_key = vec![b'x'; 123];
        split_key.extend_from_slice(b"MemTotal: 42 kB\n");
        assert!(memory_total_text(&split_key).is_none());
    }

    #[test]
    fn boot_time_uses_wall_clock_minus_uptime_integer_prefix() {
        assert_eq!(boot_time_text(b"234.99 ignored", 1500).unwrap(), b"1266");
        assert_eq!(boot_time_text(b"234.99 ignored", 1501).unwrap(), b"1267");
        assert_eq!(boot_time_text(b"\t+234suffix 0", 1500).unwrap(), b"1266");
        assert_eq!(boot_time_text(b"-234.99 0", 1500).unwrap(), b"1734");
    }

    #[test]
    fn boot_time_requires_exact_native_space_delimited_field_count() {
        for value in [b"234.99".as_slice(), b"234.99  0", b"234.99 0 extra", b"1 "] {
            assert!(boot_time_text(value, 1500).is_none());
        }
        assert_eq!(boot_time_text(b"234.99 0 ", 1500).unwrap(), b"1266");
    }

    #[test]
    fn boot_time_rejects_invalid_numbers_and_arithmetic_overflow() {
        for value in [
            b"x234 0".as_slice(),
            b"+ 0",
            b"9223372036854775808 0",
            b"-9223372036854775809 0",
        ] {
            assert!(boot_time_text(value, 1500).is_none());
        }
        assert!(boot_time_text(b"-9223372036854775808 0", 0).is_none());
    }
}
