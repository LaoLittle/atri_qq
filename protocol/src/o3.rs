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
    ) && last > first {
        if first != 0 {
            value.copy_within(first..=last, 0);
        }
        value.truncate(last - first + 1);
    }
    value
}

pub(crate) fn validate_local_identity(machine_id: &str) -> Result<()> {
    if machine_id.is_empty() || machine_id.as_bytes().contains(&0) {
        return Err(Error::Malformed(
            "O3 requires a nonempty, NUL-free configured machine_id".into(),
        ));
    }
    Ok(())
}

pub fn local_device_properties(machine_id: &str, application_uuid: &str) -> Result<DeviceProperties> {
    validate_local_identity(machine_id)?;
    let mut system_machine_id = std::fs::read("/etc/machine-id")
        .ok()
        .map(|value| normalize_local_text(value, b"\n\r\t "))
        .filter(|value| !value.is_empty());
    let mut hostname = hostname::get()
        .ok()
        .map(|value| normalize_local_text(value.into_encoded_bytes(), b"\r\n"))
        .filter(|value| !value.is_empty());
    Ok((0..=41).map(|id| {
        let value = match id {
            0 => b"5".to_vec(),
            16 => machine_id.as_bytes().to_vec(),
            24 if !application_uuid.is_empty() => application_uuid.as_bytes().to_vec(),
            25 => system_machine_id.take().unwrap_or_else(|| b"-1".to_vec()),
            41 => hostname.take().unwrap_or_else(|| b"-1".to_vec()),
            _ => b"-1".to_vec(),
        };
        (id, value)
    }).collect())
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
        concat!(
            r#"{"/opt/QQ/resources/app/application.json":"0"}"#,
            "\n",
        )
        .into(),
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
