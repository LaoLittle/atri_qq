//! Account-bound signing operations. The runtime requires a trusted caller.

use atri_core::Operation;
use serde::{Deserialize, Serialize};

pub const SIGNING_SERVICE: &str = "qq.signing";
pub const SIGNING_METHODS: &[&str] = &[
    "set_resources",
    "set_footer_seed",
    "complete_xwid",
    "drain_reports",
    "complete_report",
    "take_token_error",
    "answer_property_challenge",
];

/// Trusted explicit signed-ID observations; the caller owns their provenance.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceProperty {
    pub id: i32,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SigningResources {
    /// Replaces the complete local property map. None restores the session's
    /// conservative synthetic defaults; Some(empty) is an explicitly empty map.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<Vec<DeviceProperty>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persistent_xwid_switch: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_module_paths: Option<Vec<String>>,
}

impl Operation for SigningResources {
    type Response = ();
    const SERVICE: &'static str = SIGNING_SERVICE;
    const METHOD: &'static str = "set_resources";
}

/// Optional externally obtained resources applied before any login request.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SigningConfig {
    pub resources: SigningResources,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub footer_seed: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xwid: Option<XwidCompletion>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FooterSeed {
    pub seed: Vec<u8>,
}

impl Operation for FooterSeed {
    type Response = ();
    const SERVICE: &'static str = SIGNING_SERVICE;
    const METHOD: &'static str = "set_footer_seed";
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XwidCompletion {
    pub xwid: Vec<u8>,
    pub auxiliary: Vec<u8>,
    pub started_at: i64,
    pub elapsed_nanoseconds: i64,
}

impl Operation for XwidCompletion {
    type Response = ();
    const SERVICE: &'static str = SIGNING_SERVICE;
    const METHOD: &'static str = "complete_xwid";
}

/// Dequeues native reports for external transport and later completion.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DrainReports;

impl Operation for DrainReports {
    type Response = Vec<SigningReport>;
    const SERVICE: &'static str = SIGNING_SERVICE;
    const METHOD: &'static str = "drain_reports";
}

/// The ID identifies the captured native report, including its original account.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigningReport {
    pub id: u64,
    pub method: String,
    pub account: Vec<u8>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportResponse {
    pub bytes: Vec<u8>,
    pub transport_succeeded: bool,
    pub error_code: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportCompletion {
    pub id: u64,
    pub response: ReportResponse,
}

impl Operation for ReportCompletion {
    type Response = ();
    const SERVICE: &'static str = SIGNING_SERVICE;
    const METHOD: &'static str = "complete_report";
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PropertyChallenge {
    /// Exact big-endian signed 16-bit property IDs from the genuine challenge.
    pub ids: Vec<u8>,
}

impl Operation for PropertyChallenge {
    type Response = serde_bytes::ByteBuf;
    const SERVICE: &'static str = SIGNING_SERVICE;
    const METHOD: &'static str = "answer_property_challenge";
}

/// Takes the latest signing token error, clearing it from the session.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TakeTokenError;

impl Operation for TakeTokenError {
    type Response = Option<SigningTokenError>;
    const SERVICE: &'static str = SIGNING_SERVICE;
    const METHOD: &'static str = "take_token_error";
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SigningTokenError {
    Resource { operation: String, message: String },
    PropertyCollection { status: i32 },
    Protobuf { code: u32, offset: usize },
    PropertyRequestTruncated { offset: usize },
    Transport { code: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use atri_core::{Value, from_value};

    #[test]
    fn property_challenge_response_decodes_native_cbor_bytes() {
        let response: <PropertyChallenge as Operation>::Response =
            from_value(&Value::Bytes(vec![0, 127, 255])).unwrap();
        assert_eq!(response.as_ref(), &[0, 127, 255]);
    }
}
