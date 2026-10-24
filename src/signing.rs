use crate::adapter::protocol_error;
use crate::authority;
use ::signing::token::{DeviceProperties, ReportResponse, TokenError, XwidAcquisition};
use atri_core::{ApiError, CallerKind, Value, from_value, to_value};
use atri_qq_api::signing::{self as api, SigningConfig, SigningResources};
use atri_qq_protocol::{Client, signing::SigningReport};
use std::{collections::BTreeMap, sync::Mutex};

#[derive(Default)]
pub(crate) struct SigningService {
    reports: Mutex<PendingReports>,
}

#[derive(Default)]
struct PendingReports {
    next_id: u64,
    reports: BTreeMap<u64, SigningReport>,
}

fn invalid(message: &str) -> ApiError {
    ApiError::new("qq.invalid_signing_resource", message)
}

fn properties(
    properties: Option<Vec<api::DeviceProperty>>,
) -> Result<Option<DeviceProperties>, ApiError> {
    properties
        .map(|properties| {
            let mut native = BTreeMap::new();
            for property in properties {
                if native.insert(property.id, property.value).is_some() {
                    return Err(invalid("device properties contain duplicate signed IDs"));
                }
            }
            Ok(native)
        })
        .transpose()
}

fn footer(seed: &[u8]) -> Result<&[u8; 48], ApiError> {
    seed.try_into()
        .map_err(|_| invalid("a genuine footer seed must contain exactly 48 bytes"))
}

fn xwid(value: api::XwidCompletion) -> Result<XwidAcquisition, ApiError> {
    if value.started_at < 0 || value.elapsed_nanoseconds < 0 {
        return Err(invalid(
            "XWID start time and elapsed nanoseconds must be nonnegative",
        ));
    }
    Ok(XwidAcquisition {
        xwid: value.xwid,
        auxiliary: value.auxiliary,
        started_at: value.started_at,
        elapsed_nanoseconds: value.elapsed_nanoseconds,
    })
}

pub(crate) fn apply_initial(client: &Client, config: SigningConfig) -> Result<(), ApiError> {
    // Validate the whole initial resource set before changing any native state.
    let properties = properties(config.resources.properties)?;
    let seed = config.footer_seed.as_deref().map(footer).transpose()?;
    let xwid = config.xwid.map(xwid).transpose()?;
    client
        .set_signing_resources(
            properties,
            config.resources.persistent_xwid_switch,
            config.resources.report_module_paths,
        )
        .map_err(|error| invalid(&error.to_string()))?;
    if let Some(seed) = seed {
        client.set_signing_footer_seed(seed);
    }
    if let Some(xwid) = xwid {
        client.complete_signing_xwid(xwid);
    }
    Ok(())
}

fn token_error(error: TokenError) -> api::SigningTokenError {
    match error {
        TokenError::Resource { operation, message } => api::SigningTokenError::Resource {
            operation: operation.into(),
            message,
        },
        TokenError::PropertyCollection(status) => {
            api::SigningTokenError::PropertyCollection { status }
        }
        TokenError::Protobuf { code, offset } => api::SigningTokenError::Protobuf { code, offset },
        TokenError::PropertyRequestTruncated { offset } => {
            api::SigningTokenError::PropertyRequestTruncated { offset }
        }
        TokenError::Transport(code) => api::SigningTokenError::Transport { code },
    }
}

impl SigningService {
    pub(crate) fn call(
        &self,
        client: &Client,
        kind: CallerKind,
        method: &str,
        args: Value,
    ) -> Result<Value, ApiError> {
        authority::require_trusted(kind)?;
        match method {
            "set_resources" => {
                let resources: SigningResources = from_value(&args)?;
                let properties = properties(resources.properties)?;
                client
                    .set_signing_resources(
                        properties,
                        resources.persistent_xwid_switch,
                        resources.report_module_paths,
                    )
                    .map_err(|error| invalid(&error.to_string()))?;
                Ok(Value::Null)
            }
            "set_footer_seed" => {
                let args: api::FooterSeed = from_value(&args)?;
                client.set_signing_footer_seed(footer(&args.seed)?);
                Ok(Value::Null)
            }
            "complete_xwid" => {
                client.complete_signing_xwid(xwid(from_value(&args)?)?);
                Ok(Value::Null)
            }
            "drain_reports" => {
                let mut pending = self.reports.lock().unwrap();
                let mut result = Vec::new();
                for report in client.drain_signing_reports() {
                    pending.next_id += 1;
                    let id = pending.next_id;
                    result.push(api::SigningReport {
                        id,
                        method: report.method.clone(),
                        account: report.account.clone(),
                        body: report.body.clone(),
                    });
                    pending.reports.insert(id, report);
                }
                to_value(&result)
            }
            "complete_report" => {
                let args: api::ReportCompletion = from_value(&args)?;
                let report = self
                    .reports
                    .lock()
                    .unwrap()
                    .reports
                    .remove(&args.id)
                    .ok_or_else(|| {
                        invalid("report ID is not an outstanding dequeued native report")
                    })?;
                client
                    .complete_signing_report(
                        &report,
                        ReportResponse {
                            bytes: args.response.bytes,
                            transport_succeeded: args.response.transport_succeeded,
                            error_code: args.response.error_code,
                        },
                    )
                    .map_err(protocol_error)?;
                Ok(Value::Null)
            }
            "take_token_error" => to_value(&client.take_signing_token_error().map(token_error)),
            "answer_property_challenge" => {
                let args: api::PropertyChallenge = from_value(&args)?;
                if args.ids.len() % 2 != 0 {
                    return Err(invalid(
                        "property challenge IDs must be signed 16-bit big-endian pairs",
                    ));
                }
                let answer = client
                    .answer_signing_property_challenge(&args.ids)
                    .map_err(protocol_error)?;
                Ok(Value::Bytes(answer))
            }
            _ => Err(ApiError::unsupported(format!("qq.signing/{method}"))),
        }
    }
}
