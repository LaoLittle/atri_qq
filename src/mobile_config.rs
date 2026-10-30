use atri_core::ApiError;
use atri_extensions::Context;
use atri_qq_protocol::{
    ClientConfig, ClientPlatform, IosAccountRecord80, IosConfig, IosDevice, IosPushStatistics,
    IosRegistration, IosReservedTemplate, IosSnapshotConfig, IosTransportAccount,
    IosTransportResources, PlatformConfig, ios_device::IosVirtualConfig,
    proto::auth::InfoSyncRequest, signing::IosSigningResources,
};
use prost::Message;
use serde::{Deserialize, Serialize};
use signing::ios::command_policy::CommandPolicy;
use std::sync::Arc;

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum MobileConfig {
    Snapshot(MobileSnapshotConfig),
    Virtual {
        #[serde(default)]
        device: Arc<IosVirtualConfig>,
    },
}

impl MobileConfig {
    pub(crate) fn validate(&self, platform: ClientPlatform) -> Result<(), ApiError> {
        if !platform.is_ios() {
            return Err(invalid(
                "iOS configuration requires an iPhone or iPad profile",
            ));
        }
        match self {
            Self::Snapshot(snapshot) => snapshot.validate(),
            Self::Virtual { device } => device
                .application
                .heartbeat_resources()
                .map(|_| ())
                .map_err(crate::adapter::protocol_error),
        }
    }

    pub(crate) async fn apply(
        &self,
        ctx: &Context,
        config: &mut ClientConfig,
    ) -> Result<(), ApiError> {
        self.validate(config.profile.platform)?;
        config.platform = Some(PlatformConfig::Ios(match self {
            Self::Snapshot(snapshot) => {
                let resources = snapshot.load(ctx).await?;
                IosConfig::Snapshot(IosSnapshotConfig {
                    device: snapshot.device.clone(),
                    signing: resources.signing,
                    transport: resources.transport,
                    registration: resources.registration,
                })
            }
            Self::Virtual { device } => IosConfig::Virtual(device.clone()),
        }));
        Ok(())
    }

    pub(crate) fn heartbeat_snapshot(
        &self,
    ) -> Option<&atri_qq_api::signing::IosHeartbeatResources> {
        match self {
            Self::Snapshot(snapshot) => Some(&snapshot.heartbeat),
            Self::Virtual { .. } => None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MobileSnapshotConfig {
    pub device: IosDevice,
    pub signing: MobileSigningConfig,
    pub transport: MobileTransportConfig,
    pub registration: MobileRegistrationConfig,
    #[serde(default)]
    pub heartbeat: atri_qq_api::signing::IosHeartbeatResources,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MobileSigningConfig {
    pub provenance: String,
    pub raw_device_token_file: String,
    #[serde(default)]
    pub raw_device_token_expires_at: u64,
    #[serde(default)]
    pub raw_device_token_uin: String,
    pub raw_xwid_file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_state_file: Option<String>,
    #[serde(default)]
    pub command_policy: MobileCommandPolicyConfig,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct MobileCommandPolicyConfig {
    pub switches: Vec<MobileCommandSwitch>,
    pub persisted_host_commands: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MobileCommandSwitch {
    pub key: u32,
    pub value: u32,
}

impl MobileCommandPolicyConfig {
    fn policy(&self) -> Result<CommandPolicy, ApiError> {
        command_policy(
            self.switches
                .iter()
                .map(|switch| (switch.key, switch.value)),
            self.persisted_host_commands.iter().map(String::as_str),
        )
    }
}

pub(crate) fn command_policy<'a>(
    switches: impl IntoIterator<Item = (u32, u32)>,
    host_commands: impl IntoIterator<Item = &'a str>,
) -> Result<CommandPolicy, ApiError> {
    let mut policy = CommandPolicy::default();
    for (key, value) in switches {
        if policy.set_switch(key, value).is_some() {
            return Err(invalid(
                "ios.signing.command_policy.switches contains a duplicate key",
            ));
        }
    }
    for command in host_commands {
        if command.is_empty() || command.contains(',') {
            return Err(invalid(
                "ios.signing.command_policy.persisted_host_commands entries must be nonempty individual command names without commas",
            ));
        }
        policy.append_persisted_host_commands(command);
    }
    Ok(policy)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MobileTransportConfig {
    pub network_type: u8,
    pub effective_flags: [u8; 11],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_record_0x80_file: Option<String>,
    pub carrier_mcc: String,
    pub carrier_mnc: String,
    pub cf_bundle_version: String,
    pub account: MobileTransportAccountConfig,
    pub reserved_file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_service_get_statistics: Option<MobilePushStatisticsConfig>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum MobileTransportAccountConfig {
    Uin { account_type: u8 },
    Explicit { account_type: u8, text_file: String },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MobilePushStatisticsConfig {
    pub count: i32,
    pub elapsed: i64,
    pub value: i32,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MobileRegistrationConfig {
    pub initial_file: String,
    pub reconnect_file: String,
}

pub(crate) struct MobileResources {
    pub signing: IosSigningResources,
    pub transport: IosTransportResources,
    pub registration: IosRegistration,
}

impl MobileSnapshotConfig {
    pub(crate) fn validate(&self) -> Result<(), ApiError> {
        if self.device.system_version.is_empty()
            || self.device.hardware_model.is_empty()
            || self.device.system_name.is_empty()
        {
            return Err(invalid(
                "ios.device requires actual system_version, hardware_model and system_name",
            ));
        }
        if self.signing.provenance.trim().is_empty() {
            return Err(invalid(
                "ios.signing.provenance must identify the actual raw resource snapshot source",
            ));
        }
        self.signing.command_policy.policy()?;
        if self.transport.effective_flags[9] >= 4
            || !matches!(self.transport.effective_flags[10], 0 | 4)
        {
            return Err(invalid(
                "ios.transport.effective_flags must contain the actual effective eleven-byte native header flags",
            ));
        }
        Ok(())
    }

    pub(crate) async fn load(&self, ctx: &Context) -> Result<MobileResources, ApiError> {
        self.validate()?;
        let raw_device_token = read_resource(
            ctx,
            "ios.signing.raw_device_token_file",
            &self.signing.raw_device_token_file,
        )
        .await?;
        let raw_xwid = read_nonempty(
            ctx,
            "ios.signing.raw_xwid_file",
            &self.signing.raw_xwid_file,
        )
        .await?;
        let channel_state = match &self.signing.channel_state_file {
            Some(path) => {
                let bytes = read_resource(ctx, "ios.signing.channel_state_file", path).await?;
                Some(bytes.try_into().map_err(|bytes: Vec<u8>| {
                    invalid(format!(
                        "ios.signing.channel_state_file data/{path}: expected 32 raw bytes, got {}",
                        bytes.len()
                    ))
                })?)
            }
            None => None,
        };
        let account_record_0x80 = match &self.transport.account_record_0x80_file {
            Some(path) => read_resource(ctx, "ios.transport.account_record_0x80_file", path)
                .await?
                .into(),
            None => Default::default(),
        };
        let account = match &self.transport.account {
            MobileTransportAccountConfig::Uin { account_type } => IosTransportAccount::Uin {
                account_type: *account_type,
            },
            MobileTransportAccountConfig::Explicit {
                account_type,
                text_file,
            } => IosTransportAccount::Explicit {
                account_type: *account_type,
                text: read_nonempty(ctx, "ios.transport.account.text_file", text_file)
                    .await?
                    .into(),
            },
        };
        let reserved_bytes = read_resource(
            ctx,
            "ios.transport.reserved_file",
            &self.transport.reserved_file,
        )
        .await?;
        let reserved = IosReservedTemplate::new(reserved_bytes.into()).map_err(|error| {
            invalid(format!(
                "ios.transport.reserved_file data/{}: {error}",
                self.transport.reserved_file
            ))
        })?;
        let initial = read_protobuf::<InfoSyncRequest>(
            ctx,
            "ios.registration.initial_file",
            &self.registration.initial_file,
        )
        .await?;
        let reconnect = read_protobuf::<InfoSyncRequest>(
            ctx,
            "ios.registration.reconnect_file",
            &self.registration.reconnect_file,
        )
        .await?;
        Ok(MobileResources {
            signing: IosSigningResources {
                provenance: self.signing.provenance.clone(),
                raw_device_token: raw_device_token.into(),
                raw_device_token_expires_at: self.signing.raw_device_token_expires_at,
                raw_device_token_uin: self.signing.raw_device_token_uin.clone(),
                raw_xwid: raw_xwid.into(),
                channel_state,
                command_policy: self.signing.command_policy.policy()?,
            },
            transport: IosTransportResources {
                network_type: self.transport.network_type,
                effective_flags: self.transport.effective_flags,
                account_record_0x80: IosAccountRecord80(account_record_0x80),
                carrier_mcc: self.transport.carrier_mcc.clone(),
                carrier_mnc: self.transport.carrier_mnc.clone(),
                cf_bundle_version: self.transport.cf_bundle_version.clone(),
                account,
                reserved,
                push_service_get_statistics: self
                    .transport
                    .push_service_get_statistics
                    .as_ref()
                    .map(|statistics| IosPushStatistics {
                        count: statistics.count,
                        elapsed: statistics.elapsed,
                        value: statistics.value,
                    }),
            },
            registration: IosRegistration { initial, reconnect },
        })
    }
}

fn invalid(message: impl Into<String>) -> ApiError {
    ApiError::new("invalid_config", message)
}

fn validate_resource_path(field: &str, path: &str) -> Result<(), ApiError> {
    if path.contains(['\\', ':'])
        || path
            .split('/')
            .any(|component| matches!(component, "" | "." | ".."))
    {
        return Err(invalid(format!(
            "{field} must name a relative managed file in runtime storage data, without empty, dot or parent components"
        )));
    }
    Ok(())
}

async fn read_resource(ctx: &Context, field: &str, path: &str) -> Result<Vec<u8>, ApiError> {
    validate_resource_path(field, path)?;
    ctx.storage().read("data", path).await.map_err(|error| {
        ApiError::new(
            error.code,
            format!("{field} data/{path}: {}", error.message),
        )
    })
}

async fn read_nonempty(ctx: &Context, field: &str, path: &str) -> Result<Vec<u8>, ApiError> {
    let bytes = read_resource(ctx, field, path).await?;
    if bytes.is_empty() {
        return Err(invalid(format!(
            "{field} data/{path}: real nonempty raw resource required; automatic iOS token collection is unavailable"
        )));
    }
    Ok(bytes)
}

async fn read_protobuf<M: Message + Default>(
    ctx: &Context,
    field: &str,
    path: &str,
) -> Result<M, ApiError> {
    let bytes = read_resource(ctx, field, path).await?;
    M::decode(bytes.as_slice())
        .map_err(|error| invalid(format!("{field} data/{path}: invalid protobuf: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_paths_stay_in_runtime_data() {
        for path in [
            "",
            "/tmp/token",
            "../token",
            "ios/../token",
            "./token",
            "ios//token",
            "ios/",
            "C:\\token",
            "ios\\token",
        ] {
            assert!(validate_resource_path("resource", path).is_err(), "{path}");
        }
        assert!(validate_resource_path("resource", "ios/token.bin").is_ok());
    }

    #[test]
    fn typed_policy_rejects_ambiguous_entries() {
        let config = MobileCommandPolicyConfig {
            switches: vec![
                MobileCommandSwitch { key: 2, value: 1 },
                MobileCommandSwitch { key: 2, value: 0 },
            ],
            persisted_host_commands: vec![],
        };
        assert!(config.policy().is_err());
        for command in ["", "first,second"] {
            let config = MobileCommandPolicyConfig {
                switches: vec![],
                persisted_host_commands: vec![command.into()],
            };
            assert!(config.policy().is_err());
        }
    }
}
