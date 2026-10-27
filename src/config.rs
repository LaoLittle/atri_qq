use crate::mobile_config::MobileConfig;
use atri_core::{ApiError, decode};
use atri_extensions::Context;
use atri_qq_api::signing::SigningConfig;
use atri_qq_protocol::{ClientConfig, ClientPlatform, Keystore, Profile};
use rand::TryRng;
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use std::time::Duration;

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct Config {
    pub uin: u64,
    pub platform: ClientPlatform,
    pub password: String,
    pub machine_id: String,
    pub application_uuid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qua: Option<String>,
    pub fresh_qr: bool,
    pub randomize_signature_for_testing: bool,
    pub timeout_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing: Option<SigningConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ios: Option<MobileConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            uin: 0,
            platform: ClientPlatform::Linux,
            password: String::new(),
            machine_id: String::new(),
            application_uuid: String::new(),
            qua: None,
            fresh_qr: false,
            randomize_signature_for_testing: false,
            timeout_seconds: 30,
            signing: None,
            ios: None,
        }
    }
}

impl Config {
    pub async fn load(ctx: &Context) -> Result<Self, ApiError> {
        let mut config: Self = ctx.config().load_or_create(&Self::default()).await?;
        config.validate()?;
        let mut changed = false;
        if config.machine_id.is_empty() {
            let mut bytes = [0u8; 16];
            rand::rngs::SysRng
                .try_fill_bytes(&mut bytes)
                .map_err(ApiError::internal)?;
            config.machine_id = String::with_capacity(32);
            for byte in bytes {
                write!(&mut config.machine_id, "{byte:02x}")
                    .expect("writing to String cannot fail");
            }
            changed = true;
        }
        if !config.platform.is_ios() && config.application_uuid.is_empty() {
            config.application_uuid = atri_qq_protocol::o3::generate_application_uuid();
            changed = true;
        }
        if changed {
            ctx.config().save(&config).await?;
        }
        Ok(config)
    }

    fn validate(&self) -> Result<(), ApiError> {
        if self.qua.as_ref().is_some_and(|qua| qua.trim().is_empty()) || self.timeout_seconds == 0 {
            return Err(ApiError::new(
                "invalid_config",
                "qua, when supplied, must be nonempty and timeout_seconds must be nonzero",
            ));
        }
        match self.platform {
            ClientPlatform::Linux => {
                if self.ios.is_some() {
                    return Err(ApiError::new(
                        "invalid_config",
                        "ios resources require platform IPhone or IPad",
                    ));
                }
            }
            ClientPlatform::IPhone | ClientPlatform::IPad => {
                if self.fresh_qr {
                    return Err(ApiError::new(
                        "unsupported",
                        "fresh_qr is unavailable for iPhone/iPad; existing login tickets were not removed",
                    ));
                }
                if self.signing.is_some() {
                    return Err(ApiError::new(
                        "invalid_config",
                        "desktop signing configuration cannot be mixed with iPhone/iPad; use ios.signing raw resources instead",
                    ));
                }
                self.ios.as_ref().ok_or_else(|| ApiError::new(
                    "invalid_config",
                    "platform IPhone/IPad requires ios device, signing, transport and registration resources; automatic mobile token collection and local QR login are unavailable",
                ))?.validate()?;
            }
            ClientPlatform::Windows | ClientPlatform::MacOS => {
                return Err(ApiError::new(
                    "unsupported",
                    "the QQ extension supports platform Linux, IPhone or IPad",
                ));
            }
        }
        Ok(())
    }

    fn profile(&self) -> Result<Profile, ApiError> {
        self.validate()?;
        let mut profile = match self.platform {
            ClientPlatform::Linux => Profile::linux(),
            ClientPlatform::IPhone => Profile::iphone(),
            ClientPlatform::IPad => Profile::ipad(),
            _ => unreachable!(),
        };
        if let Some(qua) = &self.qua {
            profile.qua.clone_from(qua);
        }
        Ok(profile)
    }

    pub async fn client_config(&self, ctx: &Context) -> Result<ClientConfig, ApiError> {
        let profile = self.profile()?;
        let mut config = ClientConfig {
            profile,
            ios_device: None,
            ios_signing: None,
            ios_registration: None,
            ios_transport: None,
            machine_id: self.machine_id.clone(),
            application_uuid: self.application_uuid.clone(),
            uin: self.uin,
            password: (!self.fresh_qr && !self.password.is_empty()).then(|| self.password.clone()),
            randomize_signature_for_testing: self.randomize_signature_for_testing,
            timeout: Duration::from_secs(self.timeout_seconds),
            host: "msfwifi.3g.qq.com".into(),
            port: 8080,
            server_selection: Default::default(),
        };
        if let Some(ios) = &self.ios {
            let resources = ios.load(ctx).await?;
            config.ios_device = Some(ios.device.clone());
            config.ios_signing = Some(resources.signing);
            config.ios_transport = Some(resources.transport);
            config.ios_registration = Some(resources.registration);
        }
        Ok(config)
    }

    pub async fn keystore(&self, ctx: &Context) -> Result<Keystore, ApiError> {
        self.validate()?;
        let (stored, missing) = match ctx.storage().read("data", "keystore.cbor").await {
            Ok(bytes) => (decode::<Keystore>(&bytes)?, false),
            Err(error) if error.code == "not_found" => (Keystore::default(), true),
            Err(error) => return Err(error),
        };
        let mut keystore = if self.fresh_qr && !missing {
            fresh_device_keystore(stored)
        } else if !self.fresh_qr && self.uin != 0 && stored.uin != 0 && self.uin != stored.uin {
            return Err(ApiError::new(
                "account_mismatch",
                if self.platform.is_ios() {
                    "configured UIN differs from stored keystore; select the matching UIN or import the matching keystore through runtime storage; mobile fresh_qr is unavailable"
                } else {
                    "configured UIN differs from stored keystore; use fresh_qr to replace it"
                },
            ));
        } else {
            stored
        };
        let identity_changed = self.platform.is_ios()
            && keystore
                .ensure_ios_identity()
                .map_err(crate::adapter::protocol_error)?;
        if missing || self.fresh_qr || identity_changed {
            ctx.storage()
                .write("data", "keystore.cbor", &atri_core::encode(&keystore)?)
                .await?;
        }
        Ok(keystore)
    }
}

fn fresh_device_keystore(stored: Keystore) -> Keystore {
    // Copy device identity only: no account identifiers, QR state, cookies or login tickets.
    Keystore {
        guid: stored.guid,
        device_name: stored.device_name,
        android_id: stored.android_id,
        qimei: stored.qimei,
        o3_xwid_switch: stored.o3_xwid_switch,
        ios_msf_imei: stored.ios_msf_imei,
        ..Keystore::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mobile_config::{
        MobileCommandPolicyConfig, MobileRegistrationConfig, MobileSigningConfig,
        MobileTransportAccountConfig, MobileTransportConfig,
    };
    use atri_qq_protocol::IosDevice;

    fn mobile(platform: ClientPlatform) -> Config {
        Config {
            platform,
            ios: Some(MobileConfig {
                device: IosDevice {
                    system_version: "18.0".into(),
                    hardware_model: "fixture-device".into(),
                    system_name: "iOS".into(),
                },
                signing: MobileSigningConfig {
                    provenance: "offline adapter configuration test".into(),
                    raw_device_token_file: "ios/token.bin".into(),
                    raw_xwid_file: "ios/xwid.bin".into(),
                    channel_state_file: None,
                    command_policy: MobileCommandPolicyConfig::default(),
                },
                transport: MobileTransportConfig {
                    network_type: 1,
                    effective_flags: [0; 11],
                    account_record_0x80_file: None,
                    carrier_mcc: String::new(),
                    carrier_mnc: String::new(),
                    cf_bundle_version: "fixture-bundle".into(),
                    account: MobileTransportAccountConfig::Uin { account_type: 0 },
                    reserved_file: "ios/reserved.pb".into(),
                    push_service_get_statistics: None,
                },
                registration: MobileRegistrationConfig {
                    initial_file: "ios/initial.pb".into(),
                    reconnect_file: "ios/reconnect.pb".into(),
                },
            }),
            ..Config::default()
        }
    }

    #[test]
    fn empty_qua_override_is_rejected() {
        let mut config = mobile(ClientPlatform::IPad);
        for qua in ["", "  "] {
            config.qua = Some(qua.into());
            assert!(config.profile().is_err());
        }
    }

    #[test]
    fn mixed_platform_resources_are_rejected() {
        let mut config = mobile(ClientPlatform::IPhone);
        config.signing = Some(SigningConfig::default());
        assert_eq!(config.validate().unwrap_err().code, "invalid_config");
        config.signing = None;
        config.platform = ClientPlatform::Linux;
        assert_eq!(config.validate().unwrap_err().code, "invalid_config");
        config.ios = None;
        config.signing = Some(SigningConfig::default());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn unsupported_mobile_login_configuration_is_rejected() {
        let mut config = mobile(ClientPlatform::IPhone);
        config.fresh_qr = true;
        assert_eq!(config.validate().unwrap_err().code, "unsupported");
        config.fresh_qr = false;
        config.ios = None;
        assert_eq!(config.validate().unwrap_err().code, "invalid_config");
    }

    #[test]
    fn fresh_desktop_login_preserves_device_identity_only() {
        let stored = Keystore {
            uin: 123,
            ios_msf_imei: "existing-sdk-identity".into(),
            ..Keystore::default()
        };
        let guid = stored.guid.clone();
        let reset = fresh_device_keystore(stored);
        assert_eq!(reset.guid, guid);
        assert_eq!(reset.ios_msf_imei, "existing-sdk-identity");
        assert_eq!(reset.uin, 0);
    }
}
