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
#[serde(default, deny_unknown_fields)]
pub(crate) struct Config {
    pub uin: u64,
    #[serde(flatten)]
    pub platform: PlatformConfig,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qua: Option<String>,
    pub fresh_qr: bool,
    pub randomize_signature_for_testing: bool,
    pub timeout_seconds: u64,
}

#[derive(Clone, Serialize)]
#[serde(tag = "platform")]
pub(crate) enum PlatformConfig {
    Linux(LinuxConfig),
    IPhone { ios: MobileConfig },
    IPad { ios: MobileConfig },
}

impl<'de> Deserialize<'de> for PlatformConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Input {
            #[serde(default)]
            platform: ClientPlatform,
            #[serde(default, deserialize_with = "present")]
            machine_id: Option<String>,
            #[serde(default, deserialize_with = "present")]
            application_uuid: Option<String>,
            #[serde(default, deserialize_with = "present")]
            signing: Option<SigningConfig>,
            #[serde(default, deserialize_with = "present")]
            ios: Option<MobileConfig>,
        }

        fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
        where
            D: serde::Deserializer<'de>,
            T: Deserialize<'de>,
        {
            T::deserialize(deserializer).map(Some)
        }

        let input = Input::deserialize(deserializer)?;
        match input.platform {
            ClientPlatform::Linux => {
                if input.ios.is_some() {
                    return Err(serde::de::Error::custom(
                        "ios resources require platform IPhone or IPad",
                    ));
                }
                Ok(Self::Linux(LinuxConfig {
                    machine_id: input.machine_id.unwrap_or_default(),
                    application_uuid: input.application_uuid.unwrap_or_default(),
                    signing: input.signing,
                }))
            }
            ClientPlatform::IPhone | ClientPlatform::IPad => {
                if input.machine_id.is_some()
                    || input.application_uuid.is_some()
                    || input.signing.is_some()
                {
                    return Err(serde::de::Error::custom(
                        "machine_id, application_uuid and desktop signing belong only to platform Linux; iPhone/iPad requires ios resources",
                    ));
                }
                let ios = input.ios.ok_or_else(|| serde::de::Error::custom(
                    "platform IPhone/IPad requires ios.mode = virtual or snapshot; local QR login is unavailable",
                ))?;
                Ok(match input.platform {
                    ClientPlatform::IPhone => Self::IPhone { ios },
                    ClientPlatform::IPad => Self::IPad { ios },
                    _ => unreachable!(),
                })
            }
            ClientPlatform::Windows | ClientPlatform::MacOS => Err(serde::de::Error::custom(
                "the QQ extension supports platform Linux, IPhone or IPad",
            )),
        }
    }
}

impl Default for PlatformConfig {
    fn default() -> Self {
        Self::Linux(LinuxConfig::default())
    }
}

impl PlatformConfig {
    fn client_platform(&self) -> ClientPlatform {
        match self {
            Self::Linux(_) => ClientPlatform::Linux,
            Self::IPhone { .. } => ClientPlatform::IPhone,
            Self::IPad { .. } => ClientPlatform::IPad,
        }
    }

    fn ios(&self) -> Option<&MobileConfig> {
        match self {
            Self::Linux(_) => None,
            Self::IPhone { ios } | Self::IPad { ios } => Some(ios),
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct LinuxConfig {
    pub machine_id: String,
    pub application_uuid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing: Option<SigningConfig>,
}

impl LinuxConfig {
    fn ensure_identity(&mut self) -> Result<bool, ApiError> {
        let mut changed = false;
        if self.machine_id.is_empty() {
            let mut bytes = [0u8; 16];
            rand::rngs::SysRng
                .try_fill_bytes(&mut bytes)
                .map_err(ApiError::internal)?;
            self.machine_id = String::with_capacity(32);
            for byte in bytes {
                write!(&mut self.machine_id, "{byte:02x}").expect("writing to String cannot fail");
            }
            changed = true;
        }
        if self.application_uuid.is_empty() {
            self.application_uuid = atri_qq_protocol::o3::generate_application_uuid();
            changed = true;
        }
        Ok(changed)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            uin: 0,
            platform: PlatformConfig::default(),
            password: String::new(),
            qua: None,
            fresh_qr: false,
            randomize_signature_for_testing: false,
            timeout_seconds: 30,
        }
    }
}

impl Config {
    pub async fn load(ctx: &Context) -> Result<Self, ApiError> {
        let mut config: Self = ctx.config().load_or_create(&Self::default()).await?;
        config.validate()?;
        let changed = match &mut config.platform {
            PlatformConfig::Linux(linux) => linux.ensure_identity()?,
            PlatformConfig::IPhone { .. } | PlatformConfig::IPad { .. } => false,
        };
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
        if let Some(ios) = self.platform.ios() {
            if self.fresh_qr {
                return Err(ApiError::new(
                    "unsupported",
                    "fresh_qr is unavailable for iPhone/iPad; existing login tickets were not removed",
                ));
            }
            ios.validate(self.platform.client_platform())?;
        }
        Ok(())
    }

    fn profile(&self) -> Result<Profile, ApiError> {
        self.validate()?;
        let mut profile = match self.platform {
            PlatformConfig::Linux(_) => Profile::linux(),
            PlatformConfig::IPhone { .. } => Profile::iphone(),
            PlatformConfig::IPad { .. } => Profile::ipad(),
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
            platform: match &self.platform {
                PlatformConfig::Linux(linux) => Some(atri_qq_protocol::PlatformConfig::Linux(
                    atri_qq_protocol::LinuxConfig {
                        machine_id: linux.machine_id.clone(),
                        application_uuid: linux.application_uuid.clone(),
                    },
                )),
                PlatformConfig::IPhone { .. } | PlatformConfig::IPad { .. } => None,
            },
            uin: self.uin,
            password: (!self.fresh_qr && !self.password.is_empty()).then(|| self.password.clone()),
            randomize_signature_for_testing: self.randomize_signature_for_testing,
            timeout: Duration::from_secs(self.timeout_seconds),
            host: "msfwifi.3g.qq.com".into(),
            port: 8080,
            server_selection: Default::default(),
        };
        if let Some(ios) = self.platform.ios() {
            ios.apply(ctx, &mut config).await?;
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
                if self.platform.client_platform().is_ios() {
                    "configured UIN differs from stored keystore; select the matching UIN or import the matching keystore through runtime storage; mobile fresh_qr is unavailable"
                } else {
                    "configured UIN differs from stored keystore; use fresh_qr to replace it"
                },
            ));
        } else {
            stored
        };
        let identity_changed = self.platform.client_platform().is_ios()
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
        MobileSnapshotConfig, MobileTransportAccountConfig, MobileTransportConfig,
    };
    use atri_core::{Value, from_value, to_value};
    use atri_qq_protocol::IosDevice;

    fn mobile(platform: ClientPlatform) -> Config {
        let ios = MobileConfig::Snapshot(MobileSnapshotConfig {
            heartbeat: Default::default(),
            device: IosDevice {
                system_version: "18.0".into(),
                hardware_model: "fixture-device".into(),
                system_name: "iOS".into(),
            },
            signing: MobileSigningConfig {
                provenance: "offline adapter configuration test".into(),
                raw_device_token_file: "ios/token.bin".into(),
                raw_device_token_expires_at: 0,
                raw_device_token_uin: String::new(),
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
        });
        Config {
            platform: match platform {
                ClientPlatform::IPhone => PlatformConfig::IPhone { ios },
                ClientPlatform::IPad => PlatformConfig::IPad { ios },
                _ => panic!("mobile fixture requires an iOS platform"),
            },
            ..Config::default()
        }
    }

    fn fields(config: &Config) -> Vec<(Value, Value)> {
        let Value::Map(fields) = to_value(config).unwrap() else {
            panic!("configuration must serialize as a map")
        };
        fields
    }

    fn field<'a>(fields: &'a [(Value, Value)], name: &str) -> Option<&'a Value> {
        fields
            .iter()
            .find_map(|(key, value)| (key == &Value::Text(name.into())).then_some(value))
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
        for platform in [ClientPlatform::IPhone, ClientPlatform::IPad] {
            for (name, resource) in [
                ("machine_id", Value::Text("desktop-machine".into())),
                (
                    "application_uuid",
                    Value::Text("desktop-application".into()),
                ),
                ("signing", to_value(&SigningConfig::default()).unwrap()),
            ] {
                let mut fields = fields(&mobile(platform));
                fields.push((Value::Text(name.into()), resource));
                let error = from_value::<Config>(&Value::Map(fields)).err().unwrap();
                assert!(error.message.contains(name), "{}", error.message);
            }
        }
        let mobile_fields = fields(&mobile(ClientPlatform::IPhone));
        let mut linux_fields = fields(&Config::default());
        linux_fields.push((
            Value::Text("ios".into()),
            field(&mobile_fields, "ios").unwrap().clone(),
        ));
        let error = from_value::<Config>(&Value::Map(linux_fields))
            .err()
            .unwrap();
        assert!(error.message.contains("ios"), "{}", error.message);
    }

    #[test]
    fn unsupported_mobile_login_configuration_is_rejected() {
        let mut config = mobile(ClientPlatform::IPhone);
        config.fresh_qr = true;
        assert_eq!(config.validate().unwrap_err().code, "unsupported");
        let mut fields = fields(&mobile(ClientPlatform::IPhone));
        fields.retain(|(key, _)| key != &Value::Text("ios".into()));
        let error = from_value::<Config>(&Value::Map(fields)).err().unwrap();
        assert!(error.message.contains("ios"), "{}", error.message);
    }

    #[test]
    fn platform_configuration_round_trips_without_cross_platform_fields() {
        for platform in [ClientPlatform::IPhone, ClientPlatform::IPad] {
            let config = mobile(platform);
            let fields = fields(&config);
            for name in ["machine_id", "application_uuid", "signing"] {
                assert!(field(&fields, name).is_none());
            }
            assert!(field(&fields, "ios").is_some());
            let decoded: Config = from_value(&Value::Map(fields)).unwrap();
            assert_eq!(decoded.platform.client_platform(), platform);
            assert!(decoded.validate().is_ok());
        }
        let fields = fields(&Config::default());
        assert!(field(&fields, "ios").is_none());
        assert_eq!(
            field(&fields, "platform"),
            Some(&Value::Text("Linux".into()))
        );
        let decoded: Config = from_value(&Value::Map(fields)).unwrap();
        assert!(matches!(decoded.platform, PlatformConfig::Linux(_)));
    }

    #[test]
    fn linux_identity_initialization_preserves_existing_bytes() {
        let mut linux = LinuxConfig {
            machine_id: "MiXeD-existing-identity".into(),
            application_uuid: "existing-application-uuid".into(),
            signing: None,
        };
        assert!(!linux.ensure_identity().unwrap());
        assert_eq!(linux.machine_id, "MiXeD-existing-identity");
        assert_eq!(linux.application_uuid, "existing-application-uuid");
        let mut linux = LinuxConfig::default();
        assert!(linux.ensure_identity().unwrap());
        assert_eq!(linux.machine_id.len(), 32);
        assert!(!linux.application_uuid.is_empty());
        assert!(!linux.ensure_identity().unwrap());
        linux.machine_id.clear();
        assert!(linux.ensure_identity().unwrap());
        let machine_id = linux.machine_id.clone();
        linux.application_uuid.clear();
        assert!(linux.ensure_identity().unwrap());
        assert_eq!(linux.machine_id, machine_id);
        assert!(!linux.ensure_identity().unwrap());
    }

    #[test]
    fn virtual_mobile_configuration_needs_no_desktop_resources() {
        for platform in ["IPhone", "IPad"] {
            let value = Value::Map(vec![
                (Value::Text("platform".into()), Value::Text(platform.into())),
                (
                    Value::Text("ios".into()),
                    Value::Map(vec![(
                        Value::Text("mode".into()),
                        Value::Text("virtual".into()),
                    )]),
                ),
            ]);
            let config: Config = from_value(&value).unwrap();
            assert!(config.validate().is_ok());
            assert!(matches!(
                config.platform.ios(),
                Some(MobileConfig::Virtual { .. })
            ));
            let fields = fields(&config);
            for name in ["machine_id", "application_uuid", "signing"] {
                assert!(field(&fields, name).is_none());
            }
        }
    }

    #[test]
    fn mobile_snapshot_requires_each_resource_group() {
        for name in ["device", "signing", "transport", "registration"] {
            let mut fields = fields(&mobile(ClientPlatform::IPad));
            let (_, Value::Map(ios)) = fields
                .iter_mut()
                .find(|(key, _)| key == &Value::Text("ios".into()))
                .unwrap()
            else {
                panic!("snapshot must serialize its ios table")
            };
            ios.retain(|(key, _)| key != &Value::Text(name.into()));
            let error = from_value::<Config>(&Value::Map(fields)).err().unwrap();
            assert!(error.message.contains(name), "{}", error.message);
        }
    }

    #[test]
    fn missing_platform_keeps_existing_minimal_linux_configuration() {
        let value = Value::Map(vec![
            (Value::Text("uin".into()), Value::Integer(123.into())),
            (
                Value::Text("machine_id".into()),
                Value::Text("saved-machine".into()),
            ),
            (
                Value::Text("application_uuid".into()),
                Value::Text("saved-application".into()),
            ),
        ]);
        let config: Config = from_value(&value).unwrap();
        let PlatformConfig::Linux(mut linux) = config.platform else {
            panic!("missing platform must retain the Linux default")
        };
        assert!(!linux.ensure_identity().unwrap());
        assert_eq!(linux.machine_id, "saved-machine");
        assert_eq!(linux.application_uuid, "saved-application");
        let config: Config = from_value(&Value::Map(vec![(
            Value::Text("uin".into()),
            Value::Integer(123.into()),
        )]))
        .unwrap();
        assert!(matches!(config.platform, PlatformConfig::Linux(_)));
    }

    #[test]
    fn unknown_platform_and_resource_fields_are_rejected() {
        for platform in ["Windows", "MacOS", "iphone", "unknown"] {
            let value = Value::Map(vec![(
                Value::Text("platform".into()),
                Value::Text(platform.into()),
            )]);
            assert!(from_value::<Config>(&value).is_err());
        }
        for config in [
            Config::default(),
            mobile(ClientPlatform::IPhone),
            mobile(ClientPlatform::IPad),
        ] {
            let mut fields = fields(&config);
            fields.push((
                Value::Text("unknown_resource".into()),
                Value::Text("invalid".into()),
            ));
            let error = from_value::<Config>(&Value::Map(fields)).err().unwrap();
            assert!(
                error.message.contains("unknown_resource"),
                "{}",
                error.message
            );
        }
        let mobile_fields = fields(&mobile(ClientPlatform::IPad));
        let mut fields = fields(&Config::default());
        fields.retain(|(key, _)| key != &Value::Text("platform".into()));
        fields.push((
            Value::Text("ios".into()),
            field(&mobile_fields, "ios").unwrap().clone(),
        ));
        assert!(from_value::<Config>(&Value::Map(fields)).is_err());
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
