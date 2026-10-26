use atri_core::{ApiError, decode};
use atri_extensions::Context;
use atri_qq_api::signing::SigningConfig;
use atri_qq_protocol::{ClientConfig, Keystore, Profile};
use rand::TryRng;
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use std::time::Duration;

pub const LINUX_QUA: &str = "V1_LNX_NQ_3.2.34_53644_GW_B";

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub uin: u64,
    pub password: String,
    pub machine_id: String,
    pub qua: String,
    pub fresh_qr: bool,
    pub randomize_signature_for_testing: bool,
    pub timeout_seconds: u64,
    pub signing: SigningConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            uin: 0,
            password: String::new(),
            machine_id: String::new(),
            qua: LINUX_QUA.into(),
            fresh_qr: false,
            randomize_signature_for_testing: false,
            timeout_seconds: 30,
            signing: SigningConfig::default(),
        }
    }
}

impl Config {
    pub async fn load(ctx: &Context) -> Result<Self, ApiError> {
        let mut config: Self = ctx.config().load_or_create(&Self::default()).await?;
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
            ctx.config().save(&config).await?;
        }
        if config.qua.is_empty() || config.timeout_seconds == 0 {
            return Err(ApiError::new(
                "invalid_config",
                "qua and a nonzero timeout_seconds are required",
            ));
        }
        Ok(config)
    }

    pub fn client_config(&self) -> ClientConfig {
        let mut profile = Profile::linux();
        profile.qua.clone_from(&self.qua);
        ClientConfig {
            profile,
            machine_id: self.machine_id.clone(),
            uin: self.uin,
            password: (!self.fresh_qr && !self.password.is_empty()).then(|| self.password.clone()),
            randomize_signature_for_testing: self.randomize_signature_for_testing,
            timeout: Duration::from_secs(self.timeout_seconds),
            host: "msfwifi.3g.qq.com".into(),
            port: 8080,
            server_selection: Default::default(),
        }
    }

    pub async fn keystore(&self, ctx: &Context) -> Result<Keystore, ApiError> {
        let (stored, missing) = match ctx.storage().read("data", "keystore.cbor").await {
            Ok(bytes) => (decode::<Keystore>(&bytes)?, false),
            Err(error) if error.code == "not_found" => (Keystore::default(), true),
            Err(error) => return Err(error),
        };
        let keystore = if self.fresh_qr && !missing {
            fresh_device_keystore(stored)
        } else if !self.fresh_qr && self.uin != 0 && stored.uin != 0 && self.uin != stored.uin {
            return Err(ApiError::new(
                "account_mismatch",
                "configured UIN differs from stored keystore; use fresh_qr to replace it",
            ));
        } else {
            stored
        };
        if missing || self.fresh_qr {
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
        ..Keystore::default()
    }
}
