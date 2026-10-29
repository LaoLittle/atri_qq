use crate::{
    Error, Result, crypto,
    models::{ClientPlatform, IosDevice, Keystore, Profile},
    signing::IosSigningResources,
};
use ::signing::ios::{
    command_policy::CommandPolicy,
    fingerprint,
    token::TokenRecord,
    xwid::{self, ResourceSample},
};
use bytes::Bytes;
use md5::{Digest, Md5};
use rand::{
    Rng, RngExt, SeedableRng,
    rngs::{StdRng, SysRng},
};
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Instant,
};
use uuid::Uuid;

mod application;
pub(crate) mod guild;
pub(crate) mod network;
pub(crate) mod registration;
pub use application::{IosVirtualApplication, IosVirtualBatteryState};
pub use network::{IosIpStack, IosNetworkLimits, IosVirtualNetwork, IosVirtualNetworkKind};

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IosVirtualConfig {
    pub identity: Option<IosDevice>,
    pub device_name: Option<String>,
    pub product_build_version: String,
    pub kernel_release: Option<String>,
    pub kernel_version: Option<String>,
    pub hardware: Option<IosVirtualHardware>,
    pub screen_width_points: Option<f64>,
    pub screen_height_points: Option<f64>,
    pub bundle_version: String,
    pub bundle_display_name: String,
    pub process_name: String,
    pub locale: IosVirtualLocale,
    pub carrier: Option<IosVirtualCarrier>,
    pub filesystem_size_bytes: u64,
    pub core_services_attributes: Option<String>,
    pub resource_inodes: Vec<IosVirtualInode>,
    pub advertising_id: Option<Uuid>,
    pub application: IosVirtualApplication,
    pub network: IosVirtualNetwork,
}

impl Default for IosVirtualConfig {
    fn default() -> Self {
        Self {
            identity: None,
            device_name: None,
            product_build_version: "22A3354".into(),
            kernel_release: Some("24.0.0".into()),
            kernel_version: None,
            hardware: None,
            screen_width_points: None,
            screen_height_points: None,
            bundle_version: "1".into(),
            bundle_display_name: "QQ".into(),
            process_name: "QQ".into(),
            locale: IosVirtualLocale::default(),
            carrier: None,
            filesystem_size_bytes: 128 * 1024 * 1024 * 1024,
            core_services_attributes: None,
            resource_inodes: Vec::new(),
            advertising_id: None,
            application: IosVirtualApplication::default(),
            network: IosVirtualNetwork::default(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct IosVirtualInode {
    pub index: u8,
    pub inode: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IosVirtualHardware {
    pub board_model: String,
    pub processor_count: u32,
    pub active_processor_count: u32,
    pub memory_bytes: u64,
    pub cpu_frequency: Option<u64>,
    pub bus_frequency: Option<u64>,
    pub cpu_type: i32,
    pub cpu_subtype: i32,
    pub byte_order: u32,
    pub page_size: u32,
    pub cache_line_size: Option<u64>,
    pub l1_instruction_cache_size: Option<u64>,
    pub l1_data_cache_size: Option<u64>,
    pub l2_cache_size: Option<u64>,
}

impl Default for IosVirtualHardware {
    fn default() -> Self {
        Self {
            board_model: "D54AP".into(),
            processor_count: 6,
            active_processor_count: 6,
            memory_bytes: 6 * 1024 * 1024 * 1024,
            cpu_frequency: None,
            bus_frequency: None,
            cpu_type: 0x100000c,
            cpu_subtype: 2,
            byte_order: 1234,
            page_size: 16384,
            cache_line_size: Some(128),
            l1_instruction_cache_size: None,
            l1_data_cache_size: None,
            l2_cache_size: None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IosVirtualLocale {
    pub country_code: String,
    pub identifier: String,
    pub preferred_language: String,
    pub timezone_name: String,
}

impl Default for IosVirtualLocale {
    fn default() -> Self {
        Self {
            country_code: "CN".into(),
            identifier: "zh_CN".into(),
            preferred_language: "zh-Hans-CN".into(),
            timezone_name: "Asia/Shanghai".into(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct IosVirtualCarrier {
    pub country_code: String,
    pub mobile_country_code: String,
    pub mobile_network_code: String,
    pub name: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IosVirtualState {
    pub hardware_model: String,
    pub collector_uuid: Uuid,
    pub vendor_uuid: Uuid,
    pub home_uuid: Uuid,
    pub bundle_uuid: Uuid,
    pub runtime_id: String,
    pub installed_unix_micros: u64,
    pub boot_unix_micros: u64,
    pub filesystem_created_unix_micros: u64,
    pub private_var_inode: u64,
    pub mobile_preferences_inode: u64,
    pub xwid_candidate: String,
    #[serde(default)]
    pub connection_sequence: Option<u32>,
    #[serde(default)]
    pub guild_sync: BTreeMap<u64, crate::ios_device::guild::IosGuildSyncState>,
    #[serde(default)]
    pub registered_accounts: BTreeSet<u64>,
    pub token: TokenRecord,
}

pub(crate) struct IosVirtualRuntime {
    config: Arc<IosVirtualConfig>,
    platform: ClientPlatform,
    properties: BTreeMap<i32, Bytes>,
    sample: ResourceSample,
    random: StdRng,
    fingerprint: [u8; 32],
    raw_xwid: Bytes,
    started: Instant,
    background_since: Option<u64>,
}

impl IosVirtualConfig {
    pub fn device(&self, profile: &Profile) -> Result<IosDevice> {
        if !profile.platform.is_ios() {
            return Err(Error::Malformed(
                "An explicit iOS virtual device requires an iPhone or iPad profile".into(),
            ));
        }
        let device = self.identity.clone().unwrap_or_else(|| IosDevice {
            system_version: "18.0".into(),
            hardware_model: if profile.platform == ClientPlatform::IPad {
                "iPad14,5"
            } else {
                "iPhone13,4"
            }
            .into(),
            system_name: "iOS".into(),
        });
        device.validate()?;
        Ok(device)
    }

    fn hardware(&self, platform: ClientPlatform) -> Cow<'_, IosVirtualHardware> {
        if let Some(hardware) = &self.hardware {
            return Cow::Borrowed(hardware);
        }
        Cow::Owned({
            if platform == ClientPlatform::IPad {
                IosVirtualHardware {
                    board_model: "J620AP".into(),
                    processor_count: 8,
                    active_processor_count: 8,
                    memory_bytes: 8 * 1024 * 1024 * 1024,
                    ..IosVirtualHardware::default()
                }
            } else {
                IosVirtualHardware::default()
            }
        })
    }

    pub(crate) fn registration_locale(&self) -> u32 {
        if self.locale.identifier == "zh_CN" {
            2052
        } else {
            1033
        }
    }

    pub(crate) fn device_name(&self, platform: ClientPlatform) -> &str {
        self.device_name
            .as_deref()
            .unwrap_or(if platform == ClientPlatform::IPad {
                "iPad"
            } else {
                "iPhone"
            })
    }
}

impl IosVirtualState {
    pub(crate) fn confirm_registration(&mut self, uin: u64) -> bool {
        self.registered_accounts.insert(uin)
    }
}

impl IosVirtualRuntime {
    pub(crate) fn initialize(
        config: Arc<IosVirtualConfig>,
        profile: &Profile,
        keystore: &mut Keystore,
        now_micros: u64,
    ) -> Result<(Self, IosDevice)> {
        let device = config.device(profile)?;
        let hardware = config.hardware(profile.platform);
        if now_micros > u64::MAX / 1000 {
            return Err(Error::Malformed(
                "Virtual iOS filesystem time is out of range".into(),
            ));
        }
        let mut inodes = [None; 26];
        for resource in &config.resource_inodes {
            let slot = inodes.get_mut(usize::from(resource.index)).ok_or_else(|| {
                Error::Malformed("Virtual iOS resource inode index must be 0..25".into())
            })?;
            if slot.replace(resource.inode).is_some() {
                return Err(Error::Malformed(
                    "Virtual iOS resource inode index is duplicated".into(),
                ));
            }
        }
        let sample = ResourceSample::from_inodes(&inodes);
        if let Some(state) = &keystore.ios_virtual_state {
            if state.hardware_model != device.hardware_model {
                return Err(Error::Malformed("The saved iOS virtual device belongs to another hardware model; use a separate keystore".into()));
            }
            if state.installed_unix_micros > u64::MAX / 1000
                || state.filesystem_created_unix_micros > u64::MAX / 1000
            {
                return Err(Error::Malformed(
                    "Saved iOS virtual filesystem time is out of range".into(),
                ));
            }
        }
        let (default_width, default_height) = if profile.platform == ClientPlatform::IPad {
            (1024.0, 1366.0)
        } else {
            (428.0, 926.0)
        };
        let width = config.screen_width_points.unwrap_or(default_width);
        let height = config.screen_height_points.unwrap_or(default_height);
        if !width.is_finite() || width < 0.0 || !height.is_finite() || height < 0.0 {
            return Err(Error::Malformed(
                "Virtual iOS screen bounds must be finite nonnegative point values".into(),
            ));
        }
        if hardware.processor_count == 0
            || hardware.active_processor_count > hardware.processor_count
        {
            return Err(Error::Malformed(
                "Virtual iOS active processor count exceeds available processors".into(),
            ));
        }
        let mut random = StdRng::try_from_rng(&mut SysRng)
            .map_err(|error| Error::Crypto(format!("iOS virtual device entropy: {error}")))?;
        if keystore.ios_virtual_state.is_none() {
            let mut uuid = || {
                let mut bytes = [0; 16];
                random.fill_bytes(&mut bytes);
                uuid::Builder::from_random_bytes(bytes).into_uuid()
            };
            let collector_uuid = uuid();
            let vendor_uuid = uuid();
            let home_uuid = uuid();
            let bundle_uuid = uuid();
            let words: [u64; 4] = std::array::from_fn(|_| random.random());
            let runtime_id = format!(
                "{:016x}-{:016x}-{:016x}-{:016x}",
                words[0], words[1], words[2], words[3]
            );
            keystore.ios_virtual_state = Some(IosVirtualState {
                hardware_model: device.hardware_model.clone(),
                collector_uuid,
                vendor_uuid,
                home_uuid,
                bundle_uuid,
                runtime_id,
                installed_unix_micros: now_micros,
                boot_unix_micros: now_micros,
                filesystem_created_unix_micros: now_micros,
                private_var_inode: random.random::<u64>() & i64::MAX as u64,
                mobile_preferences_inode: random.random::<u64>() & i64::MAX as u64,
                xwid_candidate: String::new(),
                connection_sequence: Some((now_micros / 1_000_000) as u32),
                token: TokenRecord::default(),
                guild_sync: BTreeMap::new(),
                registered_accounts: BTreeSet::new(),
            });
        }
        let state = keystore
            .ios_virtual_state
            .as_mut()
            .expect("initialized virtual device");
        if !state.xwid_candidate.is_ascii()
            || xwid::validate_candidate(&state.xwid_candidate).is_err()
        {
            let fallback = ResourceSample::random_source(&mut random);
            state.xwid_candidate = String::from_utf8(sample.candidate(&fallback).to_vec())
                .expect("ASCII virtual candidate");
        }
        let mut random5 = [0; 5];
        random.fill_bytes(&mut random5);
        let raw_xwid = Bytes::copy_from_slice(&xwid::secure_material(
            state
                .xwid_candidate
                .as_bytes()
                .first_chunk::<36>()
                .expect("validated candidate"),
            now_micros / 1_000_000,
            &random5,
        ));
        let mut properties = BTreeMap::new();
        let pid = std::process::id() as i32;
        let name = config.device_name(profile.platform);
        let model = if profile.platform == ClientPlatform::IPad {
            "iPad"
        } else {
            "iPhone"
        };
        let home_component = format!("{:X}", state.home_uuid.hyphenated());
        let bundle = format!(
            "/private/var/containers/Bundle/Application/{:X}/QQ.app/Info.plist",
            state.bundle_uuid.hyphenated()
        );
        put(&mut properties, 0, b"2".as_slice());
        put(
            &mut properties,
            1,
            format!("{:X}", state.collector_uuid.hyphenated()),
        );
        put(
            &mut properties,
            2,
            config
                .advertising_id
                .map(|value| format!("{:X}", value.hyphenated()))
                .unwrap_or_default(),
        );
        put(
            &mut properties,
            3,
            format!("{:X}", state.vendor_uuid.hyphenated()),
        );
        for id in [4, 5, 67] {
            put(&mut properties, id, Bytes::new());
        }
        for (id, text) in [
            (6, Some("Darwin")),
            (7, Some(name)),
            (8, config.kernel_release.as_deref()),
            (9, config.kernel_version.as_deref()),
            (10, Some(device.hardware_model.as_str())),
        ] {
            put(
                &mut properties,
                id,
                md5_text(text.unwrap_or_default().as_bytes()),
            );
        }
        number(&mut properties, 11, width);
        number(&mut properties, 12, height);
        number(&mut properties, 13, state.boot_unix_micros / 1_000_000);
        number(
            &mut properties,
            14,
            state.installed_unix_micros as f64 / 1_000_000.0,
        );
        put(&mut properties, 15, profile.version.clone());
        put(&mut properties, 16, config.bundle_version.clone());
        put(
            &mut properties,
            17,
            md5_text(
                config
                    .core_services_attributes
                    .as_deref()
                    .unwrap_or_default()
                    .as_bytes(),
            ),
        );
        put(&mut properties, 18, config.product_build_version.clone());
        number(&mut properties, 19, pid);
        put(&mut properties, 20, home_component.clone());
        put(&mut properties, 21, config.bundle_display_name.clone());
        put(
            &mut properties,
            22,
            md5_text((if pid > 0 { pid } else { -1 }).to_string().as_bytes()),
        );
        put(
            &mut properties,
            23,
            md5_text(&md5_text(home_component.as_bytes())),
        );
        put(
            &mut properties,
            24,
            md5_text(config.process_name.as_bytes()),
        );
        number(&mut properties, 25, hardware.processor_count);
        number(&mut properties, 26, hardware.active_processor_count);
        number(&mut properties, 27, hardware.memory_bytes);
        put(&mut properties, 29, md5_text(name.as_bytes()));
        put(&mut properties, 30, model);
        put(&mut properties, 31, device.system_name.clone());
        put(&mut properties, 32, device.system_version.clone());
        number(
            &mut properties,
            33,
            u8::from(profile.platform == ClientPlatform::IPad),
        );
        put(&mut properties, 34, b"1".as_slice());
        put(&mut properties, 38, config.locale.country_code.clone());
        for (id, text) in [
            (
                39,
                config
                    .carrier
                    .as_ref()
                    .map(|value| value.country_code.as_str()),
            ),
            (
                40,
                config
                    .carrier
                    .as_ref()
                    .map(|value| value.mobile_country_code.as_str()),
            ),
            (
                41,
                config
                    .carrier
                    .as_ref()
                    .map(|value| value.mobile_network_code.as_str()),
            ),
        ] {
            put(&mut properties, id, text.unwrap_or_default().to_owned());
        }
        put(
            &mut properties,
            42,
            md5_text(
                config
                    .carrier
                    .as_ref()
                    .map(|value| value.name.as_str())
                    .unwrap_or_default()
                    .as_bytes(),
            ),
        );
        put(&mut properties, 43, config.locale.identifier.clone());
        put(
            &mut properties,
            44,
            config.locale.preferred_language.clone(),
        );
        put(&mut properties, 45, config.locale.timezone_name.clone());
        number(&mut properties, 46, config.filesystem_size_bytes);
        put(
            &mut properties,
            47,
            md5_text(hardware.memory_bytes.to_string().as_bytes()),
        );
        number(&mut properties, 48, hardware.processor_count);
        optional_number(&mut properties, 51, hardware.cpu_frequency);
        optional_number(&mut properties, 52, hardware.bus_frequency);
        number(&mut properties, 53, hardware.cpu_type);
        number(&mut properties, 54, hardware.cpu_subtype);
        number(&mut properties, 55, hardware.byte_order);
        number(&mut properties, 56, hardware.page_size);
        optional_number(&mut properties, 57, hardware.cache_line_size);
        put(
            &mut properties,
            58,
            md5_text(device.hardware_model.as_bytes()),
        );
        put(&mut properties, 61, hex::encode_upper(&keystore.guid));
        number(&mut properties, 62, state.boot_unix_micros);
        for id in [63, 64, 65] {
            number(
                &mut properties,
                id,
                state.filesystem_created_unix_micros * 1000,
            );
        }
        put(&mut properties, 66, device.hardware_model.clone());
        put(&mut properties, 68, state.runtime_id.clone());
        put(
            &mut properties,
            69,
            hex::encode(crypto::sha256(bundle.as_bytes())),
        );
        put(&mut properties, 71, Bytes::from_static(b"[]"));
        let var_stat = virtual_stat(
            state.private_var_inode,
            state.filesystem_created_unix_micros,
        );
        let preferences_stat =
            virtual_stat(state.mobile_preferences_inode, state.installed_unix_micros);
        let mut machine = device.hardware_model.as_bytes().to_vec();
        machine.push(0);
        let mut board = hardware.board_model.as_bytes().to_vec();
        board.push(0);
        let cache_line = hardware.cache_line_size.map(u64::to_le_bytes);
        let l1i = hardware.l1_instruction_cache_size.map(u64::to_le_bytes);
        let l1d = hardware.l1_data_cache_size.map(u64::to_le_bytes);
        let l2 = hardware.l2_cache_size.map(u64::to_le_bytes);
        let cpus = hardware.processor_count.to_le_bytes();
        let frequency = hardware.cpu_frequency.map(u64::to_le_bytes);
        let memory = hardware.memory_bytes.to_le_bytes();
        let fingerprint = fingerprint::Resources {
            machine: Some(&machine),
            model: Some(&board),
            cache_line_size: cache_line.as_ref().map(|value| value.as_slice()),
            l1_instruction_cache_size: l1i.as_ref().map(|value| value.as_slice()),
            l1_data_cache_size: l1d.as_ref().map(|value| value.as_slice()),
            l2_cache_size: l2.as_ref().map(|value| value.as_slice()),
            cpu_count: Some(&cpus),
            cpu_frequency: frequency.as_ref().map(|value| value.as_slice()),
            memory_size: Some(&memory),
            private_var_stat: Some(&var_stat),
            mobile_preferences_stat: Some(&preferences_stat),
        }
        .digest();
        drop(hardware);
        let background_since = (!config.application.foreground).then_some(now_micros / 1_000_000);
        Ok((
            Self {
                config,
                platform: profile.platform,
                properties,
                sample,
                random,
                fingerprint,
                raw_xwid,
                started: Instant::now(),
                background_since,
            },
            device,
        ))
    }

    pub(crate) fn background_since(&self) -> Option<u64> {
        self.background_since
    }

    pub(crate) fn signing_resources(&self, state: &IosVirtualState) -> IosSigningResources {
        IosSigningResources {
            provenance: "explicit-virtual-ios-device".into(),
            raw_device_token: state.token.token.clone(),
            raw_device_token_expires_at: state.token.expires_at,
            raw_device_token_uin: state.token.associated_uin.clone(),
            raw_xwid: self.raw_xwid.clone(),
            channel_state: None,
            command_policy: CommandPolicy::default(),
        }
    }

    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    pub(crate) fn update_logged_accounts(&mut self, accounts: &[&str]) {
        let capacity = 2
            + accounts.iter().map(|value| value.len()).sum::<usize>()
            + accounts.len().saturating_sub(1);
        let mut value = String::with_capacity(capacity);
        value.push('[');
        let mut first = true;
        for account in accounts.iter().filter(|account| !account.is_empty()) {
            if !first {
                value.push(',');
            }
            first = false;
            value.push_str(account.split('\0').next().unwrap());
        }
        value.push(']');
        put(&mut self.properties, 71, value);
    }

    pub(crate) fn collect(
        &mut self,
        state: &IosVirtualState,
        now_micros: u64,
        policy: &CommandPolicy,
    ) -> &BTreeMap<i32, Bytes> {
        number(
            &mut self.properties,
            28,
            now_micros.saturating_sub(state.boot_unix_micros) as f64 / 1_000_000.0,
        );
        number(
            &mut self.properties,
            82,
            self.started.elapsed().as_secs_f64(),
        );
        if policy.switch(6) == 1 {
            let mut random5 = [0; 5];
            self.random.fill_bytes(&mut random5);
            put(
                &mut self.properties,
                60,
                Bytes::copy_from_slice(&self.sample.secure(now_micros / 1_000_000, &random5)),
            );
        } else {
            put(&mut self.properties, 60, Bytes::new());
        }
        if policy.switch(54) != 0 {
            let mut bytes = [0; 16];
            self.random.fill_bytes(&mut bytes);
            put(
                &mut self.properties,
                78,
                format!("{:X}", Uuid::from_bytes(bytes).hyphenated()),
            );
            put(
                &mut self.properties,
                79,
                self.config.device_name(self.platform).to_owned(),
            );
            put(
                &mut self.properties,
                81,
                format!(
                    "/private/var/mobile/Containers/Data/Application/{:X}",
                    state.home_uuid.hyphenated()
                ),
            );
        } else {
            for id in [78, 79, 81] {
                self.properties.remove(&id);
            }
        }
        &self.properties
    }
}

fn put(properties: &mut BTreeMap<i32, Bytes>, id: i32, text: impl Into<Bytes>) {
    let text = text.into();
    let length = text
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(text.len());
    properties.insert(id, text.slice(..length));
}

fn number(properties: &mut BTreeMap<i32, Bytes>, id: i32, value: impl ToString) {
    put(properties, id, value.to_string());
}

fn optional_number(properties: &mut BTreeMap<i32, Bytes>, id: i32, value: Option<u64>) {
    match value {
        Some(value) => number(properties, id, value),
        None => put(properties, id, Bytes::new()),
    }
}

fn md5_text(input: &[u8]) -> Bytes {
    let length = input
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(input.len());
    if length == 0 {
        return Bytes::new();
    }
    let mut output = [0; 32];
    hex::encode_to_slice(Md5::digest(&input[..length]), &mut output).expect("fixed-size MD5 hex");
    Bytes::copy_from_slice(&output)
}

fn virtual_stat(inode: u64, micros: u64) -> [u8; 144] {
    let mut stat = [0; 144];
    stat[8..16].copy_from_slice(&inode.to_le_bytes());
    stat[80..88].copy_from_slice(&(micros / 1_000_000).to_le_bytes());
    stat[88..96].copy_from_slice(&(micros % 1_000_000 * 1000).to_le_bytes());
    stat
}
