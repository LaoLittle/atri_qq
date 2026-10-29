use bytes::Bytes;
use rand::{Rng, TryRng, rand_core::UnwrapErr, rngs::SysRng, seq::IndexedRandom};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, time::Duration};

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClientPlatform {
    #[default]
    Linux,
    Windows,
    MacOS,
    IPhone,
    IPad,
}

impl ClientPlatform {
    pub fn is_ios(self) -> bool {
        matches!(self, Self::IPhone | Self::IPad)
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Profile {
    pub platform: ClientPlatform,
    pub os: String,
    pub kernel: String,
    pub qua: String,
    pub version: String,
    pub package_name: String,
    pub pt_version: String,
    pub sdk_version: String,
    pub apk_signature_md5: Option<Vec<u8>>,
    pub app_id: u32,
    pub sub_app_id: u32,
    pub sso_version: u32,
    pub client_version: u16,
    pub misc_bitmap: Option<u32>,
    pub main_sig_map: Option<u32>,
    pub sub_sig_map: Option<u32>,
}
#[derive(Clone, Copy)]
struct ProfileCatalog {
    os: &'static str,
    kernel: &'static str,
    qua: &'static str,
    version: &'static str,
    package_name: &'static str,
    pt_version: &'static str,
    sdk_version: &'static str,
    apk_signature_md5: Option<&'static [u8]>,
    app_id: u32,
    sub_app_id: u32,
    sso_version: u32,
    client_version: u16,
    misc_bitmap: Option<u32>,
    main_sig_map: Option<u32>,
    sub_sig_map: Option<u32>,
}

const LINUX_PROFILE: ProfileCatalog = ProfileCatalog {
    os: "Linux",
    kernel: "Linux",
    qua: "V1_LNX_NQ_3.2.34_53644_GW_B",
    version: "3.2.34-53644",
    package_name: "com.tencent.qq",
    pt_version: "2.0.0",
    sdk_version: "nt.wtlogin.0.0.1",
    apk_signature_md5: Some(b"com.tencent.qq"),
    app_id: 1_600_001_615,
    sub_app_id: 537_391_664,
    sso_version: 19,
    client_version: 13_172,
    misc_bitmap: Some(12_058_620),
    main_sig_map: Some(169_742_560),
    sub_sig_map: Some(0),
};

const IPHONE_PROFILE: ProfileCatalog = ProfileCatalog {
    os: "iOS",
    kernel: "",
    qua: "V1_IPH_SQ_9.3.75_1_APP_A",
    version: "9.3.75",
    package_name: "com.tencent.mqq",
    pt_version: "",
    sdk_version: "6.2.2.0803",
    apk_signature_md5: None,
    app_id: 16,
    sub_app_id: 537_396_808,
    sso_version: 22,
    client_version: 8001,
    misc_bitmap: None,
    main_sig_map: None,
    sub_sig_map: None,
};

const IPAD_PROFILE: ProfileCatalog = ProfileCatalog {
    sub_app_id: 537_396_819,
    ..IPHONE_PROFILE
};

#[derive(Default, Deserialize)]
#[serde(default)]
struct ProfileInput {
    platform: ClientPlatform,
    #[serde(deserialize_with = "profile_present")]
    os: Option<String>,
    #[serde(deserialize_with = "profile_present")]
    kernel: Option<String>,
    #[serde(deserialize_with = "profile_present")]
    qua: Option<String>,
    #[serde(deserialize_with = "profile_present")]
    version: Option<String>,
    #[serde(deserialize_with = "profile_present")]
    package_name: Option<String>,
    #[serde(deserialize_with = "profile_present")]
    pt_version: Option<String>,
    #[serde(deserialize_with = "profile_present")]
    sdk_version: Option<String>,
    #[serde(deserialize_with = "profile_present")]
    apk_signature_md5: Option<Option<Vec<u8>>>,
    #[serde(deserialize_with = "profile_present")]
    app_id: Option<u32>,
    #[serde(deserialize_with = "profile_present")]
    sub_app_id: Option<u32>,
    #[serde(deserialize_with = "profile_present")]
    sso_version: Option<u32>,
    #[serde(deserialize_with = "profile_present")]
    client_version: Option<u16>,
    #[serde(deserialize_with = "profile_present")]
    misc_bitmap: Option<Option<u32>>,
    #[serde(deserialize_with = "profile_present")]
    main_sig_map: Option<Option<u32>>,
    #[serde(deserialize_with = "profile_present")]
    sub_sig_map: Option<Option<u32>>,
}

fn profile_present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

impl ProfileInput {
    fn resolve<E: serde::de::Error>(self) -> Result<Profile, E> {
        let catalog = match self.platform {
            ClientPlatform::Linux => Some(LINUX_PROFILE),
            ClientPlatform::IPhone => Some(IPHONE_PROFILE),
            ClientPlatform::IPad => Some(IPAD_PROFILE),
            ClientPlatform::Windows | ClientPlatform::MacOS => None,
        };
        macro_rules! field {
            ($name:ident, $convert:expr) => {
                match self.$name {
                    Some(value) => value,
                    None => catalog
                        .map(|catalog| ($convert)(catalog.$name))
                        .ok_or_else(|| E::missing_field(stringify!($name)))?,
                }
            };
        }
        Ok(Profile {
            platform: self.platform,
            os: field!(os, str::to_owned),
            kernel: field!(kernel, str::to_owned),
            qua: field!(qua, str::to_owned),
            version: field!(version, str::to_owned),
            package_name: field!(package_name, str::to_owned),
            pt_version: field!(pt_version, str::to_owned),
            sdk_version: field!(sdk_version, str::to_owned),
            apk_signature_md5: field!(apk_signature_md5, |value: Option<&[u8]>| value
                .map(<[u8]>::to_vec)),
            app_id: field!(app_id, std::convert::identity),
            sub_app_id: field!(sub_app_id, std::convert::identity),
            sso_version: field!(sso_version, std::convert::identity),
            client_version: field!(client_version, std::convert::identity),
            misc_bitmap: field!(misc_bitmap, std::convert::identity),
            main_sig_map: field!(main_sig_map, std::convert::identity),
            sub_sig_map: field!(sub_sig_map, std::convert::identity),
        })
    }
}

impl<'de> Deserialize<'de> for Profile {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        ProfileInput::deserialize(deserializer)?.resolve()
    }
}

impl Profile {
    fn catalog(platform: ClientPlatform) -> Self {
        ProfileInput {
            platform,
            ..Default::default()
        }
        .resolve::<serde::de::value::Error>()
        .expect("platform has a built-in profile catalog")
    }

    pub fn linux() -> Self {
        Self::catalog(ClientPlatform::Linux)
    }

    pub fn iphone() -> Self {
        Self::catalog(ClientPlatform::IPhone)
    }

    pub fn ipad() -> Self {
        Self::catalog(ClientPlatform::IPad)
    }
}
impl Default for Profile {
    fn default() -> Self {
        Self::linux()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IosDevice {
    pub system_version: String,
    pub hardware_model: String,
    pub system_name: String,
}

impl IosDevice {
    pub(crate) fn validate(&self) -> crate::Result<()> {
        if self.system_version.is_empty()
            || self.hardware_model.is_empty()
            || self.system_name.is_empty()
        {
            return Err(crate::Error::Authentication(
                "iOS requires actual system_version, hardware_model and system_name".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct IosRegistration {
    pub initial: crate::proto::auth::InfoSyncRequest,
    pub reconnect: crate::proto::auth::InfoSyncRequest,
}

#[derive(Clone)]
pub struct IosReservedTemplate(Bytes);

impl IosReservedTemplate {
    pub fn new(bytes: Bytes) -> crate::Result<Self> {
        let reserved = <crate::proto::sso::Reserved as prost::Message>::decode(bytes.clone())?;
        if reserved.trace_parent.is_some()
            || reserved.uid.is_some()
            || reserved.secure_info.is_some()
        {
            return Err(crate::Error::Authentication(
                "iOS reserved template must not contain dynamic trace, UID or secure info".into(),
            ));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone)]
pub struct IosAccountRecord80(pub Bytes);

#[derive(Clone)]
pub enum IosTransportAccount {
    Uin { account_type: u8 },
    Explicit { account_type: u8, text: Bytes },
}

#[derive(Clone, Copy, Default)]
pub struct IosPushStatistics {
    pub count: i32,
    pub elapsed: i64,
    pub value: i32,
}

#[derive(Clone)]
pub struct IosTransportResources {
    pub network_type: u8,
    pub effective_flags: [u8; 11],
    pub account_record_0x80: IosAccountRecord80,
    pub carrier_mcc: String,
    pub carrier_mnc: String,
    pub cf_bundle_version: String,
    pub account: IosTransportAccount,
    pub reserved: IosReservedTemplate,
    pub push_service_get_statistics: Option<IosPushStatistics>,
}

impl IosTransportResources {
    pub(crate) fn validate(&self) -> crate::Result<()> {
        if matches!(&self.account, IosTransportAccount::Explicit { text, .. } if text.is_empty()) {
            return Err(crate::Error::Authentication(
                "iOS transport requires explicit account text".into(),
            ));
        }
        if self.effective_flags[9] >= 4 || !matches!(self.effective_flags[10], 0 | 4) {
            return Err(crate::Error::Authentication(
                "iOS transport requires effective native eleven-byte header flags".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct ClientConfig {
    pub profile: Profile,
    pub ios_device: Option<IosDevice>,
    pub ios_virtual: Option<std::sync::Arc<crate::ios_device::IosVirtualConfig>>,
    pub ios_signing: Option<crate::signing::IosSigningResources>,
    pub ios_registration: Option<IosRegistration>,
    pub ios_transport: Option<IosTransportResources>,
    pub machine_id: String,
    pub application_uuid: String,
    pub host: String,
    pub port: u16,
    pub server_selection: crate::network::ServerSelection,
    pub timeout: Duration,
    pub uin: u64,
    pub password: Option<String>,
    pub randomize_signature_for_testing: bool,
}
impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("profile", &self.profile)
            .field("ios_device", &self.ios_device)
            .field(
                "ios_virtual",
                &self
                    .ios_virtual
                    .as_ref()
                    .map(|_| "<explicit virtual device>"),
            )
            .field(
                "ios_signing",
                &self.ios_signing.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "ios_registration",
                &self.ios_registration.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "ios_transport",
                &self.ios_transport.as_ref().map(|_| "<redacted>"),
            )
            .field("machine_id", &self.machine_id)
            .field("application_uuid", &"<redacted>")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("server_selection", &self.server_selection)
            .field("timeout", &self.timeout)
            .field("uin", &self.uin)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field(
                "randomize_signature_for_testing",
                &self.randomize_signature_for_testing,
            )
            .finish()
    }
}
impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            profile: Profile::linux(),
            ios_device: None,
            ios_virtual: None,
            ios_signing: None,
            ios_registration: None,
            ios_transport: None,
            machine_id: hex::encode(random_bytes(16)),
            application_uuid: crate::o3::generate_application_uuid(),
            host: "msfwifi.3g.qq.com".into(),
            port: 8080,
            server_selection: crate::network::ServerSelection::default(),
            timeout: Duration::from_secs(30),
            uin: 0,
            password: None,
            randomize_signature_for_testing: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NtTicketTimeValues {
    pub raw_field1: Option<u64>,
    pub raw_field2: Option<u64>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NtTicketTimeMetadata {
    pub field12: Option<NtTicketTimeValues>,
    pub field16: Option<NtTicketTimeValues>,
    pub received_unix_ms: u64,
}

impl NtTicketTimeMetadata {
    pub fn selected(&self) -> Option<NtTicketTimeValues> {
        self.field12.or(self.field16)
    }

    pub fn next_refresh_unix_seconds(&self) -> Option<u64> {
        self.selected()
            .map(|values| values.raw_field1.unwrap_or_default())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WtTicketTimeMetadata {
    pub next_refresh_unix_seconds: u64,
    pub expire_unix_seconds: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct NtKeyExchangeSession {
    key: Bytes,
    ticket: Bytes,
    reuse_until: Option<tokio::time::Instant>,
    clear_at: Option<tokio::time::Instant>,
    early_renewal: bool,
}

impl NtKeyExchangeSession {
    pub fn new(
        platform: ClientPlatform,
        key: Bytes,
        ticket: Bytes,
        expire_seconds: i64,
    ) -> crate::Result<Self> {
        Self::from_response(None, platform.is_ios(), key, ticket, expire_seconds)
    }

    pub fn renew(&self, key: Bytes, ticket: Bytes, expire_seconds: i64) -> crate::Result<Self> {
        Self::from_response(Some(self), self.early_renewal, key, ticket, expire_seconds)
    }

    fn from_response(
        previous: Option<&Self>,
        early_renewal: bool,
        key: Bytes,
        ticket: Bytes,
        expire_seconds: i64,
    ) -> crate::Result<Self> {
        if !matches!(key.len(), 16 | 24 | 32) || ticket.is_empty() {
            return Err(crate::Error::Malformed(
                "Invalid NT exchange session".into(),
            ));
        }
        let now = tokio::time::Instant::now();
        let deadline = |seconds: u64| {
            now.checked_add(Duration::from_secs(seconds))
                .ok_or_else(|| crate::Error::Malformed("NT exchange lifetime overflow".into()))
        };
        let reuse_until = if early_renewal && expire_seconds >= 301 {
            Some(deadline(expire_seconds as u64 - 60)?)
        } else {
            previous.and_then(|session| session.reuse_until)
        };
        let clear_at = if expire_seconds > 0 {
            Some(deadline(expire_seconds as u64)?)
        } else {
            previous
                .and_then(|session| session.clear_at)
                .filter(|deadline| now < *deadline)
        };
        Ok(Self {
            key,
            ticket,
            reuse_until,
            clear_at,
            early_renewal,
        })
    }

    pub fn is_reusable(&self) -> bool {
        let now = tokio::time::Instant::now();
        (!self.early_renewal || self.reuse_until.is_some_and(|deadline| now <= deadline))
            && self.clear_at.is_none_or(|deadline| now < deadline)
    }

    pub(crate) fn material(&self) -> crate::Result<(&[u8], &Bytes)> {
        if self
            .clear_at
            .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
        {
            return Err(crate::Error::Authentication(
                "NT key exchange session expired".into(),
            ));
        }
        Ok((&self.key, &self.ticket))
    }
}

// No Debug implementation: ticket/key bytes must not accidentally become log output.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Keystore {
    pub uin: u64,
    pub uid: String,
    pub guid: Vec<u8>,
    pub ios_msf_imei: String,
    pub ios_virtual_state: Option<crate::ios_device::IosVirtualState>,
    pub device_name: String,
    pub android_id: String,
    pub qimei: String,
    pub nickname: String,
    pub age: u8,
    pub gender: u8,
    pub face_id: u16,
    pub a1: Vec<u8>,
    pub a1_key: Vec<u8>,
    pub a2: Vec<u8>,
    pub a2_key: Vec<u8>,
    pub d2: Vec<u8>,
    pub d2_key: Vec<u8>,
    pub tgtgt_key: Vec<u8>,
    pub no_pic_sig: Vec<u8>,
    pub random_key: Vec<u8>,
    pub ksid: Vec<u8>,
    pub s_key: Vec<u8>,
    pub super_key: Vec<u8>,
    pub st: Vec<u8>,
    pub st_key: Vec<u8>,
    pub st_web: Vec<u8>,
    pub wt_session_ticket: Vec<u8>,
    pub wt_session_ticket_key: Vec<u8>,
    pub ps_keys: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub o3_xwid_switch: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nt_ticket_times: Option<NtTicketTimeMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wt_ticket_times: Option<WtTicketTimeMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticket_generated_unix_seconds: Option<u64>,
    #[serde(skip)]
    pub qr_sig: Vec<u8>,
    #[serde(skip)]
    pub key_exchange_session: Option<NtKeyExchangeSession>,
    #[serde(skip)]
    pub login_cookie: Vec<u8>,
}

impl Keystore {
    pub fn ensure_ios_identity(&mut self) -> crate::Result<bool> {
        if !self.ios_msf_imei.is_empty() {
            return Ok(false);
        }
        let mut bytes = [0u8; 16];
        SysRng.try_fill_bytes(&mut bytes).map_err(|error| {
            crate::Error::Crypto(format!("iOS identity entropy unavailable: {error}"))
        })?;
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let mut identity = String::with_capacity(36);
        for (index, byte) in bytes.into_iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                identity.push('-');
            }
            identity.push(HEX[usize::from(byte >> 4)] as char);
            identity.push(HEX[usize::from(byte & 0x0f)] as char);
        }
        self.ios_msf_imei = identity;
        Ok(true)
    }

    pub fn next_ticket_refresh_unix_seconds(&self) -> Option<u64> {
        self.nt_ticket_times
            .and_then(|times| times.next_refresh_unix_seconds())
            .or_else(|| {
                self.wt_ticket_times
                    .map(|times| times.next_refresh_unix_seconds)
            })
    }
}

fn default_device_name() -> String {
    const DISTRIBUTIONS: &[&str] = &[
        "Ubuntu",
        "Fedora",
        "Debian",
        "ArchLinux",
        "openSUSE",
        "LinuxMint",
        "Manjaro",
        "RockyLinux",
        "AlmaLinux",
    ];
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut rng = UnwrapErr(SysRng);
    let distribution = DISTRIBUTIONS
        .choose(&mut rng)
        .expect("nonempty distribution list");
    let mut suffix = [0u8; 3];
    rng.fill_bytes(&mut suffix);
    let mut name = String::with_capacity(distribution.len() + 7);
    name.push_str(distribution);
    name.push('-');
    for byte in suffix {
        name.push(HEX[usize::from(byte >> 4)] as char);
        name.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    name
}
impl Default for Keystore {
    fn default() -> Self {
        Self {
            uin: 0,
            uid: String::new(),
            guid: random_bytes(16),
            ios_msf_imei: String::new(),
            ios_virtual_state: None,
            device_name: default_device_name(),
            android_id: hex::encode(random_bytes(8)),
            qimei: String::new(),
            nickname: String::new(),
            age: 0,
            gender: 0,
            face_id: 0,
            a1: vec![],
            a1_key: vec![0; 16],
            a2: vec![],
            a2_key: vec![0; 16],
            d2: vec![],
            d2_key: vec![0; 16],
            tgtgt_key: vec![],
            no_pic_sig: vec![],
            random_key: random_bytes(16),
            ksid: vec![],
            s_key: vec![],
            super_key: vec![],
            st: vec![],
            st_key: vec![],
            st_web: vec![],
            wt_session_ticket: vec![],
            wt_session_ticket_key: vec![],
            ps_keys: BTreeMap::new(),
            o3_xwid_switch: None,
            nt_ticket_times: None,
            wt_ticket_times: None,
            ticket_generated_unix_seconds: None,
            qr_sig: vec![],
            key_exchange_session: None,
            login_cookie: vec![],
        }
    }
}
#[derive(Clone)]
pub struct SessionState {
    pub profile: Profile,
    pub keystore: Keystore,
    pub machine_id: String,
    pub online: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum RequestType {
    D2 = 12,
    Simple = 13,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Encryption {
    None = 0,
    D2 = 1,
    Empty = 2,
}
/// Bounded response-header fields not interpreted by the command payload decoder.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SsoResponseHeader {
    pub message_cookie: Bytes,
    pub server_reserve: Bytes,
    /// Opaque suffix inside the declared header, after the length-prefixed reserve.
    /// Its internal grammar is not established; these are not additional p32 fields.
    pub extensions: Bytes,
}
#[derive(Clone, Debug)]
pub struct IncomingPacket {
    pub sequence: i32,
    pub command: String,
    pub body: Bytes,
    pub return_code: i32,
    pub header: SsoResponseHeader,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserInfo {
    pub uin: u64,
    pub uid: String,
    pub nickname: String,
    pub age: u8,
    pub gender: u8,
}
impl From<&Keystore> for UserInfo {
    fn from(k: &Keystore) -> Self {
        Self {
            uin: k.uin,
            uid: k.uid.clone(),
            nickname: k.nickname.clone(),
            age: k.age,
            gender: k.gender,
        }
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u8)]
pub enum QrState {
    Confirmed = 0,
    Expired = 17,
    Waiting = 48,
    Scanned = 53,
    Canceled = 54,
    Invalid = 144,
}
impl TryFrom<u8> for QrState {
    type Error = crate::Error;
    fn try_from(v: u8) -> crate::Result<Self> {
        Ok(match v {
            0 => Self::Confirmed,
            17 => Self::Expired,
            48 => Self::Waiting,
            53 => Self::Scanned,
            54 => Self::Canceled,
            144 => Self::Invalid,
            _ => {
                return Err(crate::Error::Server {
                    code: v.into(),
                    message: "Unknown QR state".into(),
                });
            }
        })
    }
}
#[derive(Clone, Debug)]
pub enum LoginChallenge {
    Captcha { url: String },
    NewDevice { url: String },
}
#[derive(Clone)]
pub enum LoginEvent {
    QrCode { url: String, image: Vec<u8> },
    QrState(QrState),
    Online { uin: u64, uid: String },
    Offline { reason: String },
    Challenge(LoginChallenge),
    KeystoreChanged(Keystore),
}
pub(crate) fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0; n];
    SysRng
        .try_fill_bytes(&mut v)
        .expect("system entropy unavailable");
    v
}

#[cfg(test)]
mod ticket_time_tests {
    use super::*;

    #[test]
    fn legacy_records_do_not_invent_ticket_times_or_generation() {
        let legacy: Keystore = serde_json::from_str(r#"{"a1":[1],"a2":[2],"d2":[3]}"#).unwrap();
        assert_eq!(legacy.ticket_generated_unix_seconds, None);
        assert_eq!(legacy.wt_ticket_times, None);
        assert_eq!(legacy.next_ticket_refresh_unix_seconds(), None);

        let legacy_nt: Keystore = serde_json::from_str(
            r#"{"nt_ticket_times":{"field12":null,"field16":{"raw_field1":123,"raw_field2":456},"received_unix_ms":1000}}"#,
        )
        .unwrap();
        assert_eq!(legacy_nt.ticket_generated_unix_seconds, None);
        assert_eq!(legacy_nt.wt_ticket_times, None);
        assert_eq!(legacy_nt.next_ticket_refresh_unix_seconds(), Some(123));
    }

    #[test]
    fn present_nt_message_takes_precedence_over_wt_deadlines() {
        let mut store = Keystore {
            nt_ticket_times: Some(NtTicketTimeMetadata {
                field12: None,
                field16: None,
                received_unix_ms: 1000,
            }),
            wt_ticket_times: Some(WtTicketTimeMetadata {
                next_refresh_unix_seconds: 123,
                expire_unix_seconds: 456,
            }),
            ..Default::default()
        };
        assert_eq!(store.next_ticket_refresh_unix_seconds(), Some(123));
        store.nt_ticket_times.as_mut().unwrap().field12 = Some(NtTicketTimeValues::default());
        assert_eq!(store.next_ticket_refresh_unix_seconds(), Some(0));
    }
}

#[cfg(test)]
mod nt_exchange_tests {
    use super::{ClientPlatform, NtKeyExchangeSession};
    use bytes::Bytes;
    use std::time::Duration;

    fn session(expire_seconds: i64) -> NtKeyExchangeSession {
        NtKeyExchangeSession::new(
            ClientPlatform::IPhone,
            Bytes::from_static(&[7; 32]),
            Bytes::from_static(b"synthetic-ticket"),
            expire_seconds,
        )
        .unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn desktop_reuses_keys_until_the_hard_deadline() {
        for lifetime in [1, 300, 301, 3600] {
            let session = NtKeyExchangeSession::new(
                ClientPlatform::Linux,
                Bytes::from_static(&[7; 32]),
                Bytes::from_static(b"synthetic-desktop-ticket"),
                lifetime,
            )
            .unwrap();
            tokio::time::advance(Duration::from_secs(lifetime as u64) - Duration::from_nanos(1))
                .await;
            assert!(session.is_reusable());
            assert!(session.material().is_ok());
            tokio::time::advance(Duration::from_nanos(1)).await;
            assert!(!session.is_reusable());
            assert!(session.material().is_err());
        }
    }

    #[test]
    fn exchange_lifetimes_preserve_signed_sixty_four_bit_values() {
        let long = session(i64::from(i32::MAX) + 1);
        assert!(long.is_reusable());
        assert!(long.material().is_ok());
        let nonpositive = session(i64::from(i32::MIN) - 1);
        assert!(!nonpositive.is_reusable());
        assert!(nonpositive.material().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn reuse_margin_does_not_invalidate_pending_response_decryption() {
        let session = session(301);
        tokio::time::advance(Duration::from_secs(241)).await;
        assert!(session.is_reusable());
        tokio::time::advance(Duration::from_nanos(1)).await;
        assert!(!session.is_reusable());
        assert!(session.material().is_ok());
        tokio::time::advance(Duration::from_secs(60)).await;
        assert!(session.material().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn short_lifetime_keeps_previous_reuse_deadline_but_replaces_clear_timer() {
        assert!(!session(300).is_reusable());
        let previous = session(1000);
        let renewed = previous
            .renew(
                Bytes::from_static(&[8; 16]),
                Bytes::from_static(b"renewed"),
                300,
            )
            .unwrap();
        assert!(renewed.is_reusable());
        assert_eq!(renewed.material().unwrap().0, [8; 16]);
        tokio::time::advance(Duration::from_secs(300)).await;
        assert!(renewed.material().is_err());
        assert!(previous.material().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn nonpositive_lifetime_retains_an_existing_clear_deadline() {
        for platform in [ClientPlatform::Linux, ClientPlatform::IPhone] {
            for lifetime in [0, -1] {
                let previous = NtKeyExchangeSession::new(
                    platform,
                    Bytes::from_static(&[7; 32]),
                    Bytes::from_static(b"synthetic-ticket"),
                    400,
                )
                .unwrap();
                let renewed = previous
                    .renew(
                        Bytes::from_static(&[8; 16]),
                        Bytes::from_static(b"renewed"),
                        lifetime,
                    )
                    .unwrap();
                tokio::time::advance(Duration::from_secs(400)).await;
                assert!(renewed.material().is_err());
                let after_expiry = renewed
                    .renew(
                        Bytes::from_static(&[9; 16]),
                        Bytes::from_static(b"after-expiry"),
                        lifetime,
                    )
                    .unwrap();
                assert_eq!(after_expiry.is_reusable(), !platform.is_ios());
                assert_eq!(after_expiry.material().unwrap().0, [9; 16]);
            }
        }
    }
}
