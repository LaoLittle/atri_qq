use bytes::Bytes;
use rand::{RngCore, seq::SliceRandom};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, time::Duration};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Profile {
    pub os: String,
    pub kernel: String,
    pub qua: String,
    pub version: String,
    pub package_name: String,
    pub pt_version: String,
    pub sdk_version: String,
    pub apk_signature_md5: Vec<u8>,
    pub app_id: u32,
    pub sub_app_id: u32,
    pub sso_version: u32,
    pub client_version: u16,
    pub misc_bitmap: u32,
    pub main_sig_map: u32,
    pub sub_sig_map: u32,
}
impl Profile {
    pub fn linux() -> Self {
        Self {
            os: "Linux".into(),
            kernel: "Linux".into(),
            qua: "V1_LNX_NQ_3.2.34_53644_GW_B".into(),
            version: "3.2.34-53644".into(),
            package_name: "com.tencent.qq".into(),
            pt_version: "2.0.0".into(),
            sdk_version: "nt.wtlogin.0.0.1".into(),
            apk_signature_md5: b"com.tencent.qq".to_vec(),
            app_id: 1_600_001_615,
            sub_app_id: 537_391_664,
            sso_version: 19,
            client_version: 13_172,
            misc_bitmap: 12_058_620,
            main_sig_map: 169_742_560,
            sub_sig_map: 0,
        }
    }
}
impl Default for Profile {
    fn default() -> Self {
        Self::linux()
    }
}

#[derive(Clone)]
pub struct ClientConfig {
    pub profile: Profile,
    pub machine_id: String,
    pub host: String,
    pub port: u16,
    pub timeout: Duration,
    pub uin: u64,
    pub password: Option<String>,
    pub randomize_signature_for_testing: bool,
}
impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("profile", &self.profile)
            .field("machine_id", &self.machine_id)
            .field("host", &self.host)
            .field("port", &self.port)
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
            machine_id: hex::encode(random_bytes(16)),
            host: "msfwifi.3g.qq.com".into(),
            port: 8080,
            timeout: Duration::from_secs(30),
            uin: 0,
            password: None,
            randomize_signature_for_testing: false,
        }
    }
}

// No Debug implementation: ticket/key bytes must not accidentally become log output.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Keystore {
    pub uin: u64,
    pub uid: String,
    pub guid: Vec<u8>,
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
    #[serde(skip)]
    pub qr_sig: Vec<u8>,
    #[serde(skip)]
    pub key_exchange_ticket: Vec<u8>,
    #[serde(skip)]
    pub key_exchange_key: Vec<u8>,
    #[serde(skip)]
    pub login_cookie: Vec<u8>,
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
    let mut rng = rand::rngs::OsRng;
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
            qr_sig: vec![],
            key_exchange_ticket: vec![],
            key_exchange_key: vec![],
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
    rand::rngs::OsRng.fill_bytes(&mut v);
    v
}
