use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const SAMPLE_IPHONE_QUA: &str = "V1_IPH_SQ_9.3.75_1_APP_A";
pub const SIGN_SDK_VERSION: &str = "release/sq_8.6.7_99322b2c9_22_718";
pub const SIGN_PLATFORM: u32 = 2;
pub const IDFV_MIN_CORE_FOUNDATION_VERSION: f64 = 793.0;

pub mod native {
    pub const GUID_DIRECTORY: &str = "Library/WtloginConf";
    pub const CURRENT_GUID_FILE: &str = "Library/WtloginConf/guid_file";
    pub const LEGACY_GUID_FILE: &str = "Library/WtloginConf/wtlogin_config_file";
    pub const LEGACY_GUID_DICTIONARY_KEY: &str = "GUID";
    pub const CURRENT_KEYCHAIN_ACCOUNT: &str = "com.tencent.wtlogin.keychain.type.guid.metadata";
    pub const LEGACY_KEYCHAIN_ACCOUNT: &str = "com.tencent.wtlogin.keychain.type.guid";
    pub const LEGACY_NO_BACKUP_KEYCHAIN_ACCOUNT: &str =
        "com.tencent.wtlogin.keychain.type.guid.nobackup";
    pub const ARCHIVE_DATE_KEY: &str = "date";
    pub const ARCHIVE_GUID_KEY: &str = "guid";
    pub const ARCHIVE_IDFV_KEY: &str = "idfv";
    pub const ARCHIVE_DEVICE_MODEL_KEY: &str = "deviceModel";
    pub const ARCHIVE_REFRESH_DATE_KEY: &str = "refreshDate";
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DeviceFamily {
    IPhone,
    IPad,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceProfile {
    pub family: DeviceFamily,
    pub machine: String,
    pub system_version: String,
    pub system_name: String,
    pub device_model: String,
    pub device_name: String,
    pub qua: String,
    pub q36: String,
}

impl DeviceProfile {
    pub fn fge_machine(&self) -> &str {
        &self.machine
    }

    pub fn login_device_version(&self) -> &str {
        match self.machine.as_str() {
            "i386" => "iPhone Simulator",
            "x86_64" => "IMAC",
            machine => machine,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub struct AppleDate {
    pub seconds_since_reference_date: f64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct GuidInfo {
    pub date: Option<AppleDate>,
    pub guid: Vec<u8>,
    pub idfv: Option<Uuid>,
    pub device_model: Option<String>,
    pub refresh_date: Option<AppleDate>,
}

impl GuidInfo {
    pub fn fresh(now: AppleDate, device_model: &str) -> Self {
        Self::generated(Uuid::new_v4(), now, device_model)
    }

    fn generated(uuid: Uuid, now: AppleDate, device_model: &str) -> Self {
        Self {
            date: Some(now),
            guid: uuid.as_bytes().to_vec(),
            idfv: None,
            device_model: Some(device_model.to_owned()),
            refresh_date: None,
        }
    }

    pub fn guid_string(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let mut text = String::with_capacity(self.guid.len() * 2);
        for &byte in &self.guid {
            text.push(HEX[usize::from(byte >> 4)] as char);
            text.push(HEX[usize::from(byte & 0x0f)] as char);
        }
        text
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirtyStores {
    pub file: bool,
    pub keychain: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum GuidSource {
    CurrentFile,
    LegacyFile,
    CurrentKeychain,
    LegacyKeychain,
    Fresh,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct DecodedGuidSources {
    pub current_file: Option<GuidInfo>,
    pub legacy_file: Option<GuidInfo>,
    pub current_keychain: Option<GuidInfo>,
    pub legacy_keychain: Option<GuidInfo>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct GuidState {
    pub info: GuidInfo,
    pub source: GuidSource,
    pub dirty: DirtyStores,
}

impl GuidState {
    pub fn restore(sources: DecodedGuidSources, now: AppleDate, device_model: &str) -> Self {
        Self::restore_with(sources, || GuidInfo::fresh(now, device_model))
    }

    fn restore_with(sources: DecodedGuidSources, fresh: impl FnOnce() -> GuidInfo) -> Self {
        let (info, source, dirty) = if let Some(info) = sources.current_file {
            (
                info,
                GuidSource::CurrentFile,
                DirtyStores {
                    file: false,
                    keychain: true,
                },
            )
        } else if let Some(info) = sources.legacy_file {
            (
                info,
                GuidSource::LegacyFile,
                DirtyStores {
                    file: true,
                    keychain: true,
                },
            )
        } else if let Some(info) = sources.current_keychain {
            (
                info,
                GuidSource::CurrentKeychain,
                DirtyStores {
                    file: true,
                    keychain: false,
                },
            )
        } else if let Some(info) = sources.legacy_keychain {
            (
                info,
                GuidSource::LegacyKeychain,
                DirtyStores {
                    file: true,
                    keychain: true,
                },
            )
        } else {
            (
                fresh(),
                GuidSource::Fresh,
                DirtyStores {
                    file: true,
                    keychain: true,
                },
            )
        };
        Self {
            info,
            source,
            dirty,
        }
    }

    pub fn guid(&self) -> &[u8] {
        &self.info.guid
    }

    pub fn guid_string(&self) -> String {
        self.info.guid_string()
    }

    pub fn refresh(&mut self, now: AppleDate, device_model: &str) -> bool {
        self.refresh_with(now, device_model, Uuid::new_v4)
    }

    fn refresh_with(
        &mut self,
        now: AppleDate,
        device_model: &str,
        uuid: impl FnOnce() -> Uuid,
    ) -> bool {
        if self.info.refresh_date.is_some() {
            return false;
        }
        let mut info = GuidInfo::generated(uuid(), now, device_model);
        info.refresh_date = Some(now);
        self.info = info;
        self.dirty = DirtyStores {
            file: true,
            keychain: true,
        };
        true
    }
}

pub fn vendor_digest_from_uuid_string(
    core_foundation_version: f64,
    uuid_string: Option<&str>,
) -> Option<[u8; 16]> {
    if core_foundation_version < IDFV_MIN_CORE_FOUNDATION_VERSION {
        return None;
    }
    let uuid_string = uuid_string.filter(|value| !value.is_empty())?;
    Some(Md5::digest(uuid_string.as_bytes()).into())
}

pub fn vendor_digest_from_uuid(
    core_foundation_version: f64,
    uuid: Option<Uuid>,
) -> Option<[u8; 16]> {
    let uuid = uuid?;
    let mut buffer = [0; 36];
    vendor_digest_from_uuid_string(
        core_foundation_version,
        Some(uuid.hyphenated().encode_upper(&mut buffer)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: AppleDate = AppleDate {
        seconds_since_reference_date: 1234.5,
    };
    const LATER: AppleDate = AppleDate {
        seconds_since_reference_date: 2345.75,
    };

    fn uuid() -> Uuid {
        Uuid::from_bytes([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x46, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ])
    }

    fn info(marker: u8) -> GuidInfo {
        GuidInfo {
            date: Some(NOW),
            guid: vec![marker],
            idfv: None,
            device_model: Some("supplied model".into()),
            refresh_date: None,
        }
    }

    #[test]
    fn generated_metadata_and_guid_text_are_independent_of_idfv() {
        let info = GuidInfo::generated(uuid(), NOW, "iPad");
        assert_eq!(info.guid, uuid().as_bytes());
        assert_eq!(info.guid_string(), "00112233445546778899AABBCCDDEEFF");
        assert_eq!(info.date, Some(NOW));
        assert_eq!(info.device_model.as_deref(), Some("iPad"));
        assert_eq!(info.idfv, None);
        assert_eq!(info.refresh_date, None);
    }

    #[test]
    fn restores_first_non_nil_without_rejecting_non_16_byte_guid() {
        let expected = [
            (
                GuidSource::CurrentFile,
                DirtyStores {
                    file: false,
                    keychain: true,
                },
            ),
            (
                GuidSource::LegacyFile,
                DirtyStores {
                    file: true,
                    keychain: true,
                },
            ),
            (
                GuidSource::CurrentKeychain,
                DirtyStores {
                    file: true,
                    keychain: false,
                },
            ),
            (
                GuidSource::LegacyKeychain,
                DirtyStores {
                    file: true,
                    keychain: true,
                },
            ),
            (
                GuidSource::Fresh,
                DirtyStores {
                    file: true,
                    keychain: true,
                },
            ),
        ];
        for (first, (source, dirty)) in expected.into_iter().enumerate() {
            let sources = DecodedGuidSources {
                current_file: (first == 0).then(|| info(0)),
                legacy_file: (first <= 1).then(|| info(1)),
                current_keychain: (first <= 2).then(|| info(2)),
                legacy_keychain: (first <= 3).then(|| info(3)),
            };
            let state = if first < 4 {
                GuidState::restore(sources, NOW, "unused")
            } else {
                GuidState::restore_with(sources, || info(4))
            };
            assert_eq!(state.source, source);
            assert_eq!(state.dirty, dirty);
            assert_eq!(state.guid(), &[first as u8]);
            assert_eq!(state.guid_string(), format!("{first:02X}"));
        }
    }

    #[test]
    fn empty_restored_guid_is_selected_and_does_not_generate() {
        let mut restored = info(0);
        restored.guid.clear();
        let state = GuidState::restore_with(
            DecodedGuidSources {
                current_file: Some(restored),
                ..Default::default()
            },
            || panic!("non-nil current archive must win"),
        );
        assert!(state.guid().is_empty());
        assert_eq!(state.guid_string(), "");
    }

    #[test]
    fn refresh_replaces_metadata_once_and_dirties_both_stores() {
        let mut original = info(1);
        original.idfv = Some(Uuid::nil());
        let mut state = GuidState::restore(
            DecodedGuidSources {
                current_file: Some(original),
                ..Default::default()
            },
            NOW,
            "unused",
        );
        assert!(state.refresh_with(LATER, "iPhone", uuid));
        assert_eq!(state.guid(), uuid().as_bytes());
        assert_eq!(state.info.date, Some(LATER));
        assert_eq!(state.info.refresh_date, Some(LATER));
        assert_eq!(state.info.device_model.as_deref(), Some("iPhone"));
        assert_eq!(state.info.idfv, None);
        assert_eq!(
            state.dirty,
            DirtyStores {
                file: true,
                keychain: true
            }
        );
        let refreshed = state.clone();
        assert!(!state.refresh_with(NOW, "other", || panic!("must not generate twice")));
        assert_eq!(state, refreshed);

        let mut restarted = GuidState::restore(
            DecodedGuidSources {
                current_file: Some(state.info),
                ..Default::default()
            },
            NOW,
            "unused",
        );
        let before = restarted.clone();
        assert!(!restarted.refresh(NOW, "other"));
        assert_eq!(restarted, before);
    }

    #[test]
    fn vendor_string_is_hashed_verbatim_and_unavailability_has_no_fallback() {
        assert_eq!(
            vendor_digest_from_uuid_string(793.0, Some("abc")),
            Some([
                0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1,
                0x7f, 0x72
            ]),
        );
        let upper = "00112233-4455-4677-8899-AABBCCDDEEFF";
        assert_eq!(
            vendor_digest_from_uuid(793.0, Some(uuid())),
            vendor_digest_from_uuid_string(793.0, Some(upper))
        );
        assert_ne!(
            vendor_digest_from_uuid_string(793.0, Some(upper)),
            vendor_digest_from_uuid_string(793.0, Some(&upper.to_lowercase()))
        );
        assert_ne!(
            vendor_digest_from_uuid_string(793.0, Some(upper)),
            vendor_digest_from_uuid_string(793.0, Some("00112233445546778899AABBCCDDEEFF"))
        );
        assert_eq!(vendor_digest_from_uuid_string(792.99, Some(upper)), None);
        assert_eq!(vendor_digest_from_uuid_string(793.0, None), None);
        assert_eq!(vendor_digest_from_uuid_string(793.0, Some("")), None);
        assert_eq!(vendor_digest_from_uuid(793.0, None), None);
    }

    #[test]
    fn raw_fge_machine_is_not_replaced_by_login_simulator_aliases() {
        for (machine, login) in [
            ("i386", "iPhone Simulator"),
            ("x86_64", "IMAC"),
            ("iPhone15,2", "iPhone15,2"),
            ("iPad14,3", "iPad14,3"),
            ("arm64", "arm64"),
        ] {
            let profile = DeviceProfile {
                family: DeviceFamily::IPad,
                machine: machine.into(),
                system_version: "supplied version".into(),
                system_name: "supplied name".into(),
                device_model: "supplied model".into(),
                device_name: "supplied device name".into(),
                qua: "supplied QUA".into(),
                q36: "supplied q36".into(),
            };
            assert_eq!(profile.fge_machine(), machine);
            assert_eq!(profile.login_device_version(), login);
            assert_eq!(profile.qua, "supplied QUA");
        }
    }
}
