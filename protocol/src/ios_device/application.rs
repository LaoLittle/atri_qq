use crate::{
    Result,
    heartbeat::{IosResources, encode_ios_battery},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(i64)]
pub enum IosVirtualBatteryState {
    Unknown = 0,
    Unplugged = 1,
    Charging = 2,
    #[default]
    Full = 3,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IosVirtualApplication {
    pub user_trigger: bool,
    pub keep_pc_online: bool,
    pub mute: bool,
    pub notifications_enabled: bool,
    pub bound_account_notifications_enabled: bool,
    pub foreground: bool,
    pub chat_focused: bool,
    pub app_status: u32,
    pub silence_status: u32,
    pub silent_version: u32,
    pub battery_level: f32,
    pub battery_state: IosVirtualBatteryState,
}

impl Default for IosVirtualApplication {
    fn default() -> Self {
        Self {
            user_trigger: true,
            keep_pc_online: true,
            mute: false,
            notifications_enabled: true,
            bound_account_notifications_enabled: true,
            foreground: true,
            chat_focused: false,
            app_status: 1,
            silence_status: 1,
            silent_version: 0,
            battery_level: 1.0,
            battery_state: IosVirtualBatteryState::Full,
        }
    }
}

impl IosVirtualApplication {
    pub fn heartbeat_resources(&self) -> Result<IosResources> {
        Ok(IosResources {
            silence_status: self.silence_status,
            silent_version: self.silent_version,
            battery_status: encode_ios_battery(self.battery_level, self.battery_state as i64)?,
        })
    }
}
