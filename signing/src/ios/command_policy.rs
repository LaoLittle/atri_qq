use std::collections::{BTreeMap, BTreeSet};

use super::{
    command_lists::{CORE_COMMANDS, HOST_COMMANDS},
    config_defaults::SWITCHES,
    signer::Mode,
};

pub const SIGN_SWITCH: u32 = 2;
pub const COMMAND_MODE_SWITCH: u32 = 0x18;
pub const PERSISTED_HOST_COMMANDS_KEY: &str = "kO3WhiteCmdListKey";

#[derive(Clone, Debug)]
pub struct CommandPolicy {
    switches: BTreeMap<u32, u32>,
    additional_host_commands: BTreeSet<String>,
}

impl Default for CommandPolicy {
    fn default() -> Self {
        Self::new([])
    }
}

impl CommandPolicy {
    pub fn new(switches: impl IntoIterator<Item = (u32, u32)>) -> Self {
        Self {
            switches: switches.into_iter().collect(),
            additional_host_commands: BTreeSet::new(),
        }
    }

    pub fn switch(&self, key: u32) -> u32 {
        self.switches.get(&key).copied().unwrap_or_else(|| {
            key.checked_sub(1)
                .and_then(|index| SWITCHES.get(index as usize))
                .copied()
                .unwrap_or(2)
        })
    }

    pub fn set_switch(&mut self, key: u32, value: u32) -> Option<u32> {
        self.switches.insert(key, value)
    }

    pub fn append_persisted_host_commands(&mut self, commands: &str) {
        for command in commands.split_terminator(',') {
            if !self.host_requires_security(command) {
                self.additional_host_commands.insert(command.to_owned());
            }
        }
    }

    pub fn host_requires_security(&self, command: &str) -> bool {
        HOST_COMMANDS.binary_search(&command).is_ok()
            || CORE_COMMANDS.binary_search(&command).is_ok()
            || self.additional_host_commands.contains(command)
    }

    pub fn core_mode(&self, command: &str) -> Mode {
        let switched = matches!(
            command,
            "LightAppSvc.mini_app_userapp.GetDropdownAppList" | "OidbSvcTrpcTcp.0xfd4_1"
        ) || CORE_COMMANDS.binary_search(&command).is_ok();
        match if switched {
            self.switch(COMMAND_MODE_SWITCH)
        } else {
            2
        } {
            0 => Mode::Disabled,
            1 => Mode::Compact,
            _ => Mode::Primary,
        }
    }

    pub fn sdk_mode(&self, command: &str, body: &[u8]) -> Option<Mode> {
        (!body.is_empty() && self.switch(SIGN_SWITCH) == 1).then(|| self.core_mode(command))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_controlled_commands_use_the_three_state_switch() {
        let mut policy = CommandPolicy::new([(SIGN_SWITCH, 1), (COMMAND_MODE_SWITCH, 0)]);
        for command in [
            "AvatarInfoSvr.QQHeadUrlReq",
            "LightAppSvc.mini_app_userapp.GetDropdownAppList",
            "OidbSvcTrpcTcp.0xfd4_1",
        ] {
            assert_eq!(policy.sdk_mode(command, b"body"), Some(Mode::Disabled));
            policy.set_switch(COMMAND_MODE_SWITCH, 1);
            assert_eq!(policy.sdk_mode(command, b"body"), Some(Mode::Compact));
            policy.set_switch(COMMAND_MODE_SWITCH, 7);
            assert_eq!(policy.sdk_mode(command, b"body"), Some(Mode::Primary));
            policy.set_switch(COMMAND_MODE_SWITCH, 0);
        }
        assert_eq!(policy.core_mode("unlisted.command"), Mode::Primary);
        assert_eq!(
            policy.core_mode("avatarinfosvr.QQHeadUrlReq"),
            Mode::Primary
        );
        assert_eq!(policy.core_mode("OidbSvcTrpcTcp.0.fd4_1"), Mode::Primary);
    }

    #[test]
    fn sdk_empty_signature_is_distinct_from_policy_disabled_signature() {
        let mut policy = CommandPolicy::new([(SIGN_SWITCH, 1), (COMMAND_MODE_SWITCH, 0)]);
        let command = "AvatarInfoSvr.QQHeadUrlReq";
        assert_eq!(policy.sdk_mode(command, b"body"), Some(Mode::Disabled));
        assert_eq!(policy.sdk_mode(command, b""), None);
        for value in [0, 2, 3] {
            policy.set_switch(SIGN_SWITCH, value);
            assert_eq!(policy.sdk_mode(command, b"body"), None);
        }
        let unknown = CommandPolicy::new([(SIGN_SWITCH, 2), (COMMAND_MODE_SWITCH, 2)]);
        assert_eq!(unknown.switch(u32::MAX), 2);
        assert_eq!(unknown.core_mode(command), Mode::Primary);
        assert_eq!(unknown.sdk_mode(command, b"body"), None);
    }

    #[test]
    fn host_allowlist_and_core_policy_remain_separate() {
        let mut policy = CommandPolicy::new([(SIGN_SWITCH, 1), (COMMAND_MODE_SWITCH, 0)]);
        assert!(policy.host_requires_security("wtlogin.login"));
        assert!(policy.host_requires_security("MessageSvc.PbSendMsg"));
        assert!(policy.host_requires_security("AvatarInfoSvr.QQHeadUrlReq"));
        assert!(!policy.host_requires_security("custom.command"));
        policy.append_persisted_host_commands("custom.command, spaced.command,,");
        policy.append_persisted_host_commands("another.command");
        assert!(policy.host_requires_security("custom.command"));
        assert!(policy.host_requires_security("another.command"));
        assert!(policy.host_requires_security(" spaced.command"));
        assert!(!policy.host_requires_security("spaced.command"));
        assert!(policy.host_requires_security(""));
        assert_eq!(policy.core_mode("custom.command"), Mode::Primary);
        assert_eq!(policy.core_mode("wtlogin.login"), Mode::Primary);
        assert!(policy.host_requires_security("wtlogin.login"));
    }
}
