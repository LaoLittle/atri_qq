use crate::proto;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct IosGuildSyncState {
    pub last_msg_time: Option<u64>,
    pub last_pull_time: Option<u64>,
    pub entries: BTreeMap<u64, u64>,
}

impl IosGuildSyncState {
    pub(crate) fn request(&self) -> proto::guild::GuildMemoryIncrement {
        proto::guild::GuildMemoryIncrement {
            last_msg_time: self.last_msg_time,
            last_pull_time: self.last_pull_time,
            entries: self
                .entries
                .iter()
                .map(|(&guild_id, &cursor)| proto::guild::GuildIncrementEntry {
                    entry_key: Some(guild_id),
                    entry_value: Some(cursor),
                })
                .collect(),
        }
    }
}
