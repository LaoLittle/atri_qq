use super::*;

impl Client {
    pub(super) fn sync_ios_guild_cursor(&self, generation: u64) {
        let mut inner = self.inner.lock().unwrap();
        if inner.generation != generation || !inner.signer.has_ios_virtual_device() {
            return;
        }
        let uin = inner.state.keystore.uin;
        if uin == 0 {
            return;
        }
        let Some(device) = &mut inner.state.keystore.ios_virtual_state else {
            return;
        };
        let Some(mut cursor) = self.guild_session.take_ios_cursor(generation) else {
            return;
        };
        if let Some(previous) = device.guild_sync.get(&uin) {
            cursor.last_msg_time = match (previous.last_msg_time, cursor.last_msg_time) {
                (Some(previous), Some(current)) => Some(previous.max(current)),
                (previous, current) => current.or(previous),
            };
            cursor.last_pull_time = cursor.last_pull_time.or(previous.last_pull_time);
            if previous == &cursor {
                return;
            }
        }
        device.guild_sync.insert(uin, cursor);
        self.emit(LoginEvent::KeystoreChanged(inner.state.keystore.clone()));
    }
}
