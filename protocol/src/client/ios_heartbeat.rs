use super::*;
use crate::heartbeat::{IosResources, IosSource};

impl Client {
    pub fn set_ios_heartbeat_source(&self, source: Option<Arc<dyn IosSource>>) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let ios = inner.ios_mut().ok_or_else(|| {
            Error::Unsupported("iOS heartbeat resources require an iPhone or iPad client".into())
        })?;
        ios.heartbeat_source = source;
        Ok(())
    }

    pub(super) fn ios_heartbeat_time(&self) -> Result<u64> {
        let source = self
            .inner
            .lock()
            .unwrap()
            .ios()
            .and_then(|ios| ios.heartbeat_source.clone());
        match source
            .and_then(|source| source.clock_millis())
            .filter(|millis| *millis != 0)
        {
            Some(millis) => Ok(millis / 1000),
            None => crate::o3::unix_seconds(),
        }
    }

    pub(super) fn heartbeat_body(&self, trigger_time: u64) -> Bytes {
        let source = {
            let inner = self.inner.lock().unwrap();
            inner.ios().and_then(|ios| ios.heartbeat_source.clone())
        };
        let resources = source
            .map(|source| source.resources())
            .unwrap_or_else(IosResources::default);
        auth::HeartbeatRequest {
            r#type: Some(1),
            state: Some(auth::HeartbeatState {
                silence_status: Some(resources.silence_status),
                silent_version: Some(resources.silent_version),
            }),
            battery_status: Some(resources.battery_status),
            trigger_time: Some(trigger_time),
        }
        .encode_to_vec()
        .into()
    }
}
