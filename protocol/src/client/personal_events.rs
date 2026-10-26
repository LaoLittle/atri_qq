use super::*;
use crate::{
    lifecycle::personal_events::{self, COMMAND},
    personal_events::{Binding, Checkpoint, Coordinator, Snapshot},
};

impl Client {
    pub fn personal_events_snapshot(&self) -> Snapshot {
        self.personal_events.snapshot()
    }

    pub fn personal_events_changes(&self) -> watch::Receiver<()> {
        self.personal_events.subscribe()
    }

    pub fn restore_personal_events_checkpoint(&self, checkpoint: Checkpoint) -> Result<()> {
        let inner = self.inner.lock().unwrap();
        if inner.connection.is_some() || inner.state.online {
            return Err(Error::Unsupported(
                "Restore personal event checkpoints before connecting".into(),
            ));
        }
        self.personal_events.restore(
            checkpoint,
            inner.state.keystore.uin,
            &inner.state.keystore.uid,
        )
    }

    pub(crate) async fn sync_personal_events_generation(
        &self,
        generation: u64,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let Some((binding, cursor)) = ({
            let inner = self.inner.lock().unwrap();
            if !Self::current_online(&inner, generation)
                || inner.kick_reason.is_some()
                || cancel.is_cancelled()
            {
                return Err(Error::Disconnected);
            }
            let sync = self.message_sync.snapshot();
            if !sync.first_view_complete
                || sync.checkpoint.account != inner.state.keystore.uin
                || sync.checkpoint.uid != inner.state.keystore.uid
            {
                return Err(Error::Unsupported(
                    "Personal events require completed first-view message sync".into(),
                ));
            }
            self.personal_events.begin(
                generation,
                inner.state.keystore.uin,
                &inner.state.keystore.uid,
                cancel,
            )
        }) else {
            return Ok(());
        };
        let _fetching = FetchingGuard {
            coordinator: &self.personal_events,
            binding: binding.clone(),
        };
        let result = tokio::select! {
            biased;
            _ = binding.cancel.cancelled() => return Err(Error::Disconnected),
            response = self.request_online(generation, COMMAND, personal_events::build(cursor), self.config.timeout) => response.and_then(personal_events::decode),
        };
        let inner = self.inner.lock().unwrap();
        if !Self::current_online(&inner, binding.generation)
            || inner.kick_reason.is_some()
            || inner.state.keystore.uin != binding.account
            || inner.state.keystore.uid != binding.uid
            || binding.cancel.is_cancelled()
        {
            return Err(Error::Disconnected);
        }
        self.personal_events.finish(&binding, result)?;
        Ok(())
    }
}

struct FetchingGuard<'a> {
    coordinator: &'a Coordinator,
    binding: Arc<Binding>,
}

impl Drop for FetchingGuard<'_> {
    fn drop(&mut self) {
        self.coordinator.abort(&self.binding);
    }
}
