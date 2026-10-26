use crate::{Error, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    FirstViewPersonalEvents,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageBoxEvent {
    pub source: Source,
    pub event_type: Option<u64>,
    pub message_seq: Option<u64>,
    pub field_3: Option<u64>,
    pub field_4: Option<u64>,
    pub field_5: Option<u64>,
    pub raw: Bytes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupEvents {
    pub group_uin: u64,
    pub events: Vec<Arc<MessageBoxEvent>>,
    pub raw: Bytes,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GroupMessageBox {
    pub events: BTreeMap<u64, BTreeMap<u64, Arc<MessageBoxEvent>>>,
    pub unclassified_events: Vec<Arc<MessageBoxEvent>>,
    pub last_raw_groups: Vec<Bytes>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Checkpoint {
    pub account: u64,
    pub uid: String,
    pub cursor: Option<Bytes>,
    pub groups: BTreeMap<u64, GroupMessageBox>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Batch {
    pub generation: u64,
    pub account: u64,
    pub uid: String,
    pub source: Source,
    pub groups: Vec<GroupEvents>,
    pub raw_response: Bytes,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub checkpoint: Checkpoint,
    pub last_batch: Option<Arc<Batch>>,
    pub generation: Option<u64>,
    pub fetching: bool,
    pub complete: bool,
}

pub(crate) struct Binding {
    pub generation: u64,
    pub account: u64,
    pub uid: String,
    pub cancel: CancellationToken,
}

pub(crate) struct Decoded {
    pub cursor: Option<Bytes>,
    pub groups: Vec<GroupEvents>,
    pub raw_response: Bytes,
}

#[derive(Default)]
struct State {
    snapshot: Snapshot,
    binding: Option<Arc<Binding>>,
}

pub(crate) struct Coordinator {
    state: Mutex<State>,
    changed: watch::Sender<()>,
}

impl Default for Coordinator {
    fn default() -> Self {
        let (changed, _) = watch::channel(());
        Self {
            state: Mutex::new(State::default()),
            changed,
        }
    }
}

impl Coordinator {
    pub fn snapshot(&self) -> Snapshot {
        self.state.lock().unwrap().snapshot.clone()
    }

    pub fn subscribe(&self) -> watch::Receiver<()> {
        self.changed.subscribe()
    }

    pub fn replace_identity(&self, account: u64, uid: &str) {
        let mut state = self.state.lock().unwrap();
        if state.snapshot.checkpoint.account == account && state.snapshot.checkpoint.uid == uid {
            return;
        }
        if let Some(binding) = state.binding.take() {
            binding.cancel.cancel();
        }
        state.snapshot = Snapshot {
            checkpoint: Checkpoint {
                account,
                uid: uid.into(),
                ..Default::default()
            },
            ..Default::default()
        };
        self.changed.send_replace(());
    }

    pub fn cancel(&self) {
        let mut state = self.state.lock().unwrap();
        if let Some(binding) = state.binding.take() {
            binding.cancel.cancel();
        }
        state.snapshot.fetching = false;
        state.snapshot.complete = false;
        state.snapshot.generation = None;
        self.changed.send_replace(());
    }

    pub fn restore(&self, checkpoint: Checkpoint, account: u64, uid: &str) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        if state.binding.is_some() || checkpoint.account != account || checkpoint.uid != uid {
            return Err(Error::Authentication(
                "Personal event checkpoint does not match an inactive account".into(),
            ));
        }
        state.snapshot = Snapshot {
            checkpoint,
            ..Default::default()
        };
        self.changed.send_replace(());
        Ok(())
    }

    pub fn begin(
        &self,
        generation: u64,
        account: u64,
        uid: &str,
        cancel: &CancellationToken,
    ) -> Option<(Arc<Binding>, Option<Bytes>)> {
        let mut state = self.state.lock().unwrap();
        if cancel.is_cancelled() {
            return None;
        }
        if state.binding.as_ref().is_some_and(|binding| {
            binding.generation == generation
                && binding.account == account
                && binding.uid == uid
                && !binding.cancel.is_cancelled()
        }) {
            return None;
        }
        if let Some(previous) = state.binding.take() {
            previous.cancel.cancel();
        }
        if state.snapshot.checkpoint.account != account || state.snapshot.checkpoint.uid != uid {
            state.snapshot = Snapshot {
                checkpoint: Checkpoint {
                    account,
                    uid: uid.into(),
                    ..Default::default()
                },
                ..Default::default()
            };
        }
        let binding = Arc::new(Binding {
            generation,
            account,
            uid: uid.into(),
            cancel: cancel.child_token(),
        });
        let cursor = state.snapshot.checkpoint.cursor.clone();
        state.snapshot.generation = Some(generation);
        state.snapshot.fetching = true;
        state.snapshot.complete = false;
        state.binding = Some(binding.clone());
        self.changed.send_replace(());
        Some((binding, cursor))
    }

    fn current(state: &State, binding: &Arc<Binding>) -> bool {
        !binding.cancel.is_cancelled()
            && state
                .binding
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, binding))
            && state.snapshot.checkpoint.account == binding.account
            && state.snapshot.checkpoint.uid == binding.uid
    }

    pub fn abort(&self, binding: &Arc<Binding>) {
        let mut state = self.state.lock().unwrap();
        if state
            .binding
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, binding))
            && state.snapshot.fetching
        {
            state.snapshot.fetching = false;
            self.changed.send_replace(());
        }
    }

    pub fn finish(&self, binding: &Arc<Binding>, result: Result<Decoded>) -> Result<Arc<Batch>> {
        let mut state = self.state.lock().unwrap();
        if !Self::current(&state, binding) || !state.snapshot.fetching {
            return Err(Error::Disconnected);
        }
        state.snapshot.fetching = false;
        let decoded = match result {
            Ok(decoded) => decoded,
            Err(error) => {
                self.changed.send_replace(());
                return Err(error);
            }
        };
        let batch = Arc::new(Batch {
            generation: binding.generation,
            account: binding.account,
            uid: binding.uid.clone(),
            source: Source::FirstViewPersonalEvents,
            groups: decoded.groups,
            raw_response: decoded.raw_response,
        });
        let mut raw_groups: BTreeMap<u64, Vec<Bytes>> = BTreeMap::new();
        for group in &batch.groups {
            raw_groups
                .entry(group.group_uin)
                .or_default()
                .push(group.raw.clone());
            let message_box = state
                .snapshot
                .checkpoint
                .groups
                .entry(group.group_uin)
                .or_default();
            for event in &group.events {
                if let (Some(event_type), Some(sequence)) = (event.event_type, event.message_seq) {
                    message_box
                        .events
                        .entry(event_type)
                        .or_default()
                        .insert(sequence, event.clone());
                } else {
                    message_box.unclassified_events.push(event.clone());
                }
            }
        }
        for (group_uin, raw) in raw_groups {
            state
                .snapshot
                .checkpoint
                .groups
                .get_mut(&group_uin)
                .unwrap()
                .last_raw_groups = raw;
        }
        if let Some(cursor) = decoded.cursor {
            state.snapshot.checkpoint.cursor = Some(cursor);
        }
        state.snapshot.last_batch = Some(batch.clone());
        state.snapshot.complete = true;
        self.changed.send_replace(());
        Ok(batch)
    }
}
