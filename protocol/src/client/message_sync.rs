use super::*;
use crate::message_sync::{self, Action, Binding, Checkpoint, Request, Snapshot};

impl Client {
    pub fn message_sync_snapshot(&self) -> Snapshot {
        self.message_sync.snapshot()
    }

    pub fn message_sync_changes(&self) -> watch::Receiver<()> {
        self.message_sync.subscribe()
    }

    pub fn restore_message_sync_checkpoint(&self, checkpoint: Checkpoint) -> Result<()> {
        let inner = self.inner.lock().unwrap();
        if inner.connection.is_some() || inner.state.online {
            return Err(Error::Unsupported(
                "Restore message checkpoints before connecting".into(),
            ));
        }
        self.message_sync.restore(
            checkpoint,
            inner.state.keystore.uin,
            &inner.state.keystore.uid,
        )
    }

    pub(crate) async fn start_message_sync(
        &self,
        reconnect: bool,
    ) -> Result<(Arc<Binding>, auth::InfoSyncRegisterResponse)> {
        let mut changed = self.message_sync.subscribe();
        let (binding, action) = {
            let inner = self.inner.lock().unwrap();
            if inner.connection.is_none()
                || inner.cancel.is_cancelled()
                || inner.kick_reason.is_some()
            {
                return Err(Error::Disconnected);
            }
            let template = login::info_sync_for_config(&inner.state, reconnect, &self.config)?;
            let (binding, action) =
                self.message_sync
                    .begin(inner.generation, &inner.state, &inner.cancel, template);
            (binding, action)
        };
        self.spawn_message_sync_actions(binding.clone(), vec![action]);
        loop {
            if let Some(result) = self.message_sync.registration(&binding)? {
                return result.map(|registration| (binding, registration));
            }
            tokio::select! {
                biased;
                _ = binding.cancel.cancelled() => return Err(Error::Disconnected),
                result = changed.changed() => result.map_err(|_| Error::Disconnected)?,
            }
        }
    }

    pub(crate) fn confirm_message_sync_online(&self, binding: &Arc<Binding>) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if !sync_current(self, &inner, binding) {
            return Err(Error::Disconnected);
        }
        self.confirm_online_locked(&mut inner, binding.generation)
    }

    pub(crate) fn spawn_message_sync_actions(&self, binding: Arc<Binding>, actions: Vec<Action>) {
        for action in actions {
            let weak = self.weak.clone();
            let binding = binding.clone();
            let task = tokio::spawn(async move {
                tokio::select! {
                    biased;
                    _ = binding.cancel.cancelled() => return,
                    _ = tokio::time::sleep(action.delay) => {},
                }
                let request = {
                    let Some(client) = weak.upgrade() else {
                        return;
                    };
                    let inner = client.inner.lock().unwrap();
                    if !sync_current(&client, &inner, &binding) {
                        return;
                    }
                    let Some(request) = client.message_sync.prepare(&binding, action) else {
                        return;
                    };
                    Arc::new(request)
                };
                let (command, body) = match request.as_ref() {
                    Request::Info { body, .. } => (
                        message_sync::INFO_COMMAND,
                        Bytes::from(body.encode_to_vec()),
                    ),
                    Request::Group { body, .. } => (
                        message_sync::GROUP_COMMAND,
                        Bytes::from(body.encode_to_vec()),
                    ),
                };
                let Err(error) = exchange(
                    weak.clone(),
                    binding.clone(),
                    request.clone(),
                    command,
                    body,
                )
                .await
                else {
                    return;
                };
                let Some(client) = weak.upgrade() else {
                    return;
                };
                let actions = {
                    let inner = client.inner.lock().unwrap();
                    if !sync_current(&client, &inner, &binding) {
                        return;
                    }
                    client.message_sync.direct(&binding, &request, Err(error))
                };
                client.spawn_message_sync_actions(binding, actions);
            });
            self.tasks.lock().unwrap().push(task);
        }
    }
}

fn sync_current(client: &Client, inner: &Inner, binding: &Arc<Binding>) -> bool {
    inner.generation == binding.generation
        && inner.state.keystore.uin == binding.account
        && inner.state.keystore.uid == binding.uid
        && inner.connection.is_some()
        && inner.kick_reason.is_none()
        && !inner.cancel.is_cancelled()
        && client.message_sync.current(binding)
}

struct SyncPending {
    client: Weak<Client>,
    sequence: i32,
    id: u64,
}
impl Drop for SyncPending {
    fn drop(&mut self) {
        let Some(client) = self.client.upgrade() else {
            return;
        };
        let mut inner = client.inner.lock().unwrap();
        if inner
            .pending
            .get(&self.sequence)
            .is_some_and(|pending| pending.id == self.id)
        {
            inner
                .pending
                .remove(&self.sequence)
                .unwrap()
                .cancel
                .cancel();
        }
    }
}

async fn exchange(
    weak: Weak<Client>,
    binding: Arc<Binding>,
    request: Arc<Request>,
    command: &'static str,
    body: Bytes,
) -> Result<()> {
    let (sender, outgoing, receiver, _guard) = {
        let client = weak.upgrade().ok_or(Error::Disconnected)?;
        let deadline = Instant::now()
            .checked_add(client.config.timeout)
            .ok_or(Error::Timeout)?;
        let mut inner = client.inner.lock().unwrap();
        if !sync_current(&client, &inner, &binding) {
            return Err(Error::Disconnected);
        }
        if inner.pending.len() >= 4096 {
            return Err(Error::Unsupported(
                "Too many outstanding SSO requests".into(),
            ));
        }
        let sender = inner.connection.as_ref().unwrap().sender.clone();
        let (sequence, frame) =
            client.prepare_frame(&mut inner, command, body, RequestType::D2, Encryption::D2)?;
        inner.next_id = inner
            .next_id
            .checked_add(1)
            .ok_or_else(|| Error::Unsupported("Request identity space exhausted".into()))?;
        let id = inner.next_id;
        let cancel = binding.cancel.child_token();
        let (reply, receiver) = oneshot::channel();
        let key = inner.state.keystore.d2_key.clone();
        inner.pending.insert(
            sequence,
            Pending {
                id,
                command: command.into(),
                key,
                reply,
                cancel: cancel.clone(),
                message_sync: Some((binding.clone(), request)),
            },
        );
        let outgoing = Outgoing {
            command: command.into(),
            sequence,
            frame,
            deadline,
            cancel,
            required_control: false,
            terminal: false,
        };
        (
            sender,
            outgoing,
            receiver,
            SyncPending {
                client: weak.clone(),
                sequence,
                id,
            },
        )
    };
    let deadline = outgoing.deadline;
    tokio::select! {
        biased;
        _ = binding.cancel.cancelled() => Err(Error::Disconnected),
        result = timeout_at(deadline, async {
            sender.send(outgoing).await.map_err(|_| Error::Disconnected)?;
            receiver.await.map_err(|_| Error::Disconnected)??;
            Ok(())
        }) => result.map_err(|_| Error::Timeout)?,
    }
}
