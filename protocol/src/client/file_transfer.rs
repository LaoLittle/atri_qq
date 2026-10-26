use super::*;
use crate::credentials::file_transfer::{self, Binding, FileTransferTicket, Session};

struct Attempt<'a> {
    client: &'a Client,
    session: &'a Arc<Session>,
    active: bool,
}

impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if self.active
            && let Ok(mut inner) = self.client.inner.lock()
        {
            let _ =
                inner
                    .file_transfer
                    .apply(self.session, Err(Error::Disconnected), Instant::now());
        }
    }
}

impl Client {
    pub fn cached_file_transfer_ticket(&self) -> Option<FileTransferTicket> {
        let inner = self.inner.lock().unwrap();
        if !Self::current_online(&inner, inner.generation) {
            return None;
        }
        inner.file_transfer.cached(Instant::now())
    }

    fn file_transfer_binding(&self) -> Result<Arc<Binding>> {
        let mut inner = self.inner.lock().unwrap();
        if !Self::current_online(&inner, inner.generation) {
            return Err(Error::Disconnected);
        }
        if let Ok(binding) = inner.file_transfer.binding() {
            return Ok(binding);
        }
        let binding = Arc::new(Binding::new(
            inner.generation,
            inner.state.keystore.uin,
            inner.state.keystore.uid.clone(),
            Bytes::copy_from_slice(&inner.state.keystore.a2),
            inner
                .state
                .keystore
                .guid
                .as_slice()
                .try_into()
                .map_err(|_| {
                    wire::malformed("File transfer requires a sixteen-byte machine GUID")
                })?,
            &inner.cancel,
        )?);
        inner.file_transfer.activate(binding)
    }

    pub async fn file_transfer_ticket(&self) -> Result<FileTransferTicket> {
        if let Some(ticket) = self.cached_file_transfer_ticket() {
            return Ok(ticket);
        }
        let binding = self.file_transfer_binding()?;
        let ticket = self
            .refresh_file_transfer(&binding, true)
            .await?
            .ok_or_else(|| Error::Authentication("File transfer ticket was not acquired".into()))?;
        self.start_file_transfer_work(binding);
        Ok(ticket)
    }

    pub(super) fn file_transfer_current(inner: &Inner, binding: &Arc<Binding>) -> bool {
        Self::current_online(inner, binding.generation)
            && inner.state.keystore.uin == binding.uin
            && inner.state.keystore.uid == binding.uid
            && inner.file_transfer.is_current(binding)
    }

    async fn refresh_file_transfer(
        &self,
        binding: &Arc<Binding>,
        demand: bool,
    ) -> Result<Option<FileTransferTicket>> {
        let _gate = tokio::select! {
            biased;
            _ = binding.cancel.cancelled() => return Err(Error::Disconnected),
            gate = self.file_transfer_gate.lock() => gate,
        };
        let session = {
            let mut inner = self.inner.lock().unwrap();
            if !Self::file_transfer_current(&inner, binding) {
                return Err(Error::Disconnected);
            }
            let now = Instant::now();
            if demand {
                if let Some(ticket) = inner.file_transfer.cached(now) {
                    return Ok(Some(ticket));
                }
                inner.file_transfer.enable(now)?;
            }
            let Some(session) = inner.file_transfer.take_due(now)? else {
                return Ok(inner.file_transfer.cached(now));
            };
            session
        };
        let mut attempt = Attempt {
            client: self,
            session: &session,
            active: true,
        };
        let response = async {
            let body = file_transfer::build(&session)?;
            let bytes = self
                .request_inner(
                    file_transfer::COMMAND,
                    body,
                    RequestType::D2,
                    Encryption::D2,
                    self.config.timeout,
                    Some(RequestBinding::FileTransfer(binding)),
                )
                .await?;
            file_transfer::decode(bytes)
        }
        .await;
        let result =
            self.inner
                .lock()
                .unwrap()
                .file_transfer
                .apply(&session, response, Instant::now());
        attempt.active = false;
        self.file_transfer_work.notify_one();
        result.map(Some)
    }

    fn start_file_transfer_work(&self, binding: Arc<Binding>) {
        {
            let mut inner = self.inner.lock().unwrap();
            if !Self::file_transfer_current(&inner, &binding)
                || inner
                    .file_transfer_worker
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, &binding))
            {
                return;
            }
            inner.file_transfer_worker = Some(binding.clone());
        }
        let weak = self.weak.clone();
        let notify = self.file_transfer_work.clone();
        let task = tokio::spawn(async move {
            loop {
                let notified = notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                let Some(client) = weak.upgrade() else { return };
                let deadline = {
                    let inner = client.inner.lock().unwrap();
                    if !Self::file_transfer_current(&inner, &binding) {
                        return;
                    }
                    inner.file_transfer.next_due()
                };
                if deadline.is_some_and(|deadline| deadline <= Instant::now()) {
                    let result = client.refresh_file_transfer(&binding, false).await;
                    if let Err(error) = result
                        && !binding.cancel.is_cancelled()
                    {
                        tracing::warn!(%error, "File transfer ticket refresh failed; retaining valid cached credentials");
                    }
                    continue;
                }
                drop(client);
                tokio::select! {
                    biased;
                    _ = binding.cancel.cancelled() => return,
                    _ = &mut notified => {},
                    _ = tokio::time::sleep_until(deadline.unwrap_or_else(Instant::now)), if deadline.is_some() => {},
                }
            }
        });
        self.tasks.lock().unwrap().push(task);
    }
}
