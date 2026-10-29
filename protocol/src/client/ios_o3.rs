use super::*;
use crate::o3::ios::{Channel, CheckMode, Reply};
use signing_engine::ios::token::{NativePayload, TOKEN_BUSINESS, TokenPersistence};

pub(super) struct Binding {
    generation: u64,
    signing_generation: u64,
    account: u64,
    cancel: CancellationToken,
}

impl Binding {
    fn capture(inner: &Inner) -> Result<Self> {
        if !inner.state.profile.platform.is_ios() {
            return Err(Error::Unsupported(
                "Mobile O3 requires an iPhone or iPad client".into(),
            ));
        }
        if inner.connection.is_none() || inner.cancel.is_cancelled() || inner.kick_reason.is_some()
        {
            return Err(Error::Disconnected);
        }
        Ok(Self {
            generation: inner.generation,
            signing_generation: inner.signer.generation(),
            account: inner.state.keystore.uin,
            cancel: inner.signing_cancel.clone(),
        })
    }

    pub(super) fn is_current(&self, inner: &Inner) -> bool {
        !self.cancel.is_cancelled()
            && !inner.cancel.is_cancelled()
            && inner.connection.is_some()
            && inner.state.profile.platform.is_ios()
            && inner.generation == self.generation
            && inner.signer.generation() == self.signing_generation
            && inner.state.keystore.uin == self.account
    }
}

impl Client {
    pub(super) fn start_ios_signing_work(&self, generation: u64) {
        let cancel = {
            let inner = self.inner.lock().unwrap();
            if inner.generation != generation || !inner.signer.has_ios_virtual_device() {
                return;
            }
            inner.cancel.clone()
        };
        let weak = self.weak.clone();
        let notify = self.signing_work.clone();
        let task = tokio::spawn(async move {
            let mut pending = FuturesUnordered::new();
            loop {
                let notified = notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                let Some(client) = weak.upgrade() else { return };
                let requests = {
                    let mut inner = client.inner.lock().unwrap();
                    if inner.generation != generation || inner.connection.is_none() || cancel.is_cancelled() {
                        return;
                    }
                    let Inner { state, signer, .. } = &mut *inner;
                    signer.drain_ios_token_requests(state)
                };
                for request in requests {
                    let binding = {
                        let inner = client.inner.lock().unwrap();
                        if inner.signer.generation() != request.generation {
                            continue;
                        }
                        let Ok(binding) = Binding::capture(&inner) else { continue };
                        binding
                    };
                    let weak = weak.clone();
                    pending.push(async move {
                        let Some(client) = weak.upgrade() else { return };
                        if let Err(error) = client.submit_ios_token(binding, request.body, request.submission).await {
                            if !matches!(error, Error::Disconnected) {
                                tracing::warn!(%error, "Mobile token refresh failed; retaining the previous record");
                            }
                        }
                    });
                }
                drop(client);
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return,
                    _ = pending.next(), if !pending.is_empty() => {},
                    _ = &mut notified => {},
                }
            }
        });
        self.tasks.lock().unwrap().push(task);
    }

    pub async fn request_ios_o3(&self, method: &str, body: Bytes) -> Result<Reply> {
        let binding = Binding::capture(&self.inner.lock().unwrap())?;
        self.request_ios_o3_bound(&binding, method, body).await
    }

    async fn request_ios_o3_bound(
        &self,
        binding: &Binding,
        method: &str,
        body: Bytes,
    ) -> Result<Reply> {
        let request = {
            let mut inner = self.inner.lock().unwrap();
            if !binding.is_current(&inner) {
                return Err(Error::Disconnected);
            }
            inner
                .ios_o3
                .get_or_insert_with(|| Channel::new(CheckMode::Sdk))
                .prepare(method, body)?
        };
        let response = tokio::select! {
            biased;
            _ = binding.cancel.cancelled() => return Err(Error::Disconnected),
            response = self.request_inner(
                request.command(binding.account != 0),
                request.body.clone(),
                RequestType::D2,
                Encryption::D2,
                Duration::from_secs(15),
                Some(RequestBinding::IosO3(binding)),
            ) => response?,
        };
        let mut inner = self.inner.lock().unwrap();
        if !binding.is_current(&inner) {
            return Err(Error::Disconnected);
        }
        let channel = inner.ios_o3.as_mut().unwrap();
        let result = channel.complete(request, response);
        let update = channel.take_switch_update();
        if let Some(update) = &update {
            inner.signer.apply_ios_switches(update);
            if update.unresolved_native_defaults {
                tracing::warn!(
                    "Mobile O3 config omitted switches with no deterministic native default; retaining their previous values"
                );
            }
        }
        result.map(|mut reply| {
            reply.switch_update = update;
            reply
        })
    }

    pub fn create_ios_native_payload(
        &self,
        fingerprint: [u8; 32],
    ) -> Result<signing_engine::ios::token::NativePayloadResources> {
        let now = crate::o3::unix_seconds()?;
        let mut inner = self.inner.lock().unwrap();
        let Inner { signer, state, .. } = &mut *inner;
        signer.create_ios_native_payload(state, fingerprint, now)
    }

    pub fn create_ios_token_request(
        &self,
        properties: &BTreeMap<i32, Bytes>,
        payload: NativePayload,
    ) -> Result<signing_engine::ios::token::DeviceTokenRequest> {
        let mut inner = self.inner.lock().unwrap();
        let Inner { signer, state, .. } = &mut *inner;
        signer.create_ios_token_request(state, properties, payload)
    }

    pub async fn refresh_ios_token(
        &self,
        properties: &BTreeMap<i32, Bytes>,
        payload: NativePayload,
    ) -> Result<Option<TokenPersistence>> {
        let (binding, body, submission) = {
            let mut inner = self.inner.lock().unwrap();
            let binding = Binding::capture(&inner)?;
            let now = crate::o3::unix_seconds()?;
            let Inner { signer, state, .. } = &mut *inner;
            let (body, submission) = signer.prepare_ios_token(state, properties, payload, now)?;
            (binding, body, submission)
        };
        self.submit_ios_token(binding, body, submission).await
    }

    async fn submit_ios_token(
        &self,
        binding: Binding,
        body: Bytes,
        submission: signing_engine::ios::token::TokenSubmission,
    ) -> Result<Option<TokenPersistence>> {
        let response = self
            .request_ios_o3_bound(&binding, TOKEN_BUSINESS, body)
            .await
            .map(|reply| reply.body);
        let mut inner = self.inner.lock().unwrap();
        if !binding.is_current(&inner) {
            return Err(Error::Disconnected);
        }
        let persistence = inner.signer.complete_ios_token(&submission, response)?;
        if persistence.is_some() && inner.signer.has_ios_virtual_device() {
            let record = inner.signer.ios_token_record().unwrap().clone();
            if let Some(device) = &mut inner.state.keystore.ios_virtual_state {
                if device.token != record {
                    device.token = record;
                    self.emit(LoginEvent::KeystoreChanged(inner.state.keystore.clone()));
                }
            }
        }
        Ok(persistence)
    }

    pub fn ios_signing_resources_snapshot(&self) -> Result<crate::signing::IosSigningResources> {
        self.inner.lock().unwrap().signer.ios_resources_snapshot()
    }
}

#[cfg(test)]
mod tests;
