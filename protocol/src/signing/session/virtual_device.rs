use super::{Backend, IosSession, SessionSigner, ios_token};
use crate::{Error, Result, ios_device::IosVirtualRuntime, models::SessionState};
use bytes::Bytes;
use prost::Message;
use rand::TryRng;
use std::collections::VecDeque;

pub(super) struct VirtualSdk {
    device: IosVirtualRuntime,
    initialized: bool,
    host_account: Option<u64>,
    collectors: usize,
    requests: VecDeque<IosTokenRequest>,
}

pub(crate) struct IosTokenRequest {
    pub(crate) generation: u64,
    pub(crate) body: Bytes,
    pub(crate) submission: ios_token::TokenSubmission,
}

impl IosSession {
    pub(super) fn native_payload_resources(
        &mut self,
        state: &SessionState,
        fingerprint: [u8; 32],
        now: u64,
    ) -> Result<ios_token::NativePayloadResources> {
        self.initialize(state)?;
        let material = match self.native_material {
            Some(material) => material,
            None => {
                let mut material = [0; 16];
                rand::rngs::SysRng
                    .try_fill_bytes(&mut material)
                    .map_err(|error| {
                        Error::Crypto(format!("iOS token entropy unavailable: {error}"))
                    })?;
                self.native_material = Some(material);
                material
            }
        };
        Ok(ios_token::NativePayloadResources {
            material,
            material_seed: 0,
            fingerprint,
            unix_seconds: now,
            process_id: std::process::id() as i32,
            allocation_low32: None,
        })
    }

    fn collect_virtual_token(&mut self, state: &SessionState) -> Result<()> {
        let mut sdk = self
            .virtual_device
            .take()
            .expect("virtual collector was registered");
        let result = (|| {
            let micros = u64::try_from(self.source.unix_micros()?).map_err(|_| {
                Error::Malformed("Virtual iOS collection precedes Unix epoch".into())
            })?;
            let persisted = state.keystore.ios_virtual_state.as_ref().ok_or_else(|| {
                Error::Malformed("Virtual iOS device lost its persistent state".into())
            })?;
            let payload = if self.sdk.policy.switch(46) == 1 {
                ios_token::NativePayload::Generate(self.native_payload_resources(
                    state,
                    sdk.device.fingerprint(),
                    micros / 1_000_000,
                )?)
            } else {
                ios_token::NativePayload::Disabled
            };
            let properties = sdk.device.collect(persisted, micros, &self.sdk.policy);
            self.validate_token_request(properties, &payload)?;
            let body = self
                .token_request(properties, payload)
                .encode_to_vec()
                .into();
            let submission = self.token_state.capture_submission();
            sdk.requests.push_back(IosTokenRequest {
                generation: self.generation,
                body,
                submission,
            });
            Ok(())
        })();
        self.virtual_device = Some(sdk);
        self.token_state.collection_worker_exited();
        result
    }

    fn request_virtual_refresh(&mut self, state: &SessionState, force: bool) -> Result<bool> {
        if self.virtual_device.is_none()
            || !self
                .token_state
                .begin_refresh(crate::o3::unix_seconds()?, force)
        {
            return Ok(false);
        }
        if self.sdk.policy.switch(37) == 1 {
            self.virtual_device.as_mut().unwrap().collectors += 1;
        } else {
            self.collect_virtual_token(state)?;
        }
        Ok(true)
    }

    pub(super) fn before_virtual_sign(&mut self, state: &SessionState) {
        let Some(sdk) = &mut self.virtual_device else {
            return;
        };
        let initialize = !sdk.initialized;
        sdk.initialized = true;
        if initialize {
            if let Err(error) = self.request_virtual_refresh(state, false) {
                tracing::warn!(%error,"Mobile token initialization collection failed");
            }
        }
        if self.sdk.policy.switch(1) == 1 {
            match crate::o3::unix_seconds() {
                Ok(now)
                    if self
                        .token_state
                        .record()
                        .needs_refresh_at(now, self.token_state.current_uin()) =>
                {
                    if let Err(error) = self.request_virtual_refresh(state, false) {
                        tracing::warn!(%error,"Mobile signing token collection failed");
                    }
                }
                Err(error) => tracing::warn!(%error,"Mobile signing token time is unavailable"),
                _ => {}
            }
        }
    }

    pub(super) fn after_virtual_sign(&mut self, state: &SessionState) {
        let Some(sdk) = &mut self.virtual_device else {
            return;
        };
        if sdk.host_account == Some(state.keystore.uin) {
            return;
        }
        sdk.host_account = Some(state.keystore.uin);
        if let Err(error) = self.request_virtual_refresh(state, false) {
            tracing::warn!(%error,"Mobile host context token collection failed");
        }
    }
}

impl SessionSigner {
    pub(crate) fn enable_ios_virtual(&mut self, device: IosVirtualRuntime) -> Result<()> {
        let Backend::Ios(session) = &mut self.backend else {
            return Err(Error::Unsupported(
                "Virtual iOS collection requires an iPhone or iPad signing session".into(),
            ));
        };
        session.virtual_device = Some(VirtualSdk {
            device,
            initialized: false,
            host_account: None,
            collectors: 0,
            requests: VecDeque::new(),
        });
        Ok(())
    }

    pub(crate) fn has_ios_virtual_device(&self) -> bool {
        matches!(&self.backend,Backend::Ios(session) if session.virtual_device.is_some())
    }

    pub(crate) fn ios_background_since(&self) -> Option<u64> {
        match &self.backend {
            Backend::Ios(session) => session
                .virtual_device
                .as_ref()
                .and_then(|sdk| sdk.device.background_since()),
            Backend::Desktop(_) => None,
        }
    }

    pub(crate) fn drain_ios_token_requests(
        &mut self,
        state: &SessionState,
    ) -> Vec<IosTokenRequest> {
        let Backend::Ios(session) = &mut self.backend else {
            return Vec::new();
        };
        let Some(sdk) = &mut session.virtual_device else {
            return Vec::new();
        };
        let collectors = std::mem::take(&mut sdk.collectors);
        for _ in 0..collectors {
            if let Err(error) = session.collect_virtual_token(state) {
                tracing::warn!(%error,"Mobile asynchronous token collection failed");
            }
        }
        session
            .virtual_device
            .as_mut()
            .unwrap()
            .requests
            .drain(..)
            .filter(|request| request.generation == session.generation)
            .collect()
    }

    pub(crate) fn update_ios_logged_accounts(
        &mut self,
        state: &SessionState,
        accounts: &[&str],
    ) -> Result<()> {
        let Backend::Ios(session) = &mut self.backend else {
            return Err(Error::Unsupported(
                "Logged iOS accounts require an iOS signing session".into(),
            ));
        };
        let sdk = session.virtual_device.as_mut().ok_or_else(|| Error::Unsupported("Automatic iOS collection requires a virtual device; snapshot mode owns its collected properties".into()))?;
        sdk.device.update_logged_accounts(accounts);
        session.request_virtual_refresh(state, true)?;
        Ok(())
    }

    pub(crate) fn ios_token_record(&self) -> Option<&ios_token::TokenRecord> {
        match &self.backend {
            Backend::Ios(session) => Some(session.token_state.record()),
            Backend::Desktop(_) => None,
        }
    }
}
