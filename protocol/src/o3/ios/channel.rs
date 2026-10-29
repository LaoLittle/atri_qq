use super::{CheckMode, EstablishRequest};
use crate::{
    Error, Result,
    o3::{ACCESS_COMMAND, ESTABLISH_COMMAND, channel::merge_bytes, crypto},
    proto::o3 as pb,
};
use bytes::Bytes;
use prost::Message;
use rand::{TryRng, rngs::SysRng};
use std::{
    collections::{HashMap, VecDeque},
    num::Wrapping,
    sync::Arc,
    time::Duration,
};
use tokio::time::Instant;

pub struct Channel {
    peer: [u8; 33],
    identifier: [u8; 66],
    mode: CheckMode,
    scope: Wrapping<u64>,
    origin: Instant,
    current: Option<Current>,
    history: VecDeque<Arc<Material>>,
    unavailable: HashMap<Bytes, (Duration, u64)>,
    switches: [Option<u32>; 9],
    unresolved_defaults: bool,
}

struct Material {
    key: [u8; 32],
    public: [u8; 33],
    peer: [u8; 33],
    uuid: [u8; 32],
    parameter: u64,
}

struct Current {
    material: Arc<Material>,
    authenticated: bool,
    wall_deadline: u64,
    steady_deadline: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Establish,
    Access,
}

pub struct Request {
    pub body: Bytes,
    method: Bytes,
    material: Arc<Material>,
    scope: u64,
    mode: Mode,
}

impl Request {
    pub fn command(&self, account_selected: bool) -> &'static str {
        match (self.mode, account_selected) {
            (Mode::Establish, false) => ESTABLISH_COMMAND,
            (Mode::Access, false) => ACCESS_COMMAND,
            (Mode::Establish, true) => "trpc.o3.ecdh_access.EcdhAccess.SsoSecureA2Establish",
            (Mode::Access, true) => "trpc.o3.ecdh_access.EcdhAccess.SsoSecureA2Access",
        }
    }
}

pub struct Reply {
    pub body: Bytes,
    pub extra: Bytes,
    pub switch_update: Option<SwitchUpdate>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwitchUpdate {
    pub values: [Option<u32>; 9],
    pub unresolved_native_defaults: bool,
}

#[derive(Clone, Copy)]
struct Clock {
    wall: u64,
    steady: Duration,
}

impl Channel {
    pub fn new(mode: CheckMode) -> Self {
        Self::with_peer(mode, crypto::PEER_PUBLIC_KEY)
    }

    pub(crate) fn with_peer(mode: CheckMode, peer: [u8; 33]) -> Self {
        let mut identifier = *crypto::KEY_IDENTIFIER;
        if peer != crypto::PEER_PUBLIC_KEY {
            hex::encode_to_slice(crypto::encode_peer(&peer), &mut identifier)
                .expect("fixed-width O3 peer identifier");
        }
        Self {
            peer,
            identifier,
            mode,
            scope: Wrapping(0),
            origin: Instant::now(),
            current: None,
            history: VecDeque::new(),
            unavailable: HashMap::new(),
            switches: [None; 9],
            unresolved_defaults: false,
        }
    }

    pub fn reset(&mut self) {
        self.scope += Wrapping(1);
        self.current = None;
        self.history.clear();
        self.unavailable.clear();
        self.switches = [None; 9];
        self.unresolved_defaults = false;
    }

    pub fn channel_state(&self) -> Option<&[u8; 32]> {
        self.current.as_ref().map(|current| &current.material.uuid)
    }

    pub fn take_switch_update(&mut self) -> Option<SwitchUpdate> {
        if self.switches.iter().all(Option::is_none) {
            return None;
        }
        Some(SwitchUpdate {
            values: std::mem::replace(&mut self.switches, [None; 9]),
            unresolved_native_defaults: std::mem::take(&mut self.unresolved_defaults),
        })
    }

    fn clock(&self) -> Result<Clock> {
        Ok(Clock {
            wall: crate::o3::unix_seconds()?,
            steady: self.origin.elapsed(),
        })
    }

    pub fn prepare(&mut self, method: &str, body: Bytes) -> Result<Request> {
        self.prepare_at(method, body, self.clock()?)
    }

    fn prepare_at(&mut self, method: &str, body: Bytes, now: Clock) -> Result<Request> {
        if let Some(&(started, seconds)) = self.unavailable.get(method.as_bytes()) {
            if now.steady.saturating_sub(started).as_nanos() < u128::from(seconds) * 1_000_000_000 {
                return Err(unavailable());
            }
            self.unavailable.remove(method.as_bytes());
        }
        if self.current.as_ref().is_some_and(|current| {
            now.wall > current.wall_deadline && now.steady.as_secs() > current.steady_deadline
        }) {
            self.retire();
        }
        if self.current.is_none() {
            let agreement = crypto::Agreement::new(&self.peer)?;
            let mut random = [0; 40];
            SysRng
                .try_fill_bytes(&mut random)
                .map_err(|error| Error::Crypto(format!("iOS O3 entropy unavailable: {error}")))?;
            self.current = Some(Current {
                material: Arc::new(Material {
                    key: agreement.key,
                    public: agreement.public,
                    peer: self.peer,
                    uuid: random[..32].try_into().unwrap(),
                    parameter: u64::from_le_bytes(random[32..].try_into().unwrap()),
                }),
                authenticated: false,
                wall_deadline: u64::MAX,
                steady_deadline: u64::MAX,
            });
        }
        let current = self.current.as_ref().unwrap();
        let material = current.material.clone();
        let method = Bytes::copy_from_slice(method.as_bytes());
        let uuid = Bytes::copy_from_slice(&material.uuid);
        let (mode, body) = if current.authenticated {
            let encrypted_body = crypto::seal(&material.key, &body)?;
            let encoded = pb::SecureAccessRequest {
                method: method.clone(),
                encrypted_body,
                channel_uuid: uuid,
            }
            .encode_to_vec()
            .into();
            (Mode::Access, encoded)
        } else {
            let plaintext = pb::ChannelPlaintext {
                parameter: material.parameter,
                body,
                uuid: uuid.clone(),
            }
            .encode_to_vec();
            let encoded = EstablishRequest {
                method: method.clone(),
                client_public_key: Bytes::copy_from_slice(&material.public),
                local_hkdf_succeeded: true,
                key_identifier: Bytes::copy_from_slice(&self.identifier),
                encrypted_body: crypto::seal(&material.key, &plaintext)?,
                channel_uuid: uuid,
            }
            .encode(self.mode)?;
            (Mode::Establish, encoded)
        };
        Ok(Request {
            body,
            method,
            material,
            scope: self.scope.0,
            mode,
        })
    }

    fn retire(&mut self) {
        if let Some(current) = self.current.take() {
            if self.history.len() == 50 {
                self.history.pop_back();
            }
            self.history.push_front(current.material);
        }
    }

    pub fn complete(&mut self, request: Request, response: Bytes) -> Result<Reply> {
        self.complete_at(request, response, self.clock()?)
    }

    fn complete_at(&mut self, request: Request, response: Bytes, now: Clock) -> Result<Reply> {
        if request.scope != self.scope.0 {
            return Err(Error::Authentication("Stale iOS O3 request scope".into()));
        }
        let (status, duration, encrypted, extra) = match request.mode {
            Mode::Establish => {
                let outer = pb::IosEstablishShareKeyResponse::decode(response)?;
                (
                    outer.status,
                    outer.unavailable_duration_seconds,
                    merge_bytes(outer.encrypted_body),
                    Bytes::new(),
                )
            }
            Mode::Access => {
                let outer = pb::IosSecureAccessResponse::decode(response)?;
                (
                    outer.status,
                    outer.unavailable_duration_seconds,
                    merge_bytes(outer.encrypted_body),
                    merge_bytes(outer.extra),
                )
            }
        };
        if duration != 0 {
            self.unavailable
                .insert(request.method, (now.steady, duration));
            return Err(unavailable());
        }
        let current = self
            .current
            .as_ref()
            .is_some_and(|current| current.material.uuid == request.material.uuid);
        if status != 0 {
            let code = match status {
                1000..=1004 | 2000 => status,
                _ => 2000,
            };
            if current && code != 1003 {
                self.retire();
            }
            return Err(Error::Server {
                code: code as i32,
                message: format!("iOS O3 server status {status}"),
            });
        }
        let material = if current {
            self.current.as_ref().unwrap().material.clone()
        } else {
            self.history
                .iter()
                .find(|material| material.uuid == request.material.uuid)
                .cloned()
                .ok_or_else(|| Error::Authentication("Unknown iOS O3 channel UUID".into()))?
        };
        if encrypted.len() <= 28 {
            return Err(Error::Crypto(
                "iOS O3 response has no encrypted business payload".into(),
            ));
        }
        let plaintext = crypto::open(&material.key, &encrypted)?;
        if request.mode == Mode::Access {
            return Ok(Reply {
                body: plaintext,
                extra,
                switch_update: None,
            });
        }
        let inner = pb::IosEstablishInnerResponse::decode(plaintext)?;
        if current {
            let channel = self.current.as_mut().unwrap();
            channel.wall_deadline = inner.channel_time;
            channel.steady_deadline = (Wrapping(now.steady.as_secs()) + Wrapping(60)).0;
            self.apply_config(inner.config.as_ref());
        }
        let authenticated = current && self.current.as_ref().unwrap().authenticated;
        if !authenticated {
            crypto::authenticate(
                &material.peer,
                material.parameter,
                inner.parameter,
                &merge_bytes(inner.material),
            )?;
            if current {
                self.current.as_mut().unwrap().authenticated = true;
            }
        }
        Ok(Reply {
            body: merge_bytes(inner.business_response),
            extra,
            switch_update: None,
        })
    }

    fn apply_config(&mut self, config: Option<&pb::IosChannelConfig>) {
        let default = pb::IosChannelConfig::default();
        let config = config.unwrap_or(&default);
        if config.skip_update != 0 {
            return;
        }
        self.unresolved_defaults |= config.option1.is_none() || config.option2.is_none();
        let values = [
            config.option1,
            config.option2,
            Some(config.option3.unwrap_or(0)),
            Some(config.option4.unwrap_or(2)),
            Some(config.option5.unwrap_or(0)),
            Some(config.option6.unwrap_or(0)),
            Some(config.option7.unwrap_or(0)),
            Some(config.option8.unwrap_or(0)),
            Some(config.option9.unwrap_or(0)),
        ];
        for (saved, value) in self.switches.iter_mut().zip(values) {
            if let Some(value) = value {
                *saved = Some(value.min(2));
            }
        }
    }
}

fn unavailable() -> Error {
    Error::Server {
        code: 1999,
        message: "iOS O3 business temporarily unavailable".into(),
    }
}

#[cfg(test)]
mod tests;
