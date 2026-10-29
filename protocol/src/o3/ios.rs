use crate::{Error, Result, crypto, proto::o3::IosEstablishShareKeyRequest};
use bytes::Bytes;
use prost::Message;
use rand::{TryRng, rngs::SysRng};

pub use ::signing::ios::o3_check::CheckMode;

mod channel;
pub use channel::{Channel, Reply, Request, SwitchUpdate};

#[derive(Clone)]
pub struct EstablishRequest {
    pub method: Bytes,
    pub client_public_key: Bytes,
    pub local_hkdf_succeeded: bool,
    pub key_identifier: Bytes,
    pub encrypted_body: Bytes,
    pub channel_uuid: Bytes,
}

impl EstablishRequest {
    pub fn encode(self, mode: CheckMode) -> Result<Bytes> {
        let mut counter = [0; 16];
        SysRng
            .try_fill_bytes(&mut counter)
            .map_err(|error| Error::Crypto(format!("iOS O3 check entropy unavailable: {error}")))?;
        Ok(self.encode_with_counter(mode, &counter))
    }

    pub fn encode_with_counter(self, mode: CheckMode, counter: &[u8; 16]) -> Bytes {
        let check = mode.encode(&crypto::sha256(&self.encrypted_body), counter);
        IosEstablishShareKeyRequest {
            method: self.method,
            client_public_key: self.client_public_key,
            local_derivation_failed: !self.local_hkdf_succeeded,
            key_identifier: self.key_identifier,
            encrypted_body: self.encrypted_body,
            channel_uuid: self.channel_uuid,
            check: Bytes::copy_from_slice(&check),
            version: 3,
        }
        .encode_to_vec()
        .into()
    }
}
