use super::{ACCESS_COMMAND, ESTABLISH_COMMAND, crypto};
use crate::{Error, Result, proto::o3 as pb};
use bytes::{Bytes, BytesMut};
use prost::Message;
use rand::RngCore;

pub(crate) struct Channel {
    peer: [u8; 33],
    state: State,
}

enum State {
    Vacant,
    Establishing { uuid: [u8; 32] },
    Established(Established),
}

struct Established {
    key: [u8; 32],
    uuid: [u8; 32],
    parameter: u64,
    expires_at: u64,
}

pub(crate) struct Request {
    pub command: &'static str,
    pub body: Bytes,
    key: [u8; 32],
    uuid: [u8; 32],
    parameter: u64,
    mode: Mode,
}

enum Mode {
    Establish,
    Access,
}

pub(crate) struct Reply {
    pub body: Bytes,
    pub config: Option<pb::ChannelConfig>,
}

impl Default for Channel {
    fn default() -> Self {
        Self::new()
    }
}

impl Channel {
    pub(crate) fn new() -> Self {
        Self::with_peer(crypto::PEER_PUBLIC_KEY)
    }

    pub(crate) fn reset(&mut self) {
        self.state = State::Vacant;
    }

    pub(crate) fn is_establishing(&self) -> bool {
        matches!(self.state, State::Establishing { .. })
    }

    pub(crate) fn failed(&mut self, request: &Request) {
        if matches!(
            (&self.state, &request.mode),
            (State::Establishing { uuid }, Mode::Establish) if *uuid == request.uuid
        ) {
            self.state = State::Vacant;
        }
    }

    pub(crate) fn with_peer(peer: [u8; 33]) -> Self {
        Self {
            peer,
            state: State::Vacant,
        }
    }

    pub(crate) fn prepare(&mut self, method: &str, body: Bytes, now: u64) -> Result<Request> {
        if let State::Established(channel) = &self.state {
            if now < channel.expires_at {
                let uuid = Bytes::copy_from_slice(&channel.uuid);
                let encrypted_body = crypto::seal(&channel.key, &body)?;
                let body = pb::SecureAccessRequest {
                    method: Bytes::copy_from_slice(method.as_bytes()),
                    encrypted_body,
                    channel_uuid: uuid,
                }
                .encode_to_vec()
                .into();
                return Ok(Request {
                    command: ACCESS_COMMAND,
                    body,
                    key: channel.key,
                    uuid: channel.uuid,
                    parameter: channel.parameter,
                    mode: Mode::Access,
                });
            }
        }

        self.state = State::Vacant;
        let agreement = crypto::Agreement::new(&self.peer)?;
        let mut random = [0; 40];
        rand::rngs::OsRng
            .try_fill_bytes(&mut random)
            .map_err(|_| Error::Crypto("O3 channel entropy unavailable".into()))?;
        let uuid: [u8; 32] = random[..32].try_into().unwrap();
        let parameter = u64::from_be_bytes(random[32..].try_into().unwrap());
        let encoded_uuid = Bytes::copy_from_slice(&uuid);
        let plaintext = pb::ChannelPlaintext {
            parameter,
            body,
            uuid: encoded_uuid.clone(),
        };
        let encrypted_body = crypto::seal(&agreement.key, &plaintext.encode_to_vec())?;
        let body = pb::EstablishShareKeyRequest {
            method: Bytes::copy_from_slice(method.as_bytes()),
            client_public_key: Bytes::copy_from_slice(&agreement.public),
            key_identifier: Bytes::from_static(crypto::KEY_IDENTIFIER),
            encrypted_body,
            channel_uuid: encoded_uuid,
        }
        .encode_to_vec()
        .into();
        self.state = State::Establishing { uuid };
        Ok(Request {
            command: ESTABLISH_COMMAND,
            body,
            key: agreement.key,
            uuid,
            parameter,
            mode: Mode::Establish,
        })
    }

    pub(crate) fn complete(
        &mut self,
        request: Request,
        response: Bytes,
        _now: u64,
    ) -> Result<Reply> {
        let current = match (&self.state, &request.mode) {
            (State::Establishing { uuid }, Mode::Establish) => *uuid == request.uuid,
            (State::Established(channel), Mode::Access) => {
                channel.uuid == request.uuid && channel.parameter == request.parameter
            }
            _ => false,
        };
        if !current {
            return Err(Error::Authentication("Stale O3 channel response".into()));
        }
        let result = self.complete_current(&request, response);
        if result.is_err() && matches!(request.mode, Mode::Establish) {
            self.state = State::Vacant;
        }
        result
    }

    fn complete_current(&mut self, request: &Request, response: Bytes) -> Result<Reply> {
        match request.mode {
            Mode::Establish => {
                let outer = pb::EstablishShareKeyResponse::decode(response)?;
                check_status(outer.status)?;
                let encrypted = merge_bytes(outer.encrypted_body);
                let plaintext = crypto::open(&request.key, &encrypted)?;
                let inner = pb::EstablishInnerResponse::decode(plaintext)?;
                crypto::authenticate(
                    &self.peer,
                    request.parameter,
                    inner.parameter,
                    &merge_bytes(inner.material),
                )?;
                self.state = State::Established(Established {
                    key: request.key,
                    uuid: request.uuid,
                    parameter: request.parameter,
                    expires_at: inner.channel_time,
                });
                Ok(Reply {
                    body: merge_bytes(inner.business_response),
                    config: Some(inner.config.unwrap_or_default()),
                })
            }
            Mode::Access => {
                let outer = pb::SecureAccessResponse::decode(response)?;
                if let Err(error) = check_status(outer.status) {
                    self.state = State::Vacant;
                    return Err(error);
                }
                let encrypted = merge_bytes(outer.encrypted_body);
                let body = crypto::open(&request.key, &encrypted)?;
                if body.is_empty() {
                    return Err(Error::Crypto("Empty O3 access response payload".into()));
                }
                Ok(Reply { body, config: None })
            }
        }
    }
}

fn merge_bytes(mut parts: Vec<Bytes>) -> Bytes {
    match parts.len() {
        0 => Bytes::new(),
        1 => parts.pop().unwrap(),
        _ => {
            let mut output = BytesMut::with_capacity(parts.iter().map(Bytes::len).sum());
            for part in parts {
                output.extend_from_slice(&part);
            }
            output.freeze()
        }
    }
}

fn check_status(status: Option<u32>) -> Result<()> {
    match status.unwrap_or_default() {
        0 => Ok(()),
        code => Err(Error::Server {
            code: code as i32,
            message: "O3 encrypted channel request rejected".into(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        bn::{BigNum, BigNumContext},
        ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
        ecdsa::EcdsaSig,
        nid::Nid,
        pkey::Private,
    };

    fn local_peer() -> (Channel, EcKey<Private>) {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let private = BigNum::from_u32(1).unwrap();
        let mut context = BigNumContext::new().unwrap();
        let mut public = EcPoint::new(&group).unwrap();
        public
            .mul_generator2(&group, &private, &mut context)
            .unwrap();
        let peer = public
            .to_bytes(&group, PointConversionForm::COMPRESSED, &mut context)
            .unwrap()
            .try_into()
            .unwrap();
        let key = EcKey::from_private_components(&group, &private, &public).unwrap();
        (Channel::with_peer(peer), key)
    }

    fn inner_response(
        channel: &Channel,
        key: &EcKey<Private>,
        request: &Request,
    ) -> pb::EstablishInnerResponse {
        let parameter = 0x1020_3040_5060_7080u64;
        let mut message = [0; 49];
        message[..33].copy_from_slice(&channel.peer);
        message[33..41].copy_from_slice(&request.parameter.to_be_bytes());
        message[41..].copy_from_slice(&parameter.to_be_bytes());
        let signature = EcdsaSig::sign(&crate::crypto::sha256(&message), key).unwrap();
        let mut material = Vec::with_capacity(64);
        material.extend_from_slice(&signature.r().to_vec_padded(32).unwrap());
        material.extend_from_slice(&signature.s().to_vec_padded(32).unwrap());
        pb::EstablishInnerResponse {
            material: vec![material.into()],
            parameter,
            channel_time: 500,
            business_response: vec![Bytes::from_static(b"offline synthetic business reply")],
            config: Some(pb::ChannelConfig {
                option1: 1,
                option2: 1,
                option3: 1,
                option6: 4,
                option7: 1,
                ..Default::default()
            }),
        }
    }

    fn establish_response(request: &Request, inner: pb::EstablishInnerResponse) -> Bytes {
        pb::EstablishShareKeyResponse {
            status: Some(0),
            encrypted_body: vec![crypto::seal(&request.key, &inner.encode_to_vec()).unwrap()],
        }
        .encode_to_vec()
        .into()
    }

    fn access_response(request: &Request, body: &[u8]) -> pb::SecureAccessResponse {
        pb::SecureAccessResponse {
            status: Some(0),
            encrypted_body: vec![crypto::seal(&request.key, body).unwrap()],
        }
    }

    fn established() -> Channel {
        let (mut channel, key) = local_peer();
        let request = channel
            .prepare("getToken", Bytes::from_static(b"report"), 100)
            .unwrap();
        let inner = inner_response(&channel, &key, &request);
        let response = establish_response(&request, inner);
        channel.complete(request, response, 100).unwrap();
        channel
    }

    #[test]
    fn authenticated_establishment_then_access_returns_only_business_bytes() {
        let (mut channel, key) = local_peer();
        let request = channel
            .prepare("getToken", Bytes::from_static(b"report"), 100)
            .unwrap();
        assert_eq!(request.command, ESTABLISH_COMMAND);
        let outer = pb::EstablishShareKeyRequest::decode(request.body.clone()).unwrap();
        assert_eq!(outer.method.as_ref(), b"getToken");
        assert_eq!(outer.key_identifier.as_ref(), crypto::KEY_IDENTIFIER);
        assert_eq!(outer.client_public_key.len(), 33);
        assert_eq!(outer.channel_uuid.as_ref(), request.uuid.as_slice());
        let plain = crypto::open(&request.key, &outer.encrypted_body).unwrap();
        let plain = pb::ChannelPlaintext::decode(plain).unwrap();
        assert_eq!(plain.parameter, request.parameter);
        assert_eq!(plain.body.as_ref(), b"report");
        assert_eq!(plain.uuid, outer.channel_uuid);
        let inner = inner_response(&channel, &key, &request);
        let expected = merge_bytes(inner.business_response.clone());
        let response = establish_response(&request, inner);
        let reply = channel.complete(request, response, 100).unwrap();
        assert_eq!(reply.body, expected);
        assert_eq!(reply.config.unwrap().option6, 4);
        let report = ::signing::proto::TokenReport {
            properties: vec![::signing::proto::DeviceProperty {
                id: 16,
                value: b"offline-device".to_vec(),
            }],
            previous_token: b"previous-token".to_vec(),
        };
        let request = channel
            .prepare("getToken", report.encode_to_vec().into(), 101)
            .unwrap();
        assert_eq!(request.command, ACCESS_COMMAND);
        let outer = pb::SecureAccessRequest::decode(request.body.clone()).unwrap();
        let plain = crypto::open(&request.key, &outer.encrypted_body).unwrap();
        let report = ::signing::proto::TokenReport::decode(plain).unwrap();
        assert_eq!(report.previous_token, b"previous-token");
        assert_eq!(report.properties[0].id, 16);
        assert_eq!(report.properties[0].value, b"offline-device");
        let response = access_response(&request, b"next opaque reply")
            .encode_to_vec()
            .into();
        let reply = channel.complete(request, response, 101).unwrap();
        assert_eq!(reply.body.as_ref(), b"next opaque reply");
        assert!(reply.config.is_none());
    }

    #[test]
    fn unauthenticated_establishment_never_commits() {
        let (mut channel, key) = local_peer();
        let request = channel
            .prepare("getToken", Bytes::from_static(b"report"), 100)
            .unwrap();
        let mut inner = inner_response(&channel, &key, &request);
        inner.material = vec![Bytes::from_static(&[0; 64])];
        let response = establish_response(&request, inner);
        assert!(channel.complete(request, response, 100).is_err());
        assert!(matches!(channel.state, State::Vacant));
        assert_eq!(
            channel
                .prepare("getToken", Bytes::from_static(b"report"), 100)
                .unwrap()
                .command,
            ESTABLISH_COMMAND
        );
    }

    #[test]
    fn authenticated_expired_establishment_returns_business_then_rebuilds() {
        let (mut channel, key) = local_peer();
        let request = channel
            .prepare("getToken", Bytes::from_static(b"report"), 100)
            .unwrap();
        let mut inner = inner_response(&channel, &key, &request);
        inner.channel_time = 100;
        let expected = merge_bytes(inner.business_response.clone());
        let response = establish_response(&request, inner);
        let reply = channel.complete(request, response, 100).unwrap();
        assert_eq!(reply.body, expected);
        assert_eq!(reply.config.unwrap().option6, 4);
        assert_eq!(
            channel
                .prepare("getToken", Bytes::from_static(b"report"), 100)
                .unwrap()
                .command,
            ESTABLISH_COMMAND
        );
    }

    #[test]
    fn access_authenticates_ciphertext_without_requiring_a_uuid_echo() {
        for echoed in [None, Some(Bytes::from_static(b"unrelated metadata"))] {
            let mut channel = established();
            let request = channel
                .prepare("getToken", Bytes::from_static(b"report"), 101)
                .unwrap();
            let mut response = access_response(&request, b"authenticated reply").encode_to_vec();
            if let Some(channel_uuid) = echoed {
                pb::SecureAccessRequest {
                    channel_uuid,
                    ..Default::default()
                }
                .encode(&mut response)
                .unwrap();
            }
            let reply = channel.complete(request, response.into(), 101).unwrap();
            assert_eq!(reply.body.as_ref(), b"authenticated reply");
        }
    }

    #[test]
    fn access_authentication_error_preserves_channel_but_remote_status_invalidates_it() {
        let mut channel = established();
        let request = channel
            .prepare("getToken", Bytes::from_static(b"report"), 101)
            .unwrap();
        let uuid = request.uuid;
        let mut response = access_response(&request, b"reply");
        let mut encrypted = response.encrypted_body.pop().unwrap().to_vec();
        *encrypted.last_mut().unwrap() ^= 1;
        response.encrypted_body = vec![encrypted.into()];
        assert!(
            channel
                .complete(request, response.encode_to_vec().into(), 101)
                .is_err()
        );
        let request = channel
            .prepare("getToken", Bytes::from_static(b"retry"), 102)
            .unwrap();
        assert_eq!(request.command, ACCESS_COMMAND);
        assert_eq!(request.uuid, uuid);
        let mut response = access_response(&request, b"reply");
        response.status = Some(7);
        assert!(
            channel
                .complete(request, response.encode_to_vec().into(), 102)
                .is_err()
        );
        assert_eq!(
            channel
                .prepare("getToken", Bytes::from_static(b"retry"), 103)
                .unwrap()
                .command,
            ESTABLISH_COMMAND
        );
    }

    #[test]
    fn transport_failure_preserves_access_and_stale_failure_cannot_erase_new_handshake() {
        let mut channel = established();
        let request = channel
            .prepare("getToken", Bytes::from_static(b"report"), 101)
            .unwrap();
        let uuid = request.uuid;
        channel.failed(&request);
        let next = channel
            .prepare("getToken", Bytes::from_static(b"report"), 102)
            .unwrap();
        assert_eq!(next.command, ACCESS_COMMAND);
        assert_eq!(next.uuid, uuid);
        let handshake = channel
            .prepare("getToken", Bytes::from_static(b"report"), 500)
            .unwrap();
        channel.failed(&next);
        assert!(channel.is_establishing());
        channel.failed(&handshake);
        assert!(!channel.is_establishing());
        let current = channel
            .prepare("getToken", Bytes::from_static(b"report"), 501)
            .unwrap();
        channel.failed(&handshake);
        assert!(matches!(
            channel.state,
            State::Establishing { uuid } if uuid == current.uuid
        ));
    }

    #[test]
    fn authenticated_establishment_can_omit_business_and_config() {
        let (mut channel, key) = local_peer();
        let request = channel
            .prepare("getToken", Bytes::from_static(b"report"), 100)
            .unwrap();
        let mut inner = inner_response(&channel, &key, &request);
        inner.business_response = Vec::new();
        inner.config = None;
        let response = pb::EstablishShareKeyResponse {
            status: None,
            encrypted_body: vec![crypto::seal(&request.key, &inner.encode_to_vec()).unwrap()],
        };
        let reply = channel
            .complete(request, response.encode_to_vec().into(), 100)
            .unwrap();
        assert!(reply.body.is_empty());
        let config = reply.config.unwrap();
        assert_eq!(config.option2, 0);
        assert_eq!(config.option6, 0);
    }

    #[test]
    fn replacement_rejects_late_requests_without_erasing_current_state() {
        let mut channel = established();
        let old = channel
            .prepare("getToken", Bytes::from_static(b"old"), 499)
            .unwrap();
        let old_response = access_response(&old, b"late reply").encode_to_vec().into();
        let replacement = channel
            .prepare("getToken", Bytes::from_static(b"new"), 500)
            .unwrap();
        assert_eq!(replacement.command, ESTABLISH_COMMAND);
        let replacement_uuid = replacement.uuid;
        assert!(channel.complete(old, old_response, 500).is_err());
        assert!(matches!(
            channel.state,
            State::Establishing { uuid } if uuid == replacement_uuid
        ));
    }

    #[test]
    fn superseded_establishment_cannot_publish_or_clear_newer_request() {
        let (mut channel, key) = local_peer();
        let old = channel
            .prepare("getToken", Bytes::from_static(b"old"), 100)
            .unwrap();
        let inner = inner_response(&channel, &key, &old);
        let response = establish_response(&old, inner);
        let current = channel
            .prepare("getToken", Bytes::from_static(b"current"), 100)
            .unwrap();
        assert!(channel.complete(old, response, 100).is_err());
        assert!(matches!(
            channel.state,
            State::Establishing { uuid } if uuid == current.uuid
        ));
        let inner = inner_response(&channel, &key, &current);
        let response = establish_response(&current, inner);
        assert!(channel.complete(current, response, 100).is_ok());
    }

    #[test]
    fn reset_preserves_peer_and_rejects_previous_scope_completion() {
        let (mut channel, key) = local_peer();
        let peer = channel.peer;
        let old = channel
            .prepare("getToken", Bytes::from_static(b"old"), 100)
            .unwrap();
        let inner = inner_response(&channel, &key, &old);
        let response = establish_response(&old, inner);
        channel.reset();
        assert_eq!(channel.peer, peer);
        assert!(matches!(channel.state, State::Vacant));
        assert!(channel.complete(old, response, 100).is_err());
        let current = channel
            .prepare("getToken", Bytes::from_static(b"current"), 100)
            .unwrap();
        let inner = inner_response(&channel, &key, &current);
        let response = establish_response(&current, inner);
        assert!(channel.complete(current, response, 100).is_ok());
        let old = channel
            .prepare("getToken", Bytes::from_static(b"old access"), 101)
            .unwrap();
        let response = access_response(&old, b"old scope reply");
        channel.reset();
        let current = channel
            .prepare("getToken", Bytes::from_static(b"new scope"), 101)
            .unwrap();
        assert!(
            channel
                .complete(old, response.encode_to_vec().into(), 101)
                .is_err()
        );
        assert!(matches!(
            channel.state,
            State::Establishing { uuid } if uuid == current.uuid
        ));
        assert_eq!(channel.peer, peer);
    }

    #[test]
    fn unknown_outer_fields_are_skipped_by_prost() {
        let mut channel = established();
        let request = channel
            .prepare("getToken", Bytes::from_static(b"report"), 101)
            .unwrap();
        let mut response = access_response(&request, b"reply").encode_to_vec();
        pb::ChannelConfig {
            option7: 77,
            ..Default::default()
        }
        .encode(&mut response)
        .unwrap();
        let reply = channel.complete(request, response.into(), 101).unwrap();
        assert_eq!(reply.body.as_ref(), b"reply");
    }

    #[test]
    fn in_flight_access_remains_valid_after_expiry_then_next_prepare_rebuilds() {
        let mut channel = established();
        let request = channel
            .prepare("getToken", Bytes::from_static(b"report"), 499)
            .unwrap();
        let response = access_response(&request, b"late valid business reply");
        let reply = channel
            .complete(request, response.encode_to_vec().into(), 500)
            .unwrap();
        assert_eq!(reply.body.as_ref(), b"late valid business reply");
        assert_eq!(
            channel
                .prepare("getToken", Bytes::from_static(b"next"), 500)
                .unwrap()
                .command,
            ESTABLISH_COMMAND
        );
    }

    fn split(bytes: Bytes) -> Vec<Bytes> {
        let middle = bytes.len() / 2;
        vec![bytes.slice(..middle), Bytes::new(), bytes.slice(middle..)]
    }

    #[test]
    fn fragmented_establishment_ciphertext_signature_and_business_reply_interoperate() {
        let (mut channel, key) = local_peer();
        let request = channel
            .prepare("getToken", Bytes::from_static(b"report"), 100)
            .unwrap();
        let mut inner = inner_response(&channel, &key, &request);
        let expected = merge_bytes(inner.business_response.clone());
        inner.material = split(inner.material.pop().unwrap());
        inner.business_response = split(inner.business_response.pop().unwrap());
        let encrypted = crypto::seal(&request.key, &inner.encode_to_vec()).unwrap();
        let response = pb::EstablishShareKeyResponse {
            encrypted_body: split(encrypted),
            status: Some(0),
        };
        let reply = channel
            .complete(request, response.encode_to_vec().into(), 100)
            .unwrap();
        assert_eq!(reply.body, expected);
        assert_eq!(reply.config.unwrap().option6, 4);
    }

    #[test]
    fn empty_access_response_rejects_business_completion_without_rekeying() {
        let mut channel = established();
        let request = channel
            .prepare("getToken", Bytes::from_static(b"report"), 101)
            .unwrap();
        let uuid = request.uuid;
        let response = access_response(&request, b"").encode_to_vec().into();
        assert!(channel.complete(request, response, 101).is_err());
        let next = channel
            .prepare("getToken", Bytes::from_static(b"report"), 102)
            .unwrap();
        assert_eq!(next.command, ACCESS_COMMAND);
        assert_eq!(next.uuid, uuid);
    }

    #[test]
    fn fragmented_access_ciphertext_interoperates() {
        let mut channel = established();
        let request = channel
            .prepare("getToken", Bytes::from_static(b"report"), 101)
            .unwrap();
        let mut response = access_response(&request, b"fragmented encrypted business reply");
        response.encrypted_body = split(response.encrypted_body.pop().unwrap());
        let reply = channel
            .complete(request, response.encode_to_vec().into(), 101)
            .unwrap();
        assert_eq!(reply.body.as_ref(), b"fragmented encrypted business reply");
    }
}
