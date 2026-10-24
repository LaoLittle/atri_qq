use std::borrow::Cow;

use crate::proto::{append_bytes_field, encoded_bytes_len};

pub trait ExtraEntropy {
    type Error;

    fn clock_ns(&mut self) -> Result<u64, Self::Error>;
    fn random_u32(&mut self) -> Result<u32, Self::Error>;
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExtraState {
    pub channel_uuid: Option<[u8; 32]>,
}

impl ExtraState {
    pub fn reset(&mut self) {
        self.channel_uuid = None;
    }

    pub fn sign_extra<E: ExtraEntropy>(
        &mut self,
        command: &str,
        body: &[u8],
        qua: &[u8],
        entropy: &mut E,
    ) -> Result<Vec<u8>, E::Error> {
        let command = command.split('\0').next().unwrap_or("");
        let uuid_field = match command {
            "trpc.o3.ecdh_access.EcdhAccess.SsoSecureAccess"
            | "trpc.o3.ecdh_access.EcdhAccess.SsoSecureA2Access" => Some(3),
            "trpc.o3.ecdh_access.EcdhAccess.SsoEstablishShareKey"
            | "trpc.o3.ecdh_access.EcdhAccess.SsoSecureA2Establish" => Some(6),
            _ => None,
        };
        let uuid: Cow<'_, [u8]> = if let Some(field) = uuid_field {
            if body.is_empty() {
                if self.channel_uuid.is_none() {
                    self.channel_uuid = Some(generate_uuid(entropy)?);
                }
                match &self.channel_uuid {
                    Some(uuid) => Cow::Borrowed(uuid.as_slice()),
                    None => unreachable!("UUID initialized immediately above"),
                }
            } else {
                protobuf_bytes_field(body, field).unwrap_or_default()
            }
        } else {
            Cow::Borrowed(&[])
        };

        let qua = &qua[..qua.iter().position(|&byte| byte == 0).unwrap_or(qua.len())];
        let capacity = encoded_bytes_len(&uuid) + encoded_bytes_len(qua);
        let mut output = Vec::with_capacity(capacity);
        append_bytes_field(&mut output, 1, &uuid);
        append_bytes_field(&mut output, 2, qua);

        Ok(output)
    }
}

fn generate_uuid<E: ExtraEntropy>(entropy: &mut E) -> Result<[u8; 32], E::Error> {
    let mut uuid = [0_u8; 32];
    for bytes in uuid.chunks_exact_mut(4) {
        bytes.copy_from_slice(&entropy.random_u32()?.to_le_bytes());
    }
    Ok(uuid)
}

fn read_varint(bytes: &[u8], position: &mut usize) -> Option<u64> {
    let mut value = 0_u64;
    for shift in (0..70).step_by(7) {
        let byte = *bytes.get(*position)?;
        *position += 1;
        if shift == 63 && byte > 1 {
            return None;
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

fn protobuf_bytes_field(bytes: &[u8], wanted: u64) -> Option<Cow<'_, [u8]>> {
    let mut position = 0;
    let mut found: Option<Cow<'_, [u8]>> = None;
    while position < bytes.len() {
        let key = read_varint(bytes, &mut position)?;
        if key >> 3 == wanted {
            let length = usize::try_from(read_varint(bytes, &mut position)?).ok()?;
            let end = position
                .checked_add(length)
                .filter(|&end| end <= bytes.len())?;
            match &mut found {
                Some(value) => value.to_mut().extend_from_slice(&bytes[position..end]),
                None => found = Some(Cow::Borrowed(&bytes[position..end])),
            }
            position = end;
            continue;
        }
        match key & 7 {
            0 => {
                read_varint(bytes, &mut position)?;
            }
            1 => {
                position = position.saturating_add(8);
            }
            2 => {
                let length = usize::try_from(read_varint(bytes, &mut position)?).ok()?;
                position = position
                    .checked_add(length)
                    .filter(|&end| end <= bytes.len())?;
            }
            5 => {
                position = position.saturating_add(4);
            }
            _ => return None,
        }
    }
    found
}
