use std::{error::Error, fmt};

use bytes::Bytes;

use super::{
    command_policy::CommandPolicy,
    extra::{ExtraError, build_extra},
    signer::{Mode, Request, Signature, Signer, Source},
    trailer::SeedSource,
};

pub struct Inputs<'a> {
    pub command: &'a str,
    pub body: Bytes,
    pub qua: Bytes,
    pub raw_xwid: Bytes,
    pub device_token: Bytes,
    pub channel_state: Option<&'a [u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityInfo {
    pub sign: Option<Signature>,
    pub token: Bytes,
    pub extra: Bytes,
}

impl SecurityInfo {
    pub fn signature_bytes(&self) -> &[u8] {
        self.sign.as_ref().map_or(&[], AsRef::as_ref)
    }
}

#[derive(Debug)]
pub enum SignError<E> {
    Extra(ExtraError),
    Source(E),
}

impl<E: fmt::Display> fmt::Display for SignError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Extra(error) => error.fmt(formatter),
            Self::Source(error) => error.fmt(formatter),
        }
    }
}

impl<E: Error + 'static> Error for SignError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Extra(error) => Some(error),
            Self::Source(error) => Some(error),
        }
    }
}

pub struct SdkSigner {
    pub core: Signer,
    pub policy: CommandPolicy,
}

impl SdkSigner {
    pub fn new(core: Signer, policy: CommandPolicy) -> Self {
        Self { core, policy }
    }

    pub fn sign<S: Source>(
        &mut self,
        input: Inputs<'_>,
        source: &mut S,
    ) -> Result<SecurityInfo, SignError<<S as SeedSource>::Error>> {
        let mode = self.policy.sdk_mode(input.command, &input.body);
        let extra = build_extra(
            input.command,
            input.body.clone(),
            input.qua,
            input.raw_xwid,
            input.channel_state,
        )
        .map_err(SignError::Extra)?;
        let sign = match mode {
            None => None,
            Some(Mode::Disabled) => Some(Signature::Disabled),
            Some(mode) => {
                let digest = crate::digest::md5_parts(&[&input.device_token, &extra, &input.body]);
                Some(
                    self.core
                        .sign(
                            Request {
                                digest: &digest,
                                command: input.command.as_bytes(),
                                device_token: &input.device_token,
                                mode,
                            },
                            source,
                            None,
                        )
                        .map_err(SignError::Source)?,
                )
            }
        };
        Ok(SecurityInfo {
            sign,
            token: input.device_token,
            extra,
        })
    }
}
