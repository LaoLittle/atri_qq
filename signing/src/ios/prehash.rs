use std::{error::Error, fmt};

use bytes::Bytes;
use md5::{Digest, Md5};

use super::extra::{ExtraError, build_extra};

pub fn request_body(request_data: Bytes) -> Option<Bytes> {
    (request_data.len() >= 5).then(|| request_data.slice(4..))
}

pub struct Inputs<'a> {
    pub command: &'a [u8],
    pub body: Bytes,
    pub qua: Bytes,
    pub raw_xwid: Bytes,
    pub device_token: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prepared {
    pub digest: [u8; 16],
    pub extra: Bytes,
    pub device_token: Bytes,
}

#[derive(Debug)]
pub enum PrepareError {
    EmptyBody,
    Extra(ExtraError),
}

impl fmt::Display for PrepareError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyBody => formatter.write_str("FGESDK rejects an empty signing body"),
            Self::Extra(error) => error.fmt(formatter),
        }
    }
}

impl Error for PrepareError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::EmptyBody => None,
            Self::Extra(error) => Some(error),
        }
    }
}

pub fn prepare(input: Inputs<'_>) -> Result<Prepared, PrepareError> {
    if input.body.is_empty() {
        return Err(PrepareError::EmptyBody);
    }
    let extra = build_extra(
        input.command,
        input.body.clone(),
        input.qua,
        input.raw_xwid,
        None,
    )
    .map_err(PrepareError::Extra)?;
    let mut hash = Md5::new();
    hash.update(&input.device_token);
    hash.update(&extra);
    hash.update(&input.body);
    Ok(Prepared {
        digest: hash.finalize().into(),
        extra,
        device_token: input.device_token,
    })
}
