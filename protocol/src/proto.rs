//! Generated QQ protobuf contracts. Reflection supports unknown fields and response diagnostics.

use crate::{Error, Result};
use bytes::Buf;
use std::sync::LazyLock;

include!(concat!(env!("OUT_DIR"), "/generated.rs"));
pub use self::atri::qq::*;

/// Decode a known schema without accepting a frame larger than the transport limit.
pub fn decode<M: prost::Message + Default>(source: impl Buf) -> Result<M> {
    if source.remaining() > crate::wire::MAX_FRAME_SIZE {
        return Err(Error::Malformed("Protobuf message exceeds limit".into()));
    }
    M::decode(source).map_err(Into::into)
}

static DESCRIPTORS: LazyLock<prost_reflect::DescriptorPool> = LazyLock::new(|| {
    prost_reflect::DescriptorPool::decode(
        include_bytes!(concat!(env!("OUT_DIR"), "/atri-qq-descriptors.bin")).as_slice(),
    )
    .expect("build-generated QQ descriptors")
});

pub fn descriptor_pool() -> &'static prost_reflect::DescriptorPool {
    &DESCRIPTORS
}
