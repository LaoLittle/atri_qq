pub use ::signing as signature;
pub use atri_qq_protocol::*;
pub use atri_qq_silk as voice;

#[cfg(feature = "extension")]
mod adapter;
#[cfg(feature = "extension")]
mod authority;
#[cfg(feature = "extension")]
mod config;
#[cfg(feature = "extension")]
mod conversion;
#[cfg(feature = "extension")]
#[path = "signing.rs"]
mod extension_signing;
#[cfg(feature = "extension")]
mod guild_conversion;
#[cfg(feature = "extension")]
pub use adapter::QQExtension;
