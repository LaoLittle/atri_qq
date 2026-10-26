//! Linux desktop NT protocol client. Session persistence belongs to the embedding adapter.
pub mod admin;
pub mod client;
mod clock;
pub mod contacts;
mod credentials;
pub mod crypto;
mod diagnostics;
pub mod guild;
mod http;
mod lifecycle;
pub mod login;
pub mod media;
pub mod messages;
pub mod message_sync;
pub mod mini_app;
pub mod models;
pub mod network;
pub mod o3;
pub mod personal_events;
pub mod proto;
pub mod signing;
mod ticket_refresh;
pub mod wire;

pub use client::{Client, ServiceClient};
pub use models::*;
pub use credentials::file_transfer::FileTransferTicket;

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("Malformed protocol data: {0}")]
    Malformed(String),
    #[error("Authentication failed: {0}")]
    Authentication(String),
    #[error("Server error {code}: {message}")]
    Server { code: i32, message: String },
    #[error("Request timed out")]
    Timeout,
    #[error("Connection closed")]
    Disconnected,
    #[error("Unsupported operation: {0}")]
    Unsupported(String),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("Cryptographic operation failed: {0}")]
    Crypto(String),
    #[error(
        "File {file_id} was accepted but confirmation failed ({cause}); do not resend automatically"
    )]
    UnconfirmedFileSend { file_id: String, cause: String },
}
pub type Result<T, E = Error> = std::result::Result<T, E>;
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}
impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        Self::Io(error.to_string())
    }
}

impl From<prost::DecodeError> for Error {
    fn from(error: prost::DecodeError) -> Self {
        Self::Malformed(error.to_string())
    }
}
