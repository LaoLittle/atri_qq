use std::{net::SocketAddr, sync::Arc, time::Duration};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

impl AddressFamily {
    pub(crate) fn accepts(self, stack: u8) -> bool {
        matches!((self, stack), (Self::Ipv4, 1 | 3) | (Self::Ipv6, 2 | 3))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    HttpDiscovery { bucket: String },
    ConfigPush,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub timeout: Duration,
    pub family: AddressFamily,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Connected {
        local_addr: Option<SocketAddr>,
        peer_addr: Option<SocketAddr>,
    },
    Failed {
        message: String,
        raw_os_error: Option<i32>,
    },
    TimedOut,
}

#[derive(Clone, Debug)]
pub struct Report {
    pub source: Arc<Source>,
    pub endpoint: Endpoint,
    pub generation: u64,
    pub network_type: u8,
    pub ip_stack: u8,
    pub started_unix_millis: i64,
    pub finished_unix_millis: i64,
    pub outcome: Outcome,
}
