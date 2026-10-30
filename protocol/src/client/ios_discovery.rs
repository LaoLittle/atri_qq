use super::*;
use crate::network::{
    ServerSelection,
    ios_discovery::{self, HttpServerListReq, NativeU32},
};

#[derive(Default)]
pub(super) struct State {
    pending: Option<PendingDiscovery>,
    next_id: u64,
    last_failure: Option<Instant>,
    retry_failure: bool,
    cursor: usize,
    loaded_bucket: Option<String>,
    #[cfg(test)]
    pub(super) url: Option<String>,
}

struct PendingDiscovery {
    id: u64,
    cancel: CancellationToken,
}

impl State {
    pub(super) fn cancel_pending(&mut self) {
        if let Some(pending) = self.pending.take() {
            pending.cancel.cancel();
        }
    }
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl Client {
    pub(super) fn ios_discovery_enabled(&self) -> bool {
        self.config.profile.platform.is_ios()
            && self.config.server_selection != ServerSelection::Configured
            && self.config.host == "msfwifi.3g.qq.com"
            && self.config.port == 8080
    }

    fn ios_discovery_context(&self, inner: &Inner) -> Option<(String, String, bool)> {
        let transport = &inner.ios()?.transport;
        let wifi = transport.network_type == 1;
        let bssid = self
            .config
            .ios_virtual()
            .and_then(|model| model.network.bssid.as_deref());
        Some((
            ios_discovery::bucket(wifi, bssid),
            format!("{}{}", transport.carrier_mcc, transport.carrier_mnc),
            wifi,
        ))
    }

    pub(super) fn record_ios_connection_failure(
        &self,
        generation: u64,
        source: &CancellationToken,
    ) {
        let mut inner = self.inner.lock().unwrap();
        if inner.generation == generation && !source.is_cancelled() {
            if let Some(ios) = inner.ios_mut() {
                ios.discovery.retry_failure = true;
            }
        }
    }

    pub(super) fn start_ios_discovery(&self, generation: u64, failure: bool) {
        if !self.ios_discovery_enabled() {
            return;
        }
        let (id, bucket, carrier, request, cancel, url, failure) = {
            let mut inner = self.inner.lock().unwrap();
            if inner.generation != generation || inner.cancel.is_cancelled() {
                return;
            }
            let Some((bucket, carrier, wifi)) = self.ios_discovery_context(&inner) else {
                return;
            };
            let retry = std::mem::take(&mut inner.ios_mut().unwrap().discovery.retry_failure);
            let failure = failure || retry;
            let changed = inner.ios_mut().unwrap().discovery.loaded_bucket.as_deref()
                != Some(bucket.as_str());
            if changed {
                inner.ios_mut().unwrap().discovery.cancel_pending();
                inner.ios_mut().unwrap().discovery.loaded_bucket = Some(bucket.clone());
                inner.ios_mut().unwrap().discovery.cursor = 0;
            }
            if failure {
                if inner
                    .ios_mut()
                    .unwrap()
                    .discovery
                    .last_failure
                    .is_some_and(|last| last.elapsed() < Duration::from_secs(3600))
                {
                    return;
                }
                inner.ios_mut().unwrap().discovery.last_failure = Some(Instant::now());
                inner.ios_mut().unwrap().discovery.cancel_pending();
            } else if !changed
                || inner.ios_mut().unwrap().discovery.pending.is_some()
                || inner
                    .state
                    .keystore
                    .ios_server_lists
                    .get(&bucket)
                    .is_some_and(|cache| cache.fresh(now_seconds(), &carrier))
            {
                return;
            }
            let server_time = inner
                .state
                .keystore
                .ios_server_lists
                .get(&bucket)
                .map_or(0, |cache| cache.server_time);
            let empty_bssid = self
                .config
                .ios_virtual()
                .and_then(|model| model.network.bssid.as_deref())
                .is_none_or(str::is_empty);
            let request = HttpServerListReq {
                account_u32: NativeU32(inner.state.keystore.uin as u32),
                server_time: NativeU32(server_time),
                carrier: carrier.clone(),
                network: if wifi { 100 } else { 1 },
                app_id: NativeU32(inner.state.profile.sub_app_id),
                device_identifier: inner.state.keystore.ios_msf_imei.clone(),
                account: inner.state.keystore.uin as i64,
                empty_bssid: i8::from(wifi && empty_bssid),
                ..Default::default()
            };
            inner.ios_mut().unwrap().discovery.next_id =
                inner.ios_mut().unwrap().discovery.next_id.wrapping_add(1);
            let id = inner.ios_mut().unwrap().discovery.next_id;
            let cancel = inner.cancel.child_token();
            inner.ios_mut().unwrap().discovery.pending = Some(PendingDiscovery {
                id,
                cancel: cancel.clone(),
            });
            #[cfg(not(test))]
            let url = ios_discovery::URL;
            #[cfg(test)]
            let url = inner
                .ios_mut()
                .unwrap()
                .discovery
                .url
                .clone()
                .unwrap_or_else(|| ios_discovery::URL.to_owned());
            (id, bucket, carrier, request, cancel, url, failure)
        };
        let weak = self.weak.clone();
        let task = tokio::spawn(async move {
            let result = tokio::select! {
                biased;
                _ = cancel.cancelled() => None,
                result = ios_discovery::fetch(&url, &request) => Some(result),
            };
            let Some(client) = weak.upgrade() else {
                return;
            };
            let mut inner = client.inner.lock().unwrap();
            if !inner
                .ios_mut()
                .unwrap()
                .discovery
                .pending
                .as_ref()
                .is_some_and(|pending| pending.id == id)
            {
                return;
            }
            inner.ios_mut().unwrap().discovery.pending = None;
            if inner.generation != generation || cancel.is_cancelled() {
                return;
            }
            let Some(result) = result else {
                return;
            };
            if !failure && inner.connection.is_some() {
                return;
            }
            if client.ios_discovery_context(&inner).is_none_or(
                |(current_bucket, current_carrier, _)| {
                    current_bucket != bucket || current_carrier != carrier
                },
            ) {
                return;
            }
            match result {
                Ok(response) => {
                    let rebuilt = response.result == 1;
                    let mut cache = inner
                        .state
                        .keystore
                        .ios_server_lists
                        .get(&bucket)
                        .cloned()
                        .unwrap_or_default();
                    match cache.accept(response, &carrier, now_seconds()) {
                        Ok(()) => {
                            if rebuilt {
                                client.enqueue_ios_http_probes(&mut inner, &cache, &bucket);
                            }
                            inner.state.keystore.ios_server_lists.insert(bucket, cache);
                            inner.ios_mut().unwrap().discovery.cursor = 0;
                            client.emit(LoginEvent::KeystoreChanged(inner.state.keystore.clone()));
                        }
                        Err(error) => tracing::debug!(%error, "Rejected iOS discovery result"),
                    }
                }
                Err(error) => {
                    tracing::debug!(%error, "iOS discovery failed; preserving cached servers")
                }
            }
        });
        self.tasks.lock().unwrap().push(task);
    }

    pub(super) async fn connect_ios_cached_socket(&self) -> Option<TcpStream> {
        if !self.ios_discovery_enabled() {
            return None;
        }
        let (servers, cursor, generation) = {
            let inner = self.inner.lock().unwrap();
            let (bucket, _, wifi) = self.ios_discovery_context(&inner)?;
            let cache = inner.state.keystore.ios_server_lists.get(&bucket)?;
            let selection = if wifi {
                ServerSelection::Wifi
            } else {
                ServerSelection::Mobile
            };
            let servers: Vec<_> = cache
                .tcp_servers(selection)
                .map(|server| {
                    (
                        server.host.clone(),
                        server.port as u16,
                        server.connect_timeout(),
                    )
                })
                .collect();
            (servers, inner.ios()?.discovery.cursor, inner.generation)
        };
        if servers.is_empty() {
            return None;
        }
        let start = cursor % servers.len();
        for offset in 0..servers.len() {
            let index = (start + offset) % servers.len();
            let (host, port, connect_timeout) = &servers[index];
            {
                let mut inner = self.inner.lock().unwrap();
                if inner.generation != generation || inner.cancel.is_cancelled() {
                    return None;
                }
                inner.ios_mut().unwrap().discovery.cursor = (index + 1) % servers.len();
            }
            if let Ok(Ok(socket)) =
                tokio::time::timeout(*connect_timeout, TcpStream::connect((host.as_str(), *port)))
                    .await
            {
                return Some(socket);
            }
            self.start_ios_discovery(generation, true);
        }
        None
    }
}

#[cfg(test)]
mod tests;
