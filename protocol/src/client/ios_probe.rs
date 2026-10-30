use super::*;
use crate::network::{SsoServerLists, ios_discovery::ServerListCache, ios_probe as probe};
use probe::{AddressFamily, Endpoint, Outcome, Report, Source};

#[cfg(test)]
mod tests;

#[derive(Default)]
pub(super) struct State {
    queue: VecDeque<Candidate>,
    running: bool,
    reports: Option<broadcast::Sender<Arc<Report>>>,
}

struct Candidate {
    endpoint: Endpoint,
    source: Arc<Source>,
}

impl State {
    pub(super) fn clear(&mut self) {
        self.queue.clear();
        self.running = false;
    }
}

impl Client {
    pub fn ios_probe_reports(&self) -> Result<broadcast::Receiver<Arc<Report>>> {
        let mut inner = self.inner.lock().unwrap();
        let ios = inner.ios_mut().ok_or_else(|| {
            Error::Unsupported("Endpoint probe reports require an iPhone or iPad client".into())
        })?;
        Ok(ios
            .probes
            .reports
            .get_or_insert_with(|| broadcast::channel(64).0)
            .subscribe())
    }

    pub(super) fn enqueue_ios_http_probes(
        &self,
        inner: &mut Inner,
        cache: &ServerListCache,
        bucket: &str,
    ) {
        if self.config.server_selection == crate::network::ServerSelection::Configured {
            return;
        }
        let Some(ios) = inner.ios_mut() else { return };
        if ios.transport.network_type == 0 {
            return;
        }
        let mut source = None;
        let primary = if ios.transport.network_type == 1 {
            &cache.wifi
        } else {
            &cache.mobile
        };
        for (servers, family) in [
            (primary, AddressFamily::Ipv4),
            (&cache.ipv6, AddressFamily::Ipv6),
        ] {
            for server in servers
                .iter()
                .filter(|server| server.transport == 0 && server.probe_eligibility != 0)
            {
                let Ok(endpoint) = server.endpoint() else {
                    continue;
                };
                ios.probes.queue.push_back(Candidate {
                    endpoint: Endpoint {
                        host: endpoint.host.to_owned(),
                        port: endpoint.port,
                        timeout: server.connect_timeout(),
                        family,
                    },
                    source: source
                        .get_or_insert_with(|| {
                            Arc::new(Source::HttpDiscovery {
                                bucket: bucket.to_owned(),
                            })
                        })
                        .clone(),
                });
            }
        }
        self.start_ios_probe_worker(inner);
    }

    pub(super) fn enqueue_ios_config_probes(&self, inner: &mut Inner, lists: &SsoServerLists) {
        if self.config.server_selection == crate::network::ServerSelection::Configured {
            return;
        }
        let Some(ios) = inner.ios_mut() else { return };
        if ios.transport.network_type == 0 {
            return;
        }
        let mut source = None;
        let primary = if ios.transport.network_type == 1 {
            &lists.list_3
        } else {
            &lists.list_1
        };
        for (servers, family) in [
            (primary, AddressFamily::Ipv4),
            (&lists.list_11, AddressFamily::Ipv6),
        ] {
            for server in servers
                .iter()
                .filter(|server| server.protocol == 0 && server.field_11 != 0)
            {
                let Ok(endpoint) = server.endpoint() else {
                    continue;
                };
                ios.probes.queue.push_back(Candidate {
                    endpoint: Endpoint {
                        host: endpoint.host.to_owned(),
                        port: endpoint.port,
                        timeout: server.connect_timeout(),
                        family,
                    },
                    source: source
                        .get_or_insert_with(|| Arc::new(Source::ConfigPush))
                        .clone(),
                });
            }
        }
        self.start_ios_probe_worker(inner);
    }

    fn ios_probe_stack(&self, inner: &Inner) -> Option<u8> {
        let ios = inner.ios()?;
        if let Some(stack) = self
            .config
            .ios_virtual()
            .and_then(|model| model.network.ip_stack)
        {
            return Some(stack as u8);
        }
        if let Some(stack) = ios
            .network
            .as_ref()
            .map(|network| network.ip_stack())
            .filter(|stack| *stack != 0)
        {
            return Some(stack);
        }
        let reserved =
            crate::proto::sso::Reserved::decode(ios.transport.reserved.as_bytes()).ok()?;
        reserved
            .ip_stack_type
            .map(|stack| u8::try_from(stack).unwrap_or(0))
    }

    pub(super) fn start_ios_probe_worker(&self, inner: &mut Inner) {
        let Some(ios) = inner.ios() else { return };
        if ios.probes.running || ios.probes.queue.is_empty() || inner.cancel.is_cancelled() {
            return;
        }
        if self.ios_probe_stack(inner).is_none() {
            return;
        }
        inner.ios_mut().unwrap().probes.running = true;
        let generation = inner.generation;
        let cancel = inner.cancel.clone();
        let weak = self.weak.clone();
        let task = tokio::spawn(async move {
            loop {
                let Some(client) = weak.upgrade() else { return };
                let next = {
                    let mut inner = client.inner.lock().unwrap();
                    if inner.generation != generation || cancel.is_cancelled() {
                        return;
                    }
                    let Some(stack) = client.ios_probe_stack(&inner) else {
                        inner.ios_mut().unwrap().probes.running = false;
                        return;
                    };
                    let ios = inner.ios_mut().unwrap();
                    let mut next = None;
                    while let Some(candidate) = ios.probes.queue.pop_front() {
                        if ios.transport.network_type != 0
                            && candidate.endpoint.family.accepts(stack)
                        {
                            next = Some((candidate, ios.transport.network_type, stack));
                            break;
                        }
                    }
                    if next.is_none() {
                        ios.probes.running = false;
                    }
                    next
                };
                drop(client);
                let Some((candidate, network_type, stack)) = next else {
                    return;
                };
                let started = match crate::ios_device::network::wall_millis() {
                    Ok(now) => now,
                    Err(error) => {
                        if let Some(client) = weak.upgrade() {
                            client.stop_ios_probe_worker(generation, &cancel);
                        }
                        tracing::warn!(%error, "Endpoint probe cannot sample its start time");
                        return;
                    }
                };
                let result = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return,
                    result = tokio::time::timeout(
                        candidate.endpoint.timeout,
                        TcpStream::connect((candidate.endpoint.host.as_str(), candidate.endpoint.port)),
                    ) => result,
                };
                let Some(client) = weak.upgrade() else { return };
                let reports = {
                    let inner = client.inner.lock().unwrap();
                    if inner.generation != generation || cancel.is_cancelled() {
                        return;
                    }
                    inner
                        .ios()
                        .unwrap()
                        .probes
                        .reports
                        .as_ref()
                        .filter(|reports| reports.receiver_count() != 0)
                        .cloned()
                };
                let Some(reports) = reports else { continue };
                let finished = match crate::ios_device::network::wall_millis() {
                    Ok(now) => now,
                    Err(error) => {
                        client.stop_ios_probe_worker(generation, &cancel);
                        tracing::warn!(%error, "Endpoint probe cannot sample its completion time");
                        return;
                    }
                };
                let outcome = match result {
                    Ok(Ok(socket)) => Outcome::Connected {
                        local_addr: socket.local_addr().ok(),
                        peer_addr: socket.peer_addr().ok(),
                    },
                    Ok(Err(error)) => Outcome::Failed {
                        message: error.to_string(),
                        raw_os_error: error.raw_os_error(),
                    },
                    Err(_) => Outcome::TimedOut,
                };
                let report = Arc::new(Report {
                    source: candidate.source,
                    endpoint: candidate.endpoint,
                    generation,
                    network_type,
                    ip_stack: stack,
                    started_unix_millis: started,
                    finished_unix_millis: finished,
                    outcome,
                });
                let inner = client.inner.lock().unwrap();
                if inner.generation == generation && !cancel.is_cancelled() {
                    let _ = reports.send(report);
                }
            }
        });
        let mut tasks = self.tasks.lock().unwrap();
        tasks.retain(|task| !task.is_finished());
        tasks.push(task);
    }

    fn stop_ios_probe_worker(&self, generation: u64, cancel: &CancellationToken) {
        let mut inner = self.inner.lock().unwrap();
        if inner.generation == generation && !cancel.is_cancelled() {
            inner.ios_mut().unwrap().probes.running = false;
        }
    }
}
