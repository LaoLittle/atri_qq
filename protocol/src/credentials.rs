use crate::{Client, Error, Result, contacts::ClientKey};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Weak},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::Notify, time::Instant};
use tokio_util::sync::CancellationToken;

pub(crate) mod file_transfer;

const STARTUP_DOMAINS: [&str; 3] = ["pd.qq.com", "mail.qq.com", "docs.qq.com"];

pub(crate) struct Session {
    pub(crate) generation: u64,
    pub(crate) cancel: CancellationToken,
}
struct Timed<T> {
    value: T,
    expires: Instant,
}
#[derive(Clone, Copy)]
struct Refresh {
    at: Instant,
    interval: Option<Duration>,
}
#[derive(Default)]
pub(crate) struct Cache {
    session: Option<Arc<Session>>,
    client_key: Option<Timed<ClientKey>>,
    client_key_refresh: Option<Refresh>,
    cookies: BTreeMap<String, Timed<String>>,
    domains: BTreeSet<String>,
    cookie_refresh: BTreeMap<String, Refresh>,
}
pub(crate) struct Work {
    pub(crate) session: Arc<Session>,
    pub(crate) client_key: bool,
    pub(crate) domains: Vec<String>,
    pub(crate) next: Option<Instant>,
}
impl Cache {
    pub(crate) fn activate(&mut self, generation: u64, cancel: &CancellationToken) {
        if self.session.is_none() {
            self.session = Some(Arc::new(Session {
                generation,
                cancel: cancel.child_token(),
            }));
        }
    }
    pub(crate) fn invalidate(&mut self, clear_domains: bool) {
        if let Some(session) = self.session.take() {
            session.cancel.cancel();
        }
        self.client_key = None;
        self.client_key_refresh = None;
        self.cookies.clear();
        self.cookie_refresh.clear();
        if clear_domains {
            self.domains.clear();
        }
    }
    pub(crate) fn session(&self) -> Result<Arc<Session>> {
        self.session
            .as_ref()
            .filter(|session| !session.cancel.is_cancelled())
            .cloned()
            .ok_or(Error::Disconnected)
    }
    pub(crate) fn is_current(&self, session: &Arc<Session>) -> bool {
        !session.cancel.is_cancelled()
            && self
                .session
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, session))
    }
    pub(crate) fn start(&mut self) {
        let now = Instant::now();
        self.client_key_refresh.get_or_insert(Refresh {
            at: now,
            interval: None,
        });
        self.domains
            .extend(STARTUP_DOMAINS.into_iter().map(str::to_owned));
        for domain in &self.domains {
            self.cookie_refresh
                .entry(domain.clone())
                .or_insert(Refresh {
                    at: now,
                    interval: None,
                });
        }
    }
    pub(crate) fn client_key(&mut self) -> Option<ClientKey> {
        let cached = self.client_key.as_ref()?;
        let remaining = cached
            .expires
            .saturating_duration_since(Instant::now())
            .as_secs();
        if remaining == 0 {
            self.client_key = None;
            return None;
        }
        let mut key = cached.value.clone();
        // The public value is a remaining TTL, not the original issuance lifetime.
        key.expiration = remaining as u32;
        Some(key)
    }
    pub(crate) fn cookies(&mut self, domains: &[String]) -> Option<BTreeMap<String, String>> {
        let now = Instant::now();
        self.cookies.retain(|_, cookie| cookie.expires > now);
        domains
            .iter()
            .map(|domain| {
                self.cookies
                    .get(domain)
                    .map(|cookie| (domain.clone(), cookie.value.clone()))
            })
            .collect()
    }
    pub(crate) fn commit_client_key(&mut self, key: &ClientKey) {
        let interval = Duration::from_secs(u64::from(key.expiration));
        let expires = Instant::now().checked_add(interval);
        self.client_key = expires
            .filter(|_| !interval.is_zero())
            .map(|expires| Timed {
                value: key.clone(),
                expires,
            });
        self.client_key_refresh = self.client_key.as_ref().map(|key| Refresh {
            at: key.expires,
            interval: Some(interval),
        });
    }
    pub(crate) fn commit_cookies(
        &mut self,
        domains: &[String],
        values: &BTreeMap<String, String>,
        expirations: &BTreeMap<String, u64>,
    ) {
        let now = Instant::now();
        let unix_now = SystemTime::now().duration_since(UNIX_EPOCH).ok();
        for domain in domains {
            self.domains.insert(domain.clone());
            self.cookies.remove(domain);
            self.cookie_refresh.remove(domain);
            let Some(value) = values.get(domain).filter(|value| !value.is_empty()) else {
                continue;
            };
            let Some(expiration) = expirations.get(domain) else {
                continue;
            };
            // CookieRecord field 3 is an absolute Unix timestamp, not a relative TTL.
            let Some(interval) =
                unix_now.and_then(|now| Duration::from_secs(*expiration).checked_sub(now))
            else {
                continue;
            };
            if interval.is_zero() {
                continue;
            }
            let Some(expires) = now.checked_add(interval) else {
                continue;
            };
            self.cookies.insert(
                domain.clone(),
                Timed {
                    value: value.clone(),
                    expires,
                },
            );
            self.cookie_refresh.insert(
                domain.clone(),
                Refresh {
                    at: expires,
                    interval: Some(interval),
                },
            );
        }
    }
    pub(crate) fn work(&self) -> Result<Work> {
        let now = Instant::now();
        let next = self
            .client_key_refresh
            .iter()
            .map(|refresh| refresh.at)
            .chain(self.cookie_refresh.values().map(|refresh| refresh.at))
            .min();
        Ok(Work {
            session: self.session()?,
            client_key: self
                .client_key_refresh
                .is_some_and(|refresh| refresh.at <= now),
            domains: self
                .cookie_refresh
                .iter()
                .filter(|(_, refresh)| refresh.at <= now)
                .map(|(domain, _)| domain.clone())
                .collect(),
            next,
        })
    }
    pub(crate) fn failed(&mut self, client_key: bool, domains: &[String]) {
        // A failure never extends a credential's validity. Only a previously received
        // server lifetime can retain a background cadence; there is no immediate retry.
        let next = |refresh: Refresh| {
            refresh.interval.and_then(|interval| {
                Instant::now().checked_add(interval).map(|at| Refresh {
                    at,
                    interval: Some(interval),
                })
            })
        };
        if client_key {
            self.client_key_refresh = self.client_key_refresh.and_then(next);
        }
        for domain in domains {
            if let Some(refresh) = self.cookie_refresh.remove(domain).and_then(next) {
                self.cookie_refresh.insert(domain.clone(), refresh);
            }
        }
    }
}

pub(crate) async fn run(
    weak: Weak<Client>,
    generation: u64,
    cancel: CancellationToken,
    notify: Arc<Notify>,
) {
    loop {
        let notified = notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let Some(client) = weak.upgrade() else { return };
        if cancel.is_cancelled() || !client.is_current_online(generation) {
            return;
        }
        let Ok(work) = client.credential_work(generation) else {
            return;
        };
        if work.client_key || !work.domains.is_empty() {
            if work.client_key {
                let result = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return,
                    result = client.refresh_client_key(&work.session) => result,
                };
                if let Err(error) = result {
                    client.credential_refresh_failed(&work.session, true, &[]);
                    if !cancel.is_cancelled() && !work.session.cancel.is_cancelled() {
                        tracing::warn!(%error, "Client key refresh failed; retaining only a known server cadence");
                    }
                }
            }
            if !work.domains.is_empty() {
                let result = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return,
                    result = client.refresh_cookies(&work.session, &work.domains) => result,
                };
                if let Err(error) = result {
                    client.credential_refresh_failed(&work.session, false, &work.domains);
                    if !cancel.is_cancelled() && !work.session.cancel.is_cancelled() {
                        tracing::warn!(%error, "Domain PSKey refresh failed; retaining only known server cadences");
                    }
                }
            }
            continue;
        }
        drop(client);
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            _ = &mut notified => {},
            _ = async {
                if let Some(next) = work.next {
                    tokio::time::sleep_until(next).await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {},
        }
    }
}
