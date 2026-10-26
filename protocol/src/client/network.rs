use super::*;
use crate::network::{self, IpDirectConfiguration, ServerSelection, SsoConfiguration};

impl Client {
    pub fn login_notifications(&self) -> broadcast::Receiver<Arc<network::LoginNotification>> {
        self.login_notifications.subscribe()
    }

    pub fn cached_ip_direct_configuration(&self) -> Option<Arc<IpDirectConfiguration>> {
        let inner = self.inner.lock().unwrap();
        if !Self::current_online(&inner, inner.generation) {
            return None;
        }
        let (session, configuration) = inner.ip_direct_configuration.as_ref()?;
        inner
            .credentials
            .is_current(session)
            .then(|| configuration.clone())
    }

    pub fn cached_sso_configuration(&self) -> Option<Arc<SsoConfiguration>> {
        self.inner.lock().unwrap().sso_configuration.clone()
    }

    pub async fn ip_direct_configuration(&self) -> Result<Arc<IpDirectConfiguration>> {
        if let Some(configuration) = self.cached_ip_direct_configuration() {
            return Ok(configuration);
        }
        self.refresh_ip_direct_configuration(self.connection_generation())
            .await
    }

    pub(crate) async fn refresh_ip_direct_configuration(
        &self,
        generation: u64,
    ) -> Result<Arc<IpDirectConfiguration>> {
        let (session, account) = {
            let inner = self.inner.lock().unwrap();
            if !Self::current_online(&inner, generation) {
                return Err(Error::Disconnected);
            }
            (inner.credentials.session()?, inner.state.keystore.uin)
        };
        let response = self
            .request_inner(
                network::GET_IP_DIRECT_COMMAND,
                network::GetIpDirectRequest.encode(),
                RequestType::D2,
                Encryption::D2,
                self.config.timeout,
                Some(RequestBinding::Credentials(&session)),
            )
            .await?;
        let configuration = Arc::new(network::decode_get_ip_direct(response, account)?);
        let mut inner = self.inner.lock().unwrap();
        if !Self::current_online(&inner, generation) || !inner.credentials.is_current(&session) {
            return Err(Error::Disconnected);
        }
        inner.ip_direct_configuration = Some((session, configuration.clone()));
        Ok(configuration)
    }

    pub(crate) fn apply_network_push(&self, generation: u64, body: Bytes) -> Result<Option<Bytes>> {
        let push = network::decode_push(body)?;
        if let network::ConfigPushBody::SsoServers(configuration) = push.body {
            match configuration {
                Ok(configuration) => {
                    let mut inner = self.inner.lock().unwrap();
                    if inner.generation != generation
                        || inner.connection.is_none()
                        || inner.kick_reason.is_some()
                    {
                        return Err(Error::Disconnected);
                    }
                    inner.sso_configuration = Some(Arc::new(configuration));
                    inner.server_cursor = 0;
                }
                Err(error) => {
                    tracing::warn!(%error, "Rejected SSO server configuration; preserving control acknowledgment")
                }
            }
        }
        Ok(push.acknowledgment)
    }

    pub(crate) async fn connect_socket(&self) -> Result<TcpStream> {
        let (configuration, cursor) = {
            let inner = self.inner.lock().unwrap();
            (inner.sso_configuration.clone(), inner.server_cursor)
        };
        if self.config.server_selection != ServerSelection::Configured
            && let Some(configuration) = configuration
        {
            let servers = configuration
                .servers
                .tcp_servers(self.config.server_selection);
            let capacity = servers.size_hint().1.unwrap_or(0);
            let mut candidates = Vec::with_capacity(capacity);
            let mut seen = std::collections::HashSet::with_capacity(capacity);
            for server in servers {
                if seen.insert((&server.host, server.port)) {
                    candidates.push(server);
                }
            }
            if !candidates.is_empty() {
                let start = cursor % candidates.len();
                for offset in 0..candidates.len() {
                    let index = (start + offset) % candidates.len();
                    let server = candidates[index];
                    let endpoint = server.endpoint()?;
                    if endpoint.is_unspecified() {
                        continue;
                    }
                    {
                        let mut inner = self.inner.lock().unwrap();
                        if inner
                            .sso_configuration
                            .as_ref()
                            .is_some_and(|current| Arc::ptr_eq(current, &configuration))
                        {
                            inner.server_cursor = (index + 1) % candidates.len();
                        }
                    }
                    if let Ok(Ok(socket)) = tokio::time::timeout(
                        server.connect_timeout(),
                        TcpStream::connect((endpoint.host, endpoint.port)),
                    )
                    .await
                    {
                        let mut inner = self.inner.lock().unwrap();
                        if inner
                            .sso_configuration
                            .as_ref()
                            .is_some_and(|current| Arc::ptr_eq(current, &configuration))
                        {
                            inner.server_cursor = index;
                        }
                        return Ok(socket);
                    }
                }
            }
        }
        TcpStream::connect((self.config.host.as_str(), self.config.port))
            .await
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{SsoServerInfo, SsoServerLists};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn configured_connections_stay_pinned_and_wifi_uses_only_tcp_candidates() {
        let bootstrap = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let wifi = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let configuration = Arc::new(SsoConfiguration {
            servers: SsoServerLists {
                list_3: vec![
                    SsoServerInfo {
                        host: "127.0.0.1".into(),
                        port: i32::from(http.local_addr().unwrap().port()),
                        protocol: 3,
                        ..Default::default()
                    },
                    SsoServerInfo {
                        host: "127.0.0.1".into(),
                        port: i32::from(wifi.local_addr().unwrap().port()),
                        protocol: 0,
                        ..Default::default()
                    },
                ],
                list_21: vec![SsoServerInfo {
                    host: "127.0.0.1".into(),
                    port: i32::from(http.local_addr().unwrap().port()),
                    protocol: 0,
                    ..Default::default()
                }],
                ..Default::default()
            },
            raw: Bytes::new(),
        });
        for selection in [ServerSelection::Configured, ServerSelection::Wifi] {
            let client = Client::new(
                ClientConfig {
                    host: "127.0.0.1".into(),
                    port: bootstrap.local_addr().unwrap().port(),
                    server_selection: selection,
                    timeout: Duration::from_secs(2),
                    ..Default::default()
                },
                Keystore::default(),
            )
            .unwrap();
            client.inner.lock().unwrap().sso_configuration = Some(configuration.clone());
            client.connect().await.unwrap();
            let expected = match selection {
                ServerSelection::Configured => &bootstrap,
                ServerSelection::Wifi => &wifi,
                ServerSelection::Mobile => unreachable!(),
            };
            let (socket, _) = tokio::time::timeout(Duration::from_secs(2), expected.accept())
                .await
                .unwrap()
                .unwrap();
            client
                .close_transport("Synthetic server selection finished".into())
                .await;
            drop(socket);
        }
    }
}
