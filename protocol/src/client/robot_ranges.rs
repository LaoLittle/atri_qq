use super::*;
use crate::{
    contacts::{
        RobotUinRangesCache, RobotUinRangesSnapshot,
        robot_ranges::{self, Binding},
    },
    proto::{contacts::OidbEnvelope, robot_ranges as pb},
};

impl Client {
    pub fn robot_uin_ranges(&self) -> Option<Arc<RobotUinRangesSnapshot>> {
        let inner = self.inner.lock().unwrap();
        inner
            .robot_ranges
            .snapshot(inner.state.keystore.uin, &inner.state.keystore.uid)
    }

    pub fn is_robot_uin(&self, uin: u64) -> Option<bool> {
        self.robot_uin_ranges()
            .map(|snapshot| snapshot.is_robot_uin(uin))
    }

    pub fn robot_uin_ranges_changes(&self) -> watch::Receiver<()> {
        self.inner.lock().unwrap().robot_ranges.subscribe()
    }

    pub fn robot_uin_ranges_cache(&self) -> Option<RobotUinRangesCache> {
        let inner = self.inner.lock().unwrap();
        inner
            .robot_ranges
            .cache(inner.state.keystore.uin, &inner.state.keystore.uid)
    }

    pub fn restore_robot_uin_ranges_cache(&self, cache: RobotUinRangesCache) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.connection.is_some() || inner.state.online {
            return Err(Error::Unsupported(
                "Restore robot range caches before connecting".into(),
            ));
        }
        let Inner {
            state,
            robot_ranges,
            ..
        } = &mut *inner;
        robot_ranges.restore(cache, state.keystore.uin, &state.keystore.uid)
    }

    pub fn restore_robot_uin_ranges_cache_bytes(&self, bytes: &[u8]) -> Result<()> {
        let cache = serde_json::from_slice(bytes)
            .map_err(|error| Error::Malformed(format!("Invalid robot range cache: {error}")))?;
        self.restore_robot_uin_ranges_cache(cache)
    }

    pub async fn fetch_robot_uin_ranges(&self) -> Result<Arc<RobotUinRangesSnapshot>> {
        let (generation, cancel) = {
            let inner = self.inner.lock().unwrap();
            (inner.generation, inner.cancel.clone())
        };
        self.fetch_robot_uin_ranges_generation(generation, &cancel)
            .await
    }

    async fn fetch_robot_uin_ranges_generation(
        &self,
        generation: u64,
        cancel: &CancellationToken,
    ) -> Result<Arc<RobotUinRangesSnapshot>> {
        let _gate = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(Error::Disconnected),
            gate = self.robot_ranges_gate.lock() => gate,
        };
        let (binding, request) = {
            let mut inner = self.inner.lock().unwrap();
            if !Self::current_online(&inner, generation)
                || inner.kick_reason.is_some()
                || inner.state.keystore.uin == 0
                || inner.state.keystore.uid.is_empty()
                || cancel.is_cancelled()
            {
                return Err(Error::Disconnected);
            }
            let now = inner.clock.unix_millis()?;
            let Inner {
                state,
                robot_ranges,
                ..
            } = &mut *inner;
            let binding =
                robot_ranges.begin(generation, state.keystore.uin, &state.keystore.uid, cancel);
            let Some(request) = robot_ranges.request(now) else {
                return robot_ranges
                    .snapshot(state.keystore.uin, &state.keystore.uid)
                    .ok_or(Error::Disconnected);
            };
            (binding, request)
        };
        let envelope = OidbEnvelope {
            command: Some(0x496),
            service: Some(0),
            reserved: Some(1),
            body: Some(request.encode_to_vec().into()),
            ..Default::default()
        };
        let bytes = tokio::select! {
            biased;
            _ = binding.cancel.cancelled() => return Err(Error::Disconnected),
            bytes = self.request_online(generation, robot_ranges::COMMAND,
                envelope.encode_to_vec().into(), self.config.timeout) => bytes?,
        };
        let response = decode_response(bytes)?;
        let mut inner = self.inner.lock().unwrap();
        if !robot_ranges_current(&inner, &binding) || cancel.is_cancelled() {
            return Err(Error::Disconnected);
        }
        let now = inner.clock.unix_millis()?;
        inner.robot_ranges.apply(&binding, response, now)
    }
}

fn robot_ranges_current(inner: &Inner, binding: &Arc<Binding>) -> bool {
    Client::current_online(inner, binding.generation)
        && inner.kick_reason.is_none()
        && inner.state.keystore.uin == binding.account_uin
        && inner.state.keystore.uid == binding.account_uid
        && inner.robot_ranges.current(binding)
}

fn decode_response(bytes: Bytes) -> Result<pb::RobotUinRangeResponse> {
    let envelope: OidbEnvelope = crate::diagnostics::decode_response(robot_ranges::COMMAND, bytes)?;
    crate::contacts::check_code(envelope.code, envelope.message)?;
    if envelope.command.is_some_and(|command| command != 0x496)
        || envelope.service.is_some_and(|service| service != 0)
    {
        return Err(Error::Malformed(
            "Mismatched robot range OIDB response".into(),
        ));
    }
    let body = envelope
        .body
        .ok_or_else(|| Error::Malformed("Robot range OIDB response has no body".into()))?;
    crate::diagnostics::decode_response(robot_ranges::COMMAND, body)
}

pub(crate) async fn run(weak: Weak<Client>, generation: u64, cancel: CancellationToken) {
    let Some(client) = weak.upgrade() else {
        return;
    };
    if let Err(error) = client
        .fetch_robot_uin_ranges_generation(generation, &cancel)
        .await
    {
        if !cancel.is_cancelled() {
            tracing::warn!(%error, "QQ robot UIN range configuration failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contacts::RobotUinRange;

    fn cache(time: u64) -> RobotUinRangesCache {
        RobotUinRangesCache {
            account_uin: 42,
            account_uid: "u_test".into(),
            snapshot: RobotUinRangesSnapshot {
                version: 17,
                ranges: vec![RobotUinRange {
                    min_uin: 100,
                    max_uin: 200,
                }],
                received_unix_ms: time,
            },
        }
    }

    fn client() -> Arc<Client> {
        let mut keys = Keystore::default();
        keys.uin = 42;
        keys.uid = "u_test".into();
        Client::new(ClientConfig::default(), keys).unwrap()
    }

    fn connect(client: &Client) -> mpsc::Receiver<Outgoing> {
        let (sender, receiver) = mpsc::channel(8);
        let mut inner = client.inner.lock().unwrap();
        inner.generation = 7;
        inner.connection = Some(Connection {
            generation: 7,
            sender,
        });
        inner.state.online = true;
        receiver
    }

    fn response(version: u32, ranges: Vec<pb::RobotUinRange>) -> Bytes {
        OidbEnvelope {
            command: Some(0x496),
            service: Some(0),
            code: Some(0),
            body: Some(
                pb::RobotUinRangeResponse {
                    robot_config: Some(pb::RobotUinRangeConfig {
                        version: Some(version),
                        ranges,
                    }),
                }
                .encode_to_vec()
                .into(),
            ),
            ..Default::default()
        }
        .encode_to_vec()
        .into()
    }

    fn reply(client: &Client, sequence: i32, bytes: Result<Bytes>) {
        let pending = client
            .inner
            .lock()
            .unwrap()
            .pending
            .remove(&sequence)
            .unwrap();
        assert!(pending.reply.send(bytes).is_ok());
    }

    fn range() -> pb::RobotUinRange {
        pb::RobotUinRange {
            min_uin: Some(u32::MAX as u64 + 1),
            max_uin: Some(u64::MAX),
        }
    }

    #[test]
    fn explicit_cache_restore_is_account_bound_and_bad_reads_do_not_erase_data() {
        let client = client();
        assert_eq!(client.is_robot_uin(100), None);
        let encoded = serde_json::to_vec(&cache(1000)).unwrap();
        client
            .restore_robot_uin_ranges_cache_bytes(&encoded)
            .unwrap();
        assert_eq!(client.is_robot_uin(100), Some(true));
        assert_eq!(client.is_robot_uin(200), Some(true));
        assert_eq!(client.is_robot_uin(201), Some(false));
        assert!(
            client
                .restore_robot_uin_ranges_cache_bytes(b"broken")
                .is_err()
        );
        let mut foreign = cache(2000);
        foreign.account_uid = "u_other".into();
        assert!(client.restore_robot_uin_ranges_cache(foreign).is_err());
        assert_eq!(client.robot_uin_ranges_cache().unwrap(), cache(1000));
    }

    #[tokio::test]
    async fn cold_lifecycle_fetch_publishes_real_ranges_and_fresh_cache_prevents_another_request() {
        let client = client();
        let mut changes = client.robot_uin_ranges_changes();
        let mut queue = connect(&client);
        let worker = tokio::spawn(run(Arc::downgrade(&client), 7, CancellationToken::new()));
        let outgoing = queue.recv().await.unwrap();
        assert_eq!(outgoing.command, robot_ranges::COMMAND);
        reply(&client, outgoing.sequence, Ok(response(18, vec![range()])));
        worker.await.unwrap();
        changes.changed().await.unwrap();
        assert_eq!(client.is_robot_uin(u32::MAX as u64), Some(false));
        assert_eq!(client.is_robot_uin(u32::MAX as u64 + 1), Some(true));
        assert_eq!(client.is_robot_uin(u64::MAX), Some(true));
        assert_eq!(
            client.robot_uin_ranges_cache().unwrap().snapshot.version,
            18
        );
        let fetched = client.fetch_robot_uin_ranges().await.unwrap();
        assert_eq!(fetched.version, 18);
        assert!(queue.try_recv().is_err());
    }

    #[tokio::test]
    async fn stale_cache_survives_server_errors_and_empty_configuration() {
        let client = client();
        client.restore_robot_uin_ranges_cache(cache(1000)).unwrap();
        let before = client.robot_uin_ranges().unwrap();
        let mut queue = connect(&client);
        let rejected = OidbEnvelope {
            command: Some(0x496),
            service: Some(0),
            code: Some(9),
            message: Some("synthetic OIDB rejection".into()),
            ..Default::default()
        }
        .encode_to_vec()
        .into();
        for result in [
            Err(Error::Server {
                code: 7,
                message: "synthetic failure".into(),
            }),
            Ok(rejected),
            Ok(Bytes::from_static(b"\xff")),
            Ok(response(18, Vec::new())),
        ] {
            let caller = client.clone();
            let task = tokio::spawn(async move { caller.fetch_robot_uin_ranges().await });
            let outgoing = queue.recv().await.unwrap();
            reply(&client, outgoing.sequence, result);
            assert!(task.await.unwrap().is_err());
            assert!(Arc::ptr_eq(&before, &client.robot_uin_ranges().unwrap()));
            assert_eq!(
                client.robot_uin_ranges_cache().unwrap().snapshot.version,
                17
            );
        }
    }

    #[tokio::test]
    async fn generation_account_replacement_and_cancellation_reject_late_publication() {
        for change in 0..3 {
            let client = client();
            client.restore_robot_uin_ranges_cache(cache(1000)).unwrap();
            let mut queue = connect(&client);
            let cancel = CancellationToken::new();
            let worker = tokio::spawn(run(Arc::downgrade(&client), 7, cancel.clone()));
            let outgoing = queue.recv().await.unwrap();
            {
                let mut inner = client.inner.lock().unwrap();
                match change {
                    0 => {
                        inner.generation = 8;
                        inner.connection.as_mut().unwrap().generation = 8;
                    }
                    1 => {
                        inner.robot_ranges.clear();
                        inner.state.keystore.uid = "u_other".into();
                        inner.robot_ranges.clear();
                        inner.state.keystore.uid = "u_test".into();
                    }
                    _ => cancel.cancel(),
                }
            }
            reply(&client, outgoing.sequence, Ok(response(18, vec![range()])));
            worker.await.unwrap();
            if change == 1 {
                assert!(client.robot_uin_ranges().is_none());
            } else {
                assert_eq!(
                    client.robot_uin_ranges_cache().unwrap().snapshot.version,
                    17
                );
            }
        }
    }
}
