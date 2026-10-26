use super::{ChannelInfo, GuildInfo, GuildSnapshot};
use crate::{Error, IncomingPacket, Result, proto};
use bytes::Bytes;
use std::{collections::BTreeMap, sync::Mutex, time::Duration};
use tokio::sync::watch;

const INFO_SYNC_PUSH: &str = "trpc.msg.register_proxy.RegisterProxy.InfoSyncPush";
const PUSH_PARAMS: &str = "trpc.msg.register_proxy.RegisterProxy.PushParams";

pub(crate) struct Session {
    state: Mutex<State>,
    changed: watch::Sender<()>,
}

#[derive(Default)]
struct State {
    generation: Option<u64>,
    request_random: u32,
    enabled: Option<bool>,
    initial_result: Option<i32>,
    push_result: Option<u32>,
    complete: bool,
    error: Option<Error>,
    self_tiny_id: Option<u64>,
    guilds: BTreeMap<u64, WorkingGuild>,
}

#[derive(Default)]
struct WorkingGuild {
    name: String,
    channels: BTreeMap<u64, ChannelInfo>,
}

impl Default for Session {
    fn default() -> Self {
        let (changed, _) = watch::channel(());
        Self {
            state: Mutex::new(State::default()),
            changed,
        }
    }
}

impl Session {
    pub(crate) fn begin(&self, generation: u64, request_random: u32) {
        *self.state.lock().unwrap() = State {
            generation: Some(generation),
            request_random,
            ..State::default()
        };
        self.changed.send_replace(());
    }

    pub(crate) fn set_request_random(&self, generation: u64, request_random: u32) {
        let mut state = self.state.lock().unwrap();
        if state.generation == Some(generation) {
            state.request_random = request_random;
        }
    }

    pub(crate) fn ingest(&self, generation: u64, packet: &IncomingPacket) -> Result<()> {
        if packet.command != INFO_SYNC_PUSH && packet.command != PUSH_PARAMS {
            return Ok(());
        }
        let mut state = self.state.lock().unwrap();
        if state.generation != Some(generation) {
            return Ok(());
        }
        let was_pending = !state.complete && state.error.is_none();
        let result = if packet.return_code != 0 {
            Err(Error::Server {
                code: packet.return_code,
                message: "Guild synchronization transport failed".into(),
            })
        } else if packet.command == INFO_SYNC_PUSH {
            if !was_pending {
                return Ok(());
            }
            proto::decode::<proto::message_sync::InfoSyncPush>(packet.body.as_ref())
                .and_then(|push| state.ingest_info(&push))
        } else {
            proto::decode::<proto::guild::PushParams>(packet.body.as_ref()).and_then(|push| {
                if let Some(enabled) = push.guild.and_then(|guild| guild.enabled) {
                    state.enabled = Some(enabled == 1);
                    if state.enabled == Some(false) && was_pending {
                        return Err(Error::Unsupported(
                            "Guild support is disabled by the server".into(),
                        ));
                    }
                }
                Ok(())
            })
        };
        if let Err(error) = &result {
            if was_pending {
                state.error = Some(error.clone());
            }
        }
        if was_pending && (state.complete || state.error.is_some()) {
            self.changed.send_replace(());
        }
        result
    }

    pub(crate) fn ingest_info_push(
        &self,
        generation: u64,
        push: &proto::message_sync::InfoSyncPush,
    ) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        if state.generation != Some(generation) || state.complete || state.error.is_some() {
            return Ok(());
        }
        let result = state.ingest_info(push);
        if let Err(error) = &result {
            state.error = Some(error.clone());
        }
        if state.complete || state.error.is_some() {
            self.changed.send_replace(());
        }
        result
    }

    pub(crate) fn close(&self, generation: u64) {
        let mut state = self.state.lock().unwrap();
        if state.generation == Some(generation) {
            *state = State::default();
            self.changed.send_replace(());
        }
    }

    pub(crate) async fn wait_ready(&self, generation: u64, timeout: Duration) -> Result<()> {
        let mut changed = self.changed.subscribe();
        tokio::time::timeout(timeout, async {
            loop {
                {
                    let state = self.state.lock().unwrap();
                    state.check_generation(generation)?;
                    if let Some(error) = &state.error {
                        return Err(error.clone());
                    }
                    if state.complete {
                        return Ok(());
                    }
                }
                changed.changed().await.map_err(|_| Error::Disconnected)?;
            }
        })
        .await
        .map_err(|_| Error::Timeout)?
    }

    pub(crate) fn snapshot(&self, generation: u64) -> Result<GuildSnapshot> {
        let state = self.state.lock().unwrap();
        state.check_generation(generation)?;
        if let Some(error) = &state.error {
            return Err(error.clone());
        }
        if !state.complete {
            return Err(Error::Unsupported(
                "Guild synchronization is not ready".into(),
            ));
        }
        Ok(GuildSnapshot {
            self_tiny_id: state.self_tiny_id,
            push_result: state.push_result,
            guilds: state
                .guilds
                .iter()
                .map(|(&id, guild)| GuildInfo {
                    id,
                    number: None,
                    name: guild.name.clone(),
                    channels: guild.channels.values().cloned().collect(),
                })
                .collect(),
        })
    }

    pub(crate) fn tiny_id(&self, generation: u64) -> Option<u64> {
        let state = self.state.lock().unwrap();
        (state.generation == Some(generation))
            .then_some(state.self_tiny_id)
            .flatten()
    }
}

impl State {
    fn check_generation(&self, generation: u64) -> Result<()> {
        if self.generation == Some(generation) {
            Ok(())
        } else {
            Err(Error::Disconnected)
        }
    }

    fn ingest_info(&mut self, push: &proto::message_sync::InfoSyncPush) -> Result<()> {
        if push.request_random.unwrap_or_default() != self.request_random {
            return Ok(());
        }
        let Some(guild) = &push.guild else {
            return Ok(());
        };
        if let Some(result) = guild.result {
            self.push_result = Some(result);
        }
        if !matches!(push.stage, Some(1..=4)) {
            return Ok(());
        }
        if matches!(push.stage, Some(1 | 2)) {
            if let Some(result) = guild.first_sync_result {
                self.initial_result = Some(result);
            }
        }
        if let Some(tiny_id) = guild.self_tiny_id.filter(|id| *id > 0) {
            self.self_tiny_id = Some(tiny_id);
        }
        if matches!(push.stage, Some(3 | 4)) && self.initial_result != Some(1) {
            return Ok(());
        }
        for node in &guild.in_tab_nodes {
            self.merge_node(node)?;
        }
        if let Some(extra) = &guild.extra {
            for node in &extra.normal_nodes {
                self.merge_node(node)?;
            }
        }
        if push.stage == Some(4) && self.initial_result == Some(1) {
            self.complete = true;
        }
        Ok(())
    }

    fn merge_node(&mut self, bytes: &[u8]) -> Result<()> {
        let node: proto::guild::FirstViewGuildNode = proto::decode(bytes)?;
        if node.node_kind.unwrap_or(0) != 0 {
            return Ok(());
        }
        let Some(guild_id) = node.guild_id.filter(|id| *id > 0) else {
            return Ok(());
        };
        let guild = self.guilds.entry(guild_id).or_default();
        if let Some(name) = node.name.filter(|name| !name.is_empty()) {
            guild.name = decode_name(name);
        }
        for bytes in node.channels {
            let channel: proto::guild::FirstViewChannelNode = proto::decode(bytes.as_ref())?;
            let Some(channel_id) = channel.channel_id.filter(|id| *id > 0) else {
                continue;
            };
            let entry = guild
                .channels
                .entry(channel_id)
                .or_insert_with(|| ChannelInfo {
                    id: channel_id,
                    guild_id,
                    name: String::new(),
                    kind: 0,
                });
            if let Some(name) = channel.name.filter(|name| !name.is_empty()) {
                entry.name = decode_name(name);
            }
            if let Some(kind) = channel.kind {
                entry.kind = kind;
            }
        }
        Ok(())
    }
}

fn decode_name(bytes: Bytes) -> String {
    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SsoResponseHeader;
    use prost::Message;
    use std::sync::Arc;

    const GENERATION: u64 = 7;
    const RANDOM: u32 = 11;

    fn packet(command: &str, message: impl Message) -> IncomingPacket {
        IncomingPacket {
            sequence: 1,
            command: command.into(),
            body: message.encode_to_vec().into(),
            return_code: 0,
            header: SsoResponseHeader::default(),
        }
    }

    fn info(stage: u32, guild: Option<proto::guild::GuildFirstViewData>) -> IncomingPacket {
        packet(
            INFO_SYNC_PUSH,
            proto::message_sync::InfoSyncPush {
                stage: Some(stage),
                request_random: Some(RANDOM),
                guild,
                ..Default::default()
            },
        )
    }

    fn initial() -> proto::guild::GuildFirstViewData {
        proto::guild::GuildFirstViewData {
            first_sync_result: Some(1),
            ..Default::default()
        }
    }

    fn node(
        guild_id: u64,
        name: Option<&str>,
        channels: &[(u64, Option<&str>, Option<u32>)],
    ) -> Bytes {
        proto::guild::FirstViewGuildNode {
            guild_id: Some(guild_id),
            name: name.map(|name| Bytes::copy_from_slice(name.as_bytes())),
            channels: channels
                .iter()
                .map(|&(id, name, kind)| {
                    proto::guild::FirstViewChannelNode {
                        channel_id: Some(id),
                        name: name.map(|name| Bytes::copy_from_slice(name.as_bytes())),
                        kind,
                    }
                    .encode_to_vec()
                    .into()
                })
                .collect(),
            ..Default::default()
        }
        .encode_to_vec()
        .into()
    }

    fn started() -> Session {
        let session = Session::default();
        session.begin(GENERATION, RANDOM);
        session
    }

    #[tokio::test(start_paused = true)]
    async fn merges_all_stages_and_finishes_only_after_stage_four() {
        let session = started();
        session
            .ingest(
                GENERATION,
                &info(
                    1,
                    Some(proto::guild::GuildFirstViewData {
                        self_tiny_id: Some(99),
                        in_tab_nodes: vec![node(10, Some("Guild"), &[(20, Some("Text"), Some(1))])],
                        ..initial()
                    }),
                ),
            )
            .unwrap();
        session
            .ingest(
                GENERATION,
                &info(
                    2,
                    Some(proto::guild::GuildFirstViewData {
                        in_tab_nodes: vec![node(10, None, &[(21, Some("Voice"), Some(2))])],
                        ..Default::default()
                    }),
                ),
            )
            .unwrap();
        session
            .ingest(
                GENERATION,
                &info(
                    3,
                    Some(proto::guild::GuildFirstViewData {
                        first_sync_result: Some(0),
                        extra: Some(proto::guild::GuildFirstViewExtra {
                            normal_nodes: vec![node(10, None, &[(20, None, Some(4))])],
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                ),
            )
            .unwrap();
        assert!(matches!(
            session.wait_ready(GENERATION, Duration::from_secs(1)).await,
            Err(Error::Timeout)
        ));
        session
            .ingest(
                GENERATION,
                &info(
                    4,
                    Some(proto::guild::GuildFirstViewData {
                        in_tab_nodes: vec![node(11, Some("Second"), &[])],
                        extra: Some(proto::guild::GuildFirstViewExtra {
                            normal_nodes: vec![node(10, None, &[(22, Some("Last"), Some(3))])],
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                ),
            )
            .unwrap();
        session
            .wait_ready(GENERATION, Duration::from_secs(1))
            .await
            .unwrap();
        let snapshot = session.snapshot(GENERATION).unwrap();
        assert_eq!(snapshot.self_tiny_id, Some(99));
        assert_eq!(snapshot.guilds.len(), 2);
        let guild = &snapshot.guilds[0];
        assert_eq!(guild.id, 10);
        assert_eq!(guild.number, None);
        assert_eq!(guild.name, "Guild");
        assert_eq!(guild.channels.len(), 3);
        assert_eq!(guild.channels[0].name, "Text");
        assert_eq!(guild.channels[0].kind, 4);
        assert_eq!(guild.channels[2].id, 22);
        let changes = session.changed.subscribe();
        session
            .ingest(GENERATION, &info(4, Some(Default::default())))
            .unwrap();
        assert!(!changes.has_changed().unwrap());
    }

    #[tokio::test(start_paused = true)]
    async fn excludes_groups_and_direct_sources() {
        let session = started();
        let grouped = proto::guild::FirstViewGuildNode {
            guild_id: Some(30),
            node_kind: Some(1),
            ..Default::default()
        }
        .encode_to_vec()
        .into();
        session
            .ingest(
                GENERATION,
                &info(
                    2,
                    Some(proto::guild::GuildFirstViewData {
                        in_tab_nodes: vec![grouped],
                        group_nodes: vec![node(31, Some("Group"), &[])],
                        extra: Some(proto::guild::GuildFirstViewExtra {
                            normal_nodes: vec![node(10, Some("Normal"), &[])],
                            direct_nodes_12: vec![node(32, Some("Direct"), &[])],
                            direct_nodes_15: vec![node(33, Some("Direct"), &[])],
                            ..Default::default()
                        }),
                        ..initial()
                    }),
                ),
            )
            .unwrap();
        session
            .ingest(GENERATION, &info(4, Some(Default::default())))
            .unwrap();
        let snapshot = session.snapshot(GENERATION).unwrap();
        assert_eq!(snapshot.guilds.len(), 1);
        assert_eq!(snapshot.guilds[0].id, 10);
    }

    #[tokio::test(start_paused = true)]
    async fn ignores_wrong_random_generation_and_nonexact_commands() {
        let session = started();
        for request_random in [None, Some(RANDOM + 1)] {
            session
                .ingest(
                    GENERATION,
                    &packet(
                        INFO_SYNC_PUSH,
                        proto::message_sync::InfoSyncPush {
                            request_random,
                            result: Some(5),
                            stage: Some(1),
                            guild: Some(initial()),
                            ..Default::default()
                        },
                    ),
                )
                .unwrap();
        }
        session
            .ingest(GENERATION - 1, &info(1, Some(initial())))
            .unwrap();
        let mut unrelated = info(1, Some(initial()));
        unrelated.command = "example.InfoSyncPush".into();
        session.ingest(GENERATION, &unrelated).unwrap();
        session.close(GENERATION - 1);
        session
            .ingest(GENERATION, &info(4, Some(Default::default())))
            .unwrap();
        assert!(matches!(
            session.wait_ready(GENERATION, Duration::from_secs(1)).await,
            Err(Error::Timeout)
        ));
        session
            .ingest(GENERATION, &info(1, Some(initial())))
            .unwrap();
        session
            .ingest(GENERATION, &info(4, Some(Default::default())))
            .unwrap();
        session
            .wait_ready(GENERATION, Duration::from_secs(1))
            .await
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn terminal_stage_requires_guild_and_allows_valid_empty_view() {
        let session = started();
        session
            .ingest(GENERATION, &info(1, Some(initial())))
            .unwrap();
        session.ingest(GENERATION, &info(4, None)).unwrap();
        assert!(matches!(
            session.wait_ready(GENERATION, Duration::from_secs(1)).await,
            Err(Error::Timeout)
        ));
        session
            .ingest(GENERATION, &info(4, Some(Default::default())))
            .unwrap();
        session
            .wait_ready(GENERATION, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(
            session.snapshot(GENERATION).unwrap(),
            GuildSnapshot {
                self_tiny_id: None,
                push_result: None,
                guilds: Vec::new(),
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn terminal_stage_cannot_forge_initial_success() {
        let session = started();
        session
            .ingest(GENERATION, &info(3, Some(initial())))
            .unwrap();
        session
            .ingest(GENERATION, &info(4, Some(initial())))
            .unwrap();
        assert!(matches!(
            session.wait_ready(GENERATION, Duration::from_secs(1)).await,
            Err(Error::Timeout)
        ));
        assert!(session.snapshot(GENERATION).is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn transport_refusal_does_not_require_a_decodable_business_body() {
        let session = started();
        let mut failed = packet(INFO_SYNC_PUSH, proto::message_sync::InfoSyncPush::default());
        failed.body = bytes::Bytes::from_static(b"\x80");
        failed.return_code = 500;
        assert!(matches!(
            session.ingest(GENERATION, &failed),
            Err(Error::Server { code: 500, .. })
        ));
        assert!(matches!(
            session.wait_ready(GENERATION, Duration::from_secs(1)).await,
            Err(Error::Server { code: 500, .. })
        ));
    }

    #[test]
    fn advisory_result_is_preserved_and_zero_random_uses_native_scalar_defaults() {
        let session = Session::default();
        session.begin(GENERATION, 0);
        session
            .ingest(
                GENERATION,
                &packet(
                    INFO_SYNC_PUSH,
                    proto::message_sync::InfoSyncPush {
                        stage: Some(1),
                        guild: Some(proto::guild::GuildFirstViewData {
                            result: Some(6),
                            ..initial()
                        }),
                        ..Default::default()
                    },
                ),
            )
            .unwrap();
        session
            .ingest(
                GENERATION,
                &packet(
                    INFO_SYNC_PUSH,
                    proto::message_sync::InfoSyncPush {
                        stage: Some(4),
                        guild: Some(Default::default()),
                        ..Default::default()
                    },
                ),
            )
            .unwrap();
        assert_eq!(session.snapshot(GENERATION).unwrap().push_result, Some(6));
    }

    #[tokio::test(start_paused = true)]
    async fn unrelated_partial_failure_does_not_terminate_guild() {
        let session = started();
        session
            .ingest(
                GENERATION,
                &packet(
                    INFO_SYNC_PUSH,
                    proto::message_sync::InfoSyncPush {
                        result: Some(0x05f5e3c0),
                        request_random: Some(RANDOM),
                        stage: Some(1),
                        guild: Some(proto::guild::GuildFirstViewData {
                            in_tab_nodes: vec![node(
                                55,
                                Some("Synthetic guild"),
                                &[(56, Some("General"), Some(1))],
                            )],
                            ..initial()
                        }),
                        ..Default::default()
                    },
                ),
            )
            .unwrap();
        session
            .ingest(GENERATION, &info(4, Some(Default::default())))
            .unwrap();
        let snapshot = session.snapshot(GENERATION).unwrap();
        assert_eq!(snapshot.guilds[0].id, 55);
        assert_eq!(snapshot.guilds[0].name, "Synthetic guild");
        assert_eq!(snapshot.guilds[0].channels[0].id, 56);
        assert_eq!(snapshot.guilds[0].channels[0].name, "General");
    }

    #[tokio::test(start_paused = true)]
    async fn push_parameters_require_explicit_enabled_flag() {
        let session = started();
        for guild in [
            None,
            Some(proto::guild::GuildPushParameters::default()),
            Some(proto::guild::GuildPushParameters { enabled: Some(1) }),
        ] {
            session
                .ingest(
                    GENERATION,
                    &packet(PUSH_PARAMS, proto::guild::PushParams { guild }),
                )
                .unwrap();
        }
        assert!(matches!(
            session.wait_ready(GENERATION, Duration::from_secs(1)).await,
            Err(Error::Timeout)
        ));
        assert!(matches!(
            session.ingest(
                GENERATION,
                &packet(
                    PUSH_PARAMS,
                    proto::guild::PushParams {
                        guild: Some(proto::guild::GuildPushParameters { enabled: Some(2) }),
                    },
                ),
            ),
            Err(Error::Unsupported(_))
        ));
        assert!(matches!(
            session.wait_ready(GENERATION, Duration::from_secs(1)).await,
            Err(Error::Unsupported(_))
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn close_wakes_waiters_and_old_connection_cannot_cancel_new_round() {
        let session = Arc::new(started());
        let waiting = session.clone();
        let waiter = tokio::spawn(async move {
            waiting
                .wait_ready(GENERATION, Duration::from_secs(60))
                .await
        });
        tokio::task::yield_now().await;
        session.close(GENERATION);
        assert!(matches!(waiter.await.unwrap(), Err(Error::Disconnected)));
        session.begin(GENERATION + 1, RANDOM);
        session.close(GENERATION);
        session
            .ingest(GENERATION, &info(1, Some(initial())))
            .unwrap();
        session
            .ingest(GENERATION + 1, &info(4, Some(Default::default())))
            .unwrap();
        assert!(matches!(
            session
                .wait_ready(GENERATION + 1, Duration::from_secs(1))
                .await,
            Err(Error::Timeout)
        ));
        session
            .ingest(GENERATION + 1, &info(2, Some(initial())))
            .unwrap();
        session
            .ingest(GENERATION + 1, &info(4, Some(Default::default())))
            .unwrap();
        assert!(session.snapshot(GENERATION + 1).unwrap().guilds.is_empty());
        assert!(matches!(
            session.snapshot(GENERATION),
            Err(Error::Disconnected)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn completion_wakes_all_waiters_without_snapshot_copies() {
        let session = Arc::new(started());
        let mut waiters = Vec::new();
        for _ in 0..3 {
            let session = session.clone();
            waiters.push(tokio::spawn(async move {
                session
                    .wait_ready(GENERATION, Duration::from_secs(60))
                    .await
            }));
        }
        tokio::task::yield_now().await;
        session
            .ingest(GENERATION, &info(1, Some(initial())))
            .unwrap();
        session
            .ingest(GENERATION, &info(4, Some(Default::default())))
            .unwrap();
        for waiter in waiters {
            waiter.await.unwrap().unwrap();
        }
        session
            .wait_ready(GENERATION, Duration::from_secs(1))
            .await
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn provisional_results_and_unaccepted_stages_cannot_pollute_the_completed_view() {
        let session = started();
        session
            .ingest(
                GENERATION,
                &info(
                    1,
                    Some(proto::guild::GuildFirstViewData {
                        first_sync_result: Some(0),
                        error: Some(Bytes::from_static(b"progress")),
                        ..Default::default()
                    }),
                ),
            )
            .unwrap();
        session
            .ingest(
                GENERATION,
                &info(
                    3,
                    Some(proto::guild::GuildFirstViewData {
                        in_tab_nodes: vec![node(99, Some("unaccepted"), &[])],
                        ..Default::default()
                    }),
                ),
            )
            .unwrap();
        assert!(matches!(
            session.wait_ready(GENERATION, Duration::from_secs(1)).await,
            Err(Error::Timeout)
        ));
        session
            .ingest(
                GENERATION,
                &info(
                    2,
                    Some(proto::guild::GuildFirstViewData {
                        in_tab_nodes: vec![
                            node(
                                10,
                                Some("accepted"),
                                &[(20, Some("text"), Some(1)), (0, Some("invalid"), None)],
                            ),
                            node(0, Some("invalid"), &[]),
                        ],
                        ..initial()
                    }),
                ),
            )
            .unwrap();
        session
            .ingest(
                GENERATION,
                &info(
                    9,
                    Some(proto::guild::GuildFirstViewData {
                        in_tab_nodes: vec![node(98, Some("unknown stage"), &[])],
                        ..Default::default()
                    }),
                ),
            )
            .unwrap();
        session
            .ingest(
                GENERATION,
                &info(
                    4,
                    Some(proto::guild::GuildFirstViewData {
                        error: Some(Bytes::from_static(b"success")),
                        ..Default::default()
                    }),
                ),
            )
            .unwrap();
        assert_eq!(
            session.snapshot(GENERATION).unwrap().guilds,
            vec![GuildInfo {
                id: 10,
                number: None,
                name: "accepted".into(),
                channels: vec![ChannelInfo {
                    id: 20,
                    guild_id: 10,
                    name: "text".into(),
                    kind: 1
                }],
            }]
        );
    }

    #[test]
    fn tiny_id_requires_nonzero_server_identity_and_resets_per_round() {
        let session = started();
        assert_eq!(session.tiny_id(GENERATION), None);
        for (tiny_id, expected) in [(99, Some(99)), (0, Some(99))] {
            session
                .ingest(
                    GENERATION,
                    &info(
                        1,
                        Some(proto::guild::GuildFirstViewData {
                            self_tiny_id: Some(tiny_id),
                            ..initial()
                        }),
                    ),
                )
                .unwrap();
            assert_eq!(session.tiny_id(GENERATION), expected);
        }
        session.begin(GENERATION + 1, RANDOM + 1);
        assert_eq!(session.tiny_id(GENERATION), None);
        assert_eq!(session.tiny_id(GENERATION + 1), None);
        session.close(GENERATION + 1);
        assert_eq!(session.tiny_id(GENERATION + 1), None);
    }
}
