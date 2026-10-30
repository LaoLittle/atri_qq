use super::*;

impl Client {
    pub(super) fn sync_ios_guild_cursor(&self, generation: u64) {
        let mut inner = self.inner.lock().unwrap();
        if inner.generation != generation || !inner.signer.has_ios_virtual_device() {
            return;
        }
        let uin = inner.state.keystore.uin;
        if uin == 0 {
            return;
        }
        let Some(device) = &mut inner.state.keystore.ios_virtual_state else {
            return;
        };
        let Some(mut cursor) = self.guild_session.take_ios_cursor(generation) else {
            return;
        };
        if let Some(previous) = device.guild_sync.get(&uin) {
            cursor.last_msg_time = match (previous.last_msg_time, cursor.last_msg_time) {
                (Some(previous), Some(current)) => Some(previous.max(current)),
                (previous, current) => current.or(previous),
            };
            if previous == &cursor {
                return;
            }
        }
        device.guild_sync.insert(uin, cursor);
        self.emit(LoginEvent::KeystoreChanged(inner.state.keystore.clone()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ios_device::{IosVirtualConfig, guild::IosGuildSyncState};
    use prost::Message;

    #[tokio::test]
    async fn native_message_time_reaches_next_registration_with_monotonic_persistence() {
        let model = Arc::new(IosVirtualConfig::default());
        let client = Client::new(
            ClientConfig {
                profile: Profile::ipad(),
                platform: Some(PlatformConfig::Ios(IosConfig::Virtual(model.clone()))),
                ..Default::default()
            },
            Keystore {
                uin: 42,
                ..Default::default()
            },
        )
        .unwrap();
        let high = (1_u64 << 63) + 123;
        for (random, raw_time, expected) in
            [(7, high, high), (8, 17, high), (9, high + 1, high + 1)]
        {
            let message: bytes::Bytes = crate::proto::guild::FirstViewRawMessage {
                head: Some(crate::proto::guild::MessageHead {
                    routing: Some(crate::proto::guild::RoutingHead::default()),
                    content: Some(crate::proto::guild::ContentHead {
                        time: Some(raw_time),
                        ..Default::default()
                    }),
                }),
            }
            .encode_to_vec()
            .into();
            let channel: bytes::Bytes = crate::proto::guild::FirstViewChannelNode {
                channel_id: Some(20),
                messages: vec![message],
                ..Default::default()
            }
            .encode_to_vec()
            .into();
            let node: bytes::Bytes = crate::proto::guild::FirstViewGuildNode {
                guild_id: Some(10),
                node_kind: Some(0),
                incremental_cursor: Some(raw_time),
                channels: vec![channel],
                ..Default::default()
            }
            .encode_to_vec()
            .into();
            client.guild_session.begin(0, random);
            for stage in [1, 4] {
                client
                    .guild_session
                    .ingest_info_push(
                        0,
                        &crate::proto::message_sync::InfoSyncPush {
                            request_random: Some(random),
                            stage: Some(stage),
                            guild: Some(crate::proto::guild::GuildFirstViewData {
                                first_sync_result: Some(1),
                                in_tab_nodes: if stage == 1 {
                                    vec![node.clone()]
                                } else {
                                    Vec::new()
                                },
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    )
                    .unwrap();
            }
            client.sync_ios_guild_cursor(0);
            let saved = client.snapshot().await;
            let cursor = &saved
                .keystore
                .ios_virtual_state
                .as_ref()
                .unwrap()
                .guild_sync[&42];
            assert_eq!(cursor.last_msg_time, Some(expected));
            assert_eq!(cursor.entries, BTreeMap::from([(10, raw_time)]));
            let request = crate::ios_device::registration::build(
                &saved,
                true,
                &model,
                crate::ios_device::registration::Context {
                    now_seconds: 1234,
                    background_since: None,
                    first_register: false,
                },
            )
            .unwrap();
            let decoded: crate::proto::auth::InfoSyncRequest =
                crate::proto::decode(request.encode_to_vec().as_slice()).unwrap();
            let memory = decoded.guild_sync.unwrap().memory_increment.unwrap();
            assert_eq!(memory.last_msg_time, Some(expected));
            assert_eq!(memory.entries[0].entry_key, Some(10));
            assert_eq!(memory.entries[0].entry_value, Some(raw_time));
        }
    }

    #[tokio::test]
    async fn successful_empty_view_replaces_increment_state_without_rolling_back_message_time() {
        let client = Client::new(
            ClientConfig {
                profile: Profile::ipad(),
                platform: Some(PlatformConfig::Ios(IosConfig::Virtual(Arc::new(
                    IosVirtualConfig::default(),
                )))),
                ..Default::default()
            },
            Keystore {
                uin: 42,
                ..Default::default()
            },
        )
        .unwrap();
        client
            .inner
            .lock()
            .unwrap()
            .state
            .keystore
            .ios_virtual_state
            .as_mut()
            .unwrap()
            .guild_sync
            .insert(
                42,
                IosGuildSyncState {
                    last_msg_time: Some(999),
                    last_pull_time: Some(123),
                    entries: BTreeMap::from([(10, 100)]),
                },
            );
        client.guild_session.begin(0, 7);
        for stage in [1, 4] {
            client
                .guild_session
                .ingest_info_push(
                    0,
                    &crate::proto::message_sync::InfoSyncPush {
                        request_random: Some(7),
                        stage: Some(stage),
                        guild: Some(crate::proto::guild::GuildFirstViewData {
                            first_sync_result: Some(1),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        client.sync_ios_guild_cursor(0);
        let saved = client.snapshot().await.keystore.ios_virtual_state.unwrap();
        let cursor = &saved.guild_sync[&42];
        assert_eq!(cursor.last_pull_time, Some(0));
        assert!(cursor.entries.is_empty());
        assert_eq!(cursor.last_msg_time, Some(999));
    }
}
