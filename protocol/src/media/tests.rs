use super::*;
use tokio::net::TcpListener;

struct HighwayReplyClient {
    state: std::sync::Mutex<crate::models::SessionState>,
    calls: AtomicU32,
    packets: tokio::sync::broadcast::Sender<crate::models::IncomingPacket>,
}
#[async_trait::async_trait]
impl ServiceClient for HighwayReplyClient {
    async fn request(
        &self,
        command: &str,
        _: Bytes,
        _: RequestType,
        _: Encryption,
        _: Duration,
    ) -> Result<Bytes> {
        assert_eq!(command, "HttpConn.0x6ff_501");
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(Bytes::from_static(&[
            0x8a, 0x50, 0x10, 0x0a, 1, 0x11, 0x1a, 0x0b, 8, 1, 0x12, 7, 0x15, 127, 0, 0, 1, 0x18,
            80,
        ]))
    }
    async fn snapshot(&self) -> crate::models::SessionState {
        self.state.lock().unwrap().clone()
    }
    async fn replace_state(&self, state: crate::models::SessionState) {
        *self.state.lock().unwrap() = state;
    }
    fn subscribe(&self) -> tokio::sync::broadcast::Receiver<crate::models::IncomingPacket> {
        self.packets.subscribe()
    }
}
#[tokio::test]
async fn highway_fixed32_reply_produces_an_endpoint_and_account_scoped_cache() {
    let client = Arc::new(HighwayReplyClient {
        state: std::sync::Mutex::new(crate::models::SessionState {
            profile: crate::models::Profile::linux(),
            keystore: crate::models::Keystore {
                uin: 7,
                ..Default::default()
            },
            machine_id: "synthetic-machine".into(),
            online: true,
        }),
        calls: AtomicU32::new(0),
        packets: tokio::sync::broadcast::channel(8).0,
    });
    let media = Media::new(client.clone());
    let first = media.highway_session().await.unwrap();
    assert_eq!(
        first.1,
        "http://127.0.0.1:80/cgi-bin/httpconn?htcmd=0x6FF0087&uin=7"
    );
    assert_eq!(first.0, [0x11]);
    assert_eq!(media.highway_session().await.unwrap(), first);
    assert_eq!(client.calls.load(Ordering::Relaxed), 1);
    client.state.lock().unwrap().keystore.uin = 8;
    assert_eq!(
        media.highway_session().await.unwrap().1,
        "http://127.0.0.1:80/cgi-bin/httpconn?htcmd=0x6FF0087&uin=8"
    );
    assert_eq!(client.calls.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn highway_cap_is_enforced_before_stream_finishes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        stream.read(&mut request).await.unwrap();
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let chunk = vec![b'x'; 64 * 1024];
        for _ in 0..65 {
            if stream.write_all(b"10000\r\n").await.is_err() {
                return;
            }
            if stream.write_all(&chunk).await.is_err() {
                return;
            }
            if stream.write_all(b"\r\n").await.is_err() {
                return;
            }
        }
        // Deliberately never send the final chunk: a buffering implementation would hang.
        std::future::pending::<()>().await;
    });
    let response = crate::http::client_builder()
        .build()
        .unwrap()
        .get(format!("http://{address}/"))
        .send()
        .await
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(3), bounded_acknowledgement(response))
        .await
        .expect("must reject while peer is still streaming");
    server.abort();
    assert!(matches!(result,Err(Error::Malformed(message))if message.contains("4 MiB")));
}
#[test]
fn highway_ack_requires_exact_frame_and_server_success() {
    let head = pb::HighwayAcknowledgement {
        result: Some(0),
        ..Default::default()
    }
    .encode_to_vec();
    let mut frame = vec![0x28];
    frame.extend_from_slice(&(head.len() as u32).to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.extend_from_slice(&head);
    frame.push(0x29);
    assert!(decode_highway_ack(&frame).is_ok());
    let mut trailing = frame.clone();
    trailing.push(0);
    assert!(decode_highway_ack(&trailing).is_err());
    let mut truncated = frame.clone();
    truncated.pop();
    assert!(decode_highway_ack(&truncated).is_err());
    let error = pb::HighwayAcknowledgement {
        result: Some(5),
        message: Some(Bytes::from_static(b"denied")),
        ..Default::default()
    }
    .encode_to_vec();
    let mut frame = vec![0x28];
    frame.extend_from_slice(&(error.len() as u32).to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.extend_from_slice(&error);
    frame.push(0x29);
    assert!(matches!(
        decode_highway_ack(&frame),
        Err(Error::Server { code: 5, .. })
    ));
    let error = pb::HighwayAcknowledgement {
        result: Some(0),
        segment: Some(pb::HighwaySegmentAcknowledgement { result: Some(9) }),
        ..Default::default()
    }
    .encode_to_vec();
    let mut frame = vec![0x28];
    frame.extend_from_slice(&(error.len() as u32).to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.extend_from_slice(&error);
    frame.push(0x29);
    assert!(matches!(
        decode_highway_ack(&frame),
        Err(Error::Server { code: 9, message }) if message == "QQ request failed"
    ));
}
#[test]
fn media_download_routing_uses_distinct_uid_scene() {
    let head = media_head(
        MediaKind::Image,
        &MediaConversation::Friend {
            uid: "u_not_a_number".into(),
        },
        200,
        2,
    )
    .unwrap();
    let scene = head.scene.unwrap();
    assert_eq!(scene.scene_type, Some(1));
    assert_eq!(
        scene.direct_peer.unwrap().uid.as_deref(),
        Some("u_not_a_number")
    );
    assert!(
        media_head(
            MediaKind::Image,
            &MediaConversation::Friend { uid: String::new() },
            200,
            2,
        )
        .is_err()
    );
    assert!(
        media_head(
            MediaKind::Video,
            &MediaConversation::Group { uin: 0 },
            100,
            2
        )
        .is_err()
    );
}

struct VideoIndexClient(std::sync::Mutex<Vec<(String, pb::MediaDownloadRequest)>>);
#[async_trait::async_trait]
impl ServiceClient for VideoIndexClient {
    async fn request(
        &self,
        command: &str,
        body: Bytes,
        _: RequestType,
        _: Encryption,
        _: Duration,
    ) -> Result<Bytes> {
        let envelope = pb::MediaOidbEnvelope::decode(body).unwrap();
        let request = pb::MediaDownloadRequest::decode(envelope.body.unwrap()).unwrap();
        self.0.lock().unwrap().push((command.to_owned(), request));
        Err(Error::Unsupported("captured video request".into()))
    }
    async fn snapshot(&self) -> crate::models::SessionState {
        unreachable!()
    }
    async fn replace_state(&self, _: crate::models::SessionState) {
        unreachable!()
    }
    fn subscribe(&self) -> tokio::sync::broadcast::Receiver<crate::models::IncomingPacket> {
        tokio::sync::broadcast::channel(1).1
    }
}
#[tokio::test]
async fn video_thumbnail_uses_its_own_index_and_video_service_for_both_conversations() {
    for conversation in [
        MediaConversation::Friend { uid: "peer".into() },
        MediaConversation::Group { uin: 42 },
    ] {
        let client = Arc::new(VideoIndexClient(std::sync::Mutex::new(Vec::new())));
        let media = Media::new(client.clone());
        let index = |uuid: &'static [u8], kind, marker: u8, size| {
            pb::MediaIndex {
                file: Some(pb::MediaFileInfo {
                    media_type: Some(pb::MediaFileType {
                        kind: Some(kind),
                        ..Default::default()
                    }),
                    md5: Some(hex::encode([marker; 16]).into()),
                    sha1: Some(hex::encode([marker; 20]).into()),
                    size: Some(size),
                    ..Default::default()
                }),
                uuid: Some(Bytes::from_static(uuid)),
                subtype: Some(if kind == 1 { 100 } else { 0 }),
            }
            .encode_to_vec()
        };
        let main = index(b"main-video", 2, 0x11, 64000);
        let thumb = index(b"thumbnail", 1, 0x22, 1024);
        let mut reference = MediaReference::new(MediaKind::Video, conversation.clone());
        reference.message_info = pb::MediaMessageInfo {
            bodies: [main.clone(), thumb.clone()]
                .into_iter()
                .map(|index| {
                    pb::MediaMessageInfoBody {
                        index: Some(index.into()),
                        ..Default::default()
                    }
                    .encode_to_vec()
                    .into()
                })
                .collect(),
            ..Default::default()
        }
        .encode_to_vec();
        assert!(media.video_thumbnail_url(&reference).await.is_err());
        assert!(media.download_url(&reference).await.is_err());
        let calls = client.0.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(
            calls[0].0,
            format!(
                "OidbSvcTrpcTcp.0x{:x}_200",
                media_command(MediaKind::Video, &conversation)
            )
        );
        assert_eq!(
            calls[0]
                .1
                .head
                .as_ref()
                .unwrap()
                .scene
                .as_ref()
                .unwrap()
                .business_type,
            Some(2)
        );
        assert_eq!(
            calls[0].1.request.as_ref().unwrap().index.as_deref(),
            Some(thumb.as_slice())
        );
        assert_eq!(
            calls[1].1.request.as_ref().unwrap().index.as_deref(),
            Some(main.as_slice())
        );
        drop(calls);
        reference.message_info.clear();
        assert!(media.video_thumbnail_url(&reference).await.is_err());
        assert_eq!(client.0.lock().unwrap().len(), 2);
    }
}

#[test]
fn legacy_voice_accepts_private_keys_and_server_urls() {
    // Ptt fields 14, 17 and 31, independently encoded from the reference schema.
    let conversation = MediaConversation::Friend { uid: "peer".into() };
    let reference = MediaReference::decode_ptt(
        b"\x72\x0bprivate-key\x98\x01\x03",
        conversation.clone(),
        100,
    )
    .unwrap();
    assert_eq!(reference.kind, MediaKind::Voice);
    assert_eq!(reference.duration, 3);
    let url = reqwest::Url::parse(reference.download_url.as_ref().unwrap()).unwrap();
    let rkey = url
        .query_pairs()
        .find(|(name, _)| name == "rkey")
        .unwrap()
        .1
        .into_owned();
    assert!(
        hex::decode(rkey)
            .unwrap()
            .windows(11)
            .any(|bytes| bytes == b"private-key")
    );
    for (tag, url, expected) in [
        (
            [0x8a, 0x01],
            "https://voice.qq.com/a",
            "https://voice.qq.com/a",
        ),
        (
            [0xfa, 0x01],
            "/voice/a",
            "https://grouptalk.c2c.qq.com/voice/a",
        ),
    ] {
        let mut raw = tag.to_vec();
        raw.push(url.len() as u8);
        raw.extend(url.as_bytes());
        let reference = MediaReference::decode_ptt(&raw, conversation.clone(), 100).unwrap();
        assert_eq!(reference.download_url.as_deref(), Some(expected));
    }
}

struct VideoDownloadReplyClient {
    state: std::sync::Mutex<crate::models::SessionState>,
    requests: std::sync::Mutex<Vec<Bytes>>,
    packets: tokio::sync::broadcast::Sender<crate::models::IncomingPacket>,
}

#[async_trait::async_trait]
impl ServiceClient for VideoDownloadReplyClient {
    async fn request(
        &self,
        command: &str,
        body: Bytes,
        _: RequestType,
        _: Encryption,
        _: Duration,
    ) -> Result<Bytes> {
        assert_eq!(command, "OidbSvcTrpcTcp.0x11e9_200");
        let mut requests = self.requests.lock().unwrap();
        requests.push(body);
        let response = match requests.len() {
            1 => pb::MediaOidbEnvelope {
                result: Some(0),
                body: Some(
                    pb::MediaDownloadResponse {
                        head: Some(pb::MediaRichResponseHead {
                            code: Some(0),
                            ..Default::default()
                        }),
                        download: Some(pb::MediaDownloadResult {
                            location: Some(pb::MediaDownloadLocation {
                                domain: Some(Bytes::from_static(b"media.example")),
                                path: Some(Bytes::from_static(b"/cover")),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                    }
                    .encode_to_vec()
                    .into(),
                ),
                ..Default::default()
            },
            2 => pb::MediaOidbEnvelope {
                result: Some(170013002),
                message: Some("后台频控，禁止自动下载！".as_bytes().into()),
                ..Default::default()
            },
            _ => panic!("a refused main-video download must not be retried"),
        };
        Ok(response.encode_to_vec().into())
    }

    async fn snapshot(&self) -> crate::models::SessionState {
        self.state.lock().unwrap().clone()
    }

    async fn replace_state(&self, state: crate::models::SessionState) {
        *self.state.lock().unwrap() = state;
    }

    fn subscribe(&self) -> tokio::sync::broadcast::Receiver<crate::models::IncomingPacket> {
        self.packets.subscribe()
    }
}

#[tokio::test]
async fn video_downloads_use_the_companion_index_without_rewriting_the_requested_index() {
    // Vary the cover subtype to ensure it comes from MsgInfo, not a download flag.
    for cover_subtype in [100, 107] {
        let make_index = |kind, marker, size, subtype| {
            let mut raw = pb::MediaIndex {
                file: Some(pb::MediaFileInfo {
                    media_type: Some(pb::MediaFileType {
                        kind: Some(kind),
                        ..Default::default()
                    }),
                    md5: Some(hex::encode([marker; 16]).into()),
                    sha1: Some(hex::encode([marker; 20]).into()),
                    size: Some(size),
                    ..Default::default()
                }),
                uuid: Some(format!("resource-{marker}").into()),
                subtype: Some(subtype),
            }
            .encode_to_vec();
            pb::MediaElement {
                common: Some(pb::MediaCommonElement {
                    service_type: Some(48),
                    business_type: Some(marker as u64),
                    payload: Some(Bytes::from_static(b"opaque-index-metadata")),
                }),
                ..Default::default()
            }
            .encode(&mut raw)
            .unwrap();
            Bytes::from(raw)
        };
        let main = make_index(2, 0x11u8, 552785, 0);
        let cover = make_index(1, 0x22u8, 17067, cover_subtype);
        let mut reference = MediaReference::new(
            MediaKind::Video,
            MediaConversation::Friend {
                uid: "u_test_peer".into(),
            },
        );
        reference.message_info = pb::MediaMessageInfo {
            bodies: [&main, &cover]
                .into_iter()
                .map(|index| {
                    pb::MediaMessageInfoBody {
                        index: Some(index.clone()),
                    }
                    .encode_to_vec()
                    .into()
                })
                .collect(),
        }
        .encode_to_vec();
        // These cached main-file fields must not override either companion index.
        reference.md5 = vec![0x33; 16];
        reference.sha1 = vec![0x33; 20];
        reference.size = 999;
        let client = Arc::new(VideoDownloadReplyClient {
            state: std::sync::Mutex::new(crate::models::SessionState {
                profile: crate::models::Profile::linux(),
                keystore: Default::default(),
                machine_id: "synthetic-machine".into(),
                online: true,
            }),
            requests: Default::default(),
            packets: tokio::sync::broadcast::channel(8).0,
        });
        let media = Media::new(client.clone());
        assert_eq!(
            media.video_thumbnail_url(&reference).await.unwrap(),
            "https://media.example/cover"
        );
        assert!(matches!(
            media.download_url(&reference).await,
            Err(Error::Server {
                code: 170013002,
                ..
            })
        ));
        let requests = client.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        for (raw, selected, marker, size, subtype) in [
            (&requests[0], &cover, 0x11u8, 552785, 0),
            (&requests[1], &main, 0x22u8, 17067, cover_subtype),
        ] {
            let envelope: pb::MediaOidbEnvelope = crate::proto::decode(raw.clone()).unwrap();
            let request: pb::MediaDownloadRequest =
                crate::proto::decode(envelope.body.unwrap()).unwrap();
            let download = request.request.unwrap();
            assert_eq!(download.index.as_ref(), Some(selected));
            let ext: pb::MediaDownloadExtension =
                crate::proto::decode(download.ext.unwrap()).unwrap();
            let companion = ext.video.unwrap().reserved_6.unwrap();
            assert_eq!(companion.reserved_1, Some(subtype));
            assert_eq!(
                companion.file_md5.as_deref(),
                Some(hex::encode([marker; 16]).as_bytes())
            );
            assert_eq!(
                companion.file_sha1.as_deref(),
                Some(hex::encode([marker; 20]).as_bytes())
            );
            assert_eq!(companion.file_size, Some(size));
        }
    }
}
