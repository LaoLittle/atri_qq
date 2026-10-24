use super::*;
use crate::models::{Encryption, IncomingPacket, RequestType, SessionState};
use bytes::Bytes;
use prost::Message;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

struct ReplyClient {
    reply: Bytes,
    requests: Mutex<Vec<(String, Bytes)>>,
}
#[async_trait::async_trait]
impl crate::ServiceClient for ReplyClient {
    async fn request(
        &self,
        command: &str,
        body: Bytes,
        kind: RequestType,
        encryption: Encryption,
        _: Duration,
    ) -> Result<Bytes> {
        assert!(matches!(kind, RequestType::D2));
        assert!(matches!(encryption, Encryption::D2));
        self.requests.lock().unwrap().push((command.into(), body));
        Ok(self.reply.clone())
    }
    async fn snapshot(&self) -> SessionState {
        panic!("original identities must not be guessed from session state")
    }
    async fn replace_state(&self, _: SessionState) {
        unreachable!()
    }
    fn subscribe(&self) -> tokio::sync::broadcast::Receiver<IncomingPacket> {
        tokio::sync::broadcast::channel(1).1
    }
}
fn context(to_uin: u64) -> LegacyVideoPlayContext {
    LegacyVideoPlayContext {
        from_uin: 11,
        to_uin,
        client_type: 7,
        ..Default::default()
    }
}
fn reference(conversation: MediaConversation) -> MediaReference {
    let mut reference = MediaReference::new(MediaKind::Video, conversation);
    // A modern UUID and cached MD5 must not silently replace the old identity.
    reference.uuid = Some("modern-resource".into());
    reference.md5 = vec![0x33; 16];
    reference.compatibility = Some(
        pb::VideoFile {
            uuid: Some(Bytes::from_static(b"old-id")),
            md5: Some(Bytes::from_static(&[0, 255])),
            ..Default::default()
        }
        .encode_to_vec(),
    );
    reference
}
fn response(address: pb::LegacyVideoDownloadAddress) -> pb::LegacyVideoPlayResponse {
    pb::LegacyVideoPlayResponse {
        command: Some(410),
        download: Some(pb::LegacyVideoDownloadResponse {
            code: Some(0),
            address: Some(address),
            ..Default::default()
        }),
        ..Default::default()
    }
}
fn client(reply: pb::LegacyVideoPlayResponse) -> Arc<ReplyClient> {
    Arc::new(ReplyClient {
        reply: reply.encode_to_vec().into(),
        requests: Mutex::new(vec![]),
    })
}

#[tokio::test]
async fn private_and_group_playback_use_the_independent_legacy_wire_contract() {
    for (conversation, to, command, golden) in [
        (
            MediaConversation::Friend {
                uid: "u_peer".into(),
            },
            22,
            "PttCenterSvr.ShortVideoDownReq",
            "08900310002230080b1016180020072a066f6c642d69643800420200ff480050025802600068007002780ba00101f00100f80100880200a206020800",
        ),
        (
            MediaConversation::Group { uin: 42 },
            42,
            "PttCenterSvr.GroupShortVideoDownReq",
            "08900310002232080b102a180120072a066f6c642d6964302a3800420200ff480050025802600068007002780ba00101f00100f80100880200a206020800",
        ),
    ] {
        let transport = client(response(pb::LegacyVideoDownloadAddress {
            domain_hosts: vec!["https://domain.invalid".into()],
            ipv4_hosts: vec!["http://192.0.2.1".into()],
            url_args: Some("/play?key=a%2Bb".into()),
            ..Default::default()
        }));
        let media = Media::new(transport.clone());
        let url = media
            .legacy_video_play_url(&reference(conversation), context(to))
            .await
            .unwrap();
        assert_eq!(url, "https://domain.invalid/play?key=a%2Bb&filename=1.mp4");
        let requests = transport.requests.lock().unwrap();
        assert_eq!(
            requests.as_slice(),
            &[(command.into(), Bytes::from(hex::decode(golden).unwrap()))]
        );
    }
}

#[test]
fn domain_field_22_ipv6_field_21_and_raw_signed_args_follow_current_native_schema() {
    // Real field numbers, independent of the older reference schema's domain13.
    let address = pb::LegacyVideoDownloadAddress::decode(Bytes::from_static(
        b"\x5a\x0b/x?key=%2F+\xb2\x01\x11https://d.invalid",
    ))
    .unwrap();
    assert_eq!(
        legacy_url(response(address)).unwrap(),
        "https://d.invalid/x?key=%2F+&filename=1.mp4"
    );
    let address = pb::LegacyVideoDownloadAddress {
        domain_hosts: vec!["ftp://unsupported.invalid".into()],
        ipv4_hosts: vec![],
        ipv6_hosts: vec!["http://[2001:db8::1]".into()],
        url_args: Some("/v?k=1".into()),
    };
    assert_eq!(
        legacy_url(response(address)).unwrap(),
        "http://[2001:db8::1]/v?k=1&filename=1.mp4"
    );
}

#[tokio::test]
async fn unavailable_original_identity_or_wrong_conversation_never_issues_a_request() {
    let transport = client(pb::LegacyVideoPlayResponse::default());
    let media = Media::new(transport.clone());
    let mut missing = reference(MediaConversation::Friend {
        uid: "u_peer".into(),
    });
    missing.compatibility = None;
    assert!(matches!(
        media.legacy_video_play_url(&missing, context(22)).await,
        Err(Error::Unsupported(_))
    ));
    missing.compatibility = Some(pb::VideoFile::default().encode_to_vec());
    assert!(matches!(
        media.legacy_video_play_url(&missing, context(22)).await,
        Err(Error::Malformed(_))
    ));
    missing.kind = MediaKind::Image;
    assert!(matches!(
        media.legacy_video_play_url(&missing, context(22)).await,
        Err(Error::Malformed(_))
    ));
    let group = reference(MediaConversation::Group { uin: 42 });
    assert!(matches!(
        media.legacy_video_play_url(&group, context(43)).await,
        Err(Error::Malformed(_))
    ));
    let private = reference(MediaConversation::Friend {
        uid: "u_peer".into(),
    });
    let mut invalid = context(22);
    invalid.from_uin = 0;
    assert!(matches!(
        media.legacy_video_play_url(&private, invalid).await,
        Err(Error::Malformed(_))
    ));
    assert!(transport.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn server_refusal_is_preserved_without_retry_or_ntv2_fallback() {
    let transport = client(pb::LegacyVideoPlayResponse {
        command: Some(410),
        download: Some(pb::LegacyVideoDownloadResponse {
            code: Some(170013002),
            message: Some(Bytes::from_static(b"limited")),
            ..Default::default()
        }),
        ..Default::default()
    });
    let media = Media::new(transport.clone());
    assert!(matches!(media.legacy_video_play_url(
        &reference(MediaConversation::Friend { uid: "u_peer".into() }), context(22)
    ).await, Err(Error::Server { code: 170013002, message }) if message == "limited"));
    assert_eq!(transport.requests.lock().unwrap().len(), 1);
}

#[test]
fn missing_or_wrong_response_contract_cannot_turn_into_a_successful_url() {
    for invalid in [
        pb::LegacyVideoPlayResponse::default(),
        pb::LegacyVideoPlayResponse {
            command: Some(400),
            ..Default::default()
        },
        pb::LegacyVideoPlayResponse {
            command: Some(410),
            ..Default::default()
        },
        pb::LegacyVideoPlayResponse {
            command: Some(410),
            download: Some(Default::default()),
            ..Default::default()
        },
        response(pb::LegacyVideoDownloadAddress::default()),
    ] {
        assert!(matches!(legacy_url(invalid), Err(Error::Malformed(_))));
    }
}

#[test]
fn old_request_way_changes_download_kind_without_becoming_an_ntv2_scene() {
    let reference = reference(MediaConversation::Friend {
        uid: "u_peer".into(),
    });
    for (way, down_type) in [(0, 2), (1, 1)] {
        let mut context = context(22);
        context.video_request_way = way;
        let (_, request) = legacy_request(&reference, context).unwrap();
        let download = request.download.unwrap();
        assert_eq!(download.down_type, Some(down_type));
        assert_eq!(download.scene_type, Some(0));
    }
}
