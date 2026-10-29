use super::*;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

struct Source {
    millis: AtomicU64,
    value: AtomicU32,
    client: Weak<Client>,
}
impl crate::heartbeat::IosSource for Source {
    fn resources(&self) -> crate::heartbeat::IosResources {
        self.client.upgrade().unwrap().account_uin();
        let value = self.value.load(Ordering::Relaxed);
        crate::heartbeat::IosResources {
            silence_status: value,
            silent_version: value + 1,
            battery_status: 0x8000_0000 | value,
        }
    }
    fn clock_millis(&self) -> Option<u64> {
        Some(self.millis.load(Ordering::Relaxed))
    }
}

#[tokio::test(start_paused = true)]
async fn mobile_heartbeat_captures_clock_at_arm_and_resources_at_send_without_holding_client_lock()
{
    let client = Client::new(
        ios_signing_tests::config(Profile::ipad()),
        Keystore::default(),
    )
    .unwrap();
    let (sender, mut queue) = mpsc::channel(8);
    client.inner.lock().unwrap().connection = Some(Connection {
        generation: 0,
        sender,
    });
    let source = Arc::new(Source {
        millis: AtomicU64::new(1_000_123),
        value: AtomicU32::new(1),
        client: Arc::downgrade(&client),
    });
    client
        .set_ios_heartbeat_source(Some(source.clone()))
        .unwrap();
    client.start_heartbeat(7, 1);
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(119)).await;
    assert!(queue.try_recv().is_err());
    source.value.store(9, Ordering::Relaxed);
    source.millis.store(2_000_999, Ordering::Relaxed);
    tokio::time::advance(Duration::from_secs(1)).await;
    let packet = queue.recv().await.unwrap();
    let request =
        auth::HeartbeatRequest::decode(ios_signing_tests::request_parts(packet.frame, &[0; 16]).4)
            .unwrap();
    assert_eq!(request.trigger_time, Some(1000));
    let state = request.state.unwrap();
    assert_eq!(state.silence_status, Some(9));
    assert_eq!(state.silent_version, Some(10));
    assert_eq!(request.battery_status, Some(0x8000_0009));
    client
        .receive(
            tests::incoming(
                packet.sequence,
                &packet.command,
                &auth::HeartbeatResponse {
                    interval_seconds: Some(501),
                }
                .encode_to_vec(),
                Some(&[0; 16]),
            ),
            0,
        )
        .unwrap();
    tokio::task::yield_now().await;
    source.value.store(17, Ordering::Relaxed);
    source.millis.store(3_000_789, Ordering::Relaxed);
    tokio::time::advance(Duration::from_secs(499)).await;
    assert!(queue.try_recv().is_err());
    tokio::time::advance(Duration::from_secs(1)).await;
    let packet = queue.recv().await.unwrap();
    let request =
        auth::HeartbeatRequest::decode(ios_signing_tests::request_parts(packet.frame, &[0; 16]).4)
            .unwrap();
    assert_eq!(request.trigger_time, Some(2000));
    assert_eq!(request.battery_status, Some(0x8000_0011));
    client.inner.lock().unwrap().heartbeat_cancel.cancel();
    tokio::task::yield_now().await;
}
