use super::*;

#[tokio::test(start_paused = true)]
async fn unregistered_mobile_clock_does_not_reuse_registration_time() {
    let client = Client::new(
        ios_signing_tests::config(Profile::iphone()),
        Keystore::default(),
    )
    .unwrap();
    let (sender, mut queue) = mpsc::channel(8);
    client.inner.lock().unwrap().connection = Some(Connection {
        generation: 0,
        sender,
    });
    client.start_heartbeat(1, 120);
    tokio::task::yield_now().await;
    assert!(queue.try_recv().is_err());
    tokio::time::advance(Duration::from_secs(119)).await;
    assert!(queue.try_recv().is_err());
    tokio::time::advance(Duration::from_secs(1)).await;
    let packet = queue.recv().await.unwrap();
    let body = ios_signing_tests::request_parts(packet.frame, &[0; 16]).4;
    let request = auth::HeartbeatRequest::decode(body).unwrap();
    assert_ne!(request.trigger_time, Some(1));
    assert_eq!(request.battery_status, Some(0));
    assert_eq!(request.state.unwrap().silence_status, Some(0));
    client.inner.lock().unwrap().heartbeat_cancel.cancel();
}
