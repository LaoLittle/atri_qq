use super::*;

fn binding(generation: u64, parent: &CancellationToken) -> Arc<Binding> {
    Arc::new(Binding::new(
        generation,
        123456,
        "u_synthetic_file_owner".into(),
        Bytes::from_static(b"synthetic-a2"),
        [0x35; 16],
        parent,
    ).unwrap())
}

fn response(sign: &'static [u8], lifetime_seconds: u64) -> Result<Response> {
    Ok(Response { sign: Bytes::from_static(sign), lifetime_seconds })
}

fn envelope(ticket: Option<pb::FileTransSignTicket>) -> OidbEnvelope {
    OidbEnvelope {
        command: Some(0x9a2),
        service: Some(8),
        code: Some(0),
        body: Some(pb::FileTransSignResponse {
            field1: Some(Bytes::from_static(b"opaque-neutral-field")),
            ticket,
        }.encode_to_vec().into()),
        ..Default::default()
    }
}

fn decoded(envelope: OidbEnvelope) -> Result<Response> {
    decode(envelope.encode_to_vec().into())
}

#[test]
fn dormant_provider_never_queues_and_active_provider_renews_from_response_time() {
    let now = Instant::now();
    let parent = CancellationToken::new();
    let mut cache = Cache::default();
    cache.activate(binding(1, &parent)).unwrap();
    assert!(cache.cached(now).is_none());
    assert!(cache.next_due().is_none());
    assert!(cache.take_due(now + Duration::from_secs(86400)).unwrap().is_none());
    cache.enable(now).unwrap();
    let session = cache.take_due(now).unwrap().unwrap();
    assert!(cache.take_due(now).unwrap().is_none());
    cache.enable(now).unwrap();
    assert!(cache.next_due().is_none());
    let received = now + Duration::from_secs(3);
    let ticket = cache.apply(&session, response(b"opaque-file-sign", 43200), received).unwrap();
    assert_eq!(ticket.sign(), b"opaque-file-sign");
    let due = received + Duration::from_secs(21600);
    assert_eq!(cache.next_due(), Some(due));
    assert!(cache.take_due(due - Duration::from_nanos(1)).unwrap().is_none());
    assert!(cache.take_due(due).unwrap().is_some());
    assert!(cache.cached(received + Duration::from_secs(43199)).is_some());
    assert!(cache.cached(received + Duration::from_secs(43200)).is_none());
}

#[test]
fn native_threshold_and_odd_lifetime_are_not_fixed_refresh_periods() {
    for (lifetime, expected) in [(1, 1800), (3600, 1800), (3601, 1800), (3603, 1801), (43200, 21600)] {
        let now = Instant::now();
        let parent = CancellationToken::new();
        let mut cache = Cache::default();
        cache.activate(binding(1, &parent)).unwrap();
        cache.enable(now).unwrap();
        let session = cache.take_due(now).unwrap().unwrap();
        cache.apply(&session, response(b"ticket", lifetime), now).unwrap();
        assert_eq!(cache.next_due(), Some(now + Duration::from_secs(expected)));
        assert!(cache.cached(now + Duration::from_secs(lifetime)).is_none());
    }
}

#[test]
fn error_or_invalid_renewal_retains_old_valid_ticket_without_fabricating_retry() {
    for result in [
        Err(Error::Timeout),
        response(b"", 43200),
        response(b"replacement", 0),
        response(b"replacement", u64::MAX),
    ] {
        let now = Instant::now();
        let parent = CancellationToken::new();
        let mut cache = Cache::default();
        cache.activate(binding(1, &parent)).unwrap();
        cache.enable(now).unwrap();
        let initial = cache.take_due(now).unwrap().unwrap();
        cache.apply(&initial, response(b"still-valid", 43200), now).unwrap();
        let renewal_time = now + Duration::from_secs(21600);
        let renewal = cache.take_due(renewal_time).unwrap().unwrap();
        assert!(cache.apply(&renewal, result, renewal_time).is_err());
        assert_eq!(cache.cached(renewal_time).unwrap().sign(), b"still-valid");
        assert!(cache.next_due().is_none());
        cache.enable(renewal_time).unwrap();
        assert!(cache.next_due().is_none());
        let expired = now + Duration::from_secs(43200);
        cache.enable(expired).unwrap();
        assert!(cache.take_due(expired).unwrap().is_some());
    }
}

#[test]
fn initial_failure_can_only_be_requeued_by_explicit_demand() {
    let now = Instant::now();
    let parent = CancellationToken::new();
    let mut cache = Cache::default();
    cache.activate(binding(1, &parent)).unwrap();
    cache.enable(now).unwrap();
    let session = cache.take_due(now).unwrap().unwrap();
    assert!(cache.apply(&session, Err(Error::Timeout), now).is_err());
    assert!(cache.next_due().is_none());
    assert!(cache.take_due(now + Duration::from_secs(60)).unwrap().is_none());
    cache.enable(now).unwrap();
    let replacement = cache.take_due(now).unwrap().unwrap();
    assert!(!Arc::ptr_eq(&session, &replacement));
    assert!(cache.apply(&session, response(b"late-response", 43200), now).is_err());
    assert!(cache.cached(now).is_none());
    cache.apply(&replacement, response(b"current-response", 43200), now).unwrap();
    assert_eq!(cache.cached(now).unwrap().sign(), b"current-response");
}

#[test]
fn every_identity_component_revokes_inflight_and_cached_credentials() {
    for component in 0..6 {
        let now = Instant::now();
        let parent = CancellationToken::new();
        let mut cache = Cache::default();
        let old = cache.activate(binding(1, &parent)).unwrap();
        cache.enable(now).unwrap();
        let initial = cache.take_due(now).unwrap().unwrap();
        cache.apply(&initial, response(b"old-ticket", 43200), now).unwrap();
        let renewal = cache.take_due(now + Duration::from_secs(21600)).unwrap().unwrap();
        let mut replacement = Binding::new(
            1, 123456, "u_synthetic_file_owner".into(),
            Bytes::from_static(b"synthetic-a2"), [0x35; 16], &parent,
        ).unwrap();
        match component {
            0 => replacement.generation += 1,
            1 => replacement.uin += 1,
            2 => replacement.uid.push('2'),
            3 => replacement.a2 = Bytes::from_static(b"new-a2"),
            4 => replacement.machine_guid[0] ^= 1,
            5 => {
                replacement = Binding::new(
                    1, 123456, "u_synthetic_file_owner".into(),
                    Bytes::from_static(b"synthetic-a2"), [0x35; 16], &CancellationToken::new(),
                ).unwrap();
            }
            _ => unreachable!(),
        }
        cache.activate(Arc::new(replacement)).unwrap();
        assert!(old.cancel.is_cancelled());
        assert!(cache.cached(now).is_none());
        assert!(cache.apply(&renewal, response(b"old-inflight", 43200), now).is_err());
        assert!(cache.next_due().is_none());
        cache.enable(now).unwrap();
        let current = cache.take_due(now).unwrap().unwrap();
        cache.apply(&current, response(b"new-ticket", 43200), now).unwrap();
        assert_eq!(cache.cached(now).unwrap().sign(), b"new-ticket");
    }
}

#[test]
fn equivalent_identity_reuses_state_but_cancellation_prevents_publish_and_request() {
    let now = Instant::now();
    let parent = CancellationToken::new();
    let mut cache = Cache::default();
    let original = cache.activate(binding(1, &parent)).unwrap();
    let same = cache.activate(binding(1, &parent)).unwrap();
    assert!(Arc::ptr_eq(&original, &same));
    cache.enable(now).unwrap();
    let session = cache.take_due(now).unwrap().unwrap();
    parent.cancel();
    assert!(build(&session).is_err());
    assert!(cache.apply(&session, response(b"cancelled", 43200), now).is_err());
    assert!(cache.cached(now).is_none());
    assert!(cache.next_due().is_none());
    assert!(cache.enable(now).is_err());
    assert!(cache.take_due(now).is_err());
}

#[test]
fn required_response_boundaries_reject_absence_empty_zero_and_wrong_envelope() {
    let valid = || pb::FileTransSignTicket {
        sign: Some(Bytes::from_static(b"opaque-ticket")),
        lifetime_seconds: Some(43200),
    };
    assert_eq!(decoded(envelope(Some(valid()))).unwrap().sign.as_ref(), b"opaque-ticket");
    assert!(decoded(envelope(None)).is_err());
    for ticket in [
        pb::FileTransSignTicket { sign: None, ..valid() },
        pb::FileTransSignTicket { sign: Some(Bytes::new()), ..valid() },
        pb::FileTransSignTicket { lifetime_seconds: None, ..valid() },
        pb::FileTransSignTicket { lifetime_seconds: Some(0), ..valid() },
    ] {
        assert!(decoded(envelope(Some(ticket))).is_err());
    }
    let mut wrong = envelope(Some(valid()));
    wrong.command = Some(0x9a3);
    assert!(decoded(wrong).is_err());
    let mut wrong = envelope(Some(valid()));
    wrong.service = Some(9);
    assert!(decoded(wrong).is_err());
    let mut missing = envelope(Some(valid()));
    missing.command = None;
    assert!(decoded(missing).is_err());
    let mut missing = envelope(Some(valid()));
    missing.service = None;
    assert!(decoded(missing).is_err());
    let mut missing = envelope(Some(valid()));
    missing.code = None;
    assert!(decoded(missing).is_err());
    for body in [None, Some(Bytes::new()), Some(Bytes::from_static(b"\xff"))] {
        let mut malformed = envelope(Some(valid()));
        malformed.body = body;
        assert!(decoded(malformed).is_err());
    }
    let mut rejected = envelope(Some(valid()));
    rejected.code = Some(1001);
    rejected.message = Some("synthetic-private-server-text".into());
    let error = decoded(rejected).unwrap_err();
    assert!(matches!(error, Error::Server { code: 1001, .. }));
    assert!(!error.to_string().contains("synthetic-private-server-text"));
}

#[test]
fn request_uses_current_bound_binary_credentials_and_never_reuses_ticket_as_a2() {
    let now = Instant::now();
    let parent = CancellationToken::new();
    let mut cache = Cache::default();
    cache.activate(binding(1, &parent)).unwrap();
    cache.enable(now).unwrap();
    let session = cache.take_due(now).unwrap().unwrap();
    let initial = OidbEnvelope::decode(build(&session).unwrap()).unwrap();
    let request = pb::FileTransSignRequest::decode(initial.body.unwrap()).unwrap();
    assert_eq!(request.a2.unwrap().as_ref(), b"synthetic-a2");
    assert_eq!(request.machine_guid.unwrap().as_ref(), &[0x35; 16]);
    cache.apply(&session, response(b"different-opaque-sign", 43200), now).unwrap();
    let renewal = cache.take_due(now + Duration::from_secs(21600)).unwrap().unwrap();
    let envelope = OidbEnvelope::decode(build(&renewal).unwrap()).unwrap();
    let request = pb::FileTransSignRequest::decode(envelope.body.unwrap()).unwrap();
    assert_eq!(request.a2.unwrap().as_ref(), b"synthetic-a2");
}

#[test]
fn public_debug_does_not_expose_any_credential_or_account_identity() {
    let now = Instant::now();
    let parent = CancellationToken::new();
    let mut cache = Cache::default();
    let identity = cache.activate(binding(1, &parent)).unwrap();
    cache.enable(now).unwrap();
    let session = cache.take_due(now).unwrap().unwrap();
    let value = response(b"unique-private-ticket", 43200).unwrap();
    let response_debug = format!("{value:?}");
    let ticket = cache.apply(&session, Ok(value), now).unwrap();
    let output = format!("{identity:?} {session:?} {ticket:?} {response_debug}");
    for secret in ["123456", "u_synthetic_file_owner", "synthetic-a2", "unique-private-ticket"] {
        assert!(!output.contains(secret));
    }
}
