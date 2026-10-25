use crate::{
    Error, Result,
    models::SessionState,
    proto::{self, o3 as pb},
    signing::{SessionSigner, SigningReport},
};
use bytes::Bytes;
use prost::Message;
use rand::RngCore;
use std::time::Duration;
use tokio::time::Instant;

const INTERVAL: Duration = Duration::from_secs(180);

pub(crate) enum Work {
    Report(SigningReport),
    RotatePeer {
        material: [u8; 33],
        generation: u64,
        account: u64,
    },
}

pub(crate) struct Heartbeat {
    identifier: Option<Bytes>,
    sequence: u64,
    deadline: Option<Instant>,
    interval_seconds: u32,
    candidate_interval_seconds: u32,
}

impl Default for Heartbeat {
    fn default() -> Self {
        Self {
            identifier: None,
            sequence: 0,
            deadline: None,
            interval_seconds: INTERVAL.as_secs() as u32,
            candidate_interval_seconds: 0,
        }
    }
}

impl Heartbeat {
    pub(crate) fn reset(&mut self) {
        *self = Self::default();
    }

    pub(crate) fn configure(&mut self, enabled: bool) {
        if !enabled {
            self.deadline = None;
        } else if self.deadline.is_none() {
            self.deadline = Some(Instant::now());
        }
    }

    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    fn header(&self, state: &SessionState) -> Result<pb::HeartbeatHeader> {
        Ok(pb::HeartbeatHeader {
            field1: 1,
            account: state.keystore.uin.to_string().into_bytes().into(),
            machine_id: Bytes::copy_from_slice(state.machine_id.as_bytes()),
            identifier: self.identifier.clone().ok_or_else(|| {
                Error::Authentication("O3 heartbeat identifier unavailable".into())
            })?,
            kind: 4,
            qua: Bytes::copy_from_slice(state.profile.qua.as_bytes()),
        })
    }

    pub(crate) fn take_due(&mut self, state: &SessionState) -> Result<Option<Vec<u8>>> {
        let now = Instant::now();
        if self.deadline.is_none_or(|deadline| deadline > now) {
            return Ok(None);
        }
        if self.candidate_interval_seconds >= 61
            && self.candidate_interval_seconds != self.interval_seconds
        {
            self.interval_seconds = self.candidate_interval_seconds;
        }
        self.deadline = Some(now + Duration::from_secs(u64::from(self.interval_seconds)));
        if self.identifier.is_none() {
            let mut random = [0; 16];
            rand::rngs::OsRng
                .try_fill_bytes(&mut random)
                .map_err(|error| Error::Crypto(format!("O3 heartbeat entropy: {error}")))?;
            let mut identifier = vec![0; 32];
            hex::encode_to_slice(random, &mut identifier)
                .expect("sixteen bytes encode into thirty-two hex bytes");
            self.identifier = Some(identifier.into());
        }
        let body = pb::HeartbeatRequest {
            header: Some(self.header(state)?),
            sequence: self.sequence,
            interval_seconds: self.interval_seconds,
        }
        .encode_to_vec();
        self.sequence = self.sequence.wrapping_add(1);
        Ok(Some(body))
    }

    pub(crate) fn complete(
        &mut self,
        body: Bytes,
        state: &SessionState,
        signer: &mut SessionSigner,
    ) -> Result<Vec<Work>> {
        let response: pb::HeartbeatResponse = proto::decode(body)?;
        if response.tasks.is_empty() {
            return Ok(Vec::new());
        }
        let header = self.header(state)?;
        let mut reports = vec![Work::Report(signer.channel_report(
            "taskAck",
            pb::TaskAckRequest {
                header: Some(header.clone()),
                identifier: response.identifier.clone(),
            }
            .encode_to_vec(),
        ))];
        let mut results = Vec::new();
        for task in response.tasks {
            let body = match task.kind {
                6 => {
                    let Some(value) = task.payload.get(..4) else {
                        tracing::warn!(task_kind = task.kind, "O3 interval task payload is too short");
                        continue;
                    };
                    self.candidate_interval_seconds = u32::from_be_bytes(value.try_into().unwrap());
                    Vec::new()
                }
                7 => match signer.refresh_token_task() {
                    Ok(()) => {
                        reports.extend(signer.drain_token_reports().into_iter().map(Work::Report));
                        Vec::new()
                    }
                    Err(error) => {
                        tracing::warn!(%error, task_kind = task.kind, "O3 token task failed");
                        continue;
                    }
                },
                8 => match signer.answer_property_challenge(&task.payload) {
                    Ok(body) => body,
                    Err(error) => {
                        tracing::warn!(%error, task_kind = task.kind, "O3 property task failed");
                        continue;
                    }
                },
                9 => {
                    let Some(material) = task.payload.get(..33) else {
                        tracing::warn!(
                            task_kind = task.kind,
                            "O3 peer rotation task payload is too short"
                        );
                        continue;
                    };
                    reports.push(Work::RotatePeer {
                        material: material.try_into().unwrap(),
                        generation: signer.generation(),
                        account: state.keystore.uin,
                    });
                    Vec::new()
                }
                kind => {
                    tracing::warn!(
                        task_kind = kind,
                        "Unsupported O3 task; acknowledging receipt without reporting execution success"
                    );
                    continue;
                }
            };
            results.push(pb::TaskResult {
                identifier: task.identifier,
                body: body.into(),
            });
        }
        if !results.is_empty() {
            reports.push(Work::Report(
                signer.channel_report(
                    "taskReport",
                    pb::TaskReportRequest {
                        header: Some(header),
                        identifier: response.identifier,
                        results,
                    }
                    .encode_to_vec(),
                ),
            ));
        }
        Ok(reports)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Keystore, Profile};

    fn state() -> SessionState {
        SessionState {
            profile: Profile::linux(),
            keystore: Keystore {
                uin: 1234,
                ..Default::default()
            },
            machine_id: "offline-o3-device".into(),
            online: true,
        }
    }

    struct Fixture {
        state: SessionState,
        signer: SessionSigner,
        heartbeat: Heartbeat,
        channel: super::super::Channel,
    }

    impl Fixture {
        fn new() -> Self {
            let state = state();
            let mut signer = SessionSigner::default();
            signer.ticket_complete(&state).unwrap();
            let mut heartbeat = Heartbeat::default();
            heartbeat.configure(true);
            heartbeat.take_due(&state).unwrap().unwrap();
            Self {
                state,
                signer,
                heartbeat,
                channel: super::super::Channel::default(),
            }
        }

        fn work(&mut self, tasks: Vec<pb::HeartbeatTask>) -> Vec<Work> {
            self.heartbeat
                .complete(
                    pb::HeartbeatResponse {
                        identifier: Bytes::from_static(b"offline-batch"),
                        tasks,
                    }
                    .encode_to_vec()
                    .into(),
                    &self.state,
                    &mut self.signer,
                )
                .unwrap()
        }

        fn complete(&mut self, tasks: Vec<pb::HeartbeatTask>) -> Vec<SigningReport> {
            let mut reports = Vec::new();
            for work in self.work(tasks) {
                match work {
                    Work::Report(report) => reports.push(report),
                    Work::RotatePeer {
                        material,
                        generation,
                        account,
                    } => {
                        assert_eq!(generation, self.signer.generation());
                        assert_eq!(account, self.state.keystore.uin);
                        self.channel.rotate_peer(&material).unwrap();
                    }
                }
            }
            reports
        }

        fn due(&mut self) -> Option<pb::HeartbeatRequest> {
            self.heartbeat
                .take_due(&self.state)
                .unwrap()
                .map(|body| pb::HeartbeatRequest::decode(body.as_slice()).unwrap())
        }

        fn interval(&mut self, value: u32) -> Vec<SigningReport> {
            self.complete(vec![task(6, b"interval", value.to_be_bytes().to_vec())])
        }
    }

    fn task(kind: u32, identifier: &'static [u8], payload: Vec<u8>) -> pb::HeartbeatTask {
        pb::HeartbeatTask {
            kind,
            identifier: Bytes::from_static(identifier),
            payload: payload.into(),
        }
    }

    fn encoded_generator(prefix: u8) -> Vec<u8> {
        let mut peer =
            hex::decode("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
                .unwrap();
        peer[0] = prefix;
        for (index, value) in peer.iter_mut().enumerate() {
            *value ^= b"3UEBOKPY"[index % 8];
        }
        peer.rotate_left(8);
        peer
    }

    #[tokio::test(start_paused = true)]
    async fn interval_candidate_waits_for_due_work_and_changes_its_body_and_next_wait() {
        let mut fixture = Fixture::new();
        let identifier = fixture.heartbeat.identifier.clone().unwrap();
        let waiting = fixture.heartbeat.deadline().unwrap();
        tokio::time::advance(Duration::from_secs(30)).await;
        let mut payload = 61u32.to_be_bytes().to_vec();
        payload.extend_from_slice(b"accepted trailing bytes");
        let reports = fixture.complete(vec![task(6, b"interval", payload)]);
        assert_eq!(reports[0].method, "taskAck");
        assert_eq!(reports[1].method, "taskReport");
        let result = pb::TaskReportRequest::decode(reports[1].body.as_slice()).unwrap();
        assert_eq!(result.results.len(), 1);
        assert_eq!(result.results[0].identifier.as_ref(), b"interval");
        assert!(result.results[0].body.is_empty());
        assert_eq!(fixture.heartbeat.deadline(), Some(waiting));
        assert_eq!(fixture.heartbeat.interval_seconds, 180);
        tokio::time::advance(Duration::from_secs(149)).await;
        assert!(fixture.due().is_none());
        tokio::time::advance(Duration::from_secs(1)).await;
        let body = fixture.due().unwrap();
        assert_eq!(body.interval_seconds, 61);
        assert_eq!(body.sequence, 1);
        assert_eq!(body.header.unwrap().identifier, identifier);
        assert_eq!(
            fixture.heartbeat.deadline(),
            Some(Instant::now() + Duration::from_secs(61))
        );
        tokio::time::advance(Duration::from_secs(60)).await;
        assert!(fixture.due().is_none());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(fixture.due().unwrap().interval_seconds, 61);
        let waiting = fixture.heartbeat.deadline();
        fixture.interval(61);
        assert_eq!(fixture.heartbeat.deadline(), waiting);
        assert!(fixture.due().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn interval_boundaries_are_unsigned_and_low_candidates_preserve_the_active_period() {
        let mut fixture = Fixture::new();
        for (candidate, active) in [
            (0, 180),
            (60, 180),
            (61, 61),
            (180, 180),
            (0x8000_0000, 0x8000_0000),
            (u32::MAX, u32::MAX),
            (60, u32::MAX),
            (0, u32::MAX),
        ] {
            let waiting = fixture.heartbeat.deadline().unwrap();
            fixture.interval(candidate);
            assert_eq!(fixture.heartbeat.deadline(), Some(waiting));
            assert!(fixture.due().is_none());
            tokio::time::advance(waiting - Instant::now()).await;
            assert_eq!(fixture.due().unwrap().interval_seconds, active);
            assert_eq!(
                fixture.heartbeat.deadline(),
                Some(Instant::now() + Duration::from_secs(u64::from(active)))
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn disabling_preserves_candidates_and_active_period_until_an_explicit_reset() {
        let mut fixture = Fixture::new();
        let identifier = fixture.heartbeat.identifier.clone().unwrap();
        fixture.heartbeat.configure(false);
        fixture.interval(90);
        assert_eq!(fixture.heartbeat.deadline(), None);
        tokio::time::advance(Duration::from_secs(200)).await;
        assert!(fixture.due().is_none());
        fixture.heartbeat.configure(true);
        let body = fixture.due().unwrap();
        assert_eq!(body.interval_seconds, 90);
        assert_eq!(body.sequence, 1);
        assert_eq!(body.header.unwrap().identifier, identifier);
        fixture.interval(120);
        fixture.heartbeat.configure(false);
        tokio::time::advance(Duration::from_secs(200)).await;
        assert!(fixture.due().is_none());
        fixture.heartbeat.configure(true);
        assert_eq!(fixture.due().unwrap().interval_seconds, 120);
        fixture.heartbeat.configure(false);
        fixture.interval(60);
        fixture.heartbeat.configure(true);
        assert_eq!(fixture.due().unwrap().interval_seconds, 120);
        fixture.interval(240);
        fixture.heartbeat.reset();
        assert!(fixture.due().is_none());
        fixture.heartbeat.configure(true);
        let body = fixture.due().unwrap();
        assert_eq!(body.interval_seconds, 180);
        assert_eq!(body.sequence, 0);
        assert_eq!(fixture.heartbeat.candidate_interval_seconds, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn short_interval_tasks_are_isolated_without_erasing_a_valid_candidate() {
        let mut fixture = Fixture::new();
        let mut tasks = vec![task(6, b"valid", 90u32.to_be_bytes().to_vec())];
        for length in 0..4 {
            tasks.push(task(6, b"short", vec![0xff; length]));
        }
        let reports = fixture.complete(tasks);
        assert_eq!(
            reports.iter().map(|report| report.method.as_str()).collect::<Vec<_>>(),
            ["taskAck", "taskReport"]
        );
        let results = pb::TaskReportRequest::decode(reports[1].body.as_slice()).unwrap();
        assert_eq!(results.results.len(), 1);
        assert_eq!(results.results[0].identifier.as_ref(), b"valid");
        assert_eq!(fixture.heartbeat.candidate_interval_seconds, 90);
        tokio::time::advance(INTERVAL).await;
        assert_eq!(fixture.due().unwrap().interval_seconds, 90);
        let reports = fixture.complete(vec![task(6, b"short", vec![0xff; 3])]);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].method, "taskAck");
        assert_eq!(fixture.heartbeat.candidate_interval_seconds, 90);
    }

    #[tokio::test(start_paused = true)]
    async fn ordered_tasks_rotate_peers_and_report_only_successful_results() {
        let mut fixture = Fixture::new();
        fixture.channel.prepare("heartbeat", Bytes::new(), 0).unwrap();
        assert!(fixture.channel.is_establishing());
        let first_peer = encoded_generator(2);
        let final_peer = encoded_generator(3);
        let mut first_payload = first_peer;
        first_payload.extend_from_slice(b"first trailing bytes");
        let mut final_payload = final_peer.clone();
        final_payload.extend_from_slice(b"last trailing bytes");
        let work = fixture.work(vec![
            task(9, b"first-rotation", first_payload),
            task(6, b"first-interval", 90u32.to_be_bytes().to_vec()),
            task(9, b"short-rotation", vec![0xff; 32]),
            task(8, b"property", 16i16.to_be_bytes().to_vec()),
            task(9, b"last-rotation", final_payload),
            task(8, b"short-property", vec![0]),
            task(6, b"last-interval", 120u32.to_be_bytes().to_vec()),
            task(999, b"unsupported", Vec::new()),
        ]);
        assert_eq!(work.len(), 4);
        let mut reports = Vec::new();
        let mut rotations = Vec::new();
        for work in work {
            match work {
                Work::Report(report) => {
                    let request = fixture
                        .channel
                        .prepare(&report.method, report.body.clone().into(), 0)
                        .unwrap();
                    let request = pb::EstablishShareKeyRequest::decode(request.body).unwrap();
                    if report.method == "taskAck" {
                        assert!(rotations.is_empty());
                        assert_eq!(
                            request.key_identifier.as_ref(),
                            super::super::crypto::KEY_IDENTIFIER
                        );
                    } else {
                        assert_eq!(rotations.len(), 2);
                        assert_eq!(
                            request.key_identifier.as_ref(),
                            hex::encode(&final_peer).as_bytes()
                        );
                    }
                    reports.push(report);
                }
                Work::RotatePeer {
                    material,
                    generation,
                    account,
                } => {
                    assert_eq!(reports.len(), 1);
                    assert_eq!(generation, fixture.signer.generation());
                    assert_eq!(account, fixture.state.keystore.uin);
                    fixture.channel.rotate_peer(&material).unwrap();
                    assert!(!fixture.channel.is_establishing());
                    rotations.push(material);
                }
            }
        }
        assert_eq!(rotations[0].as_slice(), encoded_generator(2));
        assert_eq!(rotations[1].as_slice(), final_peer);
        assert_eq!(
            reports
                .iter()
                .map(|report| report.method.as_str())
                .collect::<Vec<_>>(),
            ["taskAck", "taskReport"]
        );
        let ack = pb::TaskAckRequest::decode(reports[0].body.as_slice()).unwrap();
        let report = pb::TaskReportRequest::decode(reports[1].body.as_slice()).unwrap();
        assert_eq!(ack.identifier.as_ref(), b"offline-batch");
        assert_eq!(report.identifier, ack.identifier);
        assert_eq!(
            report
                .results
                .iter()
                .map(|result| result.identifier.as_ref())
                .collect::<Vec<_>>(),
            [
                b"first-rotation".as_slice(),
                b"first-interval".as_slice(),
                b"property".as_slice(),
                b"last-rotation".as_slice(),
                b"last-interval".as_slice(),
            ]
        );
        for (index, result) in report.results.iter().enumerate() {
            if index == 2 {
                let properties =
                    ::signing::proto::TokenReport::decode(result.body.clone()).unwrap();
                assert_eq!(properties.properties.len(), 1);
                assert_eq!(properties.properties[0].value, b"offline-o3-device");
            } else {
                assert!(result.body.is_empty());
            }
        }
        let request = fixture.channel.prepare("heartbeat", Bytes::new(), 0).unwrap();
        let request = pb::EstablishShareKeyRequest::decode(request.body).unwrap();
        assert_eq!(request.key_identifier.as_ref(), hex::encode(final_peer).as_bytes());
        tokio::time::advance(INTERVAL).await;
        assert_eq!(fixture.due().unwrap().interval_seconds, 120);
    }

    #[tokio::test(start_paused = true)]
    async fn every_short_rotation_is_isolated_without_resetting_an_inflight_channel() {
        let mut fixture = Fixture::new();
        let peer = encoded_generator(2);
        fixture.complete(vec![task(9, b"valid", peer.clone())]);
        fixture.channel.prepare("heartbeat", Bytes::new(), 0).unwrap();
        let reports = fixture.complete(
            (0..33)
                .map(|length| task(9, b"short", vec![0xff; length]))
                .collect(),
        );
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].method, "taskAck");
        assert!(fixture.channel.is_establishing());
        let request = fixture.channel.prepare("heartbeat", Bytes::new(), 0).unwrap();
        let request = pb::EstablishShareKeyRequest::decode(request.body).unwrap();
        assert_eq!(request.key_identifier.as_ref(), hex::encode(peer).as_bytes());
    }

    #[tokio::test(start_paused = true)]
    async fn remote_gate_starts_immediately_then_keeps_the_native_period_and_identity() {
        let state = state();
        let mut heartbeat = Heartbeat::default();
        assert!(heartbeat.take_due(&state).unwrap().is_none());
        heartbeat.configure(true);
        let first =
            pb::HeartbeatRequest::decode(heartbeat.take_due(&state).unwrap().unwrap().as_slice())
                .unwrap();
        assert_eq!(first.sequence, 0);
        assert_eq!(first.interval_seconds, 180);
        let header = first.header.unwrap();
        assert_eq!(header.kind, 4);
        assert_eq!(header.account.as_ref(), b"1234");
        assert_eq!(header.machine_id.as_ref(), b"offline-o3-device");
        assert_eq!(header.qua.as_ref(), state.profile.qua.as_bytes());
        assert!(header.identifier.iter().all(u8::is_ascii_hexdigit));
        tokio::time::advance(Duration::from_secs(179)).await;
        heartbeat.configure(true);
        assert!(heartbeat.take_due(&state).unwrap().is_none());
        tokio::time::advance(Duration::from_secs(1)).await;
        let second =
            pb::HeartbeatRequest::decode(heartbeat.take_due(&state).unwrap().unwrap().as_slice())
                .unwrap();
        assert_eq!(second.sequence, 1);
        assert_eq!(second.header.unwrap().identifier, header.identifier);
        heartbeat.configure(false);
        tokio::time::advance(INTERVAL).await;
        assert!(heartbeat.take_due(&state).unwrap().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn latest_candidate_wins_even_when_it_is_below_the_activation_threshold() {
        let mut fixture = Fixture::new();
        fixture.interval(90);
        tokio::time::advance(INTERVAL).await;
        assert_eq!(fixture.due().unwrap().interval_seconds, 90);
        let waiting = fixture.heartbeat.deadline().unwrap();
        fixture.complete(vec![
            task(6, b"high", 240u32.to_be_bytes().to_vec()),
            task(6, b"low", 60u32.to_be_bytes().to_vec()),
        ]);
        assert_eq!(fixture.heartbeat.deadline(), Some(waiting));
        tokio::time::advance(Duration::from_secs(100)).await;
        assert_eq!(fixture.due().unwrap().interval_seconds, 90);
        assert_eq!(
            fixture.heartbeat.deadline(),
            Some(Instant::now() + Duration::from_secs(90))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn token_tasks_keep_ack_and_background_report_order_in_a_state_task_batch() {
        let mut fixture = Fixture::new();
        let reports = fixture.complete(vec![
            task(7, b"first-token", Vec::new()),
            task(6, b"interval", 90u32.to_be_bytes().to_vec()),
            task(7, b"pending-token", Vec::new()),
        ]);
        assert_eq!(
            reports
                .iter()
                .map(|report| report.method.as_str())
                .collect::<Vec<_>>(),
            ["taskAck", "getToken", "taskReport"]
        );
        let report = pb::TaskReportRequest::decode(reports[2].body.as_slice()).unwrap();
        assert_eq!(
            report
                .results
                .iter()
                .map(|result| result.identifier.as_ref())
                .collect::<Vec<_>>(),
            [
                b"first-token".as_slice(),
                b"interval".as_slice(),
                b"pending-token".as_slice(),
            ]
        );
        assert!(report.results.iter().all(|result| result.body.is_empty()));
    }

    #[tokio::test(start_paused = true)]
    async fn task_batch_is_acknowledged_and_unknown_execution_is_not_fabricated() {
        let mut fixture = Fixture::new();
        let reports = fixture.complete(vec![task(999, b"unknown", Vec::new())]);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].method, "taskAck");
        let ack = pb::TaskAckRequest::decode(reports[0].body.as_slice()).unwrap();
        assert_eq!(ack.identifier.as_ref(), b"offline-batch");
        assert!(
            fixture.heartbeat
                .complete(
                    pb::HeartbeatResponse::default().encode_to_vec().into(),
                    &fixture.state,
                    &mut fixture.signer,
                )
                .unwrap()
                .is_empty()
        );
        assert!(
            fixture.heartbeat
                .complete(
                    Bytes::from_static(b"\xff"),
                    &fixture.state,
                    &mut fixture.signer,
                )
                .is_err()
        );
    }
}
