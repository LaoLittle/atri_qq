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

#[derive(Default)]
pub(crate) struct Heartbeat {
    identifier: Option<Bytes>,
    sequence: u64,
    deadline: Option<Instant>,
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
        self.deadline = Some(now + INTERVAL);
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
            interval_seconds: INTERVAL.as_secs() as u32,
        }
        .encode_to_vec();
        self.sequence = self.sequence.wrapping_add(1);
        Ok(Some(body))
    }

    pub(crate) fn complete(
        &self,
        body: Bytes,
        state: &SessionState,
        signer: &mut SessionSigner,
    ) -> Result<Vec<SigningReport>> {
        let response: pb::HeartbeatResponse = proto::decode(body)?;
        if response.tasks.is_empty() {
            return Ok(Vec::new());
        }
        let header = self.header(state)?;
        let mut reports = vec![
            signer.channel_report(
                "taskAck",
                pb::TaskAckRequest {
                    header: Some(header.clone()),
                    identifier: response.identifier.clone(),
                }
                .encode_to_vec(),
            ),
        ];
        let mut results = Vec::new();
        for task in response.tasks {
            let body = match task.kind {
                7 => match signer.refresh_token_task() {
                    Ok(()) => {
                        reports.extend(signer.drain_token_reports());
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
            reports.push(
                signer.channel_report(
                    "taskReport",
                    pb::TaskReportRequest {
                        header: Some(header),
                        identifier: response.identifier,
                        results,
                    }
                    .encode_to_vec(),
                ),
            );
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
    async fn task_batch_is_acknowledged_and_unknown_execution_is_not_fabricated() {
        let state = state();
        let mut signer = SessionSigner::default();
        signer.ticket_complete(&state).unwrap();
        let mut heartbeat = Heartbeat::default();
        heartbeat.configure(true);
        heartbeat.take_due(&state).unwrap();
        let response = pb::HeartbeatResponse {
            identifier: Bytes::from_static(b"offline-batch"),
            tasks: vec![pb::HeartbeatTask {
                kind: 999,
                identifier: Bytes::from_static(b"unknown"),
                ..Default::default()
            }],
        };
        let reports = heartbeat
            .complete(response.encode_to_vec().into(), &state, &mut signer)
            .unwrap();
        assert_eq!(
            reports
                .iter()
                .map(|report| report.method.as_str())
                .collect::<Vec<_>>(),
            ["taskAck"]
        );
        let ack = pb::TaskAckRequest::decode(reports[0].body.as_slice()).unwrap();
        assert_eq!(ack.identifier.as_ref(), b"offline-batch");
        assert!(
            heartbeat
                .complete(
                    pb::HeartbeatResponse::default().encode_to_vec().into(),
                    &state,
                    &mut signer
                )
                .unwrap()
                .is_empty()
        );
        assert!(
            heartbeat
                .complete(Bytes::from_static(b"\xff"), &state, &mut signer)
                .is_err()
        );
    }
}
