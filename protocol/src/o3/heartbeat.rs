use crate::{
    Error, Result,
    models::SessionState,
    proto::{self, o3 as pb},
    signing::{SessionSigner, SigningReport},
};
use bytes::Bytes;
use prost::Message;
use rand::TryRng;
use std::time::Duration;
use tokio::time::Instant;

const INTERVAL: Duration = Duration::from_secs(180);

pub(crate) enum Work {
    Report(SigningReport),
    Compute(TaskReport),
    RotatePeer {
        material: [u8; 33],
        generation: u64,
        account: u64,
    },
}


pub(crate) struct TaskReport {
    binding: SigningReport,
    header: pb::HeartbeatHeader,
    identifier: Bytes,
    results: Vec<pb::TaskResult>,
    jobs: Vec<(usize, super::task11::Job)>,
}

impl TaskReport {
    pub(crate) fn binding(&self) -> &SigningReport {
        &self.binding
    }

    pub(crate) fn execute(mut self) -> Option<SigningReport> {
        let mut jobs = self.jobs.into_iter().peekable();
        if jobs.peek().is_some() {
            let mut index = 0;
            self.results.retain_mut(|result| {
                let current = index;
                index += 1;
                if !jobs.peek().is_some_and(|(index, _)| *index == current) {
                    return true;
                }
                let (_, job) = jobs.next().unwrap();
                match job.execute() {
                    Ok(body) => {
                        result.body = body.into();
                        true
                    }
                    Err(error) => {
                        tracing::warn!(%error, task_kind = 11, "O3 calculation task failed");
                        false
                    }
                }
            });
        }
        if self.results.is_empty() {
            return None;
        }
        let mut report = self.binding;
        report.body = pb::TaskReportRequest {
            header: Some(self.header),
            identifier: self.identifier,
            results: self.results,
        }
        .encode_to_vec();
        Some(report)
    }
}

#[derive(Default, Debug, PartialEq, Eq)]
pub(super) struct TaskMaterial {
    pub(super) identifier: u32,
    pub(super) prefix: [u8; 8],
    pub(super) material: Vec<u8>,
    pub(super) word: u32,
    pub(super) runtime: [u8; 8],
}

fn material_payload(payload: &[u8], current_identifier: u32) -> Option<(u32, &[u8], usize)> {
    let identifier = u32::from_be_bytes(payload.get(..4)?.try_into().ok()?);
    if identifier == current_identifier {
        return None;
    }
    let length = usize::from(u16::from_be_bytes(payload.get(4..6)?.try_into().ok()?));
    let bitmap = payload.get(6..6usize.checked_add(length)?)?;
    if bitmap.len() < 54 || bitmap.get(..2)? != b"BM" {
        return None;
    }
    let offset = usize::try_from(u32::from_le_bytes(bitmap.get(10..14)?.try_into().ok()?)).ok()?;
    let width = usize::try_from(u32::from_le_bytes(bitmap.get(18..22)?.try_into().ok()?)).ok()?;
    let height = usize::try_from(u32::from_le_bytes(bitmap.get(22..26)?.try_into().ok()?)).ok()?;
    if u16::from_le_bytes(bitmap.get(28..30)?.try_into().ok()?) != 24 {
        return None;
    }
    let pixel_count = width.checked_mul(height)?;
    let pixel_bytes = pixel_count.checked_mul(3)?;
    let available = bitmap.get(offset..)?;
    let pixels = available.get(..pixel_bytes)?;
    let mut bytes = pixels.chunks_exact(8).map(hidden_byte);
    let embedded_identifier =
        u32::from_le_bytes([bytes.next()?, bytes.next()?, bytes.next()?, bytes.next()?]);
    let length = usize::from(bytes.next()?);
    if embedded_identifier != identifier
        || length == 0
        || length > pixel_count.checked_sub(5)?
        || pixels.len() < 5usize.checked_add(length)?.checked_mul(8)?
    {
        return None;
    }
    Some((identifier, pixels, length))
}

fn hidden_byte(bits: &[u8]) -> u8 {
    bits.iter().fold(0, |byte, bit| (byte << 1) | (bit & 1))
}

pub(crate) struct Heartbeat {
    identifier: Option<Bytes>,
    sequence: u64,
    deadline: Option<Instant>,
    interval_seconds: u32,
    candidate_interval_seconds: u32,
    pub(super) material: Option<TaskMaterial>,
    material_account: Option<u64>,
    generator: super::task11::Generator,
}

impl Default for Heartbeat {
    fn default() -> Self {
        Self {
            identifier: None,
            sequence: 0,
            deadline: None,
            interval_seconds: INTERVAL.as_secs() as u32,
            candidate_interval_seconds: 0,
            material: None,
            material_account: None,
            generator: super::task11::Generator::default(),
        }
    }
}

impl Heartbeat {
    pub(crate) fn reset(&mut self) {
        self.identifier = None;
        self.sequence = 0;
        self.deadline = None;
        self.interval_seconds = INTERVAL.as_secs() as u32;
        self.candidate_interval_seconds = 0;
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

    fn bind_material_account(&mut self, account: u64) {
        if self
            .material_account
            .is_some_and(|previous| previous != account)
        {
            self.material = None;
        }
        self.material_account = Some(account);
    }

    fn update_material(&mut self, payload: &[u8]) {
        let current_identifier = self
            .material
            .as_ref()
            .map_or(0, |material| material.identifier);
        let Some((identifier, pixels, length)) = material_payload(payload, current_identifier)
        else {
            return;
        };
        let cache = self.material.get_or_insert_with(TaskMaterial::default);
        cache.material.clear();
        cache
            .material
            .extend(pixels.chunks_exact(8).skip(5).take(length).map(hidden_byte));
        let prefix_length = length.min(cache.prefix.len());
        cache.prefix[..prefix_length].copy_from_slice(&cache.material[..prefix_length]);
        cache.identifier = identifier;
    }

    fn update_material_word(&mut self, payload: &[u8]) {
        let Ok(word) = <[u8; 4]>::try_from(payload) else {
            return;
        };
        self.material.get_or_insert_with(TaskMaterial::default).word = u32::from_le_bytes(word);
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
            rand::rngs::SysRng
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
        self.bind_material_account(state.keystore.uin);
        let mut reports = vec![Work::Report(
            signer.channel_report(
                "taskAck",
                pb::TaskAckRequest {
                    header: Some(header.clone()),
                    identifier: response.identifier.clone(),
                }
                .encode_to_vec(),
            ),
        )];
        let mut results = Vec::new();
        let mut jobs = Vec::new();
        for task in response.tasks {
            let body = match task.kind {
                5 => {
                    self.update_material(&task.payload);
                    Vec::new()
                }
                6 => {
                    let Some(value) = task.payload.get(..4) else {
                        tracing::warn!(
                            task_kind = task.kind,
                            "O3 interval task payload is too short"
                        );
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
                10 => {
                    self.update_material_word(&task.payload);
                    Vec::new()
                }
                11 if task.payload.is_empty() => Vec::new(),
                11 => {
                    let cache = self.material.get_or_insert_with(TaskMaterial::default);
                    match self.generator.prepare(task.payload, cache) {
                        Ok(job) => {
                            jobs.push((results.len(), job));
                            results.push(pb::TaskResult {
                                identifier: task.identifier,
                                body: Bytes::new(),
                            });
                        }
                        Err(error) => {
                            tracing::warn!(%error, task_kind = task.kind, "O3 calculation task could not be prepared");
                        }
                    }
                    continue;
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
            let report = TaskReport {
                binding: signer.channel_report("taskReport", Vec::new()),
                header,
                identifier: response.identifier,
                results,
                jobs,
            };
            if !report.jobs.is_empty() {
                reports.push(Work::Compute(report));
            } else if let Some(report) = report.execute() {
                reports.push(Work::Report(report));
            }
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
                    Work::Compute(report) => {
                        if let Some(report) = report.execute() {
                            reports.push(report);
                        }
                    }
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

    fn bitmap_payload(outer_identifier: u32, inner_identifier: u32, material: &[u8]) -> Vec<u8> {
        let mut hidden = inner_identifier.to_le_bytes().to_vec();
        hidden.push(u8::try_from(material.len()).unwrap());
        hidden.extend_from_slice(material);
        let width = (hidden.len() * 8).div_ceil(3);
        let offset = 61;
        let mut bitmap = vec![0xa4; offset + width * 3];
        bitmap[..2].copy_from_slice(b"BM");
        bitmap[10..14].copy_from_slice(&(offset as u32).to_le_bytes());
        bitmap[18..22].copy_from_slice(&(width as u32).to_le_bytes());
        bitmap[22..26].copy_from_slice(&1u32.to_le_bytes());
        bitmap[28..30].copy_from_slice(&24u16.to_le_bytes());
        for (index, byte) in hidden.into_iter().enumerate() {
            for bit in 0..8 {
                bitmap[offset + index * 8 + bit] |= (byte >> (7 - bit)) & 1;
            }
        }
        let mut payload = outer_identifier.to_be_bytes().to_vec();
        payload.extend_from_slice(&(bitmap.len() as u16).to_be_bytes());
        payload.extend_from_slice(&bitmap);
        payload
    }

    fn calculation_tlv(body: &[u8], expected: u16) -> &[u8] {
        assert_eq!(body.len(), 215);
        let mut fields = &body[37..203];
        while !fields.is_empty() {
            let tag = u16::from_be_bytes(fields[..2].try_into().unwrap());
            let length = usize::from(u16::from_be_bytes(fields[2..4].try_into().unwrap()));
            if tag == expected {
                return &fields[4..4 + length];
            }
            fields = &fields[4 + length..];
        }
        panic!("missing calculation field {expected}");
    }

    #[tokio::test(start_paused = true)]
    async fn empty_calculation_reports_without_allocating_material_or_executing_server_programs() {
        let mut fixture = Fixture::new();
        let work = fixture.work(vec![
            task(4, b"server-program", b"return 1".to_vec()),
            task(11, b"empty-calculation", Vec::new()),
        ]);
        assert!(fixture.heartbeat.material.is_none());
        let mut reports = work.into_iter().map(|work| match work {
            Work::Report(report) => report,
            Work::Compute(_) => panic!("empty calculation must not schedule blocking work"),
            Work::RotatePeer { .. } => panic!("batch must not rotate peers"),
        });
        assert_eq!(reports.next().unwrap().method, "taskAck");
        let report = reports.next().unwrap();
        assert_eq!(report.method, "taskReport");
        let report = pb::TaskReportRequest::decode(report.body.as_slice()).unwrap();
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].identifier.as_ref(), b"empty-calculation");
        assert!(report.results[0].body.is_empty());
        assert!(reports.next().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn calculation_jobs_preserve_result_order_and_snapshot_preceding_material_and_word() {
        let mut fixture = Fixture::new();
        let reports = fixture.complete(vec![
            task(11, b"empty-first", Vec::new()),
            task(10, b"first-word", 0x1234_5678u32.to_le_bytes().to_vec()),
            task(5, b"first-material", bitmap_payload(1, 1, b"ABCDEFGH")),
            task(11, b"first-calculation", b"synthetic payload".to_vec()),
            task(4, b"server-program", b"return 1".to_vec()),
            task(10, b"second-word", 0x90ab_cdefu32.to_le_bytes().to_vec()),
            task(5, b"second-material", bitmap_payload(2, 2, b"XY")),
            task(11, b"second-calculation", b"synthetic payload".to_vec()),
            task(11, b"empty-last", Vec::new()),
        ]);
        assert_eq!(
            reports.iter().map(|report| report.method.as_str()).collect::<Vec<_>>(),
            ["taskAck", "taskReport"]
        );
        let report = pb::TaskReportRequest::decode(reports[1].body.as_slice()).unwrap();
        assert_eq!(
            report.results.iter().map(|result| result.identifier.as_ref()).collect::<Vec<_>>(),
            [
                b"empty-first".as_slice(),
                b"first-word".as_slice(),
                b"first-material".as_slice(),
                b"first-calculation".as_slice(),
                b"second-word".as_slice(),
                b"second-material".as_slice(),
                b"second-calculation".as_slice(),
                b"empty-last".as_slice(),
            ]
        );
        let first = &report.results[3].body;
        let second = &report.results[6].body;
        assert_eq!(&first[203..207], &1u32.to_be_bytes());
        assert_eq!(&second[203..207], &2u32.to_be_bytes());
        assert_eq!(&first[211..215], &0x1234_5678u32.to_le_bytes());
        assert_eq!(&second[211..215], &0x90ab_cdefu32.to_le_bytes());
        assert_eq!(
            &calculation_tlv(first, 11)[8..],
            &crate::crypto::md5(b"ABCDEFGH")[..8]
        );
        assert_eq!(
            &calculation_tlv(second, 11)[8..],
            &crate::crypto::md5(b"XY")[..8]
        );
        assert_eq!(&calculation_tlv(first, 11)[..8], &calculation_tlv(second, 11)[..8]);
        let runtime = fixture.heartbeat.material.as_ref().unwrap().runtime;
        assert_eq!(&first[207..211], &runtime[..4]);
        assert_eq!(&second[207..211], &runtime[..4]);
        for (index, result) in report.results.iter().enumerate() {
            if index != 3 && index != 6 {
                assert!(result.body.is_empty());
            }
        }
        fixture.heartbeat.reset();
        fixture.heartbeat.configure(true);
        fixture.due().unwrap();
        let reports = fixture.complete(vec![task(11, b"after-reset", vec![1])]);
        let report = pb::TaskReportRequest::decode(reports[1].body.as_slice()).unwrap();
        assert_eq!(&report.results[0].body[207..211], &runtime[..4]);
        assert_eq!(&report.results[0].body[203..207], &2u32.to_be_bytes());
        assert_eq!(&report.results[0].body[211..215], &0x90ab_cdefu32.to_le_bytes());
    }

    #[tokio::test(start_paused = true)]
    async fn material_task_decodes_mixed_endian_contiguous_lsb_pixels_and_empty_wire_result() {
        let mut fixture = Fixture::new();
        fixture.signer.drain_token_reports();
        let material: Vec<u8> = (0..=254).collect();
        let mut payload = bitmap_payload(0x1234_5678, 0x1234_5678, &material);
        payload[24..28].copy_from_slice(&2u32.to_le_bytes());
        payload[28..32].copy_from_slice(&347u32.to_le_bytes());
        payload.extend_from_slice(b"permitted outer trailing bytes");
        let reports = fixture.complete(vec![task(5, b"material", payload)]);
        assert_eq!(
            reports
                .iter()
                .map(|report| report.method.as_str())
                .collect::<Vec<_>>(),
            ["taskAck", "taskReport"]
        );
        let report = pb::TaskReportRequest::decode(reports[1].body.as_slice()).unwrap();
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].identifier.as_ref(), b"material");
        assert!(report.results[0].body.is_empty());
        let cache = fixture.heartbeat.material.as_ref().unwrap();
        assert_eq!(cache.identifier, 0x1234_5678);
        assert_eq!(cache.material, material);
        assert_eq!(cache.prefix, [0, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(cache.word, 0);
        assert_eq!(cache.runtime, [0; 8]);
        assert!(fixture.signer.drain_token_reports().is_empty());
    }

    #[test]
    fn material_cache_deduplicates_and_preserves_short_prefix_word_and_runtime() {
        let mut heartbeat = Heartbeat::default();
        heartbeat.update_material_word(&0x1234_5678u32.to_le_bytes());
        heartbeat.material.as_mut().unwrap().runtime = *b"runtime8";
        heartbeat.update_material(&bitmap_payload(1, 1, b"ABCDEFGH"));
        heartbeat.update_material(&bitmap_payload(1, 1, b"ignored duplicate"));
        assert_eq!(heartbeat.material.as_ref().unwrap().material, b"ABCDEFGH");
        heartbeat.update_material(&bitmap_payload(2, 3, b"mismatched identifier"));
        assert_eq!(heartbeat.material.as_ref().unwrap().identifier, 1);
        heartbeat.update_material(&bitmap_payload(2, 2, b"XY"));
        assert_eq!(
            heartbeat.material.as_ref().unwrap(),
            &TaskMaterial {
                identifier: 2,
                prefix: *b"XYCDEFGH",
                material: b"XY".to_vec(),
                word: 0x1234_5678,
                runtime: *b"runtime8",
            }
        );
        heartbeat.update_material_word(&[0, 0, 0, 1]);
        let cache = heartbeat.material.as_ref().unwrap();
        assert_eq!(cache.word, 0x0100_0000);
        assert_eq!(cache.material, b"XY");
        assert_eq!(cache.prefix, *b"XYCDEFGH");
        assert_eq!(cache.runtime, *b"runtime8");
    }

    #[test]
    fn invalid_material_never_allocates_or_changes_existing_cache() {
        let mut empty = Heartbeat::default();
        empty.update_material(&bitmap_payload(0, 0, b"initial identifier is already zero"));
        assert!(empty.material.is_none());
        let payload = bitmap_payload(0x1234_5678, 0x1234_5678, b"abcdefgh");
        let mut invalid = (0..payload.len())
            .map(|length| payload[..length].to_vec())
            .collect::<Vec<_>>();
        invalid.push(bitmap_payload(2, 3, b"mismatch"));
        invalid.push(bitmap_payload(2, 2, b""));
        invalid.push(bitmap_payload(0x1234_5678, 0x7856_3412, b"abcdefgh"));
        let mut bad_signature = payload.clone();
        bad_signature[6] = b'X';
        invalid.push(bad_signature);
        let mut short_header = payload.clone();
        short_header[4..6].copy_from_slice(&53u16.to_be_bytes());
        invalid.push(short_header);
        let mut bad_depth = payload.clone();
        bad_depth[34..36].copy_from_slice(&32u16.to_be_bytes());
        invalid.push(bad_depth);
        let mut bad_offset = payload.clone();
        bad_offset[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        invalid.push(bad_offset);
        let mut overflow_dimensions = payload.clone();
        overflow_dimensions[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
        overflow_dimensions[28..32].copy_from_slice(&u32::MAX.to_le_bytes());
        invalid.push(overflow_dimensions);
        let mut insufficient_pixels = payload.clone();
        insufficient_pixels[24..28].copy_from_slice(&34u32.to_le_bytes());
        invalid.push(insufficient_pixels);
        let mut insufficient_capacity = payload.clone();
        insufficient_capacity[24..28].copy_from_slice(&12u32.to_le_bytes());
        invalid.push(insufficient_capacity);
        let mut zero_dimensions = payload.clone();
        zero_dimensions[28..32].copy_from_slice(&0u32.to_le_bytes());
        invalid.push(zero_dimensions);
        let mut wrong_outer_endian = payload.clone();
        wrong_outer_endian[..4].reverse();
        invalid.push(wrong_outer_endian);
        for payload in invalid {
            let mut heartbeat = Heartbeat::default();
            heartbeat.update_material(&payload);
            assert!(heartbeat.material.is_none());
            heartbeat.update_material(&bitmap_payload(1, 1, b"preserve"));
            heartbeat.update_material(&payload);
            assert_eq!(heartbeat.material.as_ref().unwrap().identifier, 1);
            assert_eq!(heartbeat.material.as_ref().unwrap().material, b"preserve");
        }
    }

    #[test]
    fn material_declared_length_limits_hidden_bits_even_with_outer_trailing_bytes() {
        let mut heartbeat = Heartbeat::default();
        let mut payload = bitmap_payload(9, 9, b"XY");
        let length = u16::from_be_bytes(payload[4..6].try_into().unwrap());
        payload[4..6].copy_from_slice(&(length - 2).to_be_bytes());
        heartbeat.update_material(&payload);
        assert!(heartbeat.material.is_none());
        payload[4..6].copy_from_slice(&length.to_be_bytes());
        heartbeat.update_material(&payload);
        assert_eq!(heartbeat.material.as_ref().unwrap().material, b"XY");
    }

    #[test]
    fn material_word_requires_exactly_four_bytes_without_requiring_a_material_identifier() {
        let mut heartbeat = Heartbeat::default();
        for length in [0, 1, 2, 3, 5] {
            heartbeat.update_material_word(&vec![0xff; length]);
            assert!(heartbeat.material.is_none());
        }
        heartbeat.update_material_word(&[1, 0, 0, 0]);
        let cache = heartbeat.material.as_ref().unwrap();
        assert_eq!(cache.identifier, 0);
        assert!(cache.material.is_empty());
        assert_eq!(cache.prefix, [0; 8]);
        assert_eq!(cache.word, 1);
        heartbeat.update_material(&bitmap_payload(0, 0, b"duplicate zero identifier"));
        assert!(heartbeat.material.as_ref().unwrap().material.is_empty());
        for length in [0, 3, 5] {
            heartbeat.update_material_word(&vec![0xff; length]);
            assert_eq!(heartbeat.material.as_ref().unwrap().word, 1);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn malformed_material_tasks_keep_empty_results_and_following_batch_work_in_order() {
        let mut fixture = Fixture::new();
        let reports = fixture.complete(vec![
            task(5, b"bad-material", vec![0]),
            task(10, b"short-word", vec![1, 2, 3]),
            task(10, b"word", vec![1, 0, 0, 0]),
            task(5, b"material", bitmap_payload(5, 5, b"abcdefgh")),
            task(7, b"token", Vec::new()),
            task(9, b"rotation", encoded_generator(2)),
            task(6, b"interval", 90u32.to_be_bytes().to_vec()),
            task(10, b"long-word", vec![0xff; 5]),
            task(5, b"short-material", bitmap_payload(6, 6, b"XY")),
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
                b"bad-material".as_slice(),
                b"short-word".as_slice(),
                b"word".as_slice(),
                b"material".as_slice(),
                b"token".as_slice(),
                b"rotation".as_slice(),
                b"interval".as_slice(),
                b"long-word".as_slice(),
                b"short-material".as_slice(),
            ]
        );
        assert!(report.results.iter().all(|result| result.body.is_empty()));
        assert_eq!(fixture.heartbeat.candidate_interval_seconds, 90);
        let cache = fixture.heartbeat.material.as_ref().unwrap();
        assert_eq!(cache.identifier, 6);
        assert_eq!(cache.material, b"XY");
        assert_eq!(cache.prefix, *b"XYcdefgh");
        assert_eq!(cache.word, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn material_survives_batches_channel_rotation_and_reset_but_not_an_account_change() {
        let mut fixture = Fixture::new();
        fixture.complete(vec![
            task(5, b"material", bitmap_payload(1, 1, b"ABCDEFGH")),
            task(10, b"word", vec![1, 0, 0, 0]),
        ]);
        fixture.heartbeat.material.as_mut().unwrap().runtime = *b"runtime8";
        fixture.complete(vec![task(9, b"rotation", encoded_generator(2))]);
        fixture.heartbeat.reset();
        fixture.heartbeat.configure(true);
        fixture.due().unwrap();
        fixture.complete(vec![task(5, b"short", bitmap_payload(2, 2, b"XY"))]);
        let cache = fixture.heartbeat.material.as_ref().unwrap();
        assert_eq!(cache.identifier, 2);
        assert_eq!(cache.prefix, *b"XYCDEFGH");
        assert_eq!(cache.word, 1);
        assert_eq!(cache.runtime, *b"runtime8");
        fixture.state.keystore.uin += 1;
        fixture.complete(vec![task(10, b"invalid-after-account-change", Vec::new())]);
        assert!(fixture.heartbeat.material.is_none());
        fixture.complete(vec![task(5, b"new-account", bitmap_payload(2, 2, b"Z"))]);
        let cache = fixture.heartbeat.material.as_ref().unwrap();
        assert_eq!(cache.identifier, 2);
        assert_eq!(cache.prefix, [b'Z', 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(cache.word, 0);
        assert_eq!(cache.runtime, [0; 8]);
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
            reports
                .iter()
                .map(|report| report.method.as_str())
                .collect::<Vec<_>>(),
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
        fixture
            .channel
            .prepare("heartbeat", Bytes::new(), 0)
            .unwrap();
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
                Work::Compute(_) => panic!("rotation-only batch must not defer calculation"),
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
        let request = fixture
            .channel
            .prepare("heartbeat", Bytes::new(), 0)
            .unwrap();
        let request = pb::EstablishShareKeyRequest::decode(request.body).unwrap();
        assert_eq!(
            request.key_identifier.as_ref(),
            hex::encode(final_peer).as_bytes()
        );
        tokio::time::advance(INTERVAL).await;
        assert_eq!(fixture.due().unwrap().interval_seconds, 120);
    }

    #[tokio::test(start_paused = true)]
    async fn every_short_rotation_is_isolated_without_resetting_an_inflight_channel() {
        let mut fixture = Fixture::new();
        let peer = encoded_generator(2);
        fixture.complete(vec![task(9, b"valid", peer.clone())]);
        fixture
            .channel
            .prepare("heartbeat", Bytes::new(), 0)
            .unwrap();
        let reports = fixture.complete(
            (0..33)
                .map(|length| task(9, b"short", vec![0xff; length]))
                .collect(),
        );
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].method, "taskAck");
        assert!(fixture.channel.is_establishing());
        let request = fixture
            .channel
            .prepare("heartbeat", Bytes::new(), 0)
            .unwrap();
        let request = pb::EstablishShareKeyRequest::decode(request.body).unwrap();
        assert_eq!(
            request.key_identifier.as_ref(),
            hex::encode(peer).as_bytes()
        );
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
            fixture
                .heartbeat
                .complete(
                    pb::HeartbeatResponse::default().encode_to_vec().into(),
                    &fixture.state,
                    &mut fixture.signer,
                )
                .unwrap()
                .is_empty()
        );
        assert!(
            fixture
                .heartbeat
                .complete(
                    Bytes::from_static(b"\xff"),
                    &fixture.state,
                    &mut fixture.signer,
                )
                .is_err()
        );
    }
}
