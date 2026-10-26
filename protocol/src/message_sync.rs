use crate::{
    Error, Result, SessionState,
    messages::{self, Conversation, Message},
    proto::{self, auth, message_sync as pb},
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
#[cfg(test)]
mod tests;

pub(crate) const INFO_COMMAND: &str = "trpc.msg.register_proxy.RegisterProxy.SsoInfoSync";
pub(crate) const INFO_PUSH: &str = "trpc.msg.register_proxy.RegisterProxy.InfoSyncPush";
pub(crate) const GROUP_COMMAND: &str = "trpc.msg.register_proxy.RegisterProxy.SsoSyncGroupMsg";
pub(crate) const GROUP_PUSH: &str = "trpc.msg.register_proxy.RegisterProxy.GroupMsgPush";
const FIRST_VIEW: u32 = 0x40c;
const TERMINAL_RESULT: u32 = 0x05f5e0ff;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GroupProgress {
    pub received_message_seq: u64,
    pub total_seq: u64,
    pub expired_message_seq: u64,
    pub expired_total_seq: u64,
    pub clear_message_seq: Option<u64>,
    pub clear_total_seq: Option<u64>,
    pub priority: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Checkpoint {
    pub account: u64,
    pub uid: String,
    pub current_cookie: Bytes,
    pub previous_cookie: Bytes,
    pub c2c_last_message_time: u64,
    pub group_last_message_time: u64,
    pub groups: BTreeMap<u64, GroupProgress>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    FirstView,
    GroupAdditional,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Batch {
    pub generation: u64,
    pub source: Source,
    pub messages: Vec<Message>,
    pub opaque_messages: Vec<Bytes>,
    pub group_results: Vec<pb::GroupMessageResult>,
    pub old_offline_message_flag: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub checkpoint: Checkpoint,
    pub batches: Vec<Arc<Batch>>,
    pub server_groups: Vec<pb::GroupNode>,
    pub first_view_complete: bool,
    pub additional_complete: bool,
    pub c2c_additional_complete: bool,
    pub group_additional_complete: bool,
    pub protocol_complete: bool,
    pub sent_flag: u32,
    pub initial_flag: u32,
    pub retry_mask: u32,
}

pub(crate) struct Binding {
    pub generation: u64,
    pub account: u64,
    pub uid: String,
    pub cancel: CancellationToken,
}

#[derive(Clone)]
pub(crate) struct Action {
    pub delay: Duration,
    kind: ActionKind,
}
#[derive(Clone)]
enum ActionKind {
    Info {
        revision: u64,
        flag: u32,
        replay: Option<auth::InfoSyncRequest>,
    },
    Group {
        revision: u64,
        request: pb::GroupSyncRequest,
    },
}
pub(crate) enum Request {
    Info {
        body: auth::InfoSyncRequest,
    },
    Group {
        revision: u64,
        body: pb::GroupSyncRequest,
    },
}

#[derive(Default)]
struct State {
    checkpoint: Checkpoint,
    batches: Vec<Arc<Batch>>,
    binding: Option<Arc<Binding>>,
    round: Option<Round>,
}
struct Round {
    template: auth::InfoSyncRequest,
    revision: u64,
    sent_flag: u32,
    initial_flag: u32,
    random: u32,
    last_random: u32,
    retry_mask: u32,
    retry_count: u32,
    retry_interval: u64,
    first_view: bool,
    protocol_complete: bool,
    candidate_current: Option<Bytes>,
    candidate_previous: Option<Bytes>,
    c2c_time: u64,
    group_time: u64,
    server_groups: BTreeMap<u64, pb::GroupNode>,
    pending: VecDeque<Candidate>,
    inflight: BTreeSet<u64>,
    group_random: u32,
    group_revision: u64,
    group_replenishment: usize,
    group_active: bool,
    c2c_done: bool,
    group_done: bool,
    registration: Option<Result<auth::InfoSyncRegisterResponse>>,
}
struct Candidate {
    node: pb::GroupNode,
    local: u64,
    total: u64,
    priority: bool,
    limit: Option<u32>,
    aio: Option<u32>,
}

#[derive(Clone, Copy)]
struct ReceivedGroupSequence {
    group_uin: u64,
    sequence: u64,
    total_sequence: u64,
    field_30: bool,
    message_id: u64,
}

impl ReceivedGroupSequence {
    fn compare(&self, other: &Self) -> std::cmp::Ordering {
        self.sequence
            .cmp(&other.sequence)
            .then_with(|| {
                if self.field_30 && other.field_30 {
                    self.total_sequence.cmp(&other.total_sequence)
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .then_with(|| self.message_id.cmp(&other.message_id))
    }
}

pub(crate) struct Coordinator {
    state: Mutex<State>,
    changed: watch::Sender<()>,
    guild: Arc<crate::guild::Session>,
}
impl Default for Coordinator {
    fn default() -> Self {
        Self::with_guild(Arc::new(crate::guild::Session::default()))
    }
}
impl Coordinator {
    pub fn with_guild(guild: Arc<crate::guild::Session>) -> Self {
        let (changed, _) = watch::channel(());
        Self {
            state: Mutex::new(State::default()),
            changed,
            guild,
        }
    }
    pub fn subscribe(&self) -> watch::Receiver<()> {
        self.changed.subscribe()
    }

    pub fn snapshot(&self) -> Snapshot {
        let state = self.state.lock().unwrap();
        let mut snapshot = Snapshot {
            checkpoint: state.checkpoint.clone(),
            batches: state.batches.clone(),
            ..Default::default()
        };
        if let Some(round) = &state.round {
            snapshot.server_groups = round.server_groups.values().cloned().collect();
            snapshot.first_view_complete = round.first_view;
            snapshot.c2c_additional_complete = round.c2c_done;
            snapshot.group_additional_complete = round.group_done;
            snapshot.additional_complete = round.c2c_done && round.group_done;
            snapshot.protocol_complete = round.protocol_complete;
            snapshot.sent_flag = round.sent_flag;
            snapshot.initial_flag = round.initial_flag;
            snapshot.retry_mask = round.retry_mask;
        }
        snapshot
    }

    pub fn replace_identity(&self, account: u64, uid: &str) {
        let mut state = self.state.lock().unwrap();
        if state.checkpoint.account != account || state.checkpoint.uid != uid {
            if let Some(binding) = state.binding.take() {
                binding.cancel.cancel();
            }
            *state = State {
                checkpoint: Checkpoint {
                    account,
                    uid: uid.into(),
                    ..Default::default()
                },
                ..Default::default()
            };
            self.changed.send_replace(());
        }
    }

    pub fn restore(&self, checkpoint: Checkpoint, account: u64, uid: &str) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        if state.binding.is_some() || checkpoint.account != account || checkpoint.uid != uid {
            return Err(Error::Authentication(
                "Message checkpoint does not match an inactive account".into(),
            ));
        }
        state.checkpoint = checkpoint;
        state.batches.clear();
        self.changed.send_replace(());
        Ok(())
    }

    pub fn begin(
        &self,
        generation: u64,
        session: &SessionState,
        cancel: &CancellationToken,
        template: auth::InfoSyncRequest,
    ) -> (Arc<Binding>, Action) {
        self.replace_identity(session.keystore.uin, &session.keystore.uid);
        let mut state = self.state.lock().unwrap();
        if let Some(previous) = state.binding.take() {
            previous.cancel.cancel();
        }
        let binding = Arc::new(Binding {
            generation,
            account: session.keystore.uin,
            uid: session.keystore.uid.clone(),
            cancel: cancel.child_token(),
        });
        state.binding = Some(binding.clone());
        state.round = Some(Round {
            template,
            revision: 1,
            sent_flag: 1759,
            initial_flag: 1759,
            random: 0,
            last_random: 0,
            retry_mask: 0,
            retry_count: 0,
            retry_interval: 30,
            first_view: false,
            protocol_complete: false,
            candidate_current: None,
            candidate_previous: None,
            c2c_time: state.checkpoint.c2c_last_message_time,
            group_time: state.checkpoint.group_last_message_time,
            server_groups: BTreeMap::new(),
            pending: VecDeque::new(),
            inflight: BTreeSet::new(),
            group_random: 0,
            group_revision: 0,
            group_replenishment: 50,
            group_active: false,
            c2c_done: false,
            group_done: false,
            registration: None,
        });
        self.guild.begin(generation, 0);
        self.changed.send_replace(());
        (
            binding,
            Action {
                delay: Duration::ZERO,
                kind: ActionKind::Info {
                    revision: 1,
                    flag: 1759,
                    replay: None,
                },
            },
        )
    }

    pub fn close(&self, generation: u64) {
        let mut state = self.state.lock().unwrap();
        if state
            .binding
            .as_ref()
            .is_some_and(|binding| binding.generation == generation)
        {
            state.binding.take().unwrap().cancel.cancel();
            state.round = None;
            self.changed.send_replace(());
        }
    }

    pub fn current(&self, binding: &Arc<Binding>) -> bool {
        current(&self.state.lock().unwrap(), binding)
    }

    pub fn registration(
        &self,
        binding: &Arc<Binding>,
    ) -> Result<Option<Result<auth::InfoSyncRegisterResponse>>> {
        let state = self.state.lock().unwrap();
        if !current(&state, binding) {
            return Err(Error::Disconnected);
        }
        Ok(state
            .round
            .as_ref()
            .and_then(|round| round.registration.clone()))
    }

    pub fn prepare(&self, binding: &Arc<Binding>, action: Action) -> Option<Request> {
        let mut state = self.state.lock().unwrap();
        if !current(&state, binding) {
            return None;
        }
        let State {
            checkpoint, round, ..
        } = &mut *state;
        let round = round.as_mut()?;
        match action.kind {
            ActionKind::Info {
                revision,
                flag,
                replay,
            } => {
                if round.revision != revision {
                    return None;
                }
                if flag == 1759 && revision > 1 && replay.is_none() {
                    round.first_view = false;
                    round.protocol_complete = false;
                    round.candidate_current = None;
                    round.candidate_previous = None;
                    round.c2c_time = checkpoint.c2c_last_message_time;
                    round.group_time = checkpoint.group_last_message_time;
                    round.server_groups.clear();
                    round.pending.clear();
                    round.inflight.clear();
                    round.group_random = 0;
                    round.group_active = false;
                    round.c2c_done = false;
                    round.group_done = false;
                }
                let mut body = replay.unwrap_or_else(|| {
                    let mut body = round.template.clone();
                    body.group_last_message_time = Some(checkpoint.group_last_message_time);
                    body.sync = Some(auth::SyncState {
                        current_cookie: Some(checkpoint.current_cookie.clone()),
                        previous_cookie: Some(checkpoint.previous_cookie.clone()),
                        last_message_time: Some(checkpoint.c2c_last_message_time),
                    });
                    body
                });
                let mut random = new_random();
                while random == round.last_random {
                    random = new_random();
                }
                round.random = random;
                round.last_random = random;
                round.sent_flag = flag;
                round.retry_mask = 0;
                body.sync_flag = Some(flag);
                body.request_random = Some(round.random);
                if flag & 0x40 == 0 {
                    body.register = None;
                }
                self.guild
                    .set_request_random(binding.generation, round.random);
                Some(Request::Info { body })
            }
            ActionKind::Group { revision, request } => {
                if round.group_revision != revision
                    || !round.group_active
                    || round.group_random != request.request_random.unwrap_or_default()
                {
                    return None;
                }
                Some(Request::Group {
                    revision,
                    body: request,
                })
            }
        }
    }

    pub fn direct(
        &self,
        binding: &Arc<Binding>,
        request: &Request,
        result: Result<Bytes>,
    ) -> Vec<Action> {
        let mut state = self.state.lock().unwrap();
        if !current(&state, binding) {
            return Vec::new();
        }
        let State {
            checkpoint, round, ..
        } = &mut *state;
        let round = round.as_mut().unwrap();
        let mut actions = Vec::new();
        match request {
            Request::Info { body } => {
                match result.and_then(proto::decode::<auth::InfoSyncResponse>) {
                    Ok(response) => {
                        if let Some(count) = response.group_replenishment {
                            round.group_replenishment =
                                if count == 0 { 50 } else { count as usize };
                        }
                        if let Some(delay) = &response.delay {
                            if delay.field_1.unwrap_or_default() != 0 {
                                round.revision += 1;
                                round.random = 0;
                                actions.push(Action {
                                    delay: Duration::from_secs(
                                        u64::from(delay.field_2.unwrap_or_default()).max(60),
                                    ),
                                    kind: ActionKind::Info {
                                        revision: round.revision,
                                        flag: body.sync_flag.unwrap_or_default(),
                                        replay: Some(body.clone()),
                                    },
                                });
                                return actions;
                            }
                        }
                        if response.result.unwrap_or_default() != 0 {
                            let error =
                                server_error(response.result.unwrap(), response.error.as_deref());
                            if response.result != Some(TERMINAL_RESULT) {
                                if let Some(action) =
                                    round.retry(body.sync_flag.unwrap_or_default())
                                {
                                    actions.push(action);
                                }
                            }
                            if actions.is_empty() {
                                round.fail_registration(error);
                                round.protocol_complete = true;
                            }
                        } else if crate::login::registration_confirmed(&response) {
                            round.registration = Some(Ok(response.register.unwrap()));
                        } else if body.register.is_some() {
                            round.fail_registration(Error::Authentication(
                                "InfoSync register response is missing".into(),
                            ));
                        }
                    }
                    Err(error) => {
                        if matches!(error, Error::Timeout | Error::Io(_) | Error::Server { .. }) {
                            if let Some(action) = round.retry(body.sync_flag.unwrap_or_default()) {
                                actions.push(action);
                            }
                        }
                        if actions.is_empty() {
                            round.fail_registration(error);
                            round.protocol_complete = true;
                        }
                    }
                }
            }
            Request::Group {
                revision,
                body: request,
            } => {
                if round.group_revision != *revision
                    || !round.group_active
                    || request.request_random != Some(round.group_random)
                {
                    return actions;
                }
                if let Ok(response) = result.and_then(proto::decode::<pb::GroupSyncResponse>) {
                    if response.request_random.unwrap_or_default() != round.group_random {
                        return actions;
                    }
                    match response.result.unwrap_or_default() {
                        0 => {}
                        TERMINAL_RESULT => {
                            round.pending.clear();
                            round.inflight.clear();
                            round.group_active = false;
                            round.group_done = true;
                        }
                        _ => {
                            round.inflight.clear();
                            if let Some(action) = round.next_group() {
                                actions.push(action);
                            }
                        }
                    }
                    if round.group_done {
                        round.commit(checkpoint);
                    }
                }
            }
        }
        self.changed.send_replace(());
        actions
    }

    pub fn ingest(
        &self,
        generation: u64,
        session: &SessionState,
        command: &str,
        body: Bytes,
    ) -> Result<(bool, Option<Arc<Binding>>, Vec<Action>)> {
        if command != INFO_PUSH && command != GROUP_PUSH {
            return Ok((true, None, Vec::new()));
        }
        let mut state = self.state.lock().unwrap();
        let Some(binding) = state.binding.clone() else {
            return Ok((false, None, Vec::new()));
        };
        if binding.generation != generation
            || binding.account != session.keystore.uin
            || binding.uid != session.keystore.uid
            || !current(&state, &binding)
        {
            return Ok((false, None, Vec::new()));
        }
        let State {
            checkpoint,
            batches,
            round,
            ..
        } = &mut *state;
        let round = round.as_mut().unwrap();
        let mut actions = Vec::new();
        if command == INFO_PUSH {
            let mut push: pb::InfoSyncPush = proto::decode(body)?;
            if round.random == 0 || push.request_random.unwrap_or_default() != round.random {
                return Ok((false, None, actions));
            }
            if let Err(error) = self.guild.ingest_info_push(generation, &push) {
                tracing::warn!(%error, "QQ guild synchronization push rejected");
            }
            let mut batch = Batch {
                generation,
                source: Source::FirstView,
                messages: Vec::new(),
                opaque_messages: Vec::new(),
                group_results: Vec::new(),
                old_offline_message_flag: None,
            };
            let mut received = Vec::new();
            if let Some(groups) = push.group_messages.take() {
                if groups.result.unwrap_or_default() == 0 {
                    for group in &groups.groups {
                        consume_group(group, session, &mut batch, &mut received)?;
                    }
                }
                batch.group_results = groups.groups;
            }
            if let Some(c2c) = &push.c2c_messages {
                batch.old_offline_message_flag = c2c.old_offline_message_flag;
                if c2c.result.unwrap_or_default() == 0 {
                    let mut conversations: Vec<_> = c2c.conversations.iter().collect();
                    conversations.sort_by_key(|node| node.last_message_time.unwrap_or_default());
                    for node in conversations {
                        for raw in &node.messages {
                            if let Some(sequence) = consume(raw, session, &mut batch)? {
                                received.push(sequence);
                            }
                        }
                    }
                }
            }
            batch.messages.sort_by_key(|message| message.time);
            if binding.cancel.is_cancelled() {
                return Ok((false, None, Vec::new()));
            }
            round.accept_batch(checkpoint, &batch, &received);
            if !batch.messages.is_empty()
                || !batch.opaque_messages.is_empty()
                || !batch.group_results.is_empty()
                || batch.old_offline_message_flag.is_some()
            {
                batches.push(Arc::new(batch));
            }
            if let Some(c2c) = push.c2c_messages {
                if c2c.result.unwrap_or_default() == 0 {
                    if let Some(cookie) = c2c.current_cookie {
                        round.candidate_current = Some(cookie);
                    }
                    if let Some(cookie) = c2c.previous_cookie {
                        round.candidate_previous = Some(cookie);
                    }
                }
            }
            let late = round.first_view;
            let mut new_nodes = Vec::new();
            for node in push.groups {
                if let Some(id) = node.group_uin.filter(|id| *id != 0) {
                    round.server_groups.insert(id, node.clone());
                    new_nodes.push(node);
                }
            }
            if late && !new_nodes.is_empty() {
                round.enqueue(checkpoint, new_nodes, false);
                if !round.group_active {
                    if let Some(action) = round.next_group() {
                        actions.push(action);
                    }
                }
            }
            round.retry_mask |= result_mask(push.result.unwrap_or_default(), round.sent_flag);
            let flag = round.sent_flag;
            let mask = round.retry_mask;
            let mut first_view = false;
            match push.stage.unwrap_or_default() {
                2 if flag & FIRST_VIEW != 0 && (mask == 0 || mask & FIRST_VIEW == 0) => {
                    first_view = true;
                    if mask == 0 {
                        round.retry_count = 0;
                        round.retry_interval = 30;
                    }
                }
                2 if flag & !mask == 0 => {
                    if let Some(action) = round.retry(mask) {
                        actions.push(action);
                    } else {
                        first_view = round.initial_flag & FIRST_VIEW != 0;
                        round.protocol_complete = true;
                    }
                }
                4 => {
                    if mask != 0 {
                        if let Some(action) = round.retry(mask) {
                            actions.push(action);
                        }
                    }
                    if actions
                        .iter()
                        .all(|action| !matches!(action.kind, ActionKind::Info { .. }))
                    {
                        round.protocol_complete = true;
                        if mask != 0 && round.initial_flag & FIRST_VIEW != 0 {
                            first_view = true;
                        }
                    }
                }
                _ => {}
            }
            if first_view && !round.first_view {
                round.first_view = true;
                round.commit(checkpoint);
                round.c2c_done = true;
                round.enqueue(
                    checkpoint,
                    round.server_groups.values().cloned().collect(),
                    true,
                );
                if let Some(action) = round.next_group() {
                    actions.push(action);
                }
            }
            if round.protocol_complete && round.first_view && round.group_done {
                round.commit(checkpoint);
            }
        } else {
            let push: pb::GroupMsgPush = proto::decode(body)?;
            if !round.group_active
                || round.group_random == 0
                || push.request_random.unwrap_or_default() != round.group_random
            {
                return Ok((false, None, actions));
            }
            let mut batch = Batch {
                generation,
                source: Source::GroupAdditional,
                messages: Vec::new(),
                opaque_messages: Vec::new(),
                group_results: Vec::new(),
                old_offline_message_flag: None,
            };
            let mut received = Vec::new();
            let had_groups = !push.groups.is_empty();
            for group in push.groups {
                if !round
                    .inflight
                    .contains(&group.group_uin.unwrap_or_default())
                {
                    continue;
                }
                consume_group(&group, session, &mut batch, &mut received)?;
                batch.group_results.push(group);
            }
            if had_groups && batch.group_results.is_empty() {
                return Ok((false, None, actions));
            }
            if binding.cancel.is_cancelled() {
                return Ok((false, None, Vec::new()));
            }
            round.accept_batch(checkpoint, &batch, &received);
            if !batch.messages.is_empty()
                || !batch.opaque_messages.is_empty()
                || !batch.group_results.is_empty()
            {
                batches.push(Arc::new(batch));
            }
            if push.flag == Some(2) {
                round.inflight.clear();
                if let Some(action) = round.next_group() {
                    actions.push(action);
                }
                if round.group_done {
                    round.commit(checkpoint);
                }
            }
        }
        self.changed.send_replace(());
        Ok((true, Some(binding), actions))
    }
}

impl Round {
    fn fail_registration(&mut self, error: Error) {
        if self.registration.is_none() {
            self.registration = Some(Err(error));
        }
    }
    fn retry(&mut self, flag: u32) -> Option<Action> {
        if flag == 0 {
            return None;
        }
        self.random = 0;
        let seconds = if self.retry_count == 0 {
            3
        } else if flag & 0x40 == 0 {
            self.retry_count = 0;
            self.retry_interval = 30;
            return None;
        } else {
            let seconds = self.retry_interval;
            self.retry_interval = (seconds + 30).min(300);
            seconds
        };
        self.retry_count += 1;
        self.revision += 1;
        Some(Action {
            delay: Duration::from_secs(seconds),
            kind: ActionKind::Info {
                revision: self.revision,
                flag,
                replay: None,
            },
        })
    }
    fn commit(&self, checkpoint: &mut Checkpoint) {
        checkpoint.c2c_last_message_time = checkpoint.c2c_last_message_time.max(self.c2c_time);
        checkpoint.group_last_message_time =
            checkpoint.group_last_message_time.max(self.group_time);
        if let Some(cookie) = &self.candidate_current {
            checkpoint.current_cookie = cookie.clone();
        }
        if let Some(cookie) = &self.candidate_previous {
            checkpoint.previous_cookie = cookie.clone();
        }
    }
    fn accept_batch(
        &mut self,
        checkpoint: &mut Checkpoint,
        batch: &Batch,
        received: &[ReceivedGroupSequence],
    ) {
        for message in &batch.messages {
            let time = message.time.max(0) as u64;
            if matches!(message.conversation, Conversation::Group { .. }) {
                self.group_time = self.group_time.max(time);
            } else {
                self.c2c_time = self.c2c_time.max(time);
            }
        }
        for record in received {
            let progress = checkpoint.groups.entry(record.group_uin).or_default();
            progress.received_message_seq = progress.received_message_seq.max(record.sequence);
            if record.total_sequence != 0 {
                progress.total_seq = progress.total_seq.max(record.total_sequence);
            }
        }
    }
    fn enqueue(&mut self, checkpoint: &Checkpoint, nodes: Vec<pb::GroupNode>, budget: bool) {
        let mut candidates: Vec<_> = nodes
            .into_iter()
            .filter_map(|node| candidate(node, checkpoint))
            .collect();
        candidates.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then_with(|| b.node.message_time.cmp(&a.node.message_time))
        });
        let merging = !self.pending.is_empty();
        for (index, mut candidate) in candidates.into_iter().enumerate() {
            if budget {
                let limit = if index < self.group_replenishment {
                    15
                } else {
                    1
                };
                candidate.limit = Some(limit);
                candidate.aio = None;
                if matches!(candidate.node.mask, Some(2 | 4)) && limit != 1 {
                    candidate.aio = Some(
                        if candidate
                            .node
                            .message_seq
                            .unwrap_or_default()
                            .saturating_sub(candidate.local)
                            < u64::from(limit)
                        {
                            2
                        } else {
                            1
                        },
                    );
                }
            }
            let id = candidate.node.group_uin.unwrap();
            if merging {
                if let Some(pending) = self
                    .pending
                    .iter_mut()
                    .find(|pending| pending.node.group_uin == Some(id))
                {
                    *pending = candidate;
                    continue;
                }
            }
            self.pending.push_back(candidate);
        }
        if !self.pending.is_empty() {
            self.group_done = false;
        }
    }
    fn next_group(&mut self) -> Option<Action> {
        self.inflight.clear();
        if self.pending.is_empty() {
            self.group_active = false;
            self.group_done = true;
            return None;
        }
        self.group_active = true;
        self.group_revision += 1;
        if self.group_random == 0 {
            self.group_random = new_random();
        }
        let mut groups = Vec::with_capacity(self.pending.len().min(100));
        for _ in 0..100 {
            let Some(candidate) = self.pending.pop_front() else {
                break;
            };
            self.inflight.insert(candidate.node.group_uin.unwrap());
            groups.push(candidate.range());
        }
        Some(Action {
            delay: Duration::ZERO,
            kind: ActionKind::Group {
                revision: self.group_revision,
                request: pb::GroupSyncRequest {
                    groups,
                    request_random: Some(self.group_random),
                    field_3: Some(1),
                },
            },
        })
    }
}
impl Candidate {
    fn range(self) -> pb::GroupRange {
        let mut range = pb::GroupRange {
            group_uin: self.node.group_uin,
            aio_message_count: self.aio,
            ..Default::default()
        };
        let limit = u64::from(self.limit.unwrap_or(30));
        let server = self.node.message_seq.unwrap_or_default();
        if server > self.local {
            range.begin_seq = Some((self.local + 1).max(server.saturating_sub(limit - 1)));
            range.end_seq = Some(server);
        }
        let total = self.node.total_seq.unwrap_or_default();
        if total > self.total {
            range.end_total_seq = Some(total);
            range.pull_system_message_count = Some((total - self.total).min(limit) as u32);
        }
        range
    }
}
fn candidate(node: pb::GroupNode, checkpoint: &Checkpoint) -> Option<Candidate> {
    let id = node.group_uin.filter(|id| *id != 0)?;
    if node.mask == Some(3)
        || node.all_message_expired == Some(true)
        || node.no_further_messages == Some(true)
    {
        return None;
    }
    let progress = checkpoint.groups.get(&id).cloned().unwrap_or_default();
    let server = node.message_seq.unwrap_or_default();
    let server_total = node.total_seq.unwrap_or_default();
    let mut local = progress.received_message_seq;
    let mut total = progress.total_seq;
    let ordinary = local < server
        && progress.expired_message_seq < server
        && progress
            .clear_message_seq
            .is_none_or(|clear| clear < server);
    let system = total < server_total
        && progress.expired_total_seq < server_total
        && progress
            .clear_total_seq
            .is_none_or(|clear| clear < server_total);
    if !ordinary && !system {
        return None;
    }
    if ordinary {
        if let Some(clear) = progress
            .clear_message_seq
            .filter(|clear| local <= *clear && *clear < server)
        {
            local = clear + 1;
        }
    } else {
        local = server;
    }
    if system {
        if let Some(clear) = progress
            .clear_total_seq
            .filter(|clear| total <= *clear && *clear < server_total)
        {
            total = clear + 1;
        }
    } else {
        total = server_total;
    }
    let aio = matches!(node.mask, Some(2 | 4)).then_some(2);
    Some(Candidate {
        node,
        local,
        total,
        priority: progress.priority,
        limit: None,
        aio,
    })
}
fn consume_group(
    group: &pb::GroupMessageResult,
    session: &SessionState,
    batch: &mut Batch,
    received: &mut Vec<ReceivedGroupSequence>,
) -> Result<()> {
    if group.result.unwrap_or_default() != 0 {
        return Ok(());
    }
    let mut tail: Option<ReceivedGroupSequence> = None;
    for raw in &group.messages {
        let start = batch.messages.len();
        let record = consume(raw, session, batch)?;
        if batch.messages[start..].iter().any(|message| !matches!(message.conversation, Conversation::Group { uin } if Some(uin) == group.group_uin)) {
            return Err(Error::Malformed("Synchronized message group does not match its result node".into()));
        }
        if let Some(record) = record {
            if tail
                .as_ref()
                .is_none_or(|current| record.compare(current).is_gt())
            {
                tail = Some(record);
            }
        }
    }
    if let Some(tail) = tail {
        received.push(tail);
    }
    Ok(())
}
fn consume(
    raw: &Bytes,
    session: &SessionState,
    batch: &mut Batch,
) -> Result<Option<ReceivedGroupSequence>> {
    let common: proto::messages::CommonMessage = proto::decode(raw.clone())?;
    let head = common
        .content_head
        .as_ref()
        .ok_or_else(|| Error::Malformed("Synchronized message lacks content head".into()))?;
    if !matches!(head.message_type, Some(82 | 166 | 141)) {
        batch.opaque_messages.push(raw.clone());
        return Ok(None);
    }
    let mut record = ReceivedGroupSequence {
        group_uin: 0,
        sequence: head.sequence.unwrap_or_default(),
        total_sequence: head.total_sequence.unwrap_or_default(),
        field_30: head.field_30.unwrap_or_default(),
        message_id: head.message_id.unwrap_or_default(),
    };
    let message = messages::parse_decoded_common_message(raw, common, session)?;
    let received = if let Conversation::Group { uin } = message.conversation {
        record.group_uin = uin;
        Some(record)
    } else {
        None
    };
    batch.messages.push(message);
    Ok(received)
}
fn current(state: &State, binding: &Arc<Binding>) -> bool {
    !binding.cancel.is_cancelled()
        && state
            .binding
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, binding))
}
fn new_random() -> u32 {
    (rand::random::<u32>() % (i32::MAX as u32 - 1)) + 1
}
fn server_error(result: u32, error: Option<&[u8]>) -> Error {
    Error::Server {
        code: result as i32,
        message: error
            .map(|error| String::from_utf8_lossy(error).into_owned())
            .unwrap_or_default(),
    }
}
pub(crate) fn result_mask(result: u32, flag: u32) -> u32 {
    match result {
        0x05f5e3bd..=0x05f5e3bf | 0x05f5e3cc..=0x05f5e3cd => flag,
        0x05f5e3c0 => 1,
        0x05f5e3c1 => 2,
        0x05f5e3c3..=0x05f5e3c7 | 0x05f5e3c9 => 4,
        0x05f5e3ca => 0x12,
        0x05f5e3cf => 0x200,
        _ => 0,
    }
}
