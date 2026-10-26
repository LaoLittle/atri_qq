use crate::{
    Error, Result,
    proto::{contacts::OidbEnvelope, file_transfer as pb},
};
use bytes::Bytes;
use prost::Message;
use std::{fmt, sync::Arc, time::Duration};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

pub(crate) const COMMAND: &str = "OidbSvcTrpcTcp.0x9a2_8";

#[derive(Clone)]
pub struct FileTransferTicket {
    sign: Bytes,
    expires: Instant,
}

impl FileTransferTicket {
    pub fn sign(&self) -> &[u8] {
        &self.sign
    }

    pub fn remaining_lifetime(&self) -> Duration {
        self.expires.saturating_duration_since(Instant::now())
    }
}

impl fmt::Debug for FileTransferTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("FileTransferTicket").finish_non_exhaustive()
    }
}

pub(crate) struct Binding {
    pub(crate) generation: u64,
    pub(crate) uin: u64,
    pub(crate) uid: String,
    pub(crate) cancel: CancellationToken,
    scope_cancel: CancellationToken,
    a2: Bytes,
    machine_guid: [u8; 16],
}

impl Binding {
    pub(crate) fn new(
        generation: u64,
        uin: u64,
        uid: String,
        a2: Bytes,
        machine_guid: [u8; 16],
        cancel: &CancellationToken,
    ) -> Result<Self> {
        if uin == 0 || u32::try_from(uin).is_err() || uid.is_empty() || a2.is_empty() {
            return Err(Error::Authentication("Incomplete file transfer credential identity".into()));
        }
        if cancel.is_cancelled() {
            return Err(Error::Disconnected);
        }
        Ok(Self {
            generation,
            uin,
            uid,
            cancel: cancel.child_token(),
            a2,
            machine_guid,
            scope_cancel: cancel.clone(),
        })
    }

    fn same_identity(&self, other: &Self) -> bool {
        self.generation == other.generation
            && self.uin == other.uin
            && self.uid == other.uid
            && self.a2 == other.a2
            && self.machine_guid == other.machine_guid
            && self.scope_cancel == other.scope_cancel
    }
}

impl fmt::Debug for Binding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("FileTransferBinding").finish_non_exhaustive()
    }
}

pub(crate) struct Session {
    pub(crate) binding: Arc<Binding>,
}

impl fmt::Debug for Session {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("FileTransferSession").finish_non_exhaustive()
    }
}

pub(crate) struct Response {
    sign: Bytes,
    lifetime_seconds: u64,
}

impl fmt::Debug for Response {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("FileTransferResponse").finish_non_exhaustive()
    }
}

#[derive(Default)]
pub(crate) struct Cache {
    binding: Option<Arc<Binding>>,
    ticket: Option<FileTransferTicket>,
    enabled: bool,
    due: Option<Instant>,
    pending: Option<Arc<Session>>,
}

impl Cache {
    pub(crate) fn activate(&mut self, binding: Arc<Binding>) -> Result<Arc<Binding>> {
        if binding.cancel.is_cancelled() {
            return Err(Error::Disconnected);
        }
        if let Some(current) = self.binding.as_ref().filter(|current| {
            !current.cancel.is_cancelled() && current.same_identity(&binding)
        }) {
            return Ok(current.clone());
        }
        self.invalidate();
        self.binding = Some(binding.clone());
        Ok(binding)
    }

    pub(crate) fn invalidate(&mut self) {
        if let Some(binding) = self.binding.take() {
            binding.cancel.cancel();
        }
        self.ticket = None;
        self.enabled = false;
        self.due = None;
        self.pending = None;
    }

    pub(crate) fn binding(&self) -> Result<Arc<Binding>> {
        self.binding.as_ref()
            .filter(|binding| !binding.cancel.is_cancelled())
            .cloned()
            .ok_or(Error::Disconnected)
    }

    pub(crate) fn is_current(&self, binding: &Arc<Binding>) -> bool {
        !binding.cancel.is_cancelled()
            && self.binding.as_ref().is_some_and(|current| Arc::ptr_eq(current, binding))
    }

    pub(crate) fn cached(&self, now: Instant) -> Option<FileTransferTicket> {
        self.binding().ok()?;
        self.ticket.as_ref().filter(|ticket| ticket.expires > now).cloned()
    }

    pub(crate) fn enable(&mut self, now: Instant) -> Result<()> {
        self.binding()?;
        self.enabled = true;
        if self.pending.is_none() && self.cached(now).is_none() {
            self.due = Some(now);
        }
        Ok(())
    }

    pub(crate) fn next_due(&self) -> Option<Instant> {
        if self.enabled && self.pending.is_none() && self.binding().is_ok() {
            self.due
        } else {
            None
        }
    }

    pub(crate) fn take_due(&mut self, now: Instant) -> Result<Option<Arc<Session>>> {
        let binding = self.binding()?;
        if !self.enabled || self.pending.is_some() || !self.due.is_some_and(|due| due <= now) {
            return Ok(None);
        }
        let session = Arc::new(Session { binding });
        self.due = None;
        self.pending = Some(session.clone());
        Ok(Some(session))
    }

    pub(crate) fn apply(
        &mut self,
        session: &Arc<Session>,
        response: Result<Response>,
        now: Instant,
    ) -> Result<FileTransferTicket> {
        if !self.is_current(&session.binding)
            || !self.pending.as_ref().is_some_and(|pending| Arc::ptr_eq(pending, session))
        {
            return Err(Error::Disconnected);
        }
        self.pending = None;
        self.due = None;
        let response = response?;
        if response.sign.is_empty() || response.lifetime_seconds == 0 {
            return Err(Error::Malformed("Missing file transfer ticket or lifetime".into()));
        }
        let expires = now.checked_add(Duration::from_secs(response.lifetime_seconds))
            .ok_or_else(|| Error::Malformed("File transfer ticket lifetime exceeds clock range".into()))?;
        let interval = renewal_interval(response.lifetime_seconds);
        let due = now.checked_add(interval)
            .ok_or_else(|| Error::Malformed("File transfer renewal exceeds clock range".into()))?;
        let ticket = FileTransferTicket { sign: response.sign, expires };
        self.ticket = Some(ticket.clone());
        self.due = Some(due);
        Ok(ticket)
    }
}

fn renewal_interval(lifetime_seconds: u64) -> Duration {
    Duration::from_secs(if lifetime_seconds >= 3601 { lifetime_seconds >> 1 } else { 1800 })
}

pub(crate) fn build(session: &Session) -> Result<Bytes> {
    let binding = &session.binding;
    if binding.cancel.is_cancelled() {
        return Err(Error::Disconnected);
    }
    let body = pb::FileTransSignRequest {
        account: Some(binding.uin as u32),
        field2: Some(0x5f5e164f),
        a2: Some(binding.a2.clone()),
        field4: Some(0),
        machine_guid: Some(Bytes::copy_from_slice(&binding.machine_guid)),
    }.encode_to_vec();
    Ok(OidbEnvelope {
        command: Some(0x9a2),
        service: Some(8),
        body: Some(body.into()),
        reserved: Some(1),
        ..Default::default()
    }.encode_to_vec().into())
}

pub(crate) fn decode(bytes: Bytes) -> Result<Response> {
    let envelope: OidbEnvelope = crate::proto::decode(bytes)?;
    if envelope.command != Some(0x9a2)
        || envelope.service != Some(8)
    {
        return Err(Error::Malformed("Unexpected file transfer OIDB envelope".into()));
    }
    let code = envelope.code
        .ok_or_else(|| Error::Malformed("Missing file transfer OIDB result".into()))?;
    if code != 0 {
        return Err(Error::Server {
            code: code as i32,
            message: "File transfer credential request rejected".into(),
        });
    }
    let body = envelope.body.filter(|body| !body.is_empty())
        .ok_or_else(|| Error::Malformed("Missing file transfer response body".into()))?;
    let response: pb::FileTransSignResponse = crate::proto::decode(body)?;
    let ticket = response.ticket
        .ok_or_else(|| Error::Malformed("Missing file transfer ticket".into()))?;
    let sign = ticket.sign.filter(|sign| !sign.is_empty())
        .ok_or_else(|| Error::Malformed("Missing file transfer signature".into()))?;
    let lifetime_seconds = ticket.lifetime_seconds.filter(|lifetime| *lifetime != 0)
        .ok_or_else(|| Error::Malformed("Missing file transfer ticket lifetime".into()))?;
    Ok(Response { sign, lifetime_seconds })
}

#[cfg(test)]
mod tests;
