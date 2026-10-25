mod codec;
mod models;
mod query;
mod session;

pub use models::*;
pub(crate) use session::Session;

use crate::{Client, Error, IncomingPacket, Result, proto};
use bytes::Bytes;
use ciborium::Value;
use prost::Message;
use rand::Rng;
use std::sync::Arc;

pub const GUILD_METHODS: &[&str] = &[
    "synchronize",
    "guilds",
    "channels",
    "members",
    "send_message",
];
pub(crate) const PUSH_COMMAND: &str = "MsgPush.PushGroupProMsg";
pub(crate) const PUSH_RESPONSE_COMMAND: &str = "MsgPush.PushGroupProMsgRsp";
const SEND_COMMAND: &str = "MsgProxy.SendMsg";

#[derive(Clone)]
pub struct Guild {
    client: Arc<Client>,
    session: Arc<Session>,
}

struct QueryTransport<'a> {
    client: &'a Client,
    generation: u64,
}

impl query::Transport for QueryTransport<'_> {
    async fn request_d2(
        &self,
        command: &str,
        body: Bytes,
        timeout: std::time::Duration,
    ) -> Result<Bytes> {
        self.client
            .request_online(self.generation, command, body, timeout)
            .await
    }
}
impl Guild {
    pub fn new(client: Arc<Client>) -> Self {
        Self {
            session: client.guild_session.clone(),
            client,
        }
    }

    fn require_online(&self, generation: u64) -> Result<()> {
        if self.client.is_current_online(generation) {
            Ok(())
        } else {
            Err(Error::Disconnected)
        }
    }

    async fn ready(&self) -> Result<(u64, Option<u64>)> {
        let generation = self.client.connection_generation();
        self.require_online(generation)?;
        self.session
            .wait_ready(generation, self.client.config.timeout)
            .await?;
        self.require_online(generation)?;
        Ok((generation, self.session.tiny_id(generation)))
    }

    pub async fn synchronize(&self) -> Result<GuildSnapshot> {
        let (generation, _) = self.ready().await?;
        self.session.snapshot(generation)
    }

    pub async fn guilds(&self) -> Result<Vec<GuildInfo>> {
        let (generation, tiny_id) = self.ready().await?;
        let tiny_id = require_tiny_id(tiny_id)?;
        let transport = QueryTransport {
            client: &self.client,
            generation,
        };
        let result = query::guilds(&transport, tiny_id, self.client.config.timeout).await?;
        self.require_online(generation)?;
        Ok(result)
    }

    pub async fn channels(&self, guild_id: u64) -> Result<Vec<ChannelInfo>> {
        require_id(guild_id, "guild_id")?;
        let (generation, _) = self.ready().await?;
        let transport = QueryTransport {
            client: &self.client,
            generation,
        };
        let result = query::channels(&transport, guild_id, self.client.config.timeout).await?;
        self.require_online(generation)?;
        Ok(result)
    }

    pub async fn members(&self, guild_id: u64) -> Result<Vec<MemberInfo>> {
        require_id(guild_id, "guild_id")?;
        let (generation, _) = self.ready().await?;
        let transport = QueryTransport {
            client: &self.client,
            generation,
        };
        let result = query::members(&transport, guild_id, self.client.config.timeout).await?;
        self.require_online(generation)?;
        Ok(result)
    }

    pub async fn send_text(
        &self,
        guild_id: u64,
        channel_id: u64,
        text: &str,
    ) -> Result<SendReceipt> {
        require_id(guild_id, "guild_id")?;
        require_id(channel_id, "channel_id")?;
        if text.is_empty() {
            return Err(Error::Malformed(
                "Guild message text must not be empty".into(),
            ));
        }
        let (generation, tiny_id) = self.ready().await?;
        let tiny_id = require_tiny_id(tiny_id)?;
        let random = rand::thread_rng().gen_range(1..=i32::MAX as u64);
        let request = proto::guild::SendRequest {
            message: Some(proto::guild::SendMessage {
                head: Some(proto::guild::MessageHead {
                    routing: Some(proto::guild::RoutingHead {
                        guild_id: Some(guild_id),
                        channel_id: Some(channel_id),
                        sender_tiny_id: Some(tiny_id),
                        direct_message_flag: Some(0),
                        ..Default::default()
                    }),
                    content: Some(proto::guild::ContentHead {
                        message_type: Some(3840),
                        random: Some(random),
                        ..Default::default()
                    }),
                }),
                control: Some(proto::guild::MessageControlHead::default()),
                body: Some(codec::text_body(text)),
            }),
        };
        let response = self
            .client
            .request_online(
                generation,
                SEND_COMMAND,
                request.encode_to_vec().into(),
                self.client.config.timeout,
            )
            .await?;
        self.require_online(generation)?;
        decode_send_response(guild_id, channel_id, random, response)
    }

    pub async fn decode_push(&self, packet: &IncomingPacket) -> Option<Vec<GuildEvent>> {
        if packet.command != PUSH_COMMAND {
            return None;
        }
        if packet.return_code != 0 {
            return Some(vec![opaque_push(&packet.body)]);
        }
        let generation = self.client.connection_generation();
        let tiny_id = self.session.tiny_id(generation);
        let result = decode_events(packet.body.clone(), tiny_id, self.client.account_uin());
        Some(match result {
            Ok(events) => events,
            Err(error) => {
                tracing::warn!(%error, command = packet.command, "QQ guild message push rejected");
                vec![opaque_push(&packet.body)]
            }
        })
    }

    pub async fn call(&self, method: &str, args: Value) -> Result<Value> {
        use crate::contacts::{Args, value};
        let args = Args::new(&args)?;
        match method {
            "synchronize" => value(&self.synchronize().await?),
            "guilds" => value(&self.guilds().await?),
            "channels" => value(&self.channels(args.u64("guild_id")?).await?),
            "members" => value(&self.members(args.u64("guild_id")?).await?),
            "send_message" => value(
                &self
                    .send_text(
                        args.u64("guild_id")?,
                        args.u64("channel_id")?,
                        args.string("text")?,
                    )
                    .await?,
            ),
            _ => Err(Error::Unsupported(format!("Unknown guild method {method}"))),
        }
    }
}

fn require_id(id: u64, name: &str) -> Result<()> {
    if id == 0 {
        Err(Error::Malformed(format!(
            "{name} must be a positive integer"
        )))
    } else {
        Ok(())
    }
}

fn require_tiny_id(tiny_id: Option<u64>) -> Result<u64> {
    tiny_id.filter(|id| *id > 0).ok_or_else(|| {
        Error::Unsupported("The current QQ session did not supply a guild TinyID".into())
    })
}

fn decode_send_response(
    guild_id: u64,
    channel_id: u64,
    random: u64,
    raw: Bytes,
) -> Result<SendReceipt> {
    let response: proto::guild::SendResponse =
        crate::diagnostics::decode_response(SEND_COMMAND, raw)?;
    let code = response.result.unwrap_or_default();
    if code != 0 {
        return Err(Error::Server {
            code: code as i32,
            message: String::from_utf8_lossy(response.error.as_deref().unwrap_or_default())
                .into_owned(),
        });
    }
    if let Some(transfer) = response.transfer {
        let code = transfer.code.unwrap_or_default();
        if code != 0 {
            return Err(Error::Server {
                code,
                message: String::from_utf8_lossy(transfer.error.as_deref().unwrap_or_default())
                    .into_owned(),
            });
        }
    }
    let content = response.head.and_then(|head| head.content);
    Ok(SendReceipt {
        guild_id,
        channel_id,
        sequence: content.as_ref().and_then(|head| head.sequence),
        time: response.send_time.map(u64::from),
        random,
    })
}

pub(crate) fn encode_push_ack(body: Bytes) -> Result<Option<Bytes>> {
    let push: proto::guild::OnlinePush = proto::decode(body)?;
    if push.need_response.unwrap_or_default() == 0 {
        return Ok(None);
    }
    Ok(Some(
        proto::guild::PushResponse {
            server_buffer: Some(push.server_buffer.unwrap_or_default()),
        }
        .encode_to_vec()
        .into(),
    ))
}

fn decompress_messages(input: &[u8], limit: usize) -> Result<Bytes> {
    if input.is_empty() || limit == 0 || input.len() > limit {
        return Err(Error::Malformed(
            "Invalid guild compressed message length".into(),
        ));
    }
    let mut output = vec![0; input.len().saturating_mul(2).min(limit)];
    loop {
        match lz4_flex::block::decompress_into(input, &mut output) {
            Ok(size) if size > 0 => {
                output.truncate(size);
                return Ok(output.into());
            }
            Ok(_) => {
                return Err(Error::Malformed(
                    "Guild compressed messages decoded to empty data".into(),
                ));
            }
            Err(lz4_flex::block::DecompressError::OutputTooSmall { .. })
                if output.len() < limit =>
            {
                output.resize(output.len().saturating_mul(2).min(limit), 0);
            }
            Err(error) => {
                return Err(Error::Malformed(format!(
                    "Invalid guild LZ4 block: {error}"
                )));
            }
        }
    }
}

fn opaque_push(body: &[u8]) -> GuildEvent {
    GuildEvent::Opaque {
        command: PUSH_COMMAND.into(),
        payload: body.to_vec(),
    }
}

fn decode_events(body: Bytes, tiny_id: Option<u64>, own_uin: u64) -> Result<Vec<GuildEvent>> {
    let push: proto::guild::OnlinePush = proto::decode(body.clone())?;
    let messages = if push.compression_flag.unwrap_or_default() == 0 {
        push.messages
    } else {
        let compressed = push.compressed_messages.ok_or_else(|| {
            Error::Malformed("Guild compressed push has no compressed messages".into())
        })?;
        let raw = decompress_messages(&compressed, crate::wire::MAX_FRAME_SIZE)?;
        proto::decode::<proto::guild::CompressedMessages>(raw)?.messages
    };
    let mut events = Vec::with_capacity(messages.len());
    let mut retain_push = messages.is_empty();
    for raw in messages {
        match codec::decode_message(&raw, tiny_id, own_uin) {
            Ok(Some(message)) => events.push(GuildEvent::Message { message }),
            Ok(None) => retain_push = true,
            Err(error) => {
                retain_push = true;
                tracing::warn!(%error, command = PUSH_COMMAND, "QQ guild message in push rejected");
            }
        }
    }
    if retain_push {
        events.push(opaque_push(&body));
    }
    Ok(events)
}

#[cfg(test)]
mod tests;
