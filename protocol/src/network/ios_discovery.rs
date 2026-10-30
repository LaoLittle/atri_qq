use super::{Endpoint, ServerSelection};
use crate::{Error, Result, crypto, wire};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use jce::{JceStruct, types::JceType};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, time::Duration};

pub const URL: &str = "https://configsvr.msf.3g.qq.com/configsvr/serverlist.jsp";
const KEY: [u8; 16] = [
    0xf0, 0x44, 0x1f, 0x5f, 0xf4, 0x2d, 0xa5, 0x8f, 0xdc, 0xf7, 0x94, 0x9a, 0xba, 0x62, 0xd4, 0x11,
];

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NativeU32(pub u32);

impl JceType for NativeU32 {
    fn read<B: Buf>(
        buf: &mut B,
        kind: u8,
        structure: &'static str,
        field: &'static str,
    ) -> jce::error::DecodeResult<Self> {
        i64::read(buf, kind, structure, field).map(|value| Self(value as u32))
    }
    fn write<B: BufMut>(&self, buf: &mut B, tag: u8) {
        i64::from(self.0).write(buf, tag);
    }
    fn write_len(&self) -> usize {
        8
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NativeU16(pub u16);

impl JceType for NativeU16 {
    fn read<B: Buf>(
        buf: &mut B,
        kind: u8,
        structure: &'static str,
        field: &'static str,
    ) -> jce::error::DecodeResult<Self> {
        i32::read(buf, kind, structure, field).map(|value| Self(value as u16))
    }
    fn write<B: BufMut>(&self, buf: &mut B, tag: u8) {
        i32::from(self.0).write(buf, tag);
    }
    fn write_len(&self) -> usize {
        4
    }
}
#[derive(Clone, Debug, JceStruct)]
pub struct HttpServerListReq {
    #[jce(tag = "1", required)]
    pub account_u32: NativeU32,
    #[jce(tag = "2", required)]
    pub server_time: NativeU32,
    #[jce(tag = "3", default = 1)]
    pub field_3: i8,
    #[jce(tag = "4", required)]
    pub carrier: String,
    #[jce(tag = "5", required)]
    pub network: i32,
    #[jce(tag = "6", required)]
    pub app_id: NativeU32,
    #[jce(tag = "7", required)]
    pub device_identifier: String,
    #[jce(tag = "8")]
    pub field_8: NativeU32,
    #[jce(tag = "9", required)]
    pub account: i64,
    #[jce(tag = "10")]
    pub field_10: NativeU32,
    #[jce(tag = "11")]
    pub field_11: i8,
    #[jce(tag = "12", default = 3)]
    pub field_12: i8,
    #[jce(tag = "13")]
    pub field_13: NativeU32,
    #[jce(tag = "14")]
    pub empty_bssid: i8,
}

#[derive(Clone, Debug, JceStruct, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerInfo {
    #[jce(tag = "1", required)]
    pub host: String,
    #[jce(tag = "2", required)]
    pub port: i32,
    #[jce(tag = "3", required)]
    pub field_3: i8,
    #[jce(tag = "4", required)]
    pub field_4: i8,
    #[jce(tag = "5")]
    pub transport: i8,
    #[jce(tag = "6", default = 8)]
    pub timeout_seconds: i32,
    #[jce(tag = "7")]
    pub field_7: i8,
    #[jce(tag = "8")]
    pub field_8: String,
    #[jce(tag = "9")]
    pub field_9: String,
    #[jce(tag = "10")]
    pub field_10: NativeU32,
    #[jce(tag = "11")]
    pub probe_eligibility: i8,
    #[jce(tag = "12")]
    pub field_12: String,
}

impl ServerInfo {
    pub fn endpoint(&self) -> Result<Endpoint<'_>> {
        super::endpoint(
            &self.host,
            u32::try_from(self.port).map_err(|_| wire::malformed("Invalid iOS server port"))?,
        )
    }
    pub fn is_tcp(&self) -> bool {
        matches!(self.transport, 0 | 1)
    }
    pub(crate) fn connect_timeout(&self) -> Duration {
        super::connect_timeout(self.timeout_seconds)
    }
}

#[derive(Clone, Debug, JceStruct)]
pub struct HttpServerListRes {
    #[jce(tag = "1", required)]
    pub result: i32,
    #[jce(tag = "2", required)]
    pub mobile: Vec<ServerInfo>,
    #[jce(tag = "3", required)]
    pub wifi: Vec<ServerInfo>,
    #[jce(tag = "4", required)]
    pub server_time: i32,
    #[jce(tag = "5", required, default = 86400)]
    pub interval_seconds: i32,
    #[jce(tag = "6")]
    pub field_6: i8,
    #[jce(tag = "7")]
    pub use_new_list: i8,
    #[jce(tag = "8", default = 1)]
    pub field_8: i32,
    #[jce(tag = "9", default = 5)]
    pub field_9: i32,
    #[jce(tag = "10")]
    pub field_10: NativeU32,
    #[jce(tag = "11")]
    pub field_11: NativeU16,
    #[jce(tag = "12")]
    pub list_12: Vec<ServerInfo>,
    #[jce(tag = "13")]
    pub list_13: Vec<ServerInfo>,
    #[jce(tag = "14")]
    pub(crate) field_14: wire::config_push::TarsBytes,
    #[jce(tag = "15")]
    pub ipv6: Vec<ServerInfo>,
    #[jce(tag = "16")]
    pub list_16: Vec<ServerInfo>,
    #[jce(tag = "17")]
    pub list_17: Vec<ServerInfo>,
    #[jce(tag = "18")]
    pub field_18: i8,
    #[jce(tag = "19")]
    pub field_19: i32,
    #[jce(tag = "20")]
    pub field_20: String,
    #[jce(tag = "21")]
    pub field_21: i8,
    #[jce(tag = "22")]
    pub field_22: String,
    #[jce(tag = "23")]
    pub field_23: String,
    #[jce(tag = "24")]
    pub field_24: i8,
    #[jce(tag = "25")]
    pub list_25: Vec<ServerInfo>,
    #[jce(tag = "26")]
    pub list_26: Vec<ServerInfo>,
    #[jce(tag = "27")]
    pub field_27: i32,
    #[jce(tag = "28")]
    pub field_28: i32,
    #[jce(tag = "29")]
    pub field_29: i32,
    #[jce(tag = "30")]
    pub field_30: String,
    #[jce(tag = "31")]
    pub field_31: i32,
    #[jce(tag = "32")]
    pub list_32: Vec<ServerInfo>,
    #[jce(tag = "33")]
    pub field_33: String,
}

fn encrypted_packet(packet: Bytes) -> Result<Bytes> {
    let mut plain = BytesMut::with_capacity(packet.len() + 4);
    plain.put_u32(
        u32::try_from(packet.len() + 4)
            .map_err(|_| wire::malformed("iOS discovery request exceeds limit"))?,
    );
    plain.extend_from_slice(&packet);
    Ok(crypto::tea_encrypt(&plain, &KEY)?.into())
}

pub fn encode_request(request: &HttpServerListReq) -> Result<Bytes> {
    encrypted_packet(wire::config_push::encode_payload(
        "ConfigHttp",
        "HttpServerListReq",
        "HttpServerListReq",
        "ConfigHttp.HttpServerListReq",
        wire::encode_jce_raw(request),
    ))
}

pub fn decode_response(body: &[u8]) -> Result<HttpServerListRes> {
    if body.len() > wire::MAX_FRAME_SIZE {
        return Err(wire::malformed("iOS discovery response exceeds limit"));
    }
    let plain = crypto::tea_decrypt(body, &KEY)?;
    if plain.len() < 4 {
        return Err(wire::malformed("Missing iOS discovery frame length"));
    }
    let payload = wire::config_push::compatible_payload(
        Bytes::from(plain).slice(4..),
        "ConfigHttp",
        "HttpServerListRes",
        "HttpServerListRes",
        "ConfigHttp.HttpServerListRes",
    )?;
    HttpServerListRes::decode(payload)
        .map_err(|error| wire::malformed(format!("Invalid iOS server list: {error}")))
}

pub(crate) async fn fetch(url: &str, request: &HttpServerListReq) -> Result<HttpServerListRes> {
    let http = crate::http::client_builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let mut response = http
        .post(url)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(encode_request(request)?)
        .send()
        .await?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(wire::malformed("iOS discovery requires HTTP 200"));
    }
    if response
        .content_length()
        .is_some_and(|size| size > wire::MAX_FRAME_SIZE as u64)
    {
        return Err(wire::malformed("iOS discovery response exceeds limit"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > wire::MAX_FRAME_SIZE - body.len() {
            return Err(wire::malformed("iOS discovery response exceeds limit"));
        }
        body.extend_from_slice(&chunk);
    }
    decode_response(&body)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ServerListCache {
    pub server_time: u32,
    pub accepted_unix_seconds: u64,
    pub interval_seconds: u32,
    pub carrier: String,
    pub mobile: Vec<ServerInfo>,
    pub wifi: Vec<ServerInfo>,
    pub ipv6: Vec<ServerInfo>,
}

impl Default for ServerListCache {
    fn default() -> Self {
        Self {
            server_time: 0,
            accepted_unix_seconds: 0,
            interval_seconds: 86400,
            carrier: String::new(),
            mobile: Vec::new(),
            wifi: Vec::new(),
            ipv6: Vec::new(),
        }
    }
}

pub type ServerListCaches = BTreeMap<String, ServerListCache>;

pub fn bucket(wifi: bool, bssid: Option<&str>) -> String {
    match bssid.filter(|value| !value.is_empty()) {
        Some(bssid) => format!("{}:{bssid}", if wifi { "wifi" } else { "2g3g" }),
        None => if wifi { "nossid_wifi" } else { "nossid_2g3g" }.into(),
    }
}

impl ServerListCache {
    pub fn fresh(&self, now: u64, carrier: &str) -> bool {
        self.accepted_unix_seconds != 0
            && self.carrier == carrier
            && (now.wrapping_sub(self.accepted_unix_seconds) as u32 as i32)
                < self.interval_seconds.clamp(600, 604800) as i32
    }
    pub fn tcp_servers(&self, selection: ServerSelection) -> impl Iterator<Item = &ServerInfo> {
        let primary = match selection {
            ServerSelection::Configured => [].as_slice(),
            ServerSelection::Wifi => self.wifi.as_slice(),
            ServerSelection::Mobile => self.mobile.as_slice(),
        };
        let ipv6 = if selection == ServerSelection::Configured {
            [].as_slice()
        } else {
            self.ipv6.as_slice()
        };
        primary
            .iter()
            .chain(ipv6)
            .filter(|server| server.is_tcp())
            .filter(|server| {
                server
                    .endpoint()
                    .is_ok_and(|endpoint| !endpoint.is_unspecified())
            })
    }
    pub fn accept(&mut self, response: HttpServerListRes, carrier: &str, now: u64) -> Result<()> {
        if !matches!(response.result, 0 | 1) {
            return Err(Error::Server {
                code: response.result,
                message: "iOS server list rejected".into(),
            });
        }
        if response.result == 1 {
            for server in response
                .mobile
                .iter()
                .chain(&response.wifi)
                .chain(&response.ipv6)
                .filter(|server| server.is_tcp())
            {
                server.endpoint()?;
            }
        }
        self.interval_seconds = response.interval_seconds.clamp(600, 604800) as u32;
        if response.result == 0 {
            return Ok(());
        }
        self.mobile = response
            .mobile
            .into_iter()
            .filter(ServerInfo::is_tcp)
            .collect();
        self.wifi = response
            .wifi
            .into_iter()
            .filter(ServerInfo::is_tcp)
            .collect();
        self.ipv6 = response
            .ipv6
            .into_iter()
            .filter(ServerInfo::is_tcp)
            .collect();
        self.server_time = response.server_time as u32;
        self.accepted_unix_seconds = now;
        self.carrier = carrier.into();
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn response_fixture(response: &HttpServerListRes) -> Bytes {
    encrypted_packet(wire::config_push::encode_payload(
        "ConfigHttp",
        "HttpServerListRes",
        "HttpServerListRes",
        "ConfigHttp.HttpServerListRes",
        wire::encode_jce_raw(response),
    ))
    .unwrap()
}

#[cfg(test)]
mod tests;
