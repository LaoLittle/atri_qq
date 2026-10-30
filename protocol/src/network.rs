use crate::{Error, Result, proto, wire};
use bytes::Bytes;
use jce::JceStruct;
use prost::Message;
use std::net::IpAddr;

pub mod ios_discovery;
pub mod ios_probe;

pub const GET_IP_DIRECT_COMMAND: &str = "ConfigPushSvc.GetIpDirect";
pub const PUSH_REQUEST_COMMAND: &str = "ConfigPushSvc.PushReq";
pub const PUSH_RESPONSE_COMMAND: &str = "ConfigPushSvc.PushResp";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ServerSelection {
    Configured,
    #[default]
    Wifi,
    Mobile,
}

#[derive(Clone, Copy, Default)]
pub struct GetIpDirectRequest;

impl GetIpDirectRequest {
    pub fn encode(self) -> Bytes {
        proto::network::GetIpDirectRequest {
            body: Some(Bytes::new()),
        }
        .encode_to_vec()
        .into()
    }
}

pub struct IpDirectConfiguration {
    pub body: proto::network::DomainIpConfiguration,
    pub raw: Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint<'a> {
    pub host: &'a str,
    pub port: u16,
}

impl Endpoint<'_> {
    pub fn is_unspecified(&self) -> bool {
        self.host
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_unspecified())
    }
}

fn invalid(message: &'static str) -> Error {
    wire::malformed(message)
}

fn validate_host(host: &str) -> Result<()> {
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    let domain = host.strip_suffix('.').unwrap_or(host);
    if host.len() > 253
        || domain.is_empty()
        || !domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(invalid("Invalid network endpoint host"));
    }
    Ok(())
}

fn endpoint(host: &str, port: u32) -> Result<Endpoint<'_>> {
    validate_host(host)?;
    let port = u16::try_from(port)
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| invalid("Invalid network endpoint port"))?;
    Ok(Endpoint { host, port })
}

pub fn decode_get_ip_direct(body: Bytes, expected_uin: u64) -> Result<IpDirectConfiguration> {
    if expected_uin == 0 {
        return Err(invalid("GetIpDirect requires an authenticated account"));
    }
    let response: proto::network::GetIpDirectResponse = proto::decode(body.clone())?;
    let configuration = response
        .body
        .ok_or_else(|| invalid("Missing GetIpDirect response body"))?;
    let result = configuration
        .result
        .ok_or_else(|| invalid("Missing GetIpDirect result"))?;
    if result != 0 {
        return Err(Error::Server {
            code: result,
            message: "GetIpDirect failed".into(),
        });
    }
    if configuration.uin != Some(expected_uin) {
        return Err(invalid("GetIpDirect account binding mismatch"));
    }
    for list in configuration.ipv4.iter().chain(&configuration.ipv6) {
        validate_host(
            list.domain
                .as_deref()
                .ok_or_else(|| invalid("Missing GetIpDirect domain"))?,
        )?;
        for address in &list.addresses {
            ip_direct_endpoint(address)?;
        }
    }
    Ok(IpDirectConfiguration {
        body: configuration,
        raw: body,
    })
}

pub fn ip_direct_endpoint(address: &proto::network::ServerAddress) -> Result<Endpoint<'_>> {
    endpoint(
        address
            .host
            .as_deref()
            .ok_or_else(|| invalid("Missing GetIpDirect endpoint host"))?,
        address
            .port
            .ok_or_else(|| invalid("Missing GetIpDirect endpoint port"))?,
    )
}

#[derive(Clone, JceStruct)]
pub struct SsoServerInfo {
    #[jce(tag = "1", required)]
    pub host: String,
    #[jce(tag = "2", required)]
    pub port: i32,
    #[jce(tag = "3", required)]
    pub field_3: i8,
    #[jce(tag = "4", required)]
    pub field_4: i8,
    #[jce(tag = "5")]
    pub protocol: i8,
    #[jce(tag = "6", default = 8)]
    pub timeout_seconds: i32,
    #[jce(tag = "7")]
    pub login_merge: i8,
    #[jce(tag = "8")]
    pub location: String,
    #[jce(tag = "9")]
    pub field_9: String,
    #[jce(tag = "10")]
    pub field_10: i32,
    #[jce(tag = "11")]
    pub field_11: i32,
    #[jce(tag = "12")]
    pub field_12: String,
}

impl SsoServerInfo {
    pub fn endpoint(&self) -> Result<Endpoint<'_>> {
        endpoint(
            &self.host,
            u32::try_from(self.port).map_err(|_| invalid("Invalid SSO endpoint port"))?,
        )
    }

    pub(crate) fn connect_timeout(&self) -> std::time::Duration {
        connect_timeout(self.timeout_seconds)
    }
}

fn connect_timeout(seconds: i32) -> std::time::Duration {
    std::time::Duration::from_secs(if seconds > 0 { seconds as u64 } else { 8 })
}

#[derive(Clone, JceStruct)]
pub struct SsoServerLists {
    #[jce(tag = "1", required)]
    pub list_1: Vec<SsoServerInfo>,
    #[jce(tag = "3", required)]
    pub list_3: Vec<SsoServerInfo>,
    #[jce(tag = "4", required)]
    pub field_4: i32,
    #[jce(tag = "5")]
    pub field_5: i32,
    #[jce(tag = "6")]
    pub field_6: i32,
    #[jce(tag = "7", default = 1)]
    pub field_7: i32,
    #[jce(tag = "8")]
    pub list_8: Vec<SsoServerInfo>,
    #[jce(tag = "9")]
    pub list_9: Vec<SsoServerInfo>,
    #[jce(tag = "10")]
    pub list_10: Vec<SsoServerInfo>,
    #[jce(tag = "11")]
    pub list_11: Vec<SsoServerInfo>,
    #[jce(tag = "12")]
    pub list_12: Vec<SsoServerInfo>,
    #[jce(tag = "13")]
    pub list_13: Vec<SsoServerInfo>,
    #[jce(tag = "14")]
    pub field_14: i32,
    #[jce(tag = "15")]
    pub field_15: i32,
    #[jce(tag = "16")]
    pub field_16: Bytes,
    #[jce(tag = "17")]
    pub field_17: i32,
    #[jce(tag = "18")]
    pub field_18: Bytes,
    #[jce(tag = "19")]
    pub field_19: String,
    #[jce(tag = "20")]
    pub field_20: i32,
    #[jce(tag = "21")]
    pub list_21: Vec<SsoServerInfo>,
    #[jce(tag = "23")]
    pub field_23: i32,
    #[jce(tag = "24")]
    pub field_24: i32,
    #[jce(tag = "25")]
    pub field_25: i32,
    #[jce(tag = "26")]
    pub field_26: String,
    #[jce(tag = "27")]
    pub field_27: i32,
    #[jce(tag = "28")]
    pub field_28: Bytes,
}

impl SsoServerLists {
    pub fn list(&self, tag: u8) -> Option<&[SsoServerInfo]> {
        Some(match tag {
            1 => &self.list_1,
            3 => &self.list_3,
            8 => &self.list_8,
            9 => &self.list_9,
            10 => &self.list_10,
            21 => &self.list_21,
            11 => &self.list_11,
            12 => &self.list_12,
            13 => &self.list_13,
            _ => return None,
        })
    }

    pub(crate) fn tcp_servers(
        &self,
        selection: ServerSelection,
    ) -> impl Iterator<Item = &SsoServerInfo> {
        let primary = match selection {
            ServerSelection::Configured => [].as_slice(),
            ServerSelection::Wifi => self.list_3.as_slice(),
            ServerSelection::Mobile => self.list_1.as_slice(),
        };
        let ipv6 = if selection == ServerSelection::Configured {
            [].as_slice()
        } else {
            self.list_11.as_slice()
        };
        primary
            .iter()
            .chain(ipv6)
            .filter(|server| matches!(server.protocol, 0 | 1))
    }
}

pub struct SsoConfiguration {
    pub servers: SsoServerLists,
    pub raw: Bytes,
}

pub fn decode_sso_configuration(body: Bytes) -> Result<SsoConfiguration> {
    validate_sso_configuration(parse_sso_configuration(body)?)
}

fn parse_sso_configuration(body: Bytes) -> Result<SsoConfiguration> {
    if body.len() > wire::MAX_FRAME_SIZE {
        return Err(invalid("SSO configuration exceeds limit"));
    }
    let servers = SsoServerLists::decode(body.clone())
        .map_err(|error| wire::malformed(format!("Invalid SSO configuration: {error}")))?;
    Ok(SsoConfiguration { servers, raw: body })
}

fn validate_sso_configuration(configuration: SsoConfiguration) -> Result<SsoConfiguration> {
    let servers = &configuration.servers;
    for list in [
        &servers.list_1,
        &servers.list_3,
        &servers.list_8,
        &servers.list_9,
        &servers.list_10,
        &servers.list_11,
        &servers.list_12,
        &servers.list_13,
        &servers.list_21,
    ] {
        for server in list {
            server.endpoint()?;
        }
    }
    Ok(configuration)
}

pub enum ConfigPushBody {
    SsoServers(Result<SsoConfiguration>),
    Unknown { kind: i32, raw: Bytes },
}

pub struct ConfigPush {
    pub sequence: Option<i64>,
    pub body: ConfigPushBody,
    pub acknowledgment: Option<Bytes>,
}

pub fn decode_push(body: Bytes) -> Result<ConfigPush> {
    decode_push_with_delivery(body).map(|(push, _)| push)
}

pub(crate) fn decode_push_with_delivery(body: Bytes) -> Result<(ConfigPush, bool)> {
    let push = wire::config_push::decode(body)?;
    let mut consumed = false;
    let body = match push.kind {
        1 => {
            let parsed = parse_sso_configuration(push.configuration);
            consumed = parsed.is_ok();
            ConfigPushBody::SsoServers(parsed.and_then(validate_sso_configuration))
        }
        kind => ConfigPushBody::Unknown {
            kind,
            raw: push.configuration,
        },
    };
    Ok((
        ConfigPush {
            sequence: push.sequence,
            body,
            acknowledgment: push.acknowledgment,
        },
        consumed,
    ))
}

pub const LOGIN_NOTIFICATION_COMMAND: &str = "StatSvc.SvcReqMSFLoginNotify";

#[derive(Clone, JceStruct)]
pub struct LoginNotificationBody {
    #[jce(tag = "0")]
    pub raw_field0: i64,
    #[jce(tag = "1")]
    pub raw_field1: i32,
    #[jce(tag = "2")]
    pub raw_field2: i32,
    #[jce(tag = "3")]
    pub raw_field3: i32,
    #[jce(tag = "4")]
    pub title: String,
    #[jce(tag = "5")]
    pub message: String,
    #[jce(tag = "6")]
    pub raw_field6: i32,
    #[jce(tag = "7")]
    pub raw_field7: i64,
}

pub struct LoginNotification {
    pub body: LoginNotificationBody,
    pub raw: Bytes,
}

pub fn decode_login_notification(raw: Bytes) -> Result<LoginNotification> {
    let body = wire::config_push::payload(
        raw.clone(),
        "StatSvc",
        "SvcReqMSFLoginNotify",
        "SvcReqMSFLoginNotify",
        "QQService.SvcReqMSFLoginNotify",
    )?;
    let body = LoginNotificationBody::decode(body)
        .map_err(|error| wire::malformed(format!("Invalid MSF login notification: {error}")))?;
    Ok(LoginNotification { body, raw })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(uin: Option<u64>, result: Option<i32>, host: &str, port: u32) -> Bytes {
        proto::network::GetIpDirectResponse {
            body: Some(proto::network::DomainIpConfiguration {
                uin,
                result,
                ipv4: vec![proto::network::DomainAddressList {
                    domain: Some("example.test".into()),
                    addresses: vec![proto::network::ServerAddress {
                        host: Some(host.into()),
                        port: Some(port),
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }),
        }
        .encode_to_vec()
        .into()
    }

    #[test]
    fn ip_direct_requires_success_and_matching_account() {
        assert!(decode_get_ip_direct(response(Some(7), Some(0), "192.0.2.1", 80), 8).is_err());
        assert!(decode_get_ip_direct(response(None, Some(0), "192.0.2.1", 80), 7).is_err());
        assert!(decode_get_ip_direct(response(Some(7), None, "192.0.2.1", 80), 7).is_err());
        assert!(matches!(
            decode_get_ip_direct(response(Some(7), Some(1), "192.0.2.1", 80), 7),
            Err(Error::Server { code: 1, .. })
        ));
    }

    #[test]
    fn ip_direct_rejects_invalid_targets_but_preserves_ipv6_sentinel() {
        for (host, port) in [
            ("https://example.test/", 80),
            ("example.test", 0),
            ("example.test", 65536),
        ] {
            assert!(decode_get_ip_direct(response(Some(7), Some(0), host, port), 7).is_err());
        }
        let configuration = decode_get_ip_direct(response(Some(7), Some(0), "::", 80), 7).unwrap();
        let endpoint = ip_direct_endpoint(&configuration.body.ipv4[0].addresses[0]).unwrap();
        assert!(endpoint.is_unspecified());
    }

    #[test]
    fn malformed_network_body_does_not_suppress_control_ack() {
        let push = decode_push(wire::config_push::request_fixture(1, 0)).unwrap();
        assert!(matches!(push.body, ConfigPushBody::SsoServers(Err(_))));
        assert!(push.acknowledgment.is_some());
        assert_eq!(push.sequence, Some(0));
        let push = decode_push(wire::config_push::request_fixture(99, 0)).unwrap();
        assert!(matches!(
            push.body,
            ConfigPushBody::Unknown { kind: 99, .. }
        ));
        assert!(push.acknowledgment.is_none());
    }
}
