use crate::{
    Client, Encryption, Error, RequestType, Result,
    proto::{
        self,
        lifecycle::{
            ClubFlagItem, ClubFlagRequest, ClubFlagResponse, RedTouchRequest, RedTouchResponse,
            StringPair,
        },
    },
};
use bytes::Bytes;
use prost::Message;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::Instant;

const PLATFORM: u32 = 1031;
const DEFAULT_POLL_SECONDS: u32 = 300;

pub(super) fn build_request(uin: u64, version: &str, initial: bool) -> ClubFlagRequest {
    ClubFlagRequest {
        field1: Some(1),
        platform: Some(PLATFORM),
        version: Some(
            version
                .split_once('-')
                .map_or(version, |(release, _)| release)
                .into(),
        ),
        uin: Some(uin),
        paths: ["140163", "140148", "140180"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        field9: Some(0),
        field10: Some(0),
        field11: Some(Bytes::new()),
        mode: Some(if initial { 101 } else { 103 }),
        field14: Some(0),
        field15: Some(1),
        field16: Some(0),
        field17: Some(Bytes::new()),
        field18: Some(0),
        field19: Some(1),
        field21: Some(1),
        field23: Some(0),
        field24: Some(Bytes::new()),
    }
}

pub(super) fn build_report(
    uin: u64,
    version: &str,
    qimei: &str,
    item: &ClubFlagItem,
    unix_millis: u128,
) -> Option<RedTouchRequest> {
    let id = item.id?;
    let mission = item.mission.as_ref()?;
    let business_json = item.business_json.as_ref()?;
    let path = item.path.as_ref()?;
    let position = item.position?;
    let variant = item.position_variant?;
    let hash = item.hash.as_ref()?;
    let remaining = item.remaining?.checked_sub(1)?;
    let attributes = [
        ("trace_id", format!("{uin}_{unix_millis}")),
        ("position_id", format!("{position}_{variant}")),
        ("num", "0".into()),
        ("version", "0".into()),
        ("hash", hash.clone()),
        ("redType", "0".into()),
        ("qimei", qimei.into()),
        ("path", path.clone()),
        ("exp_remain", remaining.to_string()),
        ("isPCTips", "0".into()),
    ]
    .into_iter()
    .map(|(key, value)| StringPair {
        key: Some(key.into()),
        value: Some(value),
    })
    .collect();
    Some(RedTouchRequest {
        uin: Some(uin),
        platform: Some(PLATFORM),
        version: Some(version.into()),
        platform_version: Some(String::new()),
        item_id: Some(id),
        missions: vec![mission.clone()],
        business_json: Some(business_json.clone()),
        attributes,
        command: Some(30),
        heba_flag: Some(false),
        extra_json: item.extra_json.clone(),
        ..Default::default()
    })
}

fn club_reply(body: Bytes, uin: u64) -> Result<(ClubFlagResponse, Duration)> {
    let response: ClubFlagResponse = proto::decode(body)?;
    check_code(response.code, "QQClubComm.getNewFlag")?;
    if response.uin.is_some_and(|echo| echo != uin) {
        return Err(Error::Malformed(
            "QQClubComm.getNewFlag account echo mismatch".into(),
        ));
    }
    let seconds = response.poll_seconds.unwrap_or(DEFAULT_POLL_SECONDS);
    if seconds == 0 {
        return Err(Error::Malformed(
            "QQClubComm.getNewFlag returned zero poll interval".into(),
        ));
    }
    Ok((response, Duration::from_secs(u64::from(seconds))))
}

fn check_code(code: Option<i32>, command: &'static str) -> Result<()> {
    match code {
        Some(0) => Ok(()),
        // Do not propagate arbitrary server business text into outer warning logs.
        Some(code) => Err(Error::Server {
            code,
            message: format!("{command} failed"),
        }),
        None => Err(Error::Malformed(format!(
            "{command} response has no result code"
        ))),
    }
}

fn report_reply(body: Bytes) -> Result<()> {
    if body.is_empty() {
        return Ok(());
    }
    let response: RedTouchResponse = proto::decode(body)?;
    check_code(response.code, "RedTouchSvc.ClientReport")
}

fn ensure_generation(client: &Client, generation: u64) -> Result<()> {
    if client.is_current_online(generation) {
        Ok(())
    } else {
        Err(Error::Disconnected)
    }
}

fn current_identity(
    client: &Client,
    generation: u64,
    expected: Option<u64>,
) -> Result<(u64, String)> {
    let (uin, qimei) = client.business_identity(generation)?;
    if expected.is_some_and(|expected| expected != uin) {
        return Err(Error::Disconnected);
    }
    Ok((uin, qimei))
}

pub(super) async fn poll(client: &Client, generation: u64, initial: bool) -> Result<Instant> {
    let (uin, _) = current_identity(client, generation, None)?;
    ensure_generation(client, generation)?;
    let version = &client.config.profile.version;
    let request = build_request(uin, version, initial);
    let result = client
        .request(
            "QQClubComm.getNewFlag",
            Bytes::from(request.encode_to_vec()),
            RequestType::D2,
            Encryption::D2,
            client.config.timeout,
        )
        .await;
    let mut anchor = Instant::now();
    ensure_generation(client, generation)?;
    let (_, mut qimei) = current_identity(client, generation, Some(uin))?;
    ensure_generation(client, generation)?;
    let (response, interval) = club_reply(result?, uin)?;
    for item in &response.items {
        let unix_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Malformed("Client clock precedes Unix epoch".into()))?
            .as_millis();
        let Some(report) = build_report(uin, version, &qimei, item, unix_millis) else {
            continue;
        };
        ensure_generation(client, generation)?;
        anchor = Instant::now();
        let result = client
            .request(
                "RedTouchSvc.ClientReport",
                Bytes::from(report.encode_to_vec()),
                RequestType::D2,
                Encryption::D2,
                client.config.timeout,
            )
            .await;
        ensure_generation(client, generation)?;
        let (_, current_qimei) = current_identity(client, generation, Some(uin))?;
        ensure_generation(client, generation)?;
        qimei = current_qimei;
        report_reply(result?)?;
    }
    Ok(anchor + interval)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item() -> ClubFlagItem {
        ClubFlagItem {
            id: Some(7),
            business_json: Some(Bytes::from_static(b"{\"test\":true}")),
            path: Some("server/path".into()),
            mission: Some("server-mission".into()),
            position: Some(1002),
            position_variant: Some(0),
            extra_json: Some(Bytes::from_static(b"{}")),
            remaining: Some(999),
            hash: Some("server-hash".into()),
        }
    }

    #[test]
    fn incomplete_or_exhausted_items_do_not_invent_report_state() {
        let mut value = item();
        value.remaining = Some(0);
        assert!(build_report(17, "9.8.7-build", "", &value, 42).is_none());
        value.remaining = None;
        assert!(build_report(17, "9.8.7-build", "", &value, 42).is_none());
        value.remaining = Some(1);
        let report = build_report(17, "9.8.7-build", "", &value, 42).unwrap();
        assert_eq!(report.attributes[8].value.as_deref(), Some("0"));
        value.hash = None;
        assert!(build_report(17, "9.8.7-build", "", &value, 42).is_none());
    }

    #[test]
    fn report_uses_current_identity_and_only_the_supplied_item() {
        let mut value = item();
        let first = build_report(17, "9.8.7-build", "device-a", &value, 42).unwrap();
        assert_eq!(first.attributes[0].value.as_deref(), Some("17_42"));
        assert_eq!(first.version.as_deref(), Some("9.8.7-build"));
        value.id = Some(8);
        value.path = Some("new/path".into());
        value.extra_json = None;
        let next = build_report(23, "9.8.8-next", "", &value, 43).unwrap();
        assert_eq!(next.uin, Some(23));
        assert_eq!(next.item_id, Some(8));
        assert_eq!(next.attributes[0].value.as_deref(), Some("23_43"));
        assert_eq!(next.attributes[6].value.as_deref(), Some(""));
        assert_eq!(next.attributes[7].value.as_deref(), Some("new/path"));
        assert!(next.extra_json.is_none());
        assert_eq!(first.attributes[7].value.as_deref(), Some("server/path"));
    }

    #[test]
    fn club_rejects_error_wrong_account_and_zero_interval() {
        let response = ClubFlagResponse {
            code: Some(0),
            uin: Some(17),
            poll_seconds: Some(300),
            ..Default::default()
        };
        let encoded = || Bytes::from(response.encode_to_vec());
        assert!(club_reply(encoded(), 23).is_err());
        let mut zero = response.clone();
        zero.poll_seconds = Some(0);
        assert!(club_reply(Bytes::from(zero.encode_to_vec()), 17).is_err());
        let mut error = response.clone();
        error.code = Some(5);
        assert!(matches!(
            club_reply(Bytes::from(error.encode_to_vec()), 17),
            Err(Error::Server { code: 5, .. })
        ));
        let mut absent = response;
        absent.poll_seconds = None;
        absent.field8 = Some(3600);
        let (_, interval) = club_reply(Bytes::from(absent.encode_to_vec()), 17).unwrap();
        assert_eq!(interval, Duration::from_secs(300));
    }

    #[test]
    fn report_reply_requires_empty_body_or_explicit_success() {
        assert!(report_reply(Bytes::new()).is_ok());
        assert!(report_reply(Bytes::from_static(&[0x08, 0])).is_ok());
        assert!(matches!(
            report_reply(Bytes::from_static(&[0x08, 9])),
            Err(Error::Server { code: 9, .. })
        ));
        assert!(report_reply(Bytes::from_static(&[0x18, 0])).is_err());
        assert!(report_reply(Bytes::from_static(&[0x08])).is_err());
    }
}
