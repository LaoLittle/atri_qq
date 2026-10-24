use super::Operations;
use crate::{Error, Result};
use reqwest::{header, redirect::Policy};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    time::Duration,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupAnnouncement {
    pub id: String,
    pub sender_uin: u64,
    pub published_at: i64,
    pub text: String,
    pub title: String,
    pub pictures: Vec<AnnouncementPicture>,
    pub pinned: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnnouncementPicture {
    pub id: String,
    pub width: String,
    pub height: String,
}
#[derive(Deserialize)]
struct Response {
    ec: i32,
    #[serde(default)]
    em: String,
    #[serde(default)]
    feeds: Option<Vec<Feed>>,
    #[serde(default)]
    inst: Option<Vec<Feed>>,
}
#[derive(Deserialize)]
struct Feed {
    fid: String,
    u: u64,
    pubt: i64,
    msg: Content,
    settings: Option<Settings>,
}
#[derive(Deserialize)]
struct Content {
    #[serde(default)]
    text: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    pics: Option<Vec<Picture>>,
}
#[derive(Deserialize)]
struct Picture {
    id: String,
    w: String,
    h: String,
}
#[derive(Deserialize)]
struct Settings {
    inst_no_pinned: Option<u8>,
}

impl Operations {
    pub async fn fetch_group_announcements(
        &self,
        group_uin: u64,
    ) -> Result<Vec<GroupAnnouncement>> {
        let account = self.identity().await;
        let http = crate::http::client_builder()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(20))
            .build()?;
        let key = self.fetch_client_key().await?;
        let mut url = reqwest::Url::parse("https://ssl.ptlogin2.qq.com/jump").expect("static URL");
        url.query_pairs_mut().extend_pairs([
            ("ptlang", "1033"),
            ("clientuin", &account.0.to_string()),
            ("clientkey", &key.key),
            ("u1", "https://qun.qq.com/"),
            ("keyindex", "19"),
        ]);
        let mut cookies = BTreeMap::new();
        // ptlogin sets web session cookies along its redirect chain.
        for _ in 0..5 {
            let mut response = crate::diagnostics::send_http(
                http.get(url.clone())
                    .header(header::COOKIE, cookie_header(&cookies)),
            )
            .await?;
            let mut offset = 0;
            while let Some(chunk) = response.chunk().await? {
                crate::diagnostics::trace_http_chunk(&response, offset, &chunk);
                offset += chunk.len();
                if offset > 2 * 1024 * 1024 {
                    return Err(Error::Malformed("Web login response exceeds limit".into()));
                }
            }
            collect_cookies(response.headers(), &mut cookies);
            if cookies.contains_key("skey") && cookies.contains_key("p_skey") {
                break;
            }
            if !response.status().is_redirection() {
                break;
            }
            let location = response
                .headers()
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| Error::Authentication("Web login redirect is missing".into()))?;
            url = url
                .join(location)
                .map_err(|_| Error::Authentication("Invalid web login redirect".into()))?;
            if url.scheme() != "https"
                || !matches!(
                    url.host_str(),
                    Some(
                        "ssl.ptlogin2.qq.com"
                            | "ptlogin2.qun.qq.com"
                            | "qun.qq.com"
                            | "web.qun.qq.com"
                    )
                )
            {
                return Err(Error::Authentication(
                    "Unexpected web login destination".into(),
                ));
            }
        }
        if !cookies.contains_key("p_skey") {
            let keys = self.fetch_cookies(&["qun.qq.com".into()]).await?;
            if let Some(key) = keys.get("qun.qq.com").filter(|key| !key.is_empty()) {
                cookies.insert("p_skey".into(), key.clone());
            }
        }
        let skey = cookies
            .get("skey")
            .filter(|key| !key.is_empty())
            .ok_or_else(|| Error::Authentication("QQ web session was not returned".into()))?;
        let bkn = bkn(skey).to_string();
        cookies
            .entry("uin".into())
            .or_insert_with(|| format!("o{:010}", account.0));
        cookies
            .entry("p_uin".into())
            .or_insert_with(|| format!("o{:010}", account.0));
        self.check_identity(&account).await?;
        let mut response = crate::diagnostics::send_http(
            http.get("https://web.qun.qq.com/cgi-bin/announce/get_t_list")
                .query(&[
                    ("bkn", bkn.as_str()),
                    ("qid", &group_uin.to_string()),
                    ("ft", "23"),
                    ("ni", "1"),
                    ("n", "20"),
                    ("i", "1"),
                    ("log_read", "0"),
                    ("platform", "1"),
                    ("s", "-1"),
                ])
                .header(header::COOKIE, cookie_header(&cookies))
                .header(header::REFERER, "https://web.qun.qq.com/"),
        )
        .await?;
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            crate::diagnostics::trace_http_chunk(&response, body.len(), &chunk);
            if body.len() + chunk.len() > 2 * 1024 * 1024 {
                return Err(Error::Malformed(
                    "Group announcement response is too large".into(),
                ));
            }
            body.extend_from_slice(&chunk);
        }
        response.error_for_status_ref()?;
        let announcements = decode(&body).inspect_err(|error| {
            crate::diagnostics::log_raw_error("group announcements", &body, error)
        })?;
        self.check_identity(&account).await?;
        Ok(announcements)
    }
}
fn cookie_header(cookies: &BTreeMap<String, String>) -> String {
    cookies
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("; ")
}
fn collect_cookies(headers: &header::HeaderMap, cookies: &mut BTreeMap<String, String>) {
    for value in headers.get_all(header::SET_COOKIE) {
        if let Ok(value) = value.to_str()
            && let Some((name, value)) = value
                .split(';')
                .next()
                .and_then(|pair| pair.split_once('='))
            && matches!(name.trim(), "skey" | "p_skey" | "uin" | "p_uin")
            && !value.is_empty()
        {
            cookies.insert(name.trim().into(), value.into());
        }
    }
}
fn bkn(skey: &str) -> u32 {
    skey.bytes().fold(5381u32, |hash, byte| {
        hash.wrapping_mul(33).wrapping_add(byte as u32)
    }) & 0x7fff_ffff
}
fn decode(body: &[u8]) -> Result<Vec<GroupAnnouncement>> {
    let response: Response = serde_json::from_slice(body)
        .map_err(|error| Error::Malformed(format!("Group announcements: {error}")))?;
    if response.ec != 0 {
        return Err(Error::Server {
            code: response.ec,
            message: response.em,
        });
    }
    let mut seen = HashSet::new();
    let mut announcements = response
        .feeds
        .unwrap_or_default()
        .into_iter()
        .chain(response.inst.unwrap_or_default())
        .filter(|feed| seen.insert(feed.fid.clone()))
        .map(|feed| GroupAnnouncement {
            id: feed.fid,
            sender_uin: feed.u,
            published_at: feed.pubt,
            text: feed.msg.text,
            title: feed.msg.title,
            pictures: feed
                .msg
                .pics
                .unwrap_or_default()
                .into_iter()
                .map(|pic| AnnouncementPicture {
                    id: pic.id,
                    width: pic.w,
                    height: pic.h,
                })
                .collect(),
            pinned: feed.settings.and_then(|settings| settings.inst_no_pinned) == Some(0),
        })
        .collect::<Vec<_>>();
    announcements.sort_by_key(|notice| {
        (
            std::cmp::Reverse(notice.pinned),
            std::cmp::Reverse(notice.published_at),
        )
    });
    Ok(announcements)
}
