use std::time::Duration;

use bytes::Bytes;
use ricq::msg::elem::{RQElem, Text};
use ricq::msg::MessageChain;
use skia_safe::Bitmap;
use tokio::time::error::Elapsed;

use crate::{get_app, unwrap_result_or_print_err_return};
use crate::event::GroupMessageEvent;

pub mod zero;

pub trait Meme {
    fn draw(args: &[MemeArg]) -> Bitmap;
}

pub enum MemeArg {
    Text(String),
    Image(Bytes),
}

pub enum MemeError {
    Other(String)
}

pub async fn get_image_or_wait(event: &GroupMessageEvent, img: &mut Option<Bytes>) -> Result<(), Elapsed> {
    let msg = event.message().elements.clone();
    async fn get_img(msg: MessageChain, img: &mut Option<Bytes>) {
        for elem in msg {
            if let RQElem::GroupImage(i) = elem {
                let resp = unwrap_result_or_print_err_return!(
                get_app().http_client()
                .get(i.url())
                .send()
                .await
            );

                *img = Some(unwrap_result_or_print_err_return!(resp.bytes().await));
                break;
            }
        }
    }

    get_img(msg, img).await;

    if img.is_none() {
        let mut req = MessageChain::default();
        req.push(Text::new("请在30秒内发送图片".into()));
        event.group().send_message(req).await.ok();
    }

    let r = event.next_message(
        Duration::from_secs(30),
        |m| {
            let m = m.clone();

            for elem in m {
                if let RQElem::GroupImage(..) = elem {
                    return true;
                }
            }
            false
        })
        .await?;

    get_img(r, img).await;

    Ok(())
}