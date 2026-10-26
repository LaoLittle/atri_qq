use crate::{authority, config, conversion, extension_signing as signing, guild_conversion};
use async_trait::async_trait;
use atri_core::{
    ApiError, BotOffline, BotOnline, ConversationKind, EventKind, ExtensionMetadata, ExtensionRole,
    InteractionRequest, LogLevel, ServiceCall, ServiceDescriptor, UserIdentity, Value, encode,
    from_value, to_value,
};
use atri_extensions::{Context, Extension, ManagedTask};
use atri_qq_api::guild::GUILD_SERVICE;
use atri_qq_api::mini_app::MINI_APP_SERVICE;
use atri_qq_api::signing::{SIGNING_METHODS, SIGNING_SERVICE};
use atri_qq_api::{CONTACTS_SERVICE, FRIENDS_METHOD, FriendInfo, FriendsResponse};
use atri_qq_protocol::{
    Client, Error, LoginChallenge, LoginEvent, ServiceClient,
    admin::{ADMIN_METHODS, Admin},
    contacts::{CONTACT_METHODS, Operations},
    guild::{GUILD_METHODS, Guild},
    media::{MEDIA_METHODS, Media},
    messages::{MESSAGE_METHODS, Messaging},
    mini_app::{MINI_APP_METHODS, MiniApp},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

#[atri_extensions::extension]
#[derive(Default)]
pub struct QQExtension {
    state: Mutex<Option<Arc<Services>>>,
    tasks: Mutex<Vec<ManagedTask>>,
}

pub(crate) struct Services {
    pub(crate) client: Arc<Client>,
    pub(crate) configured_uin: u64,
    pub(crate) operations: Arc<Operations>,
    pub(crate) admin: Admin,
    pub(crate) media: Arc<Media>,
    pub(crate) messaging: Messaging,
    pub(crate) guild: Guild,
    pub(crate) mini_app: MiniApp,
    pub(crate) signing: signing::SigningService,
}

fn service(name: &str, methods: &[&str]) -> ServiceDescriptor {
    ServiceDescriptor {
        name: name.into(),
        version: 1,
        methods: methods.iter().map(|s| (*s).into()).collect(),
    }
}

pub(crate) fn protocol_error(error: Error) -> ApiError {
    let code = match &error {
        Error::Malformed(_) => "qq.malformed",
        Error::Authentication(_) => "qq.authentication",
        Error::Server { .. } => "qq.server",
        Error::Timeout => "qq.timeout",
        Error::Disconnected => "qq.disconnected",
        Error::Unsupported(_) => "unsupported",
        Error::Io(_) => "qq.io",
        Error::Crypto(_) => "qq.crypto",
        Error::UnconfirmedFileSend { .. } => "qq.send_unconfirmed",
    };
    ApiError::new(code, error.to_string())
}

async fn bind_services(ctx: &Context, account: Option<&str>) -> Result<(), ApiError> {
    for name in [
        CONTACTS_SERVICE,
        GUILD_SERVICE,
        MINI_APP_SERVICE,
        "qq.admin",
        "qq.messaging",
        "qq.media",
        "atri.messaging",
        "qq.login",
        SIGNING_SERVICE,
    ] {
        ctx.register_service(name, account).await?;
    }
    Ok(())
}

#[async_trait]
impl Extension for QQExtension {
    fn metadata() -> ExtensionMetadata {
        let mut descriptor =
            ExtensionMetadata::new("io.atri.qq", "QQ Linux desktop", env!("CARGO_PKG_VERSION"));
        descriptor.role = ExtensionRole::Adapter;
        descriptor.description =
            "Native Linux NT protocol, native signing, contacts and messaging".into();
        descriptor.configuration.defaults =
            to_value(&config::Config::default()).expect("static QQ defaults serialize");
        descriptor.services = vec![
            service(CONTACTS_SERVICE, CONTACT_METHODS),
            service("qq.admin", ADMIN_METHODS),
            service("qq.messaging", MESSAGE_METHODS),
            service(GUILD_SERVICE, GUILD_METHODS),
            service("qq.media", MEDIA_METHODS),
            service(MINI_APP_SERVICE, MINI_APP_METHODS),
            service(SIGNING_SERVICE, SIGNING_METHODS),
            service("atri.messaging", &["send"]),
            service(
                "qq.login",
                &[
                    "status",
                    "login",
                    "submit_captcha",
                    "refresh_tickets",
                    "logout",
                ],
            ),
        ];
        descriptor.capabilities = [
            "config.read",
            "config.write",
            "storage.read",
            "storage.write",
            "services.register",
            "events.emit",
            "interaction",
            "tasks.spawn",
            "log",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        descriptor
    }

    async fn start(&self, ctx: Context) -> Result<(), ApiError> {
        if self.state.lock().await.is_some() {
            return Err(ApiError::new(
                "already_started",
                "QQ extension is already started",
            ));
        }
        let config = config::Config::load(&ctx).await?;
        let keystore = config.keystore(&ctx).await?;
        let client = Client::new(config.client_config(), keystore).map_err(protocol_error)?;
        signing::apply_initial(&client, config.signing)?;
        let transport: Arc<dyn ServiceClient> = client.clone();
        let operations = Arc::new(Operations::new(transport.clone()));
        let media = Arc::new(Media::new(transport.clone()));
        let services = Arc::new(Services {
            client: client.clone(),
            admin: Admin::from_operations(operations.clone()),
            operations,
            configured_uin: config.uin,
            guild: Guild::new(client.clone()),
            mini_app: MiniApp::new(client.clone()),
            messaging: Messaging::new(transport, media.clone()),
            media,
            signing: signing::SigningService::default(),
        });
        let mut login_events = client.login_events();
        let mut pushes = client.subscribe();
        *self.state.lock().await = Some(services.clone());
        let initial_account = (config.uin != 0).then(|| format!("qq:{}", config.uin));
        // Pre-authentication login actions must be addressable without guessing an account.
        bind_services(&ctx, None).await?;

        let event_ctx = ctx.clone();
        let event_cancel = ctx.cancellation_token();
        let events = ctx.spawn("QQ login events", async move {
            let mut current_account = initial_account;
            loop {
                let event = tokio::select! {
                    _ = event_cancel.cancelled() => return Ok(()),
                    event = login_events.recv() => match event {
                        Ok(event) => event,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                            return Err(ApiError::new("qq.login_events_lagged", format!("lost {count} login state events")));
                        }
                    }
                };
                match event {
                    LoginEvent::QrCode { url, .. } => {
                        event_ctx.interaction(InteractionRequest {
                            kind: "qr".into(), title: "QQ login — scan and confirm on your phone".into(),
                            content: url, account: current_account.clone(), secret: true,
                        }).await?;
                    }
                    LoginEvent::Online { uin, uid } => {
                        let account = format!("qq:{uin}");
                        current_account = Some(account.clone());
                        bind_services(&event_ctx, Some(&account)).await?;
                        event_ctx.emit(EventKind::BotOnline, Some(&account), &BotOnline {
                            bot: UserIdentity { account: account.clone(), id: if uid.is_empty() { format!("uin:{uin}") } else { format!("uid:{uid}") }, display_name: None },
                        }).await?;
                    }
                    LoginEvent::Offline { reason } => {
                        event_ctx.emit(EventKind::BotOffline, current_account.as_deref(), &BotOffline {
                            account: current_account.clone().unwrap_or_default(), reason,
                        }).await?;
                    }
                    LoginEvent::KeystoreChanged(keystore) => {
                        event_ctx.storage().write("data", "keystore.cbor", &encode(&keystore)?).await?;
                    }
                    LoginEvent::Challenge(challenge) => {
                        let (title, url) = match challenge {
                            LoginChallenge::Captcha { url } => ("QQ captcha — submit ticket/random through qq.login/submit_captcha", url),
                            LoginChallenge::NewDevice { url } => ("QQ new-device confirmation — complete verification in your browser", url),
                        };
                        event_ctx.interaction(InteractionRequest {
                            kind: "url".into(), title: title.into(),
                            content: url, account: current_account.clone(), secret: true,
                        }).await?;
                    }
                    LoginEvent::QrState(_) => {}
                }
            }
        })?;
        self.tasks.lock().await.push(events);

        let push_ctx = ctx.clone();
        let push_cancel = ctx.cancellation_token();
        let push_services = services.clone();
        let push_task = ctx.spawn("QQ push events", async move {
            loop {
                let packet = tokio::select! {
                    _ = push_cancel.cancelled() => return Ok(()),
                    packet = pushes.recv() => match packet {
                        Ok(packet) => packet,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                            push_ctx.log(LogLevel::Warn, &format!("QQ push receiver lost {count} packets")).await?;
                            continue;
                        }
                    }
                };
                let account = format!("qq:{}", push_services.client.account_uin());
                if let Some(events) = push_services.guild.decode_push(&packet).await {
                    for event in events {
                        guild_conversion::publish(&push_ctx, &account, event).await?;
                    }
                } else {
                    for event in push_services.messaging.decode_push(packet).await {
                        conversion::publish(&push_ctx, &account, event).await?;
                    }
                }
            }
        })?;
        self.tasks.lock().await.push(push_task);
        let login_task = ctx.spawn("QQ login", async move {
            client.login().await.map_err(protocol_error)?;
            Ok(())
        })?;
        self.tasks.lock().await.push(login_task);
        Ok(())
    }

    async fn on_service(&self, ctx: Context, call: ServiceCall) -> Result<Value, ApiError> {
        let outbound = authority::prepare(&call)?
            .map(|mut outbound| -> Result<_, ApiError> {
                if outbound.conversation.kind == ConversationKind::Channel {
                    outbound.content = atri_core::MessageContent::Text(
                        guild_conversion::text_content(outbound.content)?,
                    );
                }
                Ok(outbound)
            })
            .transpose()?;
        let services = self
            .state
            .lock()
            .await
            .clone()
            .ok_or_else(|| ApiError::new("not_started", "QQ client is not started"))?;
        let state = services.client.snapshot().await;
        if let Some(account) = call.account.as_deref() {
            let expected_uin = if state.keystore.uin == 0 {
                services.configured_uin
            } else {
                state.keystore.uin
            };
            if account != format!("qq:{expected_uin}") {
                return Err(ApiError::new(
                    "account_mismatch",
                    "service call targets a different QQ account",
                ));
            }
        }
        if call.service == SIGNING_SERVICE {
            return services.signing.call(
                &services.client,
                call.caller_kind,
                &call.method,
                call.args,
            );
        }
        if call.service == "qq.login" {
            return match call.method.as_str() {
                "status" => {
                    #[derive(Serialize)]
                    struct Status<'a> {
                        online: bool,
                        uin: u64,
                        uid: &'a str,
                        version: &'a str,
                        qua: &'a str,
                    }
                    to_value(&Status {
                        online: state.online,
                        uin: state.keystore.uin,
                        uid: &state.keystore.uid,
                        version: &state.profile.version,
                        qua: &state.profile.qua,
                    })
                }
                "login" => {
                    if state.online {
                        return Err(ApiError::new(
                            "already_online",
                            "QQ account is already registered online",
                        ));
                    }
                    let client = services.client.clone();
                    let task = ctx.spawn("QQ requested login", async move {
                        client.login().await.map_err(protocol_error)?;
                        Ok(())
                    })?;
                    #[derive(Serialize)]
                    struct Started {
                        task_id: u64,
                    }
                    let response = to_value(&Started { task_id: task.id() })?;
                    self.tasks.lock().await.push(task);
                    Ok(response)
                }
                "submit_captcha" => {
                    #[derive(Deserialize)]
                    struct Captcha {
                        ticket: String,
                        random: String,
                    }
                    let args: Captcha = from_value(&call.args)?;
                    services
                        .client
                        .submit_captcha(args.ticket, args.random)
                        .await
                        .map_err(protocol_error)?;
                    Ok(Value::Null)
                }
                "refresh_tickets" => {
                    if !state.online {
                        return Err(ApiError::new(
                            "qq.offline",
                            "ticket refresh requires an online QQ account",
                        ));
                    }
                    services
                        .client
                        .refresh_tickets()
                        .await
                        .map_err(protocol_error)?;
                    Ok(Value::Null)
                }
                "logout" => {
                    services.client.logout().await.map_err(protocol_error)?;
                    Ok(Value::Null)
                }
                _ => Err(ApiError::unsupported(format!("qq.login/{}", call.method))),
            };
        }
        if !state.online {
            return Err(ApiError::new(
                "qq.offline",
                "QQ account has not registered online",
            ));
        }
        match call.service.as_str() {
            MINI_APP_SERVICE => services
                .mini_app
                .call(&call.method, call.args)
                .await
                .map_err(protocol_error),
            GUILD_SERVICE => services
                .guild
                .call(&call.method, call.args)
                .await
                .map_err(protocol_error),
            CONTACTS_SERVICE => {
                match call.method.as_str() {
                    "client_key" => {
                        if !matches!(call.args, Value::Map(_) | Value::Null) {
                            return Err(protocol_error(Error::Malformed(
                                "Operation arguments must be a map".into(),
                            )));
                        }
                        return to_value(
                            &services.client.client_key().await.map_err(protocol_error)?,
                        );
                    }
                    "cookies" => {
                        #[derive(Deserialize)]
                        struct Domains {
                            domains: Vec<String>,
                        }
                        let args: Domains = from_value(&call.args)?;
                        return to_value(
                            &services
                                .client
                                .cookies(&args.domains)
                                .await
                                .map_err(protocol_error)?,
                        );
                    }
                    _ => {}
                }
                let result = services
                    .operations
                    .call(&call.method, call.args)
                    .await
                    .map_err(protocol_error)?;
                if call.method == FRIENDS_METHOD {
                    let friends: Vec<FriendInfo> = from_value(&result)?;
                    to_value(&FriendsResponse { friends })
                } else {
                    Ok(result)
                }
            }
            "qq.admin" => services
                .admin
                .call(&call.method, call.args)
                .await
                .map_err(protocol_error),
            "qq.messaging" => services
                .messaging
                .call(&call.method, call.args)
                .await
                .map_err(protocol_error),
            "qq.media" => services
                .media
                .call(&call.method, call.args)
                .await
                .map_err(protocol_error),
            "atri.messaging" if call.method == "send" => {
                conversion::send(
                    &services,
                    outbound.expect("generic send decoded before service state lookup"),
                )
                .await
            }
            _ => Err(ApiError::unsupported(format!(
                "{}/{}",
                call.service, call.method
            ))),
        }
    }

    async fn stop(&self, _ctx: Context) -> Result<(), ApiError> {
        let tasks = std::mem::take(&mut *self.tasks.lock().await);
        for task in &tasks {
            task.abort();
        }
        if let Some(services) = self.state.lock().await.take() {
            services.client.close().await;
        }
        let mut failure = None;
        for task in tasks {
            if let Err(error) = task.join().await {
                if error.code != "cancelled" && failure.is_none() {
                    failure = Some(error);
                }
            }
        }
        failure.map_or(Ok(()), Err)
    }
}
