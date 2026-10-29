use super::IosVirtualConfig;
use crate::{
    Error, Result,
    models::SessionState,
    proto::{auth, guild},
};
use bytes::Bytes;
use rand::RngExt;

pub(crate) fn build(
    state: &SessionState,
    reconnect: bool,
    model: &IosVirtualConfig,
    now_seconds: u64,
    background_since: Option<u64>,
) -> Result<auth::InfoSyncRequest> {
    let device = model.device(&state.profile)?;
    let application = &model.application;
    let resources = application.heartbeat_resources()?;
    let background_time = if application.foreground {
        0
    } else {
        let since = background_since.ok_or_else(|| {
            Error::Malformed(
                "Virtual iOS background entry time is unavailable for this client".into(),
            )
        })?;
        now_seconds.saturating_sub(since) as u32
    };
    let effective_trigger = application.user_trigger && !reconnect;
    let saved = state.keystore.ios_virtual_state.as_ref().ok_or_else(|| {
        Error::Malformed("Virtual iOS registration requires initialized device state".into())
    })?;
    let mut memory_increment = saved
        .guild_sync
        .get(&state.keystore.uin)
        .map(|cursor| cursor.request())
        .unwrap_or_default();
    memory_increment.last_msg_time.get_or_insert(0);
    Ok(auth::InfoSyncRequest {
        sync_flag: Some(1759),
        request_random: Some(rand::rng().random_range(0..=i32::MAX as u32)),
        current_active_status: Some(2),
        group_last_message_time: Some(0),
        sync: Some(auth::SyncState {
            current_cookie: Some(Bytes::new()),
            last_message_time: Some(0),
            previous_cookie: Some(Bytes::new()),
        }),
        group_code: None,
        platform_extension: None,
        register: Some(auth::RegisterInfo {
            guid: Some(hex::encode(&state.keystore.guid)),
            kick_pc: Some(u32::from(!application.keep_pc_online)),
            version: Some(state.profile.version.clone()),
            first_register: Some(u32::from(!effective_trigger)),
            locale: Some(model.registration_locale()),
            device: Some(auth::RegisterDevice {
                name: Some(model.device_name(state.profile.platform).to_owned()),
                kernel: Some(device.hardware_model),
                os_version: Some(device.system_version),
                brand: Some("apple".into()),
                os: Some(device.system_name),
            }),
            mute: Some(u32::from(application.mute)),
            vendor_type: Some(0),
            user_trigger: Some(u32::from(effective_trigger)),
            business: Some(auth::RegisterBusiness {
                notify_switch: Some(u32::from(application.notifications_enabled)),
                bound_uin_notify_switch: Some(u32::from(
                    application.bound_account_notifications_enabled,
                )),
            }),
            battery_status: Some(resources.battery_status),
            set_status: None,
            flags: Some(auth::RegisterFlags {
                silence_status: Some(resources.silence_status),
                silent_version: Some(resources.silent_version),
            }),
            scene: Some(if reconnect { 4 } else { 7 }),
            background_time: Some(background_time),
            is_chat_on_focus: Some(application.chat_focused),
        }),
        guild_sync: Some(guild::GuildSyncRequest {
            pull_scene: Some(if saved.registered_accounts.contains(&state.keystore.uin) {
                2
            } else {
                0
            }),
            memory_increment: Some(memory_increment),
        }),
        app: Some(auth::AppState {
            is_delay_req: Some(0),
            app_status: Some(application.app_status),
            silence_status: Some(application.silence_status),
        }),
        ai_sync: Some(auth::AiSyncRequest {
            businesses: vec![auth::AiSyncCursor {
                business_id: Some(0),
                latest_message_time: Some(0),
                latest_change_time: Some(0),
                change_sync_enabled: Some(true),
            }],
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ios_device::IosVirtualRuntime,
        models::{ClientConfig, Keystore, Profile},
    };
    use std::sync::Arc;

    fn initialize(
        profile: Profile,
        model: Arc<IosVirtualConfig>,
    ) -> (SessionState, ClientConfig, IosVirtualRuntime) {
        let mut keystore = Keystore {
            uin: 123456,
            device_name: "unchanged-desktop-name".into(),
            ..Default::default()
        };
        let (runtime, device) =
            IosVirtualRuntime::initialize(model.clone(), &profile, &mut keystore, 1_000_000_000)
                .unwrap();
        let config = ClientConfig {
            profile: profile.clone(),
            ios_virtual: Some(model),
            ios_device: Some(device),
            ..Default::default()
        };
        (
            SessionState {
                profile,
                keystore,
                machine_id: "unused-desktop-machine".into(),
                online: false,
            },
            config,
            runtime,
        )
    }

    #[test]
    fn registration_success_is_account_scoped_and_does_not_reset_the_session_trigger() {
        for profile in [Profile::iphone(), Profile::ipad()] {
            let (mut state, config, runtime) =
                initialize(profile, Arc::new(IosVirtualConfig::default()));
            let model = config.ios_virtual.as_ref().unwrap();
            for _ in 0..2 {
                let request =
                    build(&state, false, model, 1030, runtime.background_since()).unwrap();
                assert_eq!(request.register.unwrap().first_register, Some(0));
                assert_eq!(request.guild_sync.unwrap().pull_scene, Some(0));
            }
            assert!(
                state
                    .keystore
                    .ios_virtual_state
                    .as_mut()
                    .unwrap()
                    .confirm_registration(123456)
            );
            assert!(
                !state
                    .keystore
                    .ios_virtual_state
                    .as_mut()
                    .unwrap()
                    .confirm_registration(123456)
            );
            let restarted = build(&state, false, model, 1030, None).unwrap();
            assert_eq!(restarted.register.unwrap().user_trigger, Some(1));
            assert_eq!(restarted.guild_sync.unwrap().pull_scene, Some(2));
            let reconnected = build(&state, true, model, 1030, None).unwrap();
            assert_eq!(reconnected.register.unwrap().user_trigger, Some(0));
            state.keystore.uin = 654321;
            assert_eq!(
                build(&state, false, model, 1030, None)
                    .unwrap()
                    .guild_sync
                    .unwrap()
                    .pull_scene,
                Some(0)
            );
            state.keystore.uin = 123456;
            assert_eq!(
                build(&state, false, model, 1030, None)
                    .unwrap()
                    .guild_sync
                    .unwrap()
                    .pull_scene,
                Some(2)
            );
        }
    }

    #[test]
    fn background_clock_is_client_scoped_saturating_and_native_width() {
        let mut model = IosVirtualConfig::default();
        model.application.user_trigger = false;
        model.application.foreground = false;
        let model = Arc::new(model);
        let (state, _, runtime) = initialize(Profile::ipad(), model.clone());
        for reconnect in [false, true] {
            let register = build(&state, reconnect, &model, 1031, runtime.background_since())
                .unwrap()
                .register
                .unwrap();
            assert_eq!(register.first_register, Some(1));
            assert_eq!(register.user_trigger, Some(0));
            assert_eq!(register.background_time, Some(31));
        }
        assert!(build(&state, false, &model, 1031, None).is_err());
        assert_eq!(
            build(&state, false, &model, 999, Some(1000))
                .unwrap()
                .register
                .unwrap()
                .background_time,
            Some(0)
        );
        assert_eq!(
            build(&state, false, &model, 1000 + (1_u64 << 32) + 5, Some(1000))
                .unwrap()
                .register
                .unwrap()
                .background_time,
            Some(5)
        );
        let (runtime, _) = IosVirtualRuntime::initialize(
            model.clone(),
            &state.profile,
            &mut state.keystore.clone(),
            2_000_000_000,
        )
        .unwrap();
        assert_eq!(runtime.background_since(), Some(2000));
        let desktop = SessionState {
            profile: Profile::default(),
            ..state
        };
        assert!(build(&desktop, false, &model, 1031, Some(1000)).is_err());
    }
}
