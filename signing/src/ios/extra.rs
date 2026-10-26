use std::{error::Error, fmt};

use bytes::{Bytes, BytesMut};
use prost::Message;

use super::proto::{EstablishShareKeyBody, SecureAccessBody, SecurityExtra};

pub const SECURE_ACCESS_COMMAND: &str = "trpc.o3.ecdh_access.EcdhAccess.SsoSecureAccess";
pub const ESTABLISH_SHARE_KEY_COMMAND: &str = "trpc.o3.ecdh_access.EcdhAccess.SsoEstablishShareKey";
pub const SECURE_A2_ACCESS_COMMAND: &str = "trpc.o3.ecdh_access.EcdhAccess.SsoSecureA2Access";
pub const SECURE_A2_ESTABLISH_COMMAND: &str = "trpc.o3.ecdh_access.EcdhAccess.SsoSecureA2Establish";

#[derive(Debug)]
pub enum ExtraError {
    MissingChannelState,
    MalformedBody(prost::DecodeError),
}

impl fmt::Display for ExtraError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingChannelState => {
                f.write_str("empty special-command body requires actual 32-byte channel state")
            }
            Self::MalformedBody(error) => write!(f, "malformed special-command body: {error}"),
        }
    }
}

impl Error for ExtraError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::MissingChannelState => None,
            Self::MalformedBody(error) => Some(error),
        }
    }
}

pub fn build_extra(
    command: impl AsRef<[u8]>,
    body: Bytes,
    qua: Bytes,
    raw_xwid: Bytes,
    channel_state: Option<&[u8; 32]>,
) -> Result<Bytes, ExtraError> {
    let command = command.as_ref();
    let access = command == SECURE_ACCESS_COMMAND.as_bytes()
        || command == SECURE_A2_ACCESS_COMMAND.as_bytes();
    let establish = command == ESTABLISH_SHARE_KEY_COMMAND.as_bytes()
        || command == SECURE_A2_ESTABLISH_COMMAND.as_bytes();

    let command_value = if !access && !establish {
        Bytes::new()
    } else if body.is_empty() {
        Bytes::copy_from_slice(channel_state.ok_or(ExtraError::MissingChannelState)?)
    } else {
        let selected_values = if access {
            SecureAccessBody::decode(body)
                .map_err(ExtraError::MalformedBody)?
                .selected_values
        } else {
            EstablishShareKeyBody::decode(body)
                .map_err(ExtraError::MalformedBody)?
                .selected_values
        };
        concatenate(selected_values)
    };

    Ok(SecurityExtra {
        command_value,
        qua,
        raw_xwid,
    }
    .encode_to_vec()
    .into())
}

fn concatenate(mut values: Vec<Bytes>) -> Bytes {
    values.retain(|value| !value.is_empty());
    match values.len() {
        0 => Bytes::new(),
        1 => values.pop().expect("one selected value"),
        _ => {
            let length = values.iter().map(Bytes::len).sum();
            let mut combined = BytesMut::with_capacity(length);
            for value in values {
                combined.extend_from_slice(&value);
            }
            combined.freeze()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_exact_binary_fields_in_native_order() {
        let extra = build_extra(
            SECURE_ACCESS_COMMAND,
            Bytes::from_static(&[0x1a, 2, 0, 0xff]),
            Bytes::from_static(&[0xff, 0]),
            Bytes::from_static(&[0x80, 0]),
            None,
        )
        .unwrap();
        assert_eq!(
            extra.as_ref(),
            &[0x0a, 2, 0, 0xff, 0x12, 2, 0xff, 0, 0x1a, 2, 0x80, 0]
        );
    }

    #[test]
    fn all_special_commands_concatenate_repeated_values_in_wire_order() {
        for (command, tag) in [
            (SECURE_ACCESS_COMMAND, 0x1a),
            (SECURE_A2_ACCESS_COMMAND, 0x1a),
            (ESTABLISH_SHARE_KEY_COMMAND, 0x32),
            (SECURE_A2_ESTABLISH_COMMAND, 0x32),
        ] {
            let body = Bytes::from(vec![
                tag, 2, b'a', 0, 0x08, 7, tag, 0, 0x22, 1, b'x', tag, 2, 0xff, b'b',
            ]);
            let extra = build_extra(command, body, Bytes::new(), Bytes::new(), None).unwrap();
            assert_eq!(extra.as_ref(), &[0x0a, 4, b'a', 0, 0xff, b'b']);
        }
    }

    #[test]
    fn non_special_commands_do_not_parse_the_body_or_request_state() {
        for command in [
            b"MessageSvc.PbSendMsg".as_slice(),
            b"\xff\0binary".as_slice(),
            b"trpc.o3.ecdh_access.EcdhAccess.SsoSecureAccess\0".as_slice(),
            b"trpc.o3.ecdh_access.EcdhAccess.SsoEstablishA2ShareKey".as_slice(),
        ] {
            for body in [Bytes::new(), Bytes::from_static(&[0xff])] {
                let extra = build_extra(
                    command,
                    body,
                    Bytes::from_static(b"q"),
                    Bytes::from_static(b"raw"),
                    None,
                )
                .unwrap();
                assert_eq!(extra.as_ref(), b"\x12\x01q\x1a\x03raw");
            }
        }
    }

    #[test]
    fn omits_every_empty_field() {
        let extra =
            build_extra("ordinary", Bytes::new(), Bytes::new(), Bytes::new(), None).unwrap();
        assert!(extra.is_empty());
        let extra = build_extra(
            SECURE_ACCESS_COMMAND,
            Bytes::from_static(&[0x1a, 0]),
            Bytes::new(),
            Bytes::from_static(b"x"),
            None,
        )
        .unwrap();
        assert_eq!(extra.as_ref(), b"\x1a\x01x");
    }

    #[test]
    fn nonempty_body_without_selected_fields_does_not_use_channel_state() {
        for command in [SECURE_ACCESS_COMMAND, ESTABLISH_SHARE_KEY_COMMAND] {
            let extra = build_extra(
                command,
                Bytes::from_static(&[0x08, 1]),
                Bytes::new(),
                Bytes::new(),
                Some(&[0xab; 32]),
            )
            .unwrap();
            assert!(extra.is_empty());
        }
    }

    #[test]
    fn empty_special_body_requires_actual_channel_state() {
        let state = [0xab; 32];
        for command in [
            SECURE_ACCESS_COMMAND,
            SECURE_A2_ACCESS_COMMAND,
            ESTABLISH_SHARE_KEY_COMMAND,
            SECURE_A2_ESTABLISH_COMMAND,
        ] {
            let error =
                build_extra(command, Bytes::new(), Bytes::new(), Bytes::new(), None).unwrap_err();
            assert!(matches!(error, ExtraError::MissingChannelState));
            let extra = build_extra(
                command,
                Bytes::new(),
                Bytes::new(),
                Bytes::new(),
                Some(&state),
            )
            .unwrap();
            assert_eq!(&extra[..2], &[0x0a, 32]);
            assert_eq!(&extra[2..], &state);
        }
    }

    #[test]
    fn malformed_special_bodies_return_decode_errors() {
        for command in [SECURE_ACCESS_COMMAND, ESTABLISH_SHARE_KEY_COMMAND] {
            for body in [
                Bytes::from_static(&[0xff]),
                Bytes::from_static(&[0x1a, 2, 1]),
                Bytes::from_static(&[0x32, 2, 1]),
                Bytes::from_static(&[0]),
            ] {
                assert!(matches!(
                    build_extra(command, body, Bytes::new(), Bytes::new(), None),
                    Err(ExtraError::MalformedBody(_))
                ));
            }
        }
        for (command, wrong_wire_type) in [
            (SECURE_ACCESS_COMMAND, 0x18),
            (ESTABLISH_SHARE_KEY_COMMAND, 0x30),
        ] {
            assert!(matches!(
                build_extra(
                    command,
                    Bytes::from(vec![wrong_wire_type, 1]),
                    Bytes::new(),
                    Bytes::new(),
                    None,
                ),
                Err(ExtraError::MalformedBody(_))
            ));
        }
    }
}
