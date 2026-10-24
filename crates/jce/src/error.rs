use crate::types::Type;
use std::fmt::{Display, Formatter};
use std::str::Utf8Error;
use std::string::FromUtf8Error;

pub type DecodeResult<T> = Result<T, DecodeError>;

#[derive(Debug)]
pub enum DecodeError {
    IncorrectType {
        struct_name: &'static str,
        field: &'static str,
        val_type: u8,
    },
    InvalidType,
    Eof,
    InvalidLength,
    DepthLimit,
    MissingField {
        struct_name: &'static str,
        field: &'static str,
    },
    String(Utf8Error),
}

impl Display for DecodeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IncorrectType {
                struct_name,
                field,
                val_type,
            } => {
                f.write_str("incorrect type(")?;
                if let Some(t) = Type::from_u8(*val_type) {
                    Display::fmt(&t, f)?;
                } else {
                    Display::fmt(&val_type, f)?;
                }

                write!(f, ") of field {} in struct {}", field, struct_name)?;

                Ok(())
            }
            Self::InvalidType => f.write_str("invalid type"),
            Self::Eof => f.write_str("unexpected eof"),
            Self::InvalidLength => f.write_str("invalid length"),
            Self::DepthLimit => f.write_str("JCE nesting limit exceeded"),
            Self::MissingField { struct_name, field } => {
                write!(f, "missing field {} in struct {}", field, struct_name)
            }
            Self::String(e) => Display::fmt(e, f),
        }
    }
}

impl std::error::Error for DecodeError {}

impl From<Utf8Error> for DecodeError {
    fn from(err: Utf8Error) -> Self {
        Self::String(err)
    }
}

impl From<FromUtf8Error> for DecodeError {
    fn from(err: FromUtf8Error) -> Self {
        Self::from(err.utf8_error())
    }
}

pub type EncodeResult<T> = Result<T, EncodeError>;

#[derive(Debug)]
pub struct EncodeError;

impl Display for EncodeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("encode length exceeds buffer")
    }
}

impl std::error::Error for EncodeError {}
