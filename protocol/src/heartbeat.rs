#[derive(Clone, Copy, Default)]
pub struct IosResources {
    pub silence_status: u32,
    pub silent_version: u32,
    pub battery_status: u32,
}

pub trait IosSource: Send + Sync {
    fn resources(&self) -> IosResources;
    fn clock_millis(&self) -> Option<u64>;
}

impl IosSource for IosResources {
    fn resources(&self) -> IosResources {
        *self
    }

    fn clock_millis(&self) -> Option<u64> {
        None
    }
}

pub fn encode_ios_battery(level: f32, state: i64) -> crate::Result<u32> {
    if level.is_nan() {
        return Err(crate::Error::Malformed("iOS batteryLevel is NaN".into()));
    }
    let percent = (level.clamp(0.0, 1.0) * 100.0) as u32;
    Ok(percent | if state > 1 { 0x80 } else { 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_uikit_conversion_preserves_unknown_level_charging_and_truncation() {
        for (bits, state, expected) in [
            (0xbf80_0000, 0, 0),
            (0xbf80_0000, 2, 128),
            (0x3f19_5810, 1, 59),
            (0x3f99_999a, 3, 228),
            (0x7f80_0000, 2, 228),
            (0xff80_0000, 0, 0),
        ] {
            assert_eq!(
                encode_ios_battery(f32::from_bits(bits), state).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn nan_is_an_error_not_an_unknown_or_healthy_zero() {
        assert!(matches!(
            encode_ios_battery(f32::NAN, 0),
            Err(crate::Error::Malformed(_))
        ));
    }
}
