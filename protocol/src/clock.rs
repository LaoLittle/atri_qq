use crate::{Error, Result};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Default)]
pub(crate) struct ServerClock {
    offset_nanos: i128,
}

impl ServerClock {
    pub(crate) fn correction(&mut self, server: u32, wall_now: SystemTime) {
        self.offset_nanos = i128::from(server) * 1_000_000_000 - Self::wall_nanos(wall_now);
    }

    pub(crate) fn unix_seconds(&self) -> Result<u32> {
        self.unix_seconds_at(SystemTime::now())
    }

    fn unix_seconds_at(&self, wall_now: SystemTime) -> Result<u32> {
        let nanos = Self::wall_nanos(wall_now) + self.offset_nanos;
        if nanos < 0 {
            return Err(Error::Malformed("Server clock precedes Unix epoch".into()));
        }
        u32::try_from(nanos / 1_000_000_000)
            .map_err(|_| Error::Malformed("Server clock exceeds u32 seconds".into()))
    }

    fn wall_nanos(wall_now: SystemTime) -> i128 {
        match wall_now.duration_since(UNIX_EPOCH) {
            Ok(elapsed) => elapsed.as_nanos() as i128,
            Err(error) => -(error.duration().as_nanos() as i128),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn default_clock_uses_wall_time_without_wrapping() {
        let clock = ServerClock::default();
        assert_eq!(clock.unix_seconds_at(UNIX_EPOCH).unwrap(), 0);
        assert_eq!(
            clock
                .unix_seconds_at(UNIX_EPOCH + Duration::new(42, 999_999_999))
                .unwrap(),
            42
        );
        assert!(clock.unix_seconds_at(UNIX_EPOCH - Duration::from_nanos(1)).is_err());
        assert_eq!(
            clock
                .unix_seconds_at(UNIX_EPOCH + Duration::new(u64::from(u32::MAX), 999_999_999))
                .unwrap(),
            u32::MAX
        );
        assert!(
            clock
                .unix_seconds_at(UNIX_EPOCH + Duration::from_secs(u64::from(u32::MAX) + 1))
                .is_err()
        );
    }

    #[test]
    fn positive_and_negative_corrections_preserve_subsecond_precision() {
        for server in [90, 110] {
            let wall = UNIX_EPOCH + Duration::new(100, 750_000_000);
            let mut clock = ServerClock::default();
            clock.correction(server, wall);
            assert_eq!(clock.unix_seconds_at(wall).unwrap(), server);
            assert_eq!(
                clock.unix_seconds_at(wall + Duration::from_nanos(999_999_999)).unwrap(),
                server
            );
            assert_eq!(
                clock.unix_seconds_at(wall + Duration::from_secs(1)).unwrap(),
                server + 1
            );
            assert_eq!(
                clock.unix_seconds_at(wall - Duration::from_nanos(1)).unwrap(),
                server - 1
            );
        }
    }

    #[test]
    fn new_correction_replaces_the_previous_offset() {
        let wall = UNIX_EPOCH + Duration::new(100, 750_000_000);
        let mut clock = ServerClock::default();
        clock.correction(110, wall);
        let later = wall + Duration::new(3, 500_000_000);
        clock.correction(90, later);
        assert_eq!(clock.unix_seconds_at(later).unwrap(), 90);
        assert_eq!(
            clock.unix_seconds_at(later + Duration::from_nanos(999_999_999)).unwrap(),
            90
        );
    }

    #[test]
    fn correction_can_recover_a_pre_epoch_wall_clock() {
        let wall = UNIX_EPOCH - Duration::new(100, 750_000_000);
        let mut clock = ServerClock::default();
        clock.correction(42, wall);
        assert_eq!(clock.unix_seconds_at(wall).unwrap(), 42);
        assert_eq!(clock.unix_seconds_at(wall + Duration::from_secs(1)).unwrap(), 43);
    }

    #[test]
    fn corrected_clock_rejects_epoch_underflow_and_seconds_overflow() {
        let wall = UNIX_EPOCH + Duration::new(100, 750_000_000);
        let mut clock = ServerClock::default();
        clock.correction(0, wall);
        assert_eq!(clock.unix_seconds_at(wall).unwrap(), 0);
        assert!(clock.unix_seconds_at(wall - Duration::from_nanos(1)).is_err());
        clock.correction(u32::MAX, wall);
        assert_eq!(
            clock.unix_seconds_at(wall + Duration::from_nanos(999_999_999)).unwrap(),
            u32::MAX
        );
        assert!(clock.unix_seconds_at(wall + Duration::from_secs(1)).is_err());
    }
}
