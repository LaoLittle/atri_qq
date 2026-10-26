use std::{
    io,
    sync::LazyLock,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use rand::TryRng;

use super::compact::CompactSource;

static MONOTONIC_ORIGIN: LazyLock<Instant> = LazyLock::new(Instant::now);

#[derive(Default)]
pub struct SystemSource;

impl SystemSource {
    pub fn steady_nanos(&mut self) -> io::Result<i64> {
        i64::try_from(MONOTONIC_ORIGIN.elapsed().as_nanos())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    pub fn unix_micros(&mut self) -> io::Result<i64> {
        let (duration, negative) = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => (duration, false),
            Err(error) => (error.duration(), true),
        };
        let value = i64::try_from(duration.as_micros())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        Ok(if negative { -value } else { value })
    }

    pub fn entropy_word(&mut self) -> io::Result<u32> {
        rand::rngs::SysRng.try_next_u32().map_err(io::Error::other)
    }
}

impl CompactSource for SystemSource {
    type Error = io::Error;

    fn steady_clock_nanos(&mut self) -> io::Result<i64> {
        self.steady_nanos()
    }

    fn system_clock_micros(&mut self) -> io::Result<i64> {
        self.unix_micros()
    }

    fn random_device_word(&mut self) -> io::Result<Option<u32>> {
        self.entropy_word().map(Some)
    }
}

impl super::trailer::SeedSource for SystemSource {
    type Error = io::Error;

    fn clock_nanoseconds(&mut self) -> io::Result<u64> {
        self.steady_nanos().map(|value| value as u64)
    }

    fn urandom_word(&mut self) -> io::Result<u32> {
        self.entropy_word()
    }
}

impl super::signer::Source for SystemSource {
    fn process_context(&mut self) -> io::Result<[u8; 16]> {
        let mut bytes = [0; 16];
        rand::rngs::SysRng
            .try_fill_bytes(&mut bytes)
            .map_err(io::Error::other)?;
        Ok(bytes)
    }

    fn time_seconds(&mut self) -> io::Result<i64> {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => i64::try_from(duration.as_secs())
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)),
            Err(error) => {
                let duration = error.duration();
                let seconds = i64::try_from(duration.as_secs())
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                (-seconds)
                    .checked_sub(i64::from(duration.subsec_nanos() != 0))
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "Unix seconds overflow")
                    })
            }
        }
    }

    fn process_id(&mut self) -> io::Result<i32> {
        Ok(std::process::id() as i32)
    }
}
