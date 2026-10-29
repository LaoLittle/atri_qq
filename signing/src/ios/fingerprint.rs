use md5::{Digest, Md5};

#[derive(Clone, Copy, Default)]
pub struct Resources<'a> {
    pub machine: Option<&'a [u8]>,
    pub model: Option<&'a [u8]>,
    pub cache_line_size: Option<&'a [u8]>,
    pub l1_instruction_cache_size: Option<&'a [u8]>,
    pub l1_data_cache_size: Option<&'a [u8]>,
    pub l2_cache_size: Option<&'a [u8]>,
    pub cpu_count: Option<&'a [u8]>,
    pub cpu_frequency: Option<&'a [u8]>,
    pub memory_size: Option<&'a [u8]>,
    pub private_var_stat: Option<&'a [u8; 144]>,
    pub mobile_preferences_stat: Option<&'a [u8; 144]>,
}

impl Resources<'_> {
    pub fn digest(&self) -> [u8; 32] {
        let mut hash = Md5::new();
        let mut remaining = 128;
        for bytes in [
            self.machine,
            self.model,
            self.cache_line_size,
            self.l1_instruction_cache_size,
            self.l1_data_cache_size,
            self.l2_cache_size,
            self.cpu_count,
            self.cpu_frequency,
            self.memory_size,
        ]
        .into_iter()
        .flatten()
        {
            if bytes.len() <= remaining {
                hash.update(bytes);
                remaining -= bytes.len();
            }
        }
        for stat in [self.private_var_stat, self.mobile_preferences_stat]
            .into_iter()
            .flatten()
        {
            if remaining >= 24 {
                hash.update(&stat[8..16]);
                hash.update(&stat[80..96]);
                remaining -= 24;
            }
        }
        let mut output = [0; 32];
        hex::encode_to_slice(hash.finalize(), &mut output).expect("fixed-size fingerprint digest");
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resources<'a>() -> Resources<'a> {
        Resources {
            machine: Some(b"MACH\0"),
            model: Some(b"MODL\0"),
            cache_line_size: Some(b"abcd"),
            l1_instruction_cache_size: Some(b"1234"),
            l1_data_cache_size: Some(b"!\"#$"),
            l2_cache_size: Some(b"ABCD"),
            cpu_count: Some(&[3, 0, 0, 0]),
            cpu_frequency: Some(&[17, 18, 19, 20, 21, 22, 23, 24]),
            memory_size: Some(b"QRSTUVWX"),
            ..Default::default()
        }
    }

    #[test]
    fn original_hash_preserves_raw_nuls_order_and_both_stat_regions() {
        let stat = std::array::from_fn(|i| i as u8);
        let mut second = stat;
        second[8] = 0xa8;
        second[80] = 0xb0;
        let source = Resources {
            private_var_stat: Some(&stat),
            mobile_preferences_stat: Some(&second),
            ..resources()
        };
        assert_eq!(&source.digest(), b"0bb65d1ee24d17e395c8735180195931");
    }

    #[test]
    fn stat_fits_atomically_at_128_bytes_and_later_stat_is_not_partially_hashed() {
        let machine = [b'M'; 63];
        let stat = std::array::from_fn(|i| i as u8);
        let mut second = stat;
        second[8] = 0xa8;
        second[80] = 0xb0;
        let source = Resources {
            machine: Some(&machine),
            private_var_stat: Some(&stat),
            mobile_preferences_stat: Some(&second),
            ..resources()
        };
        assert_eq!(&source.digest(), b"a356c5e72ed2236c17cf4395a4c166b3");
    }

    #[test]
    fn oversized_sysctl_is_skipped_without_blocking_later_resources() {
        let machine = [b'M'; 129];
        let stat = std::array::from_fn(|i| i as u8);
        let mut second = stat;
        second[8] = 0xa8;
        second[80] = 0xb0;
        let source = Resources {
            machine: Some(&machine),
            private_var_stat: Some(&stat),
            mobile_preferences_stat: Some(&second),
            ..resources()
        };
        assert_eq!(&source.digest(), b"839bac1764f19fdca1df026e48a9c7d2");
    }
}
