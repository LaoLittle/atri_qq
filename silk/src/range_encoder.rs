use crate::SilkError;

pub struct RangeEncoder {
    base: u32,
    range: u32,
    bytes: Vec<u8>,
}
impl RangeEncoder {
    pub fn new() -> Self {
        Self {
            base: 0,
            range: 65535,
            bytes: Vec::new(),
        }
    }
    fn carry(&mut self) -> Result<(), SilkError> {
        for byte in self.bytes.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                return Ok(());
            }
        }
        Err(SilkError::InvalidPacket)
    }
    pub fn symbol(&mut self, symbol: usize, cdf: &[u16]) -> Result<(), SilkError> {
        if symbol + 1 >= cdf.len() || cdf[symbol + 1] <= cdf[symbol] {
            return Err(SilkError::InvalidPacket);
        }
        let before = self.base;
        self.base = self.base.wrapping_add(self.range * cdf[symbol] as u32);
        let interval = self.range * (cdf[symbol + 1] - cdf[symbol]) as u32;
        if self.base < before {
            self.carry()?;
        }
        if interval & 0xff000000 != 0 {
            self.range = interval >> 16;
        } else {
            if interval & 0xffff0000 != 0 {
                self.range = interval >> 8;
            } else {
                self.range = interval;
                self.bytes.push((self.base >> 24) as u8);
                self.base <<= 8;
            }
            self.bytes.push((self.base >> 24) as u8);
            self.base <<= 8;
        }
        if self.bytes.len() > 1024 {
            return Err(SilkError::InvalidPacket);
        }
        Ok(())
    }
    pub fn finish(mut self) -> Result<Vec<u8>, SilkError> {
        let bits = self.bytes.len() * 8 + (self.range - 1).leading_zeros() as usize - 14;
        let length = bits.div_ceil(8);
        let store = bits - self.bytes.len() * 8;
        let mut base = (self.base >> 8).wrapping_add(0x00800000 >> (store - 1));
        base &= u32::MAX << (24 - store);
        if base & 0x01000000 != 0 {
            self.carry()?;
        }
        self.bytes.push((base >> 16) as u8);
        if store > 8 {
            self.bytes.push((base >> 8) as u8);
        }
        self.bytes.resize(length, 0);
        if bits & 7 != 0 {
            self.bytes[length - 1] |= 0xff >> (bits & 7);
        }
        if length > 1024 {
            return Err(SilkError::InvalidPacket);
        }
        Ok(self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::RangeEncoder;
    use crate::range_coder::RangeCoderState;
    #[test]
    fn mixed_symbols_roundtrip_through_legacy_range_decoder() {
        let cdf = [0, 100, 24000, 50000, 65535];
        let mut encoder = RangeEncoder::new();
        let symbols: Vec<_> = (0..400).map(|i| (i * i + i / 7) % 4).collect();
        for &symbol in &symbols {
            encoder.symbol(symbol, &cdf).unwrap();
        }
        let packet = encoder.finish().unwrap();
        let mut decoder = RangeCoderState::default();
        decoder.dec_init(&packet);
        for symbol in symbols {
            assert_eq!(decoder.decode_symbol(&cdf, 2), symbol);
        }
        assert_eq!(decoder.error, 0);
    }
}
