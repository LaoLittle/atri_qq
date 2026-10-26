use std::num::Wrapping;

use bytes::Bytes;
use prost::Message;

use super::{
    proto::{DeviceTokenItem, NativeTokenItem, NativeTokenProperties},
    salsa8,
};

#[derive(Clone, PartialEq, Eq)]
pub struct NativePayloadResources {
    pub material: [u8; 16],
    pub material_seed: u8,
    pub fingerprint: [u8; 32],
    pub unix_seconds: u64,
    pub process_id: i32,
    pub allocation_low32: u32,
}

impl NativePayloadResources {
    pub fn encode(&self, items: &[DeviceTokenItem]) -> Bytes {
        let mut permutation: [u32; 300] = std::array::from_fn(|i| i as u32);
        let mut random = self.unix_seconds as u32;
        for i in (1..permutation.len()).rev() {
            random = ((u64::from(if random == 0 { 123459876 } else { random }) * 16807)
                % 2147483647) as u32;
            permutation.swap(i, random as usize % (i + 1));
        }
        let mut mapping = [0u8; 901];
        for i in 0..300 {
            decimal_index(&mut mapping[i * 3..i * 3 + 3], i as u32);
        }
        let mut properties = NativeTokenProperties {
            items: Vec::with_capacity(items.len() + 4),
        };
        for item in items {
            let original = item.id as u32;
            let id = if let Some(&mapped) = permutation.get(original as usize) {
                decimal_index(
                    &mut mapping[mapped as usize * 3..mapped as usize * 3 + 3],
                    original,
                );
                mapped
            } else {
                original
            };
            if id != 0 || !item.data.is_empty() {
                properties.items.push(NativeTokenItem {
                    id,
                    data: item.data.clone(),
                });
            }
        }
        let fingerprint_id = permutation[70];
        decimal_index(
            &mut mapping[fingerprint_id as usize * 3..fingerprint_id as usize * 3 + 3],
            70,
        );
        let mut nonce = self.material;
        let mut state = Wrapping(self.material_seed);
        for (i, byte) in nonce.iter_mut().enumerate() {
            *byte ^= state.0 ^ (Wrapping(i as u8) * Wrapping(7)).0;
            state = state * Wrapping(13) + Wrapping(17);
        }
        properties.items.extend([
            NativeTokenItem {
                id: 998,
                data: Bytes::copy_from_slice(&nonce),
            },
            NativeTokenItem {
                id: fingerprint_id,
                data: Bytes::copy_from_slice(&self.fingerprint),
            },
            NativeTokenItem {
                id: 999,
                data: Bytes::copy_from_slice(&mapping),
            },
            NativeTokenItem {
                id: 997,
                data: Bytes::from(self.process_id.to_string()),
            },
        ]);
        let mask = (Wrapping(self.allocation_low32) + Wrapping(self.process_id as u32)).0 as u8;
        let header = nonce.map(|byte| byte ^ mask);
        let mut output = Vec::with_capacity(16 + properties.encoded_len());
        output.extend_from_slice(&header);
        properties
            .encode(&mut output)
            .expect("Vec accepts protobuf encoding");
        let mut key = [0x3e, 0x3b, 0xf0, 0x0e, 0xa4, 0xed, 0x26, 0x2a, 0, 0, 0, 0];
        key[8..].copy_from_slice(&header[..4]);
        salsa8::apply_keystream(&key, &mut output[16..]);
        output.into()
    }
}

impl std::fmt::Debug for NativePayloadResources {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativePayloadResources")
            .finish_non_exhaustive()
    }
}

fn decimal_index(output: &mut [u8], value: u32) {
    output[0] = b'0' + (value / 100) as u8;
    output[1] = b'0' + ((value / 10) % 10) as u8;
    output[2] = b'0' + (value % 10) as u8;
}

#[cfg(test)]
mod tests {
    use super::*;
    use md5::{Digest, Md5};

    fn resources() -> NativePayloadResources {
        NativePayloadResources {
            material: [
                0x8b, 0xbb, 0xa1, 0xc6, 0x39, 0x49, 0x5b, 0x29, 0x7e, 0x9f, 0x59, 0xb4, 0xdd, 0xa7,
                0xa5, 0x52,
            ],
            material_seed: 215,
            fingerprint: *b"efcbf0da7fd8d81232fe2e7b912f3979",
            unix_seconds: 1700000000,
            process_id: 4242,
            allocation_low32: 432880,
        }
    }

    fn decode(encoded: &[u8]) -> NativeTokenProperties {
        let mut key = [0x3e, 0x3b, 0xf0, 0x0e, 0xa4, 0xed, 0x26, 0x2a, 0, 0, 0, 0];
        key[8..].copy_from_slice(&encoded[..4]);
        let mut plaintext = encoded[16..].to_vec();
        salsa8::apply_keystream(&key, &mut plaintext);
        NativeTokenProperties::decode(plaintext.as_slice()).unwrap()
    }

    #[test]
    fn complete_native_arm64_payload_matches_all_stream_blocks_and_tail() {
        let encoded = resources().encode(&[DeviceTokenItem {
            id: 24,
            data: Bytes::from_static(&[0; 16]),
        }]);
        assert_eq!(encoded.len(), 1021);
        assert_eq!(
            &encoded[..16],
            &[
                0xde, 0xc2, 0xf0, 0x1b, 0x74, 0x20, 0xca, 0x6c, 0x4b, 0x76, 0xc8, 0x19, 0x00, 0xde,
                0x74, 0x37
            ]
        );
        assert_eq!(
            Md5::digest(&encoded).as_slice(),
            &[
                0xe4, 0xce, 0xb1, 0xd2, 0x2e, 0x56, 0xc8, 0xd6, 0x88, 0x05, 0xbb, 0x61, 0xa1, 0x35,
                0x7c, 0xe8
            ]
        );
    }

    #[test]
    fn unsigned_ids_boundaries_and_duplicate_internal_ids_keep_native_order() {
        let input = [-1, -2, 299, 300, 301, i32::MAX, i32::MIN, 998];
        let items: Vec<_> = input
            .into_iter()
            .map(|id| DeviceTokenItem {
                id,
                data: Bytes::from_static(b"\0\x80"),
            })
            .collect();
        let decoded = decode(&resources().encode(&items));
        assert_eq!(
            decoded.items.iter().map(|item| item.id).collect::<Vec<_>>(),
            [
                u32::MAX,
                u32::MAX - 1,
                12,
                300,
                301,
                i32::MAX as u32,
                1 << 31,
                998,
                998,
                103,
                999,
                997
            ]
        );
        assert_eq!(decoded.items[7].data, b"\0\x80".as_slice());
        assert_eq!(
            decoded.items[8].data,
            &[
                0x5c, 0x40, 0x72, 0x99, 0xf6, 0xa2, 0x48, 0xee, 0xc9, 0xf4, 0x4a, 0x9b, 0x82, 0x5c,
                0xf6, 0xb5
            ][..]
        );
        assert_eq!(&decoded.items[10].data[36..39], b"299");
        assert_eq!(&decoded.items[10].data[900..], b"\0");
    }

    #[test]
    fn zero_mapped_empty_item_is_omitted_but_its_inverse_mapping_survives() {
        let empty = decode(&resources().encode(&[DeviceTokenItem {
            id: 101,
            data: Bytes::new(),
        }]));
        assert_eq!(
            empty.items.iter().map(|item| item.id).collect::<Vec<_>>(),
            [998, 103, 999, 997]
        );
        assert_eq!(&empty.items[2].data[..12], b"101001002003");
        let nonempty = decode(&resources().encode(&[DeviceTokenItem {
            id: 101,
            data: Bytes::from_static(b"x"),
        }]));
        assert_eq!(nonempty.items[0].encode_to_vec(), b"\x12\x01x");
    }

    #[test]
    fn next_second_relabels_fingerprint_and_updates_its_inverse_mapping() {
        let mut source = resources();
        source.unix_seconds += 1;
        let decoded = decode(&source.encode(&[DeviceTokenItem {
            id: 24,
            data: Bytes::from_static(&[0; 16]),
        }]));
        assert_eq!(
            decoded.items.iter().map(|item| item.id).collect::<Vec<_>>(),
            [133, 998, 84, 999, 997]
        );
        assert_eq!(&decoded.items[3].data[84 * 3..85 * 3], b"070");
        assert_eq!(&decoded.items[3].data[133 * 3..134 * 3], b"024");
    }
}
