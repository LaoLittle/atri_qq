use atri_qq_silk::{decode_silk, encode_silk, inspect_silk};

fn samples(bytes: &[u8]) -> Vec<i16> {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| i16::from_le_bytes([b[0], b[1]]))
        .collect()
}
fn signal_to_error(reference: &[i16], actual: &[i16]) -> f64 {
    assert_eq!(reference.len(), actual.len());
    let energy = reference.iter().map(|&x| (x as f64).powi(2)).sum::<f64>();
    let error = reference
        .iter()
        .zip(actual)
        .map(|(&a, &b)| (a as f64 - b as f64).powi(2))
        .sum::<f64>();
    10. * (energy / error).log10()
}
#[test]
fn legacy_sdk_packets_decode_at_the_requested_rate() {
    let fixtures: &[(&[u8], &[u8])] = &[
        (
            include_bytes!("fixtures/legacy_8000.silk"),
            include_bytes!("fixtures/legacy_8000_24000.pcm"),
        ),
        (
            include_bytes!("fixtures/legacy_12000.silk"),
            include_bytes!("fixtures/legacy_12000_24000.pcm"),
        ),
        (
            include_bytes!("fixtures/legacy_16000.silk"),
            include_bytes!("fixtures/legacy_16000_24000.pcm"),
        ),
        (
            include_bytes!("fixtures/legacy_24000.silk"),
            include_bytes!("fixtures/legacy_24000_24000.pcm"),
        ),
        (
            include_bytes!("fixtures/legacy_16000_40ms.silk"),
            include_bytes!("fixtures/legacy_16000_40ms_24000.pcm"),
        ),
        (
            include_bytes!("fixtures/legacy_16000_60ms.silk"),
            include_bytes!("fixtures/legacy_16000_60ms_24000.pcm"),
        ),
        (
            include_bytes!("fixtures/legacy_16000_100ms.silk"),
            include_bytes!("fixtures/legacy_16000_100ms_24000.pcm"),
        ),
    ];
    for &(encoded, oracle) in fixtures {
        let decoded = decode_silk(encoded, 24000).unwrap();
        assert!(signal_to_error(&samples(oracle), &decoded) > 12.);
        let bare = &encoded[1..];
        assert_eq!(decoded, decode_silk(bare, 24000).unwrap());
    }
}
#[test]
fn new_packet_fixtures_played_by_the_legacy_sdk_decode_correctly() {
    let fixtures: &[(u32, &[u8], &[u8])] = &[
        (
            8000,
            include_bytes!("fixtures/rust_8000.silk"),
            include_bytes!("fixtures/rust_8000_native.pcm"),
        ),
        (
            12000,
            include_bytes!("fixtures/rust_12000.silk"),
            include_bytes!("fixtures/rust_12000_native.pcm"),
        ),
        (
            16000,
            include_bytes!("fixtures/rust_16000.silk"),
            include_bytes!("fixtures/rust_16000_native.pcm"),
        ),
        (
            24000,
            include_bytes!("fixtures/rust_24000.silk"),
            include_bytes!("fixtures/rust_24000_native.pcm"),
        ),
    ];
    for &(rate, encoded, oracle) in fixtures {
        assert!(signal_to_error(&samples(oracle), &decode_silk(encoded, rate).unwrap()) > 40.);
    }
}
#[test]
fn encoding_preserves_partial_final_frames_at_each_internal_rate() {
    for rate in [8000, 12000, 16000, 24000] {
        let length = rate as usize / 10 + 1;
        let pcm: Vec<i16> = (0..length)
            .map(|i| ((std::f64::consts::TAU * 440. * i as f64 / rate as f64).sin() * 6000.) as i16)
            .collect();
        let input: Vec<u8> = pcm.iter().flat_map(|sample| sample.to_le_bytes()).collect();
        for tencent in [true, false] {
            let encoded = encode_silk(&input, rate, 24000, tencent).unwrap();
            let decoded = decode_silk(&encoded, rate).unwrap();
            let frame = rate as usize / 50;
            assert_eq!(decoded.len(), length.div_ceil(frame) * frame);
            let energy =
                decoded.iter().map(|&x| (x as f64).powi(2)).sum::<f64>() / decoded.len() as f64;
            assert!(energy.sqrt() > 1000.);
        }
    }
}
#[test]
fn malformed_containers_return_errors() {
    for input in [
        &b""[..],
        &b"#!SILK_V3"[..],
        &b"\x02#!SILK_V3\xff\xff"[..],
        &b"#!SILK_V3\x10\x00a"[..],
        &b"#!SILK_V3\x00\x04"[..],
    ] {
        assert!(decode_silk(input, 24000).is_err());
        assert!(inspect_silk(input).is_err());
    }
    assert!(encode_silk(&[0], 24000, 24000, true).is_err());
    assert!(encode_silk(&[0, 0], 44100, 24000, true).is_err());
    assert!(decode_silk(include_bytes!("fixtures/legacy_24000.silk"), 0).is_err());
}

#[test]
fn inspected_duration_matches_native_pcm_and_internal_frame_counts() {
    let fixtures: &[(&[u8], &[u8], u64)] = &[
        (
            include_bytes!("fixtures/legacy_16000.silk"),
            include_bytes!("fixtures/legacy_16000_24000.pcm"),
            20,
        ),
        (
            include_bytes!("fixtures/legacy_16000_40ms.silk"),
            include_bytes!("fixtures/legacy_16000_40ms_24000.pcm"),
            40,
        ),
        (
            include_bytes!("fixtures/legacy_16000_60ms.silk"),
            include_bytes!("fixtures/legacy_16000_60ms_24000.pcm"),
            60,
        ),
        (
            include_bytes!("fixtures/legacy_16000_100ms.silk"),
            include_bytes!("fixtures/legacy_16000_100ms_24000.pcm"),
            100,
        ),
    ];
    for &(fixture, oracle, packet_ms) in fixtures {
        let duration = inspect_silk(fixture).unwrap();
        assert_eq!(
            duration.as_millis(),
            oracle.len() as u128 * 1000 / (24000 * 2)
        );
        assert_eq!(
            duration.as_millis(),
            decode_silk(fixture, 24000).unwrap().len() as u128 * 1000 / 24000
        );
        assert_eq!(duration, inspect_silk(&fixture[1..]).unwrap());

        let length = i16::from_le_bytes([fixture[10], fixture[11]]) as usize;
        let packet = &fixture[10..12 + length];
        for count in [1, 49, 50, 51] {
            let mut recording = b"#!SILK_V3".to_vec();
            for _ in 0..count {
                recording.extend_from_slice(packet);
            }
            let expected = std::time::Duration::from_millis(count * packet_ms);
            assert_eq!(inspect_silk(recording.as_slice()).unwrap(), expected);
            recording.extend_from_slice(&(-1i16).to_le_bytes());
            assert_eq!(inspect_silk(recording.as_slice()).unwrap(), expected);
        }
    }
}

#[test]
fn inspection_and_decoding_share_strict_packet_and_container_validation() {
    let fixture = include_bytes!("fixtures/legacy_16000.silk");
    let length = i16::from_le_bytes([fixture[10], fixture[11]]) as usize;
    let valid = fixture[..12 + length].to_vec();
    let mut cases: Vec<Vec<u8>> = vec![Vec::new(), b"#!SILK_V3".to_vec()];
    for prefix in [[0, 0], [1, 4], [254, 255], [0, 128], [1, 0], [255, 255]] {
        let mut input = b"#!SILK_V3".to_vec();
        input.extend_from_slice(&prefix);
        cases.push(input);
    }
    let mut oversized = b"#!SILK_V3\x01\x04".to_vec();
    oversized.extend_from_slice(&[0; 1025]);
    cases.push(oversized);
    cases.push(b"#!SILK_V3\x01\x00a".to_vec());
    let mut truncated = valid.clone();
    truncated.pop();
    cases.push(truncated);
    let mut short_length = valid.clone();
    short_length[10..12].copy_from_slice(&((length - 1) as i16).to_le_bytes());
    short_length.pop();
    cases.push(short_length);
    let mut packet_trailing = valid.clone();
    packet_trailing[10..12].copy_from_slice(&((length + 1) as i16).to_le_bytes());
    packet_trailing.push(0);
    cases.push(packet_trailing);
    let mut partial_length = valid.clone();
    partial_length.push(1);
    cases.push(partial_length);
    for suffix in [b"\xff\xff\0".as_slice(), b"\xff\xff\xff\xff".as_slice()] {
        let mut trailing = valid.clone();
        trailing.extend_from_slice(suffix);
        cases.push(trailing);
    }
    for input in cases {
        assert!(inspect_silk(input.as_slice()).is_err(), "{input:02x?}");
        assert!(decode_silk(&input, 24000).is_err(), "{input:02x?}");
    }
}
#[test]
fn silence_and_full_scale_inputs_produce_finite_bounded_audio() {
    for sample in [0i16, i16::MIN, i16::MAX] {
        let input: Vec<u8> = std::iter::repeat_n(sample, 2400)
            .flat_map(|sample| sample.to_le_bytes())
            .collect();
        let encoded = encode_silk(&input, 24000, 24000, true).unwrap();
        assert_eq!(decode_silk(&encoded, 24000).unwrap().len(), 2400);
    }
}
#[test]
fn arbitrary_packet_inspection_matches_decoder_acceptance_and_duration() {
    let mut seed = 0x12345678u32;
    for length in (1..=128).chain([1020, 1021, 1022, 1023, 1024]) {
        let mut input = b"\x02#!SILK_V3".to_vec();
        input.extend_from_slice(&(length as i16).to_le_bytes());
        for _ in 0..length {
            seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
            input.push((seed >> 24) as u8);
        }
        assert_inspection_matches_decoder(&input);
    }
}

#[test]
fn mutated_packet_inspection_matches_decoder_acceptance_and_duration() {
    let fixture = include_bytes!("fixtures/legacy_24000.silk");
    for iteration in 0..256 {
        let mut packet = fixture.to_vec();
        let index = 12 + (iteration * 7919) % (packet.len() - 12);
        packet[index] ^= 1 << (iteration % 8);
        assert_inspection_matches_decoder(&packet);
    }
}

fn assert_inspection_matches_decoder(input: &[u8]) {
    match (decode_silk(input, 24000), inspect_silk(input)) {
        (Ok(samples), Ok(duration)) => {
            assert_eq!(duration.as_millis(), samples.len() as u128 * 1000 / 24000);
        }
        (Err(_), Err(_)) => {}
        _ => panic!("SILK inspection and decoder disagree about packet validity"),
    }
}
