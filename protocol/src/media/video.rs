use super::payload::MediaPayload;
use crate::{Error, Result};
use mp4::{Mp4Reader, Mp4Track, TrackType};
use std::{
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom},
    ops::Range,
};

pub(super) struct VideoInfo {
    pub(super) width: u32,
    pub(super) height: u32,
    pub(super) duration: u32,
}

impl MediaPayload {
    pub(super) async fn video_info(&self) -> Result<VideoInfo> {
        let path = self.path.clone();
        let expected_size = self.size;
        tokio::task::spawn_blocking(move || {
            let file = File::open(path)?;
            if file.metadata()?.len() != expected_size {
                return Err(malformed("Video changed after hashing"));
            }
            inspect(BufReader::new(file), expected_size)
        })
        .await
        .map_err(|error| malformed(&format!("MP4 metadata parser failed: {error}")))?
    }
}

fn inspect<R: Read + Seek>(mut file: R, size: u64) -> Result<VideoInfo> {
    // The crate skips mdat by seeking. Check declared box extents first, so a
    // seek beyond EOF cannot turn a truncated media payload into a valid file.
    let media = media_ranges(&mut file, size)?;
    file.seek(SeekFrom::Start(0))?;
    let movie = Mp4Reader::read_header(file, size)
        .map_err(|error| malformed(&format!("Invalid MP4: {error}")))?;
    if movie.is_fragmented() || movie.moov.mvex.is_some() {
        return Err(Error::Unsupported(
            "Fragmented MP4 metadata is not supported; provide a nonfragmented MP4".into(),
        ));
    }
    // HashMap iteration is unspecified. Prefer the first identifiable video
    // track by its track ID, without restricting unrelated audio/subtitle tracks.
    let track = movie
        .tracks()
        .values()
        .filter(|track| matches!(track.track_type(), Ok(TrackType::Video)))
        .filter(|track| dimensions(track).is_some())
        .min_by_key(|track| track.track_id())
        .ok_or_else(|| {
            Error::Unsupported(
                "MP4 has no supported video track (recognized entries: avc1, hev1, vp09)".into(),
            )
        })?;
    validate_samples(track, &media)?;
    let (coded_width, coded_height) = dimensions(track).unwrap();
    if coded_width == 0 || coded_height == 0 {
        return Err(malformed("MP4 video track has zero dimensions"));
    }
    let header = &track.trak.tkhd;
    let matrix = &header.matrix;
    if matrix.u != 0 || matrix.v != 0 || matrix.w != 0x40000000 {
        return Err(Error::Unsupported(
            "MP4 perspective track transforms are unsupported".into(),
        ));
    }
    // tkhd describes presentation size; sample-entry dimensions describe coded
    // size. Honor display scaling and rotation without claiming to decode video.
    let width = match header.width.raw_value() {
        0 => u32::from(coded_width) << 16,
        value => value,
    };
    let height = match header.height.raw_value() {
        0 => u32::from(coded_height) << 16,
        value => value,
    };
    let extent = |a: i32, b: i32| -> Result<u32> {
        let value = u128::from(a.unsigned_abs()) * u128::from(width)
            + u128::from(b.unsigned_abs()) * u128::from(height);
        u32::try_from(value.div_ceil(1u128 << 32))
            .ok()
            .filter(|value| *value != 0)
            .ok_or_else(|| malformed("MP4 display dimensions are out of range"))
    };
    let width = extent(matrix.a, matrix.c)?;
    let height = extent(matrix.b, matrix.d)?;
    let media_header = &track.trak.mdia.mdhd;
    // tkhd uses the movie timescale and includes edit-list presentation duration.
    // Fall back only to the actual media timeline when that field is unspecified.
    let (ticks, timescale) = if header.duration != 0 && header.duration != u64::MAX {
        (header.duration, movie.timescale())
    } else {
        (media_header.duration, media_header.timescale)
    };
    if ticks == 0 || timescale == 0 {
        return Err(malformed("MP4 video duration or timescale is zero"));
    }
    let duration = u32::try_from(ticks.div_ceil(u64::from(timescale)))
        .map_err(|_| malformed("MP4 video duration exceeds whole-second protocol range"))?;
    Ok(VideoInfo {
        width,
        height,
        duration,
    })
}

fn dimensions(track: &Mp4Track) -> Option<(u16, u16)> {
    let description = &track.trak.mdia.minf.stbl.stsd;
    if let Some(entry) = &description.avc1 {
        Some((entry.width, entry.height))
    } else if let Some(entry) = &description.hev1 {
        Some((entry.width, entry.height))
    } else {
        description
            .vp09
            .as_ref()
            .map(|entry| (entry.width, entry.height))
    }
}

fn media_ranges<R: Read + Seek>(file: &mut R, size: u64) -> Result<Vec<Range<u64>>> {
    let mut ranges = Vec::new();
    let mut position = 0;
    while position < size {
        if size - position < 8 {
            return Err(malformed("Truncated MP4 box header"));
        }
        file.seek(SeekFrom::Start(position))?;
        let mut header = [0; 8];
        file.read_exact(&mut header)?;
        let short_size = u32::from_be_bytes(header[..4].try_into().unwrap());
        let (length, header_size) = match short_size {
            0 => (size - position, 8),
            1 => {
                if size - position < 16 {
                    return Err(malformed("Truncated MP4 extended box header"));
                }
                let mut extended = [0; 8];
                file.read_exact(&mut extended)?;
                (u64::from_be_bytes(extended), 16)
            }
            length => (u64::from(length), 8),
        };
        if length < header_size || length > size - position {
            return Err(malformed("Truncated or invalid MP4 box extent"));
        }
        if &header[4..] == b"mdat" {
            ranges.push(position + header_size..position + length);
        }
        position += length;
    }
    if ranges.is_empty() {
        return Err(malformed("MP4 contains no media data"));
    }
    Ok(ranges)
}

fn validate_samples(track: &Mp4Track, media: &[Range<u64>]) -> Result<()> {
    let table = &track.trak.mdia.minf.stbl;
    let sizes = &table.stsz;
    if sizes.sample_count == 0 || track.timescale() == 0 {
        return Err(malformed("MP4 video track has no samples or timescale"));
    }
    if sizes.sample_size == 0 && sizes.sample_sizes.len() != sizes.sample_count as usize {
        return Err(malformed("MP4 video sample sizes are incomplete"));
    }
    let mut samples = 0u64;
    let mut ticks = 0u64;
    for entry in &table.stts.entries {
        samples += u64::from(entry.sample_count);
        ticks = ticks
            .checked_add(u64::from(entry.sample_count) * u64::from(entry.sample_delta))
            .ok_or_else(|| malformed("MP4 sample timeline overflows"))?;
    }
    if samples != u64::from(sizes.sample_count)
        || ticks == 0
        || ticks != track.trak.mdia.mdhd.duration
    {
        return Err(malformed(
            "MP4 sample timeline does not match its video track",
        ));
    }
    let chunks = match (&table.stco, &table.co64) {
        (Some(offsets), None) => offsets.entries.len(),
        (None, Some(offsets)) => offsets.entries.len(),
        _ => return Err(malformed("MP4 requires one chunk-offset table")),
    };
    let mapping = &table.stsc.entries;
    if mapping.first().map(|entry| entry.first_chunk) != Some(1)
        || mapping
            .windows(2)
            .any(|pair| pair[0].first_chunk >= pair[1].first_chunk)
        || mapping.iter().any(|entry| {
            entry.samples_per_chunk == 0
                || entry.sample_description_index != 1
                || entry.first_chunk as usize > chunks
        })
    {
        return Err(malformed("Invalid MP4 sample-to-chunk table"));
    }
    let mut mapping_index = 0;
    let mut sample_index = 0u64;
    for chunk in 0..chunks {
        while mapping_index + 1 < mapping.len()
            && mapping[mapping_index + 1].first_chunk as usize <= chunk + 1
        {
            mapping_index += 1;
        }
        let count = u64::from(mapping[mapping_index].samples_per_chunk);
        if count > u64::from(sizes.sample_count) - sample_index {
            return Err(malformed("MP4 chunk exceeds sample count"));
        }
        let length = if sizes.sample_size != 0 {
            count * u64::from(sizes.sample_size)
        } else {
            let end = (sample_index + count) as usize;
            let slice = &sizes.sample_sizes[sample_index as usize..end];
            if slice.contains(&0) {
                return Err(malformed("MP4 video contains an empty sample"));
            }
            slice.iter().map(|size| u64::from(*size)).sum()
        };
        let offset = if let Some(offsets) = &table.stco {
            u64::from(offsets.entries[chunk])
        } else {
            table.co64.as_ref().unwrap().entries[chunk]
        };
        if !media.iter().any(|range| {
            offset >= range.start && offset <= range.end && length <= range.end - offset
        }) {
            return Err(malformed(
                "MP4 video sample data is truncated or outside mdat",
            ));
        }
        sample_index += count;
    }
    if sample_index != u64::from(sizes.sample_count) {
        return Err(malformed("MP4 chunk table omits video samples"));
    }
    Ok(())
}

fn malformed(message: &str) -> Error {
    Error::Malformed(message.into())
}

#[cfg(test)]
pub(super) fn fixture() -> Vec<u8> {
    // Deterministic container construction with a real 320x240 H.264 IDR.
    // SPS/PPS/IDR originate from mp4-rust's MIT-licensed tests/samples/minimal.mp4:
    // https://github.com/alfg/mp4-rust/blob/master/tests/samples/minimal.mp4
    let config = mp4::Mp4Config {
        major_brand: "isom".parse().unwrap(),
        minor_version: 0,
        compatible_brands: vec!["isom".parse().unwrap(), "avc1".parse().unwrap()],
        timescale: 1000,
    };
    let mut writer =
        mp4::Mp4Writer::write_start(std::io::Cursor::new(Vec::new()), &config).unwrap();
    writer
        .add_track(&mp4::TrackConfig::from(mp4::AvcConfig {
            width: 320,
            height: 240,
            seq_param_set: hex::decode("6764000dacd94141fa1000000300100000030320f1429960").unwrap(),
            pic_param_set: hex::decode("68ebe3cb22c0").unwrap(),
        }))
        .unwrap();
    let nal = hex::decode("658884002bfffef6737c0a669a2254b815dbdd9a8f97424b97ec4183eb4000629d049cf57cdddca8a009080001490f2b0d048694e2323cdd0f").unwrap();
    let mut sample = Vec::new();
    sample.extend_from_slice(&(nal.len() as u32).to_be_bytes());
    sample.extend_from_slice(&nal);
    writer
        .write_sample(
            1,
            &mp4::Mp4Sample {
                start_time: 0,
                duration: 40,
                rendering_offset: 0,
                is_sync: true,
                bytes: sample.into(),
            },
        )
        .unwrap();
    writer.write_end().unwrap();
    writer.into_writer().into_inner()
}

#[cfg(test)]
pub(super) fn audio_only_fixture() -> Vec<u8> {
    let config = mp4::Mp4Config {
        major_brand: "isom".parse().unwrap(),
        minor_version: 0,
        compatible_brands: vec!["isom".parse().unwrap()],
        timescale: 1000,
    };
    let mut writer =
        mp4::Mp4Writer::write_start(std::io::Cursor::new(Vec::new()), &config).unwrap();
    writer
        .add_track(&mp4::TrackConfig::from(mp4::AacConfig {
            freq_index: mp4::SampleFreqIndex::Freq44100,
            ..Default::default()
        }))
        .unwrap();
    // First AAC sample from the same mp4-rust fixture cited above.
    let sample = hex::decode("de02004c61766335362e36302e313030000270b15ba1082d0a088401d98000003f43a924bbbd6af5ae3577363d7bea3f52f99fb97da7ee5f79fbf7f96a60e411ccc8ba576bc2b764d675b26e649f28e3c4a964289c21232ec56ddc2b1433303d77a8b8b78ab34e86c7365523317a3aee6ebb373ad7456ba2b5aeadaead8d163458d16fc5be4df79f79f79f79f79f79f79f79f79fff2f53d4cb2cb2cb2a3460664c81818181818181e9d2f3cf3cf318c6252380").unwrap();
    writer
        .write_sample(
            1,
            &mp4::Mp4Sample {
                start_time: 0,
                duration: 23,
                rendering_offset: 0,
                is_sync: true,
                bytes: sample.into(),
            },
        )
        .unwrap();
    writer.write_end().unwrap();
    writer.into_writer().into_inner()
}
