use crate::{Error, Result};
use md5::{Digest, Md5};
use sha1::Sha1;
use std::{num::Wrapping, path::PathBuf};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt, SeekFrom},
};

const CHUNK: usize = 1024 * 1024;
const MD5_PREFIX: u64 = 10_002_432;
const TRI_SAMPLE: u64 = 10 * 1024 * 1024;

pub(crate) struct MediaPayload {
    pub(crate) path: PathBuf,
    pub(crate) name: String,
    pub(crate) size: u64,
    pub(crate) md5: Vec<u8>,
    pub(crate) sha1: Vec<u8>,
    pub(crate) md5_10m: Vec<u8>,
    pub(crate) tri_sha1: Vec<u8>,
    pub(crate) video_hashes: Vec<Vec<u8>>,
    temporary: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ImageInfo {
    pub(crate) format: u32,
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) suffix: String,
}

impl MediaPayload {
    pub(crate) async fn inspect(
        path: PathBuf,
        name: String,
        temporary: bool,
        file_checksums: bool,
        video_checkpoints: bool,
        allow_empty: bool,
    ) -> Result<Self> {
        // Establish ownership before opening or validating, including error paths.
        let mut payload = Self {
            path,
            name,
            temporary,
            size: 0,
            md5: Vec::new(),
            sha1: Vec::new(),
            md5_10m: Vec::new(),
            tri_sha1: Vec::new(),
            video_hashes: Vec::new(),
        };
        let result: Result<()> = async {
            if payload.name.is_empty()
                || payload.name == "."
                || payload.name == ".."
                || payload.name.contains(['/', '\\', '\0'])
            {
                return Err(malformed("Invalid media filename"));
            }
            let mut file = File::open(&payload.path).await?;
            let size = file.metadata().await?.len();
            payload.size = size;
            if size == 0 && !file_checksums && !allow_empty {
                return Err(malformed("Empty media input"));
            }
            let mut md5 = Md5::new();
            let mut sha1 = Sha1::new();
            let mut md5_prefix = Md5::new();
            let mut checkpoints = Sha1State::new();
            let mut data = vec![0u8; CHUNK];
            let mut offset = 0u64;
            while offset < size {
                let count = (size - offset).min(CHUNK as u64) as usize;
                file.read_exact(&mut data[..count])
                    .await
                    .map_err(truncated_file)?;
                let chunk = &data[..count];
                md5.update(chunk);
                if video_checkpoints {
                    checkpoints.update(chunk);
                } else {
                    sha1.update(chunk);
                }
                if file_checksums && offset < MD5_PREFIX {
                    md5_prefix.update(&chunk[..((MD5_PREFIX - offset).min(count as u64) as usize)]);
                }
                offset += count as u64;
                if video_checkpoints && offset % CHUNK as u64 == 0 {
                    payload.video_hashes.push(checkpoints.checkpoint().to_vec());
                }
            }
            let mut extra = [0u8; 1];
            if file.read(&mut extra).await? != 0 || file.metadata().await?.len() != size {
                return Err(malformed("Media file changed while hashing"));
            }
            payload.md5 = md5.finalize().to_vec();
            payload.sha1 = if video_checkpoints {
                checkpoints.finalize().to_vec()
            } else {
                sha1.finalize().to_vec()
            };
            if video_checkpoints {
                payload.video_hashes.push(payload.sha1.clone());
            }
            if file_checksums {
                let mut tri = Sha1::new();
                let ranges = if size <= TRI_SAMPLE * 3 {
                    [(0, size), (0, 0), (0, 0)]
                } else {
                    [
                        (0, TRI_SAMPLE),
                        (size / 2 - TRI_SAMPLE / 2, TRI_SAMPLE),
                        (size - TRI_SAMPLE, TRI_SAMPLE),
                    ]
                };
                for (start, mut count) in ranges {
                    if count == 0 {
                        continue;
                    }
                    file.seek(SeekFrom::Start(start)).await?;
                    while count > 0 {
                        let n = count.min(CHUNK as u64) as usize;
                        file.read_exact(&mut data[..n])
                            .await
                            .map_err(truncated_file)?;
                        tri.update(&data[..n]);
                        count -= n as u64;
                    }
                }
                tri.update(size.to_le_bytes());
                payload.md5_10m = md5_prefix.finalize().to_vec();
                payload.tri_sha1 = tri.finalize().to_vec();
            }
            Ok(())
        }
        .await;
        if let Err(error) = result {
            payload.dispose().await;
            return Err(error);
        }
        Ok(payload)
    }

    pub(crate) async fn dispose(&mut self) {
        if self.temporary {
            match tokio::fs::remove_file(&self.path).await {
                Ok(()) => self.temporary = false,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    self.temporary = false
                }
                Err(_) => {} // Drop retries without hiding the operation's original result.
            }
        }
    }

    pub(crate) async fn prefix(&self, count: usize) -> Result<Vec<u8>> {
        let mut file = File::open(&self.path).await?;
        let mut data = vec![0; self.size.min(count as u64) as usize];
        file.read_exact(&mut data).await.map_err(truncated_file)?;
        Ok(data)
    }

    pub(crate) async fn image_info(&self) -> Result<ImageInfo> {
        let mut reader = ImageReader {
            file: File::open(&self.path).await?,
            size: self.size,
        };
        let mut head = [0u8; 64];
        let count = self.size.min(64) as usize;
        reader.read_into(0, &mut head[..count]).await?;
        let bytes = &head[..count];
        let mut value = None;
        if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
            value = Some((
                1001,
                integer(bytes, 16, 4, false)?,
                integer(bytes, 20, 4, false)?,
                "png",
            ));
        } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
            value = Some((
                2000,
                integer(bytes, 6, 2, true)?,
                integer(bytes, 8, 2, true)?,
                "gif",
            ));
        } else if bytes.starts_with(&[255, 216]) {
            let mut offset = 2;
            while offset + 2 <= self.size {
                if reader.read::<1>(offset).await?[0] != 255 {
                    return Err(malformed("Invalid JPEG marker"));
                }
                let mut marker = 255;
                while marker == 255 && offset < self.size {
                    offset += 1;
                    marker = reader.read::<1>(offset).await?[0];
                }
                offset += 1;
                if marker == 217 || marker == 218 {
                    break;
                }
                if marker == 1 || (208..=215).contains(&marker) {
                    continue;
                }
                let length = u16::from_be_bytes(reader.read::<2>(offset).await?) as u64;
                if length < 2 || offset > self.size || length > self.size - offset {
                    return Err(malformed("Invalid JPEG segment length"));
                }
                if [
                    192, 193, 194, 195, 197, 198, 199, 201, 202, 203, 205, 206, 207,
                ]
                .contains(&marker)
                {
                    if length < 8 {
                        return Err(malformed("Truncated JPEG frame"));
                    }
                    let frame = reader.read::<8>(offset).await?;
                    value = Some((
                        1000,
                        integer(&frame, 5, 2, false)?,
                        integer(&frame, 3, 2, false)?,
                        "jpg",
                    ));
                    break;
                }
                offset += length;
            }
        } else if bytes.starts_with(b"BM") {
            let dib = integer(bytes, 14, 4, true)?;
            if dib == 12 {
                value = Some((
                    1005,
                    integer(bytes, 18, 2, true)?,
                    integer(bytes, 20, 2, true)?,
                    "bmp",
                ));
            } else if dib >= 40 {
                let width = integer(bytes, 18, 4, true)? as i32;
                let height = integer(bytes, 22, 4, true)? as i32;
                if width <= 0 || height == i32::MIN {
                    return Err(malformed("Invalid BMP dimensions"));
                }
                value = Some((1005, width as u32, height.unsigned_abs(), "bmp"));
            }
        } else if bytes.len() >= 30 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
            match &bytes[12..16] {
                b"VP8X" => {
                    value = Some((
                        1002,
                        integer(bytes, 24, 3, true)? + 1,
                        integer(bytes, 27, 3, true)? + 1,
                        "webp",
                    ))
                }
                b"VP8L" => {
                    let packed = integer(bytes, 21, 4, true)?;
                    value = Some((
                        1002,
                        (packed & 0x3fff) + 1,
                        ((packed >> 14) & 0x3fff) + 1,
                        "webp",
                    ));
                }
                b"VP8 " if bytes[23..26] == [157, 1, 42] => {
                    value = Some((
                        1002,
                        integer(bytes, 26, 2, true)? & 0x3fff,
                        integer(bytes, 28, 2, true)? & 0x3fff,
                        "webp",
                    ))
                }
                _ => {}
            }
        } else if bytes.starts_with(b"II\x2a\0") || bytes.starts_with(b"MM\0\x2a") {
            let little = bytes[0] == b'I';
            let directory = integer(bytes, 4, 4, little)? as u64;
            let entries = integer(&reader.read::<2>(directory).await?, 0, 2, little)?;
            let (mut width, mut height) = (0, 0);
            for index in 0..entries {
                let entry = reader
                    .read::<12>(directory + 2 + u64::from(index) * 12)
                    .await?;
                let tag = integer(&entry, 0, 2, little)?;
                if tag != 256 && tag != 257 {
                    continue;
                }
                let field_type = integer(&entry, 2, 2, little)?;
                if integer(&entry, 4, 4, little)? != 1 || (field_type != 3 && field_type != 4) {
                    return Err(malformed("Invalid TIFF image dimension"));
                }
                let dimension = integer(&entry, 8, if field_type == 3 { 2 } else { 4 }, little)?;
                if tag == 256 {
                    width = dimension;
                } else {
                    height = dimension;
                }
            }
            value = Some((1006, width, height, "tiff"));
        } else if bytes.starts_with(&[0, 0, 0, 12, 106, 80, 32, 32, 13, 10, 135, 10]) {
            let (mut offset, mut end) = (12, self.size);
            while offset + 8 <= end {
                let header = reader.read::<8>(offset).await?;
                let mut length = integer(&header, 0, 4, false)? as u64;
                let kind = integer(&header, 4, 4, false)?;
                let mut header_size = 8;
                if length == 1 {
                    length = u64::from_be_bytes(reader.read::<8>(offset + 8).await?);
                    header_size = 16;
                } else if length == 0 {
                    length = end - offset;
                }
                if length < header_size || length > end - offset {
                    return Err(malformed("Invalid JP2 box length"));
                }
                if kind == 0x6a703268 {
                    end = offset + length;
                    offset += header_size;
                    continue;
                }
                if kind == 0x69686472 {
                    if length < header_size + 8 {
                        return Err(malformed("Truncated JP2 image header"));
                    }
                    let dimensions = reader.read::<8>(offset + header_size).await?;
                    value = Some((
                        1003,
                        integer(&dimensions, 4, 4, false)?,
                        integer(&dimensions, 0, 4, false)?,
                        "jp2",
                    ));
                    break;
                }
                offset += length;
            }
        } else if bytes.starts_with(&[255, 79, 255, 81]) {
            let x = integer(bytes, 8, 4, false)?;
            let y = integer(bytes, 12, 4, false)?;
            let origin_x = integer(bytes, 16, 4, false)?;
            let origin_y = integer(bytes, 20, 4, false)?;
            if x <= origin_x || y <= origin_y {
                return Err(malformed("Invalid JPEG2000 canvas"));
            }
            value = Some((1003, x - origin_x, y - origin_y, "j2k"));
        }
        match value {
            Some((format, width, height, suffix)) if width > 0 && height > 0 => Ok(ImageInfo { format, width, height, suffix: suffix.into() }),
            _ => Err(Error::Unsupported("Image must have a valid JPEG, JPEG2000, PNG, GIF, BMP, TIFF or WebP header; no transcoder is installed".into())),
        }
    }

    pub(crate) async fn silk_duration(&self) -> Result<u32> {
        let head = self.prefix(10).await?;
        if !head.starts_with(b"\x02#!SILK_V3") && !head.starts_with(b"#!SILK_V3") {
            return Err(Error::Unsupported(
                "Voice requires pre-encoded SILK v3; audio transcoding is unavailable".into(),
            ));
        }
        let path = self.path.clone();
        let duration = tokio::task::spawn_blocking(move || {
            let file = std::fs::File::open(path)?;
            atri_qq_silk::inspect_silk(std::io::BufReader::new(file))
        })
        .await
        .map_err(|error| malformed(&format!("SILK inspection worker failed: {error}")))?
        .map_err(|error| match error {
            atri_qq_silk::SilkError::Io(error) => error.into(),
            error => malformed(&format!("Invalid SILK audio: {error}")),
        })?;
        // Keep the established whole-second floor policy; count internal 20 ms
        // frames, not packets (a packet can contain up to five frames).
        Ok(duration.as_secs().min(u32::MAX as u64) as u32)
    }
}

impl Drop for MediaPayload {
    fn drop(&mut self) {
        if self.temporary {
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                let path = std::mem::take(&mut self.path);
                runtime.spawn(async move {
                    let _ = tokio::fs::remove_file(path).await;
                });
            }
        }
    }
}

fn malformed(message: &str) -> Error {
    Error::Malformed(message.into())
}
fn truncated_file(error: std::io::Error) -> Error {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        malformed("Truncated media file")
    } else {
        error.into()
    }
}
fn integer(bytes: &[u8], offset: usize, count: usize, little: bool) -> Result<u32> {
    let part = bytes
        .get(offset..offset + count)
        .ok_or_else(|| malformed("Truncated image integer"))?;
    Ok(if little {
        part.iter().rev().fold(0, |v, b| (v << 8) | u32::from(*b))
    } else {
        part.iter().fold(0, |v, b| (v << 8) | u32::from(*b))
    })
}
struct ImageReader {
    file: File,
    size: u64,
}
impl ImageReader {
    async fn read_into(&mut self, offset: u64, data: &mut [u8]) -> Result<()> {
        if offset > self.size || data.len() as u64 > self.size - offset {
            return Err(malformed("Truncated image header"));
        }
        self.file.seek(SeekFrom::Start(offset)).await?;
        self.file.read_exact(data).await.map_err(|error| {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                malformed("Truncated image header")
            } else {
                error.into()
            }
        })?;
        Ok(())
    }
    async fn read<const N: usize>(&mut self, offset: u64) -> Result<[u8; N]> {
        let mut data = [0; N];
        self.read_into(offset, &mut data).await?;
        Ok(data)
    }
}

// NTV2 uses little-endian, unfinalized SHA1 chaining words at each MiB boundary.
// The final entry is instead the ordinary, padded SHA1 digest (big endian).
#[derive(Clone)]
struct Sha1State {
    state: [u32; 5],
    tail: [u8; 64],
    buffered: usize,
    length: u64,
}
impl Sha1State {
    fn new() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
            tail: [0; 64],
            buffered: 0,
            length: 0,
        }
    }
    fn update(&mut self, mut bytes: &[u8]) {
        self.length = self.length.wrapping_add(bytes.len() as u64);
        if self.buffered != 0 {
            let n = bytes.len().min(64 - self.buffered);
            self.tail[self.buffered..self.buffered + n].copy_from_slice(&bytes[..n]);
            self.buffered += n;
            bytes = &bytes[n..];
            if self.buffered == 64 {
                compress(&mut self.state, &self.tail);
                self.buffered = 0;
            }
        }
        while bytes.len() >= 64 {
            compress(&mut self.state, &bytes[..64]);
            bytes = &bytes[64..];
        }
        if !bytes.is_empty() {
            self.tail[..bytes.len()].copy_from_slice(bytes);
            self.buffered = bytes.len();
        }
    }
    fn checkpoint(&self) -> [u8; 20] {
        let mut out = [0; 20];
        for (part, word) in out.chunks_exact_mut(4).zip(self.state) {
            part.copy_from_slice(&word.to_le_bytes());
        }
        out
    }
    fn finalize(mut self) -> [u8; 20] {
        let bits = self.length.wrapping_mul(8);
        let mut padding = [0; 128];
        padding[0] = 0x80;
        let padding_len = if self.buffered < 56 {
            56 - self.buffered
        } else {
            120 - self.buffered
        };
        self.update(&padding[..padding_len]);
        self.update(&bits.to_be_bytes());
        let mut out = [0; 20];
        for (part, word) in out.chunks_exact_mut(4).zip(self.state) {
            part.copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}
fn compress(state: &mut [u32; 5], block: &[u8]) {
    let mut words = [0u32; 80];
    for (word, bytes) in words[..16].iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    for i in 16..80 {
        words[i] = (words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]).rotate_left(1);
    }
    let [mut a, mut b, mut c, mut d, mut e] = (*state).map(Wrapping);
    for (i, word) in words.iter().enumerate() {
        let (f, k) = match i {
            0..=19 => ((b & c) | (!b & d), 0x5a827999u32),
            20..=39 => (b ^ c ^ d, 0x6ed9eba1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
            _ => (b ^ c ^ d, 0xca62c1d6),
        };
        let next = Wrapping(a.0.rotate_left(5)) + f + e + Wrapping(k) + Wrapping(*word);
        e = d;
        d = c;
        c = Wrapping(b.0.rotate_left(30));
        b = a;
        a = next;
    }
    for (word, add) in state.iter_mut().zip([a, b, c, d, e]) {
        *word = (Wrapping(*word) + add).0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn payload(data: &[u8], files: bool, video: bool) -> MediaPayload {
        let path = std::env::temp_dir().join(format!(
            "atri-qq-payload-test-{:032x}",
            rand::random::<u128>()
        ));
        tokio::fs::write(&path, data).await.unwrap();
        MediaPayload::inspect(path, "input.bin".into(), true, files, video, false)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn checksums_and_explicit_temporary_disposal() {
        let mut value = payload(b"abc", true, false).await;
        assert_eq!(hex::encode(&value.md5), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            hex::encode(&value.sha1),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(value.md5_10m, value.md5);
        let mut expected = Sha1::new();
        expected.update(b"abc");
        expected.update(3u64.to_le_bytes());
        assert_eq!(value.tri_sha1, expected.finalize().as_slice());
        assert!(value.video_hashes.is_empty());
        let path = value.path.clone();
        value.dispose().await;
        assert!(!tokio::fs::try_exists(path).await.unwrap());
    }

    #[tokio::test]
    async fn sampled_file_checksums_use_exact_desktop_boundaries() {
        let data: Vec<u8> = (0..(TRI_SAMPLE as usize * 3 + 71))
            .map(|i| ((i * 37 + i / 997) & 255) as u8)
            .collect();
        let mut value = payload(&data, true, false).await;
        assert_eq!(
            value.md5_10m,
            Md5::digest(&data[..MD5_PREFIX as usize]).as_slice()
        );
        let mut tri = Sha1::new();
        tri.update(&data[..TRI_SAMPLE as usize]);
        let middle = data.len() / 2 - TRI_SAMPLE as usize / 2;
        tri.update(&data[middle..middle + TRI_SAMPLE as usize]);
        tri.update(&data[data.len() - TRI_SAMPLE as usize..]);
        tri.update((data.len() as u64).to_le_bytes());
        assert_eq!(value.tri_sha1, tri.finalize().as_slice());
        value.dispose().await;
    }

    #[test]
    fn sha1_checkpoint_is_unfinalized_little_endian_state() {
        let mut padded_abc = [0u8; 64];
        padded_abc[..4].copy_from_slice(b"abc\x80");
        padded_abc[63] = 24;
        let mut state = Sha1State::new();
        state.update(&padded_abc);
        // Standard SHA1(abc)'s chaining words, each serialized little endian.
        assert_eq!(
            hex::encode(state.checkpoint()),
            "363e99a96a81064771253eba6cc250789dd8d09c"
        );
        for length in [0, 1, 55, 56, 63, 64, 65, 1024, CHUNK, CHUNK + 63] {
            let input = vec![0x7b; length];
            let mut state = Sha1State::new();
            for chunk in input.chunks(17) {
                state.update(chunk);
            }
            assert_eq!(state.finalize().as_slice(), Sha1::digest(&input).as_slice());
        }
    }

    #[tokio::test]
    async fn video_checkpoints_include_each_mib_and_final_digest() {
        for length in [CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK] {
            let data = vec![0x53; length];
            let mut value = payload(&data, false, true).await;
            assert_eq!(value.video_hashes.len(), length / CHUNK + 1);
            assert_eq!(value.video_hashes.last(), Some(&value.sha1));
            assert_eq!(value.sha1, Sha1::digest(&data).as_slice());
            if length >= CHUNK {
                assert_ne!(
                    value.video_hashes[0],
                    Sha1::digest(&data[..CHUNK]).as_slice()
                );
            }
            value.dispose().await;
        }
    }

    #[tokio::test]
    async fn empty_files_are_permitted_only_for_file_checksums_or_explicit_opt_in() {
        let path =
            std::env::temp_dir().join(format!("atri-qq-empty-{:032x}", rand::random::<u128>()));
        tokio::fs::write(&path, []).await.unwrap();
        assert!(
            MediaPayload::inspect(path.clone(), "empty".into(), false, false, false, false)
                .await
                .is_err()
        );
        let mut empty = MediaPayload::inspect(path, "empty".into(), true, true, false, false)
            .await
            .unwrap();
        assert_eq!(empty.md5, Md5::digest([]).as_slice());
        assert_eq!(empty.sha1, Sha1::digest([]).as_slice());
        empty.dispose().await;
    }

    #[tokio::test]
    async fn silk_internal_frames_and_whole_second_floor_are_validated() {
        let fixtures: &[(&[u8], u64)] = &[
            (
                include_bytes!("../../../silk/tests/fixtures/legacy_16000.silk"),
                20,
            ),
            (
                include_bytes!("../../../silk/tests/fixtures/legacy_16000_40ms.silk"),
                40,
            ),
            (
                include_bytes!("../../../silk/tests/fixtures/legacy_16000_60ms.silk"),
                60,
            ),
            (
                include_bytes!("../../../silk/tests/fixtures/legacy_16000_100ms.silk"),
                100,
            ),
        ];
        for &(fixture, packet_ms) in fixtures {
            let length = i16::from_le_bytes([fixture[10], fixture[11]]) as usize;
            let packet = &fixture[10..12 + length];
            for header in [b"#!SILK_V3".as_slice(), b"\x02#!SILK_V3".as_slice()] {
                for count in [1, 49, 50, 51] {
                    let mut data = header.to_vec();
                    for _ in 0..count {
                        data.extend_from_slice(packet);
                    }
                    data.extend_from_slice(&(-1i16).to_le_bytes());
                    let mut value = payload(&data, false, false).await;
                    assert_eq!(
                        value.silk_duration().await.unwrap(),
                        (count * packet_ms / 1000) as u32
                    );
                    value.dispose().await;
                }
            }
        }
    }

    #[tokio::test]
    async fn silk_codec_and_native_framing_errors_are_rejected() {
        let fixture = include_bytes!("../../../silk/tests/fixtures/legacy_16000.silk");
        let mut trailing = fixture.to_vec();
        trailing.extend_from_slice(&[255, 255, 0]);
        for bytes in [
            b"not audio".as_slice(),
            b"#!SILK_V3".as_slice(),
            b"#!SILK_V3\xff\xff".as_slice(),
            b"#!SILK_V3\x01".as_slice(),
            b"#!SILK_V3\x00\x00".as_slice(),
            b"#!SILK_V3\x01\x04".as_slice(),
            b"#!SILK_V3\xfe\xff".as_slice(),
            b"#!SILK_V3\x00\x80".as_slice(),
            b"#!SILK_V3\x02\x00a".as_slice(),
            b"#!SILK_V3\x01\x00a".as_slice(),
            trailing.as_slice(),
        ] {
            let mut value = payload(bytes, false, false).await;
            assert!(value.silk_duration().await.is_err());
            value.dispose().await;
        }
    }

    fn dimensions_header(kind: &str) -> Vec<u8> {
        let mut bytes = vec![0u8; 64];
        match kind {
            "png" => {
                bytes[..8].copy_from_slice(b"\x89PNG\r\n\x1a\n");
                bytes[16..20].copy_from_slice(&23u32.to_be_bytes());
                bytes[20..24].copy_from_slice(&17u32.to_be_bytes());
            }
            "gif" => {
                bytes[..6].copy_from_slice(b"GIF89a");
                bytes[6..8].copy_from_slice(&23u16.to_le_bytes());
                bytes[8..10].copy_from_slice(&17u16.to_le_bytes());
            }
            "bmp" => {
                bytes[..2].copy_from_slice(b"BM");
                bytes[14..18].copy_from_slice(&40u32.to_le_bytes());
                bytes[18..22].copy_from_slice(&23i32.to_le_bytes());
                bytes[22..26].copy_from_slice(&(-17i32).to_le_bytes());
            }
            "bmp-core" => {
                bytes[..2].copy_from_slice(b"BM");
                bytes[14..18].copy_from_slice(&12u32.to_le_bytes());
                bytes[18..20].copy_from_slice(&23u16.to_le_bytes());
                bytes[20..22].copy_from_slice(&17u16.to_le_bytes());
            }
            "webp-x" => {
                bytes[..4].copy_from_slice(b"RIFF");
                bytes[8..16].copy_from_slice(b"WEBPVP8X");
                bytes[24] = 22;
                bytes[27] = 16;
            }
            "webp-l" => {
                bytes[..4].copy_from_slice(b"RIFF");
                bytes[8..16].copy_from_slice(b"WEBPVP8L");
                bytes[21..25].copy_from_slice(&(22u32 | (16 << 14)).to_le_bytes());
            }
            "webp" => {
                bytes[..4].copy_from_slice(b"RIFF");
                bytes[8..16].copy_from_slice(b"WEBPVP8 ");
                bytes[23..26].copy_from_slice(&[157, 1, 42]);
                bytes[26..28].copy_from_slice(&23u16.to_le_bytes());
                bytes[28..30].copy_from_slice(&17u16.to_le_bytes());
            }
            "tiff-le" | "tiff-be" => {
                let le = kind == "tiff-le";
                bytes[..4].copy_from_slice(if le { b"II\x2a\0" } else { b"MM\0\x2a" });
                bytes[4..8].copy_from_slice(&if le {
                    8u32.to_le_bytes()
                } else {
                    8u32.to_be_bytes()
                });
                bytes[8..10].copy_from_slice(&if le {
                    2u16.to_le_bytes()
                } else {
                    2u16.to_be_bytes()
                });
                for (i, tag, dimension) in [(10, 256u16, 23u32), (22, 257, 17)] {
                    bytes[i..i + 2].copy_from_slice(&if le {
                        tag.to_le_bytes()
                    } else {
                        tag.to_be_bytes()
                    });
                    bytes[i + 2..i + 4].copy_from_slice(&if le {
                        4u16.to_le_bytes()
                    } else {
                        4u16.to_be_bytes()
                    });
                    bytes[i + 4..i + 8].copy_from_slice(&if le {
                        1u32.to_le_bytes()
                    } else {
                        1u32.to_be_bytes()
                    });
                    bytes[i + 8..i + 12].copy_from_slice(&if le {
                        dimension.to_le_bytes()
                    } else {
                        dimension.to_be_bytes()
                    });
                }
            }
            "jp2" => {
                bytes[..12].copy_from_slice(&[0, 0, 0, 12, 106, 80, 32, 32, 13, 10, 135, 10]);
                bytes[12..16].copy_from_slice(&24u32.to_be_bytes());
                bytes[16..20].copy_from_slice(b"jp2h");
                bytes[20..24].copy_from_slice(&16u32.to_be_bytes());
                bytes[24..28].copy_from_slice(b"ihdr");
                bytes[28..32].copy_from_slice(&17u32.to_be_bytes());
                bytes[32..36].copy_from_slice(&23u32.to_be_bytes());
            }
            "j2k" => {
                bytes[..4].copy_from_slice(&[255, 79, 255, 81]);
                for (offset, word) in [(8, 28u32), (12, 24), (16, 5), (20, 7)] {
                    bytes[offset..offset + 4].copy_from_slice(&word.to_be_bytes());
                }
            }
            "jpg" => {
                bytes[..14]
                    .copy_from_slice(&[255, 216, 255, 194, 0, 8, 8, 0, 17, 0, 23, 1, 255, 217]);
            }
            _ => unreachable!(),
        }
        bytes
    }

    #[tokio::test]
    async fn reads_all_desktop_image_formats_without_transcoding() {
        for (kind, format, suffix) in [
            ("png", 1001, "png"),
            ("gif", 2000, "gif"),
            ("jpg", 1000, "jpg"),
            ("bmp", 1005, "bmp"),
            ("bmp-core", 1005, "bmp"),
            ("webp", 1002, "webp"),
            ("webp-x", 1002, "webp"),
            ("webp-l", 1002, "webp"),
            ("tiff-le", 1006, "tiff"),
            ("tiff-be", 1006, "tiff"),
            ("jp2", 1003, "jp2"),
            ("j2k", 1003, "j2k"),
        ] {
            let mut value = payload(&dimensions_header(kind), false, false).await;
            assert_eq!(
                value.image_info().await.unwrap(),
                ImageInfo {
                    format,
                    width: 23,
                    height: 17,
                    suffix: suffix.into()
                },
                "{kind}"
            );
            value.dispose().await;
        }
    }

    #[tokio::test]
    async fn rejects_truncated_and_invalid_image_headers() {
        let mut zero_dimensions = dimensions_header("png");
        zero_dimensions[16..20].fill(0);
        for bytes in [
            b"random bytes".to_vec(),
            b"\x89PNG\r\n\x1a\n".to_vec(),
            vec![255, 216, 255, 192, 0, 1],
            zero_dimensions,
        ] {
            let mut value = payload(&bytes, false, false).await;
            assert!(value.image_info().await.is_err());
            value.dispose().await;
        }
    }
}
