//! QQ's sixteen-round double-chained TEA and desktop SEC1 ECDH key agreement.
use crate::{Error, Result, models::random_bytes};
use aes_gcm::aes::Aes192;
use aes_gcm::{
    Aes128Gcm, Aes256Gcm, AesGcm, Nonce,
    aead::{Aead, KeyInit},
};
use md5::{Digest, Md5};
use openssl::{
    bn::{BigNum, BigNumContext},
    derive::Deriver,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    nid::Nid,
    pkey::{PKey, Private},
};
use std::num::Wrapping;

pub fn md5(data: &[u8]) -> [u8; 16] {
    Md5::digest(data).into()
}
pub fn sha256(data: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(data).into()
}
fn crypto_error(e: impl std::fmt::Display) -> Error {
    Error::Crypto(e.to_string())
}

pub fn aes_gcm_encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let nonce = random_bytes(12);
    let n: &Nonce<_> = nonce.as_slice().try_into().map_err(crypto_error)?;
    let encrypted = match key.len() {
        16 => Aes128Gcm::new_from_slice(key)
            .map_err(crypto_error)?
            .encrypt(n, data),
        24 => AesGcm::<Aes192, aes_gcm::aead::consts::U12>::new_from_slice(key)
            .map_err(crypto_error)?
            .encrypt(n, data),
        32 => Aes256Gcm::new_from_slice(key)
            .map_err(crypto_error)?
            .encrypt(n, data),
        _ => return Err(crypto_error("AES-GCM key must be 16, 24 or 32 bytes")),
    }
    .map_err(|_| crypto_error("AES-GCM encryption failed"))?;
    let mut result = nonce;
    result.extend_from_slice(&encrypted);
    Ok(result)
}
pub fn aes_gcm_decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 28 {
        return Err(crypto_error("Truncated AES-GCM nonce/ciphertext/tag"));
    }
    let nonce: &Nonce<_> = (&data[..12]).try_into().map_err(crypto_error)?;
    let encrypted = &data[12..];
    match key.len() {
        16 => Aes128Gcm::new_from_slice(key)
            .map_err(crypto_error)?
            .decrypt(nonce, encrypted),
        24 => AesGcm::<Aes192, aes_gcm::aead::consts::U12>::new_from_slice(key)
            .map_err(crypto_error)?
            .decrypt(nonce, encrypted),
        32 => Aes256Gcm::new_from_slice(key)
            .map_err(crypto_error)?
            .decrypt(nonce, encrypted),
        _ => return Err(crypto_error("AES-GCM key must be 16, 24 or 32 bytes")),
    }
    .map_err(|_| crypto_error("Invalid AES-GCM authentication tag"))
}
fn tea_keys(key: &[u8]) -> Result<[u32; 4]> {
    if key.len() != 16 {
        return Err(crypto_error("QQ TEA key must be sixteen bytes"));
    }
    Ok(std::array::from_fn(|i| {
        u32::from_be_bytes(key[i * 4..i * 4 + 4].try_into().unwrap())
    }))
}
fn tea_block(value: u64, k: &[u32; 4], decrypt: bool) -> u64 {
    let (mut x, mut y) = (Wrapping((value >> 32) as u32), Wrapping(value as u32));
    let delta = Wrapping(0x9e37_79b9u32);
    if decrypt {
        let mut sum = delta * Wrapping(16);
        for _ in 0..16 {
            y -= (x + sum) ^ ((x << 4) + Wrapping(k[2])) ^ ((x >> 5) + Wrapping(k[3]));
            x -= (y + sum) ^ ((y << 4) + Wrapping(k[0])) ^ ((y >> 5) + Wrapping(k[1]));
            sum -= delta;
        }
    } else {
        let mut sum = Wrapping(0u32);
        for _ in 0..16 {
            sum += delta;
            x += (y + sum) ^ ((y << 4) + Wrapping(k[0])) ^ ((y >> 5) + Wrapping(k[1]));
            y += (x + sum) ^ ((x << 4) + Wrapping(k[2])) ^ ((x >> 5) + Wrapping(k[3]));
        }
    }
    (u64::from(x.0) << 32) | u64::from(y.0)
}
pub fn tea_encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let fill = 10 - ((data.len() % 8 + 1) & 7);
    let mut padded = random_bytes(fill);
    padded[0] = ((fill - 3) as u8) | 0xf8;
    padded.extend_from_slice(data);
    padded.extend_from_slice(&[0; 7]);
    tea_encrypt_blocks(padded, key)
}
fn tea_encrypt_blocks(mut padded: Vec<u8>, key: &[u8]) -> Result<Vec<u8>> {
    let k = tea_keys(key)?;
    if padded.is_empty() || padded.len() % 8 != 0 {
        return Err(crypto_error("Invalid QQ TEA block length"));
    }
    let (mut previous_cipher, mut previous_mixed) = (0, 0);
    for bytes in padded.chunks_exact_mut(8) {
        let mixed = u64::from_be_bytes(bytes.try_into().unwrap()) ^ previous_cipher;
        let cipher = tea_block(mixed, &k, false) ^ previous_mixed;
        bytes.copy_from_slice(&cipher.to_be_bytes());
        previous_cipher = cipher;
        previous_mixed = mixed;
    }
    Ok(padded)
}
pub fn tea_decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let k = tea_keys(key)?;
    if data.len() < 16 || data.len() % 8 != 0 {
        return Err(crypto_error("Invalid QQ TEA ciphertext length"));
    }
    let mut result = Vec::with_capacity(data.len());
    let (mut previous_cipher, mut previous_mixed) = (0, 0);
    for bytes in data.chunks_exact(8) {
        let cipher = u64::from_be_bytes(bytes.try_into().unwrap());
        let mixed = tea_block(cipher ^ previous_mixed, &k, true);
        result.extend_from_slice(&(mixed ^ previous_cipher).to_be_bytes());
        previous_cipher = cipher;
        previous_mixed = mixed;
    }
    let fill = (result[0] & 7) as usize + 3;
    let end = result.len() - 7;
    if fill > end || result[end..].iter().fold(0u8, |a, b| a | b) != 0 {
        return Err(crypto_error("Invalid QQ TEA padding/trailer"));
    }
    result.drain(..fill);
    result.truncate(end - fill);
    Ok(result)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Curve {
    Secp192k1,
    P256,
}
pub struct Ecdh {
    curve: Curve,
    key: EcKey<Private>,
    public: Vec<u8>,
}
impl Ecdh {
    pub fn new(curve: Curve) -> Result<Self> {
        Self::generate(curve, None)
    }
    pub fn from_private(curve: Curve, scalar: &[u8]) -> Result<Self> {
        Self::generate(curve, Some(scalar))
    }
    fn generate(curve: Curve, scalar: Option<&[u8]>) -> Result<Self> {
        let group = EcGroup::from_curve_name(match curve {
            Curve::Secp192k1 => Nid::SECP192K1,
            Curve::P256 => Nid::X9_62_PRIME256V1,
        })
        .map_err(crypto_error)?;
        let mut ctx = BigNumContext::new().map_err(crypto_error)?;
        let key = if let Some(scalar) = scalar {
            let size = if curve == Curve::Secp192k1 { 24 } else { 32 };
            if scalar.len() != size {
                return Err(crypto_error("Invalid ECDH private scalar length"));
            }
            let secret = BigNum::from_slice(scalar).map_err(crypto_error)?;
            let mut order = BigNum::new().map_err(crypto_error)?;
            group.order(&mut order, &mut ctx).map_err(crypto_error)?;
            if secret.num_bits() == 0 || secret.ucmp(&order) != std::cmp::Ordering::Less {
                return Err(crypto_error("ECDH private scalar outside curve order"));
            }
            let mut public = EcPoint::new(&group).map_err(crypto_error)?;
            public
                .mul_generator2(&group, &secret, &mut ctx)
                .map_err(crypto_error)?;
            EcKey::from_private_components(&group, &secret, &public).map_err(crypto_error)?
        } else {
            EcKey::generate(&group).map_err(crypto_error)?
        };
        key.check_key().map_err(crypto_error)?;
        let public = key
            .public_key()
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .map_err(crypto_error)?;
        Ok(Self { curve, key, public })
    }
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }
    pub fn compressed_public_key(&self) -> Vec<u8> {
        let n = (self.public.len() - 1) / 2;
        let mut v = Vec::with_capacity(n + 1);
        v.push(2 | (self.public[self.public.len() - 1] & 1));
        v.extend_from_slice(&self.public[1..1 + n]);
        v
    }
    pub fn shared_secret(&self, peer: &[u8], hash: bool) -> Result<Vec<u8>> {
        let n = if self.curve == Curve::Secp192k1 {
            24
        } else {
            32
        };
        if !matches!((peer.len(),peer.first()),(len,Some(4)) if len==2*n+1)
            && !matches!((peer.len(),peer.first()),(len,Some(2|3)) if len==n+1)
        {
            return Err(crypto_error("Invalid SEC1 peer point encoding"));
        }
        let group = self.key.group();
        let mut ctx = BigNumContext::new().map_err(crypto_error)?;
        let point = EcPoint::from_bytes(group, peer, &mut ctx).map_err(crypto_error)?;
        if point.is_infinity(group) || !point.is_on_curve(group, &mut ctx).map_err(crypto_error)? {
            return Err(crypto_error("ECDH peer point outside curve"));
        }
        let peer = EcKey::from_public_key(group, &point).map_err(crypto_error)?;
        peer.check_key().map_err(crypto_error)?;
        let private = PKey::from_ec_key(self.key.clone()).map_err(crypto_error)?;
        let public = PKey::from_ec_key(peer).map_err(crypto_error)?;
        let mut derive = Deriver::new(&private).map_err(crypto_error)?;
        derive.set_peer(&public).map_err(crypto_error)?;
        let secret = derive.derive_to_vec().map_err(crypto_error)?;
        if secret.len() != n {
            return Err(crypto_error("Unexpected ECDH shared-X width"));
        }
        if hash {
            Ok(md5(&secret[..if self.curve == Curve::Secp192k1 {
                24
            } else {
                16
            }])
            .to_vec())
        } else {
            Ok(secret)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tea_all_residues_and_corruption() {
        for n in 0..40 {
            let p = vec![42; n];
            assert_eq!(
                tea_decrypt(&tea_encrypt(&p, &[7; 16]).unwrap(), &[7; 16]).unwrap(),
                p
            )
        }
        for n in [0, 7, 8, 15, 17] {
            assert!(tea_decrypt(&vec![0; n], &[0; 16]).is_err())
        }
        let mut p = vec![0; 16];
        p[0] = 0xf8;
        p[15] = 1;
        assert!(tea_decrypt(&tea_encrypt_blocks(p, &[0; 16]).unwrap(), &[0; 16]).is_err());
        let mut p = vec![0; 16];
        p[0] = 0xff;
        assert!(tea_decrypt(&tea_encrypt_blocks(p, &[0; 16]).unwrap(), &[0; 16]).is_err());
    }
    #[test]
    fn nist_empty_gcm_and_authentication() {
        let mut p =
            hex::decode("00000000000000000000000058e2fccefa7e3061367f1d57a4e7455a").unwrap();
        assert_eq!(aes_gcm_decrypt(&p, &[0; 16]).unwrap(), Vec::<u8>::new());
        p[27] ^= 1;
        assert!(aes_gcm_decrypt(&p, &[0; 16]).is_err());
    }
    #[test]
    fn ecdh_hash_width_and_sec1_validation() {
        for (curve, n, xhex) in [
            (
                Curve::Secp192k1,
                24,
                "db4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d",
            ),
            (
                Curve::P256,
                32,
                "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            ),
        ] {
            let mut scalar = vec![0; n];
            scalar[n - 1] = 1;
            let key = Ecdh::from_private(curve, &scalar).unwrap();
            let x = hex::decode(xhex).unwrap();
            assert_eq!(key.shared_secret(key.public_key(), false).unwrap(), x);
            assert_eq!(
                key.shared_secret(&key.compressed_public_key(), true)
                    .unwrap(),
                md5(&x[..if n == 24 { 24 } else { 16 }])
            );
            assert!(Ecdh::from_private(curve, &vec![0; n]).is_err());
            assert!(key.shared_secret(&vec![0; 2 * n + 1], false).is_err());
        }
    }
}
