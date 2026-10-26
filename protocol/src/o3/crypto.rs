use crate::{
    Error, Result,
    crypto::{Curve, Ecdh},
};
use aes_gcm::{
    Aes256Gcm, Nonce, Tag,
    aead::{AeadInOut, KeyInit},
};
use bytes::Bytes;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    ecdsa::EcdsaSig,
    md::Md,
    nid::Nid,
    pkey::Id,
    pkey_ctx::PkeyCtx,
};
use rand::{TryRng, rngs::SysRng};
use std::cmp::Ordering;

pub(super) const PEER_PUBLIC_KEY: [u8; 33] = [
    0x03, 0xff, 0xd4, 0x3b, 0x6c, 0xb6, 0x85, 0x97, 0xb0, 0x90, 0x27, 0x75, 0x21, 0xd9, 0xcc, 0xe3,
    0x96, 0xd2, 0xc2, 0x4d, 0xf4, 0x39, 0x88, 0x9e, 0xc0, 0x9a, 0xac, 0x35, 0x52, 0xba, 0x18, 0x51,
    0xd8,
];
pub(super) const KEY_IDENTIFIER: &[u8; 66] =
    b"83c562376e929cbaa587870fbb72d8c7f3cfe9771df14808eb30aa917923fdd5ce";

const PEER_MASK: &[u8; 8] = b"3UEBOKPY";

pub(super) fn decode_peer(encoded: &[u8; 33]) -> [u8; 33] {
    std::array::from_fn(|index| encoded[(index + 25) % 33] ^ PEER_MASK[index % 8])
}

pub(super) fn encode_peer(peer: &[u8; 33]) -> [u8; 33] {
    std::array::from_fn(|index| {
        let decoded_index = (index + 8) % 33;
        peer[decoded_index] ^ PEER_MASK[decoded_index % 8]
    })
}

pub(super) struct Agreement {
    pub public: [u8; 33],
    pub key: [u8; 32],
}

fn crypto_error(error: impl std::fmt::Display) -> Error {
    Error::Crypto(error.to_string())
}

impl Agreement {
    pub(super) fn new(peer: &[u8; 33]) -> Result<Self> {
        Self::from_ecdh(Ecdh::new(Curve::P256)?, peer)
    }

    fn from_ecdh(ecdh: Ecdh, peer: &[u8; 33]) -> Result<Self> {
        let shared = ecdh.shared_secret(peer, false)?;
        let mut context = PkeyCtx::new_id(Id::HKDF).map_err(crypto_error)?;
        context.derive_init().map_err(crypto_error)?;
        context.set_hkdf_md(Md::sha256()).map_err(crypto_error)?;
        context.set_hkdf_key(&shared).map_err(crypto_error)?;
        context.set_hkdf_salt(&[]).map_err(crypto_error)?;
        context.add_hkdf_info(&[]).map_err(crypto_error)?;
        let mut key = [0u8; 32];
        if context.derive(Some(&mut key)).map_err(crypto_error)? != key.len() {
            return Err(crypto_error("Unexpected O3 HKDF output width"));
        }
        let public = ecdh
            .compressed_public_key()
            .try_into()
            .map_err(|_| crypto_error("Unexpected O3 P256 public key width"))?;
        Ok(Self { public, key })
    }
}

pub(super) fn authenticate(
    peer: &[u8; 33],
    local_parameter: u64,
    server_parameter: u64,
    signature: &[u8],
) -> Result<()> {
    if signature.len() != 64 {
        return Err(crypto_error("O3 ECDSA signature must be raw 64 bytes"));
    }
    if !matches!(peer[0], 2 | 3) {
        return Err(crypto_error("Invalid O3 compressed SEC1 point"));
    }
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(crypto_error)?;
    let mut context = BigNumContext::new().map_err(crypto_error)?;
    let point = EcPoint::from_bytes(&group, peer, &mut context).map_err(crypto_error)?;
    if point.is_infinity(&group)
        || !point
            .is_on_curve(&group, &mut context)
            .map_err(crypto_error)?
    {
        return Err(crypto_error("O3 ECDSA peer point outside curve"));
    }
    let key = EcKey::from_public_key(&group, &point).map_err(crypto_error)?;
    key.check_key().map_err(crypto_error)?;
    let r = BigNum::from_slice(&signature[..32]).map_err(crypto_error)?;
    let s = BigNum::from_slice(&signature[32..]).map_err(crypto_error)?;
    let mut order = BigNum::new().map_err(crypto_error)?;
    group
        .order(&mut order, &mut context)
        .map_err(crypto_error)?;
    if r.num_bits() == 0
        || s.num_bits() == 0
        || r.ucmp(&order) != Ordering::Less
        || s.ucmp(&order) != Ordering::Less
    {
        return Err(crypto_error("O3 ECDSA scalar outside curve order"));
    }
    let mut transcript = [0u8; 49];
    transcript[..33].copy_from_slice(peer);
    transcript[33..41].copy_from_slice(&local_parameter.to_be_bytes());
    transcript[41..].copy_from_slice(&server_parameter.to_be_bytes());
    let signature = EcdsaSig::from_private_components(r, s).map_err(crypto_error)?;
    if !signature
        .verify(&crate::crypto::sha256(&transcript), &key)
        .map_err(crypto_error)?
    {
        return Err(crypto_error("Invalid O3 channel authentication signature"));
    }
    Ok(())
}

pub(super) fn seal(key: &[u8; 32], plain: &[u8]) -> Result<Bytes> {
    let mut nonce = [0u8; 12];
    SysRng.try_fill_bytes(&mut nonce).map_err(crypto_error)?;
    seal_with_nonce(key, plain, &nonce)
}

fn seal_with_nonce(key: &[u8; 32], plain: &[u8], nonce: &[u8; 12]) -> Result<Bytes> {
    let capacity = plain
        .len()
        .checked_add(28)
        .ok_or_else(|| crypto_error("O3 AES-GCM plaintext too large"))?;
    let mut encrypted = Vec::with_capacity(capacity);
    encrypted.extend_from_slice(nonce);
    encrypted.extend_from_slice(plain);
    let cipher = Aes256Gcm::new(key.into());
    let tag = cipher
        .encrypt_inout_detached(nonce.into(), &[], (&mut encrypted[12..]).into())
        .map_err(|_| crypto_error("O3 AES-GCM encryption failed"))?;
    encrypted.extend_from_slice(&tag);
    Ok(encrypted.into())
}

pub(super) fn open(key: &[u8; 32], encrypted: &[u8]) -> Result<Bytes> {
    if encrypted.len() < 28 {
        return Err(crypto_error("Truncated O3 AES-GCM nonce/ciphertext/tag"));
    }
    let end = encrypted.len() - 16;
    let nonce: &Nonce<_> = (&encrypted[..12]).try_into().map_err(crypto_error)?;
    let tag: &Tag = (&encrypted[end..]).try_into().map_err(crypto_error)?;
    let mut plain = encrypted[12..end].to_vec();
    Aes256Gcm::new(key.into())
        .decrypt_inout_detached(
            nonce,
            &[],
            plain.as_mut_slice().into(),
            tag,
        )
        .map_err(|_| crypto_error("Invalid O3 AES-GCM authentication tag"))?;
    Ok(plain.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode<const N: usize>(value: &str) -> [u8; N] {
        hex::decode(value).unwrap().try_into().unwrap()
    }

    const LOCAL: u64 = 0x0102030405060708;
    const SERVER: u64 = 0x1112131415161718;

    fn peer() -> [u8; 33] {
        decode("037cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978")
    }

    fn signature() -> [u8; 64] {
        decode(
            "d7fe94067fdd9d98f61454c07d0d85f57c3e9718ba62fa681d847ff8a5ade50139c2cb23577ccefa5e712f536aa331f167fbac6e5a8e9d78792cf22941359d81",
        )
    }

    #[test]
    fn encoded_peer_default_vector_and_inverse_match_native_material() {
        let encoded: [u8; 33] = hex::decode(KEY_IDENTIFIER).unwrap().try_into().unwrap();
        assert_eq!(decode_peer(&encoded), PEER_PUBLIC_KEY);
        assert_eq!(encode_peer(&PEER_PUBLIC_KEY), encoded);
        let alternate = peer();
        let encoded = encode_peer(&alternate);
        assert_eq!(decode_peer(&encoded), alternate);
        assert_ne!(encoded, encode_peer(&PEER_PUBLIC_KEY));
        authenticate(&decode_peer(&encoded), LOCAL, SERVER, &signature()).unwrap();
    }

    #[test]
    fn independent_ecdh_hkdf_and_aead_vector() {
        let mut scalar = [0u8; 32];
        scalar[31] = 1;
        let agreement =
            Agreement::from_ecdh(Ecdh::from_private(Curve::P256, &scalar).unwrap(), &peer())
                .unwrap();
        let key = decode::<32>("32c14f38e411dc17e495b9b3f93d55d04251ca23c6090b90c2b3806cd5c100c2");
        assert_eq!(agreement.key, key);
        let encrypted = hex::decode("000102030405060708090a0bb05d5848f2d833a47a69e34be6a6bc64c71d77ba7385ada106f8de25796d37f17f838b99dc").unwrap();
        let plain = b"O3 independent vector";
        assert_eq!(
            seal_with_nonce(&key, plain, &std::array::from_fn(|i| i as u8))
                .unwrap()
                .as_ref(),
            encrypted
        );
        assert_eq!(open(&key, &encrypted).unwrap().as_ref(), plain);
        for index in [0, 12, encrypted.len() - 1] {
            let mut changed = encrypted.clone();
            changed[index] ^= 1;
            assert!(open(&key, &changed).is_err());
        }
        assert!(open(&key, &encrypted[..27]).is_err());
        assert!(open(&[0u8; 32], &encrypted).is_err());
    }

    #[test]
    fn authentication_binds_peer_and_both_parameters() {
        let signature = signature();
        authenticate(&peer(), LOCAL, SERVER, &signature).unwrap();
        assert!(authenticate(&peer(), LOCAL ^ 1, SERVER, &signature).is_err());
        assert!(authenticate(&peer(), LOCAL, SERVER ^ 1, &signature).is_err());
        let mut other_peer = peer();
        other_peer[0] ^= 1;
        assert!(authenticate(&other_peer, LOCAL, SERVER, &signature).is_err());
        for index in [0, 32] {
            let mut changed = signature;
            changed[index] ^= 1;
            assert!(authenticate(&peer(), LOCAL, SERVER, &changed).is_err());
        }
    }

    #[test]
    fn malformed_points_and_signature_scalars_fail_closed() {
        let signature = signature();
        assert!(authenticate(&peer(), LOCAL, SERVER, &signature[..63]).is_err());
        assert!(authenticate(&peer(), LOCAL, SERVER, &[1u8; 65]).is_err());
        for range in [0..32, 32..64] {
            for scalar in [
                [0u8; 32],
                [0xffu8; 32],
                decode("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
            ] {
                let mut changed = signature;
                changed[range.clone()].copy_from_slice(&scalar);
                assert!(authenticate(&peer(), LOCAL, SERVER, &changed).is_err());
            }
        }
        for invalid in [[0u8; 33], [0xffu8; 33], {
            let mut point = [0xffu8; 33];
            point[0] = 2;
            point
        }] {
            assert!(Agreement::new(&invalid).is_err());
            assert!(authenticate(&invalid, LOCAL, SERVER, &signature).is_err());
        }
    }
}
