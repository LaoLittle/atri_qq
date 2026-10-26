use crate::{
    Error, Result,
    crypto::{self, Curve, Ecdh},
    models::*,
    proto::{self, auth},
    wire::{Reader, Writer, malformed},
};
use bytes::Bytes;
use prost::Message;
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct Tlv {
    entries: Vec<(u16, Vec<u8>)>,
}
impl Tlv {
    pub fn add(&mut self, tag: u16, body: impl AsRef<[u8]>) {
        self.entries.push((tag, body.as_ref().to_vec()))
    }
    pub fn write(&mut self, tag: u16, body: impl FnOnce(&mut Writer) -> Result<()>) -> Result<()> {
        let mut w = Writer::new();
        body(&mut w)?;
        self.add(tag, w.data);
        Ok(())
    }
    pub fn encode(&self, command: Option<u16>) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        if let Some(command) = command {
            w.u16(command)
        }
        w.u16(u16::try_from(self.entries.len()).map_err(|_| malformed("Too many login TLVs"))?);
        for (tag, body) in &self.entries {
            w.u16(*tag);
            w.p16(body)?
        }
        Ok(w.data)
    }
    pub fn decode(r: &mut Reader) -> Result<BTreeMap<u16, Bytes>> {
        let count = r.u16()?;
        let mut values = BTreeMap::new();
        for _ in 0..count {
            let tag = r.u16()?;
            values.insert(tag, r.p16()?);
        }
        Ok(values)
    }
}
pub(super) struct WtLogin {
    ecdh: Ecdh,
    shared: Vec<u8>,
    trans_emp_sequence: u16,
    qr_account: u64,
}
impl WtLogin {
    pub fn new() -> Result<Self> {
        let ecdh = Ecdh::new(Curve::Secp192k1)?;
        let peer=hex::decode("04928d8850673088b343264e0c6bacb8496d697799f37211deb25bb73906cb089fea9639b4e0260498b51a992d50813da8").map_err(|e|malformed(e.to_string()))?;
        let shared = ecdh.shared_secret(&peer, true)?;
        Ok(Self {
            ecdh,
            shared,
            trans_emp_sequence: 0,
            qr_account: 0,
        })
    }
    fn packet(&mut self, command: u16, body: &[u8], state: &SessionState) -> Result<Bytes> {
        // QR polling has its own outer sequence. The subsequent wtlogin.login
        // starts at zero rather than inheriting the number of QR polls.
        let sequence = if command == 0x812 {
            let sequence = self.trans_emp_sequence;
            self.trans_emp_sequence = sequence.wrapping_add(1);
            sequence
        } else {
            0
        };
        let cipher = crypto::tea_encrypt(body, &self.shared)?;
        let mut p = Writer::new();
        p.u16(8001);
        p.u16(command);
        p.u16(sequence);
        p.u32(if command == 0x812 {
            0
        } else {
            state.keystore.uin as u32
        });
        p.u8(3);
        p.u8(0x87);
        p.u32(0);
        p.u8(0x13);
        p.u16(0);
        p.u16(state.profile.client_version);
        p.u32(0);
        p.u8(1);
        p.u8(1);
        p.bytes(&state.keystore.random_key);
        p.u16(0x102);
        p.p16(self.ecdh.compressed_public_key())?;
        p.bytes(cipher);
        p.u8(3);
        let length = u16::try_from(p.data.len() + 3)
            .map_err(|_| malformed("WT packet exceeds u16 length"))?;
        let mut w = Writer::new();
        w.u8(2);
        w.u16(length);
        w.bytes(p.data);
        Ok(w.data.into())
    }
    pub fn qr(
        &mut self,
        command: u16,
        unusual: Option<&[u8]>,
        state: &SessionState,
    ) -> Result<Bytes> {
        if state.profile.platform.is_ios() {
            return Err(Error::Unsupported(
                "iOS local QR acquisition/polling is not established; desktop WT 0x31/0x12 is not a mobile login path".into(),
            ));
        }
        let p = &state.profile;
        let k = &state.keystore;
        if command == 0x31 {
            self.qr_account = if unusual.is_some() { k.uin } else { 0 };
        }
        let mut b = Writer::new();
        b.u16(0);
        b.u32(p.app_id);
        if command == 0x12 {
            b.p16(&k.qr_sig)?
        }
        b.u64(self.qr_account);
        b.u8(0);
        b.u16(0);
        if command == 0x31 {
            let mut t = Tlv::default();
            if let Some(unusual) = unusual {
                t.add(0x11, unusual)
            }
            t.write(0x16, |w| {
                w.u32(0);
                w.u32(p.app_id);
                w.u32(p.sub_app_id);
                w.bytes(&k.guid);
                w.p16(&p.package_name)?;
                w.p16(&p.pt_version)?;
                w.p16(&p.package_name)
            })?;
            t.write(0x1b, |w| {
                for v in [0, 0, 3, 4, 72, 2, 2] {
                    w.u32(v)
                }
                w.u16(0);
                Ok(())
            })?;
            t.write(0x1d, |w| {
                w.u8(1);
                w.u32(
                    p.misc_bitmap
                        .ok_or_else(|| malformed("WT misc bitmap resource missing"))?,
                );
                w.u32(0);
                w.u8(0);
                Ok(())
            })?;
            t.add(0x33, &k.guid);
            for tag in [0x35, 0x66] {
                t.write(tag, |w| {
                    w.u32(p.sso_version);
                    Ok(())
                })?
            }
            let ext = auth::QrRequestExtension {
                device: Some(auth::QrDevice {
                    os: Some(p.os.clone()),
                    name: Some(k.device_name.clone()),
                }),
                capabilities: Some(auth::QrCapabilities { nt_login: Some(1) }),
            }
            .encode_to_vec();
            t.add(0xd1, ext);
            b.bytes(t.encode(None)?);
        } else {
            b.u16(0)
        }
        let mut inner = Writer::new();
        inner.u16(command);
        inner.zeros(21);
        inner.u8(3);
        inner.u16(0);
        inner.u16(0x32);
        inner.u32(0);
        inner.u64(0);
        inner.bytes(b.data);
        inner.u8(3);
        let mut timed = Writer::new();
        timed.u32(super::unix_seconds());
        timed.u8(2);
        timed.u16(
            u16::try_from(inner.data.len() + 3)
                .map_err(|_| malformed("Code2d packet exceeds u16 length"))?,
        );
        timed.bytes(inner.data);
        let mut wrapped = Writer::new();
        wrapped.u8(0);
        wrapped.u16(
            u16::try_from(timed.data.len())
                .map_err(|_| malformed("Timed code2d exceeds u16 length"))?,
        );
        wrapped.u32(p.app_id);
        wrapped.u32(0x72);
        wrapped.u16(0);
        wrapped.u8(0);
        wrapped.bytes(timed.data);
        self.packet(0x812, &wrapped.data, state)
    }
    pub fn login(&mut self, state: &SessionState) -> Result<Bytes> {
        if state.profile.platform.is_ios() {
            return Err(Error::Unsupported(
                "iOS WT login requires native packet and signature/bitmap resources; desktop WT encoding is unavailable for mobile profiles".into(),
            ));
        }
        let p = &state.profile;
        let k = &state.keystore;
        let mut nested = Tlv::default();
        nested.add(0x16e, k.device_name.as_bytes());
        nested.write(0x147, |w| {
            w.u32(p.app_id);
            w.p16(&p.pt_version)?;
            w.p16(
                p.apk_signature_md5
                    .as_deref()
                    .ok_or_else(|| malformed("WT APK signature resource missing"))?,
            )
        })?;
        nested.write(0x128, |w| {
            w.u16(0);
            w.zeros(3);
            w.u32(0);
            w.p16(&p.os)?;
            w.p16(&k.guid)?;
            w.u16(0);
            Ok(())
        })?;
        nested.add(0x124, [0; 12]);
        let encrypted = crypto::tea_encrypt(&nested.encode(None)?, &k.tgtgt_key)?;
        let mut t = Tlv::default();
        t.add(0x106, &k.a1);
        t.add(0x144, encrypted);
        t.write(0x116, |w| {
            w.u8(0);
            w.u32(
                p.misc_bitmap
                    .ok_or_else(|| malformed("WT misc bitmap resource missing"))?,
            );
            w.u32(
                p.sub_sig_map
                    .ok_or_else(|| malformed("WT sub signature map resource missing"))?,
            );
            w.u8(0);
            Ok(())
        })?;
        t.write(0x142, |w| {
            w.u16(0);
            w.p16(&p.package_name)
        })?;
        t.add(0x145, &k.guid);
        t.write(0x18, |w| {
            w.u16(0);
            w.u32(5);
            w.u32(0);
            w.u32(8001);
            w.u32(k.uin as u32);
            w.u16(0);
            w.u16(0);
            Ok(())
        })?;
        t.write(0x141, |w| {
            w.u16(0);
            w.p16("Unknown")?;
            w.u32(0);
            Ok(())
        })?;
        t.write(0x177, |w| {
            w.u8(1);
            w.u32(0);
            w.p16(&p.sdk_version)
        })?;
        t.add(0x191, [0]);
        t.write(0x100, |w| {
            w.u16(0);
            w.u32(5);
            w.u32(p.app_id);
            w.u32(p.sub_app_id);
            w.u32(p.client_version.into());
            w.u32(
                p.main_sig_map
                    .ok_or_else(|| malformed("WT main signature map resource missing"))?,
            );
            Ok(())
        })?;
        t.write(0x107, |w| {
            w.u16(1);
            w.u8(0x0d);
            w.u16(0);
            w.u8(1);
            Ok(())
        })?;
        t.add(0x318, []);
        t.add(0x16a, &k.no_pic_sig);
        t.add(0x166, [5]);
        t.write(0x521, |w| {
            w.u32(0x13);
            w.p16("basicim")
        })?;
        self.packet(0x810, &t.encode(Some(9))?, state)
    }
    pub fn decode(&self, data: Bytes, store: &Keystore) -> Result<(u16, Bytes)> {
        let length = data.len();
        let mut r = Reader::new(data);
        if r.u8()? != 2 || r.u16()? as usize != length || r.u16()? != 8001 {
            return Err(malformed("WT header/version/length"));
        }
        let command = r.u16()?;
        r.skip(2 + 4 + 1)?;
        let encryption = r.u8()?;
        let state = r.u8()?;
        let n = r
            .remaining()
            .checked_sub(1)
            .ok_or_else(|| malformed("Empty WT ciphertext"))?;
        let mut cipher = r.bytes(n)?;
        if r.u8()? != 3 {
            return Err(malformed("WT trailer"));
        }
        let key = match encryption {
            0 => {
                if state == 180 {
                    store.random_key.clone()
                } else {
                    self.shared.clone()
                }
            }
            3 => store.wt_session_ticket_key.clone(),
            4 => {
                let mut exchange = Reader::new(crypto::tea_decrypt(&cipher, &self.shared)?);
                let peer = exchange.p16()?;
                let key = self.ecdh.shared_secret(&peer, true)?;
                cipher = exchange.rest();
                key
            }
            _ => return Err(malformed(format!("Unknown WT encryption {encryption}"))),
        };
        Ok((command, crypto::tea_decrypt(&cipher, &key)?.into()))
    }
    pub fn decode_qr(&self, data: Bytes, store: &Keystore) -> Result<(u16, Bytes)> {
        let (command, clear) = self.decode(data, store)?;
        if command != 0x812 {
            return Err(malformed("Unexpected WT QR command"));
        }
        let mut r = Reader::new(clear);
        r.skip(1)?;
        let encryption = r.u8()?;
        let len = r.u16()? as usize;
        r.skip(1)?;
        let inner = r.bytes(len)?;
        let inner = if encryption != 0 {
            crypto::tea_decrypt(&inner, &store.st_key)?.into()
        } else {
            inner
        };
        let mut r = Reader::new(inner);
        if r.u8()? != 2 {
            return Err(malformed("Code2d header"));
        }
        let _ = r.u16()?;
        let command = r.u16()?;
        r.skip(21 + 1 + 2 + 2 + 4 + 8)?;
        Ok((command, r.rest()))
    }
}
pub(super) fn apply_tickets(
    t: &BTreeMap<u16, Bytes>,
    k: &mut Keystore,
    generated_unix_seconds: u64,
) -> Result<()> {
    let mut candidate = k.clone();
    for (&tag, value) in t {
        match tag {
            0x103 => candidate.st_web = value.to_vec(),
            0x143 => candidate.d2 = value.to_vec(),
            0x108 => candidate.ksid = value.to_vec(),
            0x10a => candidate.a2 = value.to_vec(),
            0x10c => candidate.a1_key = value.to_vec(),
            0x10d => candidate.a2_key = value.to_vec(),
            0x10e => candidate.st_key = value.to_vec(),
            0x114 => candidate.st = value.to_vec(),
            0x120 => candidate.s_key = value.to_vec(),
            0x133 => candidate.wt_session_ticket = value.to_vec(),
            0x134 => candidate.wt_session_ticket_key = value.to_vec(),
            0x305 => candidate.d2_key = value.to_vec(),
            0x106 => candidate.a1 = value.to_vec(),
            0x16a => candidate.no_pic_sig = value.to_vec(),
            0x16d => candidate.super_key = value.to_vec(),
            0x11a => {
                let mut r = Reader::new(value.clone());
                candidate.face_id = r.u16()?;
                candidate.age = r.u8()?;
                candidate.gender = r.u8()?;
                candidate.nickname = String::from_utf8_lossy(&r.pref(1, false)?).into_owned();
            }
            0x512 => {
                let mut r = Reader::new(value.clone());
                let count = r.u16()?;
                let mut keys = BTreeMap::new();
                for _ in 0..count {
                    let domain = String::from_utf8_lossy(&r.p16()?).into_owned();
                    let key = String::from_utf8_lossy(&r.p16()?).into_owned();
                    let _ = r.p16()?;
                    keys.insert(domain, key);
                }
                candidate.ps_keys = keys;
            }
            0x543 => {
                if let Some(uid) = proto::decode::<auth::WtUidTicket>(value.clone())?
                    .layer
                    .and_then(|p| p.identity)
                    .and_then(|p| p.uid)
                    .filter(|s| !s.is_empty())
                {
                    candidate.uid = uid
                }
            }
            _ => {}
        }
    }
    if candidate.d2.is_empty() || candidate.a2.is_empty() || candidate.d2_key.len() != 16 {
        return Err(malformed("Successful WT response lacks D2/A2 tickets"));
    }
    candidate.nt_ticket_times = None;
    candidate.wt_ticket_times = Some(WtTicketTimeMetadata {
        next_refresh_unix_seconds: generated_unix_seconds
            .checked_add(604_800)
            .ok_or_else(|| malformed("WT ticket refresh time overflow"))?,
        expire_unix_seconds: generated_unix_seconds
            .checked_add(2_592_000)
            .ok_or_else(|| malformed("WT ticket expiry time overflow"))?,
    });
    candidate.ticket_generated_unix_seconds = Some(generated_unix_seconds);
    *k = candidate;
    Ok(())
}
pub(super) fn decode_login_error(result: u8, tlvs: &BTreeMap<u16, Bytes>) -> Result<()> {
    if let Some(error) = tlvs.get(&0x146) {
        let mut r = Reader::new(error.clone());
        r.skip(4)?;
        let title = String::from_utf8_lossy(&r.p16()?).into_owned();
        let message = String::from_utf8_lossy(&r.p16()?).into_owned();
        return Err(Error::Server {
            code: result.into(),
            message: format!("{title}: {message}"),
        });
    }
    if result != 0 {
        return Err(Error::Server {
            code: result.into(),
            message: "WT login failed".into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mobile_profiles_never_encode_desktop_qr_or_wt_login_packets() {
        for profile in [Profile::iphone(), Profile::ipad()] {
            let state = SessionState {
                profile,
                keystore: Keystore::default(),
                machine_id: "synthetic-machine".into(),
                online: false,
            };
            let mut codec = WtLogin::new().unwrap();
            for command in [0x31, 0x12] {
                assert!(matches!(
                    codec.qr(command, None, &state),
                    Err(Error::Unsupported(_))
                ));
            }
            assert!(matches!(codec.login(&state), Err(Error::Unsupported(_))));
            assert_eq!(codec.trans_emp_sequence, 0);
        }
    }
    #[test]
    fn repeated_ticket_uses_last_value_before_atomic_keystore_update() {
        let mut tlvs = Tlv::default();
        tlvs.add(0x305, [0x11; 16]);
        tlvs.add(0x143, b"new-d2");
        tlvs.add(0x10a, b"new-a2");
        tlvs.add(0x305, [0x22; 16]);
        let mut reader = Reader::new(tlvs.encode(None).unwrap());
        let tickets = Tlv::decode(&mut reader).unwrap();
        let mut keystore = Keystore {
            nt_ticket_times: Some(NtTicketTimeMetadata {
                field12: Some(NtTicketTimeValues::default()),
                field16: None,
                received_unix_ms: 1,
            }),
            ..Default::default()
        };
        apply_tickets(&tickets, &mut keystore, 1_000).unwrap();
        assert_eq!(keystore.d2_key, [0x22; 16]);
        assert_eq!(keystore.d2, b"new-d2");
        assert_eq!(keystore.a2, b"new-a2");
        assert_eq!(keystore.nt_ticket_times, None);
        assert_eq!(keystore.ticket_generated_unix_seconds, Some(1_000));
        assert_eq!(keystore.next_ticket_refresh_unix_seconds(), Some(605_800));
        assert_eq!(
            keystore.wt_ticket_times.unwrap().expire_unix_seconds,
            2_593_000
        );
        let restored: Keystore =
            serde_json::from_slice(&serde_json::to_vec(&keystore).unwrap()).unwrap();
        assert_eq!(restored.wt_ticket_times, keystore.wt_ticket_times);
        assert_eq!(restored.ticket_generated_unix_seconds, Some(1_000));
        assert_eq!(restored.next_ticket_refresh_unix_seconds(), Some(605_800));
        assert_eq!(reader.remaining(), 0);
    }

    #[test]
    fn truncated_repeated_ticket_never_falls_back_to_the_earlier_value() {
        let mut tlvs = Tlv::default();
        tlvs.add(0x305, [0x11; 16]);
        tlvs.add(0x305, [0x22; 16]);
        let mut bytes = tlvs.encode(None).unwrap();
        bytes.pop();
        assert!(Tlv::decode(&mut Reader::new(bytes)).is_err());
    }

    fn state() -> SessionState {
        SessionState {
            profile: Profile::linux(),
            keystore: Keystore::default(),
            machine_id: "machine".into(),
            online: false,
        }
    }
    #[test]
    fn outer_sequence_increments_inner_stays_zero_and_desktop_byte_is_exact() {
        let s = state();
        let mut wt = WtLogin::new().unwrap();
        for sequence in 0..3u16 {
            let p = wt.qr(0x31, None, &s).unwrap();
            assert_eq!(&p[7..9], &sequence.to_be_bytes());
            assert_eq!(p[19], 0x13);
            let mut r = Reader::new(p);
            r.skip(3 + 2 + 2 + 2 + 4 + 1 + 1 + 4 + 1 + 2 + 2 + 4 + 1 + 1 + 16 + 2)
                .unwrap();
            let public = r.p16().unwrap();
            assert_eq!(public.len(), 25);
            let n = r.remaining() - 1;
            let cipher = r.bytes(n).unwrap();
            let clear = crypto::tea_decrypt(&cipher, &wt.shared).unwrap();
            let mut r = Reader::new(clear);
            r.skip(1 + 2 + 4 + 4 + 2 + 1 + 4 + 1 + 2 + 2 + 21 + 1 + 2 + 2)
                .unwrap();
            assert_eq!(r.u32().unwrap(), 0);
        }
    }
    #[test]
    fn qr_polling_does_not_advance_the_wtlogin_login_sequence() {
        let mut s = state();
        s.keystore.tgtgt_key = vec![0x11; 16];
        let mut wt = WtLogin::new().unwrap();
        for sequence in 0..3u16 {
            let packet = wt.qr(0x12, None, &s).unwrap();
            assert_eq!(&packet[7..9], &sequence.to_be_bytes());
        }
        let packet = wt.login(&s).unwrap();
        assert_eq!(&packet[5..7], &0x810u16.to_be_bytes());
        assert_eq!(&packet[7..9], &0u16.to_be_bytes());
        let packet = wt.qr(0x12, None, &s).unwrap();
        assert_eq!(&packet[7..9], &3u16.to_be_bytes());
    }

    fn qr_accounts(packet: Bytes, shared: &[u8], command: u16) -> (u32, u64, u64) {
        let outer = u32::from_be_bytes(packet[9..13].try_into().unwrap());
        let mut r = Reader::new(packet);
        r.skip(3 + 2 + 2 + 2 + 4 + 1 + 1 + 4 + 1 + 2 + 2 + 4 + 1 + 1 + 16 + 2)
            .unwrap();
        r.p16().unwrap();
        let length = r.remaining() - 1;
        let clear = crypto::tea_decrypt(&r.bytes(length).unwrap(), shared).unwrap();
        let mut r = Reader::new(clear);
        r.skip(1 + 2 + 4 + 4 + 2 + 1 + 4 + 1 + 2 + 2 + 21 + 1 + 2 + 2 + 4)
            .unwrap();
        let secondary = r.u64().unwrap();
        r.skip(2 + 4).unwrap();
        if command == 0x12 {
            r.p16().unwrap();
        }
        (outer, secondary, r.u64().unwrap())
    }

    #[test]
    fn qr_account_binding_is_isolated_to_the_unusual_device_body() {
        let mut s = state();
        s.keystore.uin = 123456;
        s.keystore.tgtgt_key = vec![0x11; 16];
        s.keystore.qr_sig = b"synthetic-qr".to_vec();
        let mut wt = WtLogin::new().unwrap();
        for unusual in [false, true, false] {
            let signature = unusual.then_some(b"verification".as_slice());
            let packet = wt.qr(0x31, signature, &s).unwrap();
            let expected_account = if unusual { s.keystore.uin } else { 0 };
            assert_eq!(
                qr_accounts(packet, &wt.shared, 0x31),
                (0, 0, expected_account)
            );
            // Polling retains this QR attempt's account without resending its challenge.
            let packet = wt.qr(0x12, None, &s).unwrap();
            assert_eq!(
                qr_accounts(packet, &wt.shared, 0x12),
                (0, 0, expected_account)
            );
        }
        let packet = wt.login(&s).unwrap();
        assert_eq!(&packet[9..13], &(s.keystore.uin as u32).to_be_bytes());
    }

    #[test]
    fn trans_emp_sequence_wraps_without_affecting_login() {
        let mut s = state();
        s.keystore.tgtgt_key = vec![0x11; 16];
        let mut wt = WtLogin::new().unwrap();
        wt.trans_emp_sequence = u16::MAX;
        let packet = wt.qr(0x12, None, &s).unwrap();
        assert_eq!(&packet[7..9], &u16::MAX.to_be_bytes());
        let packet = wt.qr(0x12, None, &s).unwrap();
        assert_eq!(&packet[7..9], &0u16.to_be_bytes());
        let packet = wt.login(&s).unwrap();
        assert_eq!(&packet[7..9], &0u16.to_be_bytes());
    }
    #[test]
    fn ticket_failure_does_not_mutate_keystore() {
        let mut k = Keystore {
            nt_ticket_times: Some(NtTicketTimeMetadata {
                field12: Some(NtTicketTimeValues::default()),
                field16: None,
                received_unix_ms: 1,
            }),
            ..Default::default()
        };
        let old = k.clone();
        let t = BTreeMap::from([(0x143, Bytes::from_static(b"new-d2"))]);
        assert!(apply_tickets(&t, &mut k, 1_000).is_err());
        assert!(old == k);
    }

    #[test]
    fn ticket_time_overflow_never_commits_partial_tickets_or_time_source() {
        let mut store = Keystore {
            a1: b"old-a1".to_vec(),
            a2: b"old-a2".to_vec(),
            d2: b"old-d2".to_vec(),
            d2_key: vec![1; 16],
            nt_ticket_times: Some(NtTicketTimeMetadata {
                field12: Some(NtTicketTimeValues {
                    raw_field1: Some(123),
                    raw_field2: Some(456),
                }),
                field16: None,
                received_unix_ms: 1,
            }),
            ticket_generated_unix_seconds: Some(100),
            ..Default::default()
        };
        let retained = store.clone();
        let tickets = BTreeMap::from([
            (0x106, Bytes::from_static(b"new-a1")),
            (0x10a, Bytes::from_static(b"new-a2")),
            (0x143, Bytes::from_static(b"new-d2")),
            (0x305, Bytes::from_static(&[2; 16])),
        ]);
        for generated in [u64::MAX - 604_800 + 1, u64::MAX - 2_592_000 + 1] {
            assert!(apply_tickets(&tickets, &mut store, generated).is_err());
            assert!(store == retained);
        }
        let generated = u64::MAX - 2_592_000;
        apply_tickets(&tickets, &mut store, generated).unwrap();
        assert_eq!(store.ticket_generated_unix_seconds, Some(generated));
        assert_eq!(store.wt_ticket_times.unwrap().expire_unix_seconds, u64::MAX);
        assert_eq!(
            store.next_ticket_refresh_unix_seconds(),
            generated.checked_add(604_800),
        );
        assert_eq!(store.nt_ticket_times, None);
    }
}
