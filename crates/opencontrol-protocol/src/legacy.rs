//! Explicit historical kind0 compatibility. Checksums provide no cryptographic authenticity.
use crate::{
    crypto::ReplayWindow, datagram::NetworkPacket, LegacyCipherConfig, LegacyPolicy, ProtocolError,
    ProtocolLimits, WireVersion,
};
use blowfish::{
    cipher::{Block, BlockCipherEncrypt, KeyInit},
    Blowfish,
};
use bytes::Bytes;
use std::fmt;
use zeroize::Zeroizing;

pub struct LegacyDataCipher {
    cipher: Blowfish,
    salt: Zeroizing<[u8; 8]>,
    counter: u64,
    tx: u32,
    replay: ReplayWindow,
    slot: u8,
    version: WireVersion,
}
impl fmt::Debug for LegacyDataCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LegacyDataCipher")
            .field("slot", &self.slot)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}
impl LegacyDataCipher {
    pub fn new(
        config: &LegacyCipherConfig,
        version: WireVersion,
        policy: LegacyPolicy,
    ) -> Result<Self, ProtocolError> {
        if policy != LegacyPolicy::ExplicitlyEnabled {
            return Err(ProtocolError::LegacyDisabled);
        }
        if config.slot > 1 {
            return Err(ProtocolError::InvalidField("cipher slot"));
        }
        let mut initial = Zeroizing::new([0; 8]);
        getrandom::getrandom(&mut initial[..]).map_err(|_| ProtocolError::Randomness)?;
        Ok(Self {
            cipher: Blowfish::new_from_slice(config.key.key_bytes())
                .map_err(|_| ProtocolError::InvalidField("legacy key"))?,
            salt: Zeroizing::new(*config.key.salt_bytes()),
            counter: u64::from_le_bytes(*initial),
            tx: 0,
            replay: ReplayWindow::default(),
            slot: config.slot,
            version,
        })
    }
    pub fn seal(
        &mut self,
        packet: &NetworkPacket,
        limits: ProtocolLimits,
    ) -> Result<Bytes, ProtocolError> {
        let trailer = if self.version == WireVersion::V1 {
            0
        } else {
            6
        };
        let len = packet
            .payload
            .len()
            .checked_add(4 + trailer)
            .ok_or(ProtocolError::InvalidLength)?;
        let padded = len.checked_add(7).ok_or(ProtocolError::InvalidLength)? / 8 * 8;
        if padded + 13 > limits.max_datagram_size.min(8192) || len - 2 > u16::MAX as usize {
            return Err(ProtocolError::Limit("legacy datagram"));
        }
        let next_counter = self
            .counter
            .checked_add((padded / 8) as u64)
            .ok_or(ProtocolError::KeyExhausted)?;
        if trailer != 0 && self.tx >= 0xffff_ffbf {
            return Err(ProtocolError::Replay);
        }
        let mut plain = Zeroizing::new(Vec::with_capacity(padded));
        plain.extend_from_slice(&((len - 2) as u16).to_be_bytes());
        plain.extend_from_slice(&packet.ether_type.to_be_bytes());
        plain.extend_from_slice(&packet.payload);
        let next_sequence = self.tx + u32::from(trailer != 0);
        if trailer != 0 {
            plain.extend_from_slice(&next_sequence.to_be_bytes());
            let check = checksum(&plain[2..]);
            plain.extend_from_slice(&check.to_be_bytes());
        }
        plain.resize(padded, 0xff);
        crypt(&self.cipher, self.counter, &mut plain)?;
        let mut b = Vec::with_capacity(padded + 13);
        b.extend_from_slice(&[0x4b, 0, 0, self.slot, 8]);
        for (a, b_salt) in self.counter.to_le_bytes().iter().zip(self.salt.iter()) {
            b.push(a ^ b_salt)
        }
        b.extend_from_slice(&plain);
        self.tx = next_sequence;
        self.counter = next_counter;
        Ok(Bytes::from(b))
    }
    pub fn open(
        &mut self,
        bytes: &[u8],
        limits: ProtocolLimits,
    ) -> Result<NetworkPacket, ProtocolError> {
        if bytes.len() > limits.max_datagram_size.min(8192) {
            return Err(ProtocolError::Limit("legacy datagram"));
        }
        if bytes.len() < 21 || !(bytes.len() - 13).is_multiple_of(8) {
            return Err(ProtocolError::InvalidLength);
        }
        if bytes[0] != 0x4b || bytes[2] != 0 || bytes[3] != self.slot || bytes[4] != 8 {
            return Err(ProtocolError::InvalidField("legacy datagram header"));
        }
        let mut counter = Zeroizing::new([0; 8]);
        for i in 0..8 {
            counter[i] = bytes[5 + i] ^ self.salt[i];
        }
        let mut plain = Zeroizing::new(bytes[13..].to_vec());
        crypt(&self.cipher, u64::from_le_bytes(*counter), &mut plain)?;
        let declared = u16::from_be_bytes([plain[0], plain[1]]) as usize;
        let trailer = if self.version == WireVersion::V1 {
            0
        } else {
            6
        };
        if declared < 2 + trailer || declared + 2 > plain.len() || plain.len() - declared - 2 > 7 {
            return Err(ProtocolError::InvalidLength);
        }
        if plain[declared + 2..].iter().any(|b| *b != 0xff) {
            return Err(ProtocolError::InvalidField("legacy padding"));
        }
        let end = 2 + declared;
        if trailer != 0 {
            let check = u16::from_be_bytes([plain[end - 2], plain[end - 1]]);
            if checksum(&plain[2..end - 2]) != check {
                return Err(ProtocolError::ChecksumFailure);
            }
            let n = u32::from_be_bytes([
                plain[end - 6],
                plain[end - 5],
                plain[end - 4],
                plain[end - 3],
            ]);
            self.replay.accept(n)?;
        }
        Ok(NetworkPacket {
            ether_type: u16::from_be_bytes([plain[2], plain[3]]),
            payload: Bytes::copy_from_slice(&plain[4..end - trailer]),
        })
    }
    pub fn needs_rotation(&self) -> bool {
        self.tx > 0x0200_0000 || self.replay.last() > 0x0200_0000
    }
}
fn crypt(cipher: &Blowfish, first: u64, buffer: &mut [u8]) -> Result<(), ProtocolError> {
    if !buffer.len().is_multiple_of(8) {
        return Err(ProtocolError::InvalidLength);
    }
    if first.checked_add((buffer.len() / 8) as u64).is_none() {
        return Err(ProtocolError::KeyExhausted);
    }
    for (i, chunk) in buffer.as_chunks_mut::<8>().0.iter_mut().enumerate() {
        let mut block: Block<Blowfish> = (first + i as u64).to_le_bytes().into();
        cipher.encrypt_block(&mut block);
        for (dst, key) in chunk.iter_mut().zip(block.iter()) {
            *dst ^= key;
        }
        use blowfish::cipher::zeroize::Zeroize;
        block.zeroize();
    }
    Ok(())
}
fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for p in data.chunks(2) {
        sum += u16::from_be_bytes([p[0], *p.get(1).unwrap_or(&0)]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_vectors() {
        let doc: serde_json::Value = serde_json::from_str(include_str!(
            "../../../protocol/vectors/legacy_synthetic.json"
        ))
        .unwrap();
        for v in doc["vectors"].as_array().unwrap() {
            let key: [u8; 16] = hex::decode(v["key"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let salt: [u8; 8] = hex::decode(v["salt"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let cfg = LegacyCipherConfig {
                slot: 0,
                key: crate::LegacyKey::from_bytes(key, salt),
            };
            let version = WireVersion::try_from(v["wire"].as_u64().unwrap() as u8).unwrap();
            let mut cipher =
                LegacyDataCipher::new(&cfg, version, LegacyPolicy::ExplicitlyEnabled).unwrap();
            cipher.counter = u64::from_le_bytes(
                hex::decode(v["counter"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            );
            let packet = NetworkPacket {
                ether_type: 0x0800,
                payload: Bytes::from(hex::decode(v["payload"].as_str().unwrap()).unwrap()),
            };
            let wire = cipher.seal(&packet, ProtocolLimits::default()).unwrap();
            assert_eq!(hex::encode(&wire), v["datagram"].as_str().unwrap());
            assert_eq!(
                cipher.open(&wire, ProtocolLimits::default()).unwrap(),
                packet
            );
            if version != WireVersion::V1 {
                assert_eq!(
                    cipher.open(&wire, ProtocolLimits::default()),
                    Err(ProtocolError::Replay)
                );
            }
        }
    }
    #[test]
    fn checksum_failure_does_not_consume_sequence() {
        let cfg = LegacyCipherConfig {
            slot: 0,
            key: crate::LegacyKey::from_bytes([1; 16], [2; 8]),
        };
        let mut tx =
            LegacyDataCipher::new(&cfg, WireVersion::V4, LegacyPolicy::ExplicitlyEnabled).unwrap();
        let mut rx =
            LegacyDataCipher::new(&cfg, WireVersion::V4, LegacyPolicy::ExplicitlyEnabled).unwrap();
        let good = tx
            .seal(
                &NetworkPacket {
                    ether_type: 0x0800,
                    payload: Bytes::from_static(b"odd"),
                },
                ProtocolLimits::default(),
            )
            .unwrap();
        let mut bad = good.to_vec();
        bad[13 + 2 + 2] ^= 1;
        assert_eq!(
            rx.open(&bad, ProtocolLimits::default()),
            Err(ProtocolError::ChecksumFailure)
        );
        rx.open(&good, ProtocolLimits::default()).unwrap();
    }
}
