//! AES-128-GCM with empty AAD, as established by E0019. Header bytes are unauthenticated.
use crate::ProtocolError;
use aes_gcm::{aead::AeadInPlace, Aes128Gcm, KeyInit, Nonce, Tag};
use std::fmt;
use zeroize::Zeroize;

pub struct SessionKey([u8; 16]);
impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionKey([REDACTED])")
    }
}
impl Drop for SessionKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl SessionKey {
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
    pub fn generate() -> Result<Self, ProtocolError> {
        let mut key = zeroize::Zeroizing::new([0; 16]);
        getrandom::getrandom(&mut key[..]).map_err(|_| ProtocolError::Randomness)?;
        Ok(Self(*key))
    }
    /// Explicit secret access for TLS configuration serialization. Never log this value.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
    pub(crate) fn encrypt(
        &self,
        nonce: &[u8; 12],
        plaintext: &mut [u8],
    ) -> Result<[u8; 16], ProtocolError> {
        let cipher =
            Aes128Gcm::new_from_slice(&self.0).map_err(|_| ProtocolError::CryptoFailure)?;
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(nonce), b"", plaintext)
            .map_err(|_| ProtocolError::CryptoFailure)?;
        let mut result = [0; 16];
        result.copy_from_slice(&tag);
        Ok(result)
    }
    pub(crate) fn decrypt(
        &self,
        nonce: &[u8; 12],
        tag: &[u8; 16],
        ciphertext: &mut [u8],
    ) -> Result<(), ProtocolError> {
        let cipher =
            Aes128Gcm::new_from_slice(&self.0).map_err(|_| ProtocolError::CryptoFailure)?;
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(nonce),
                b"",
                ciphertext,
                Tag::from_slice(tag),
            )
            .map_err(|_| ProtocolError::CryptoFailure)
    }
}

/// Observed receive window (E0021/E0038), without modular wraparound.
#[derive(Debug, Default, Clone)]
pub struct ReplayWindow {
    last: u32,
    seen: u64,
}
impl ReplayWindow {
    /// Mutates only on acceptance. Call only after successful GCM authentication.
    pub fn accept(&mut self, sequence: u32) -> Result<(), ProtocolError> {
        if sequence == 0 || sequence > 0xffff_ffbf {
            return Err(ProtocolError::Replay);
        }
        if sequence > self.last {
            let shift = sequence - self.last;
            self.seen = if shift >= 64 {
                1
            } else {
                (self.seen << shift) | 1
            };
            self.last = sequence;
            return Ok(());
        }
        let offset = self.last - sequence;
        if offset >= 64 || self.seen & (1u64 << offset) != 0 {
            return Err(ProtocolError::Replay);
        }
        self.seen |= 1u64 << offset;
        Ok(())
    }
    pub fn last(&self) -> u32 {
        self.last
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_aes_golden_vector() {
        let key = SessionKey::from_bytes([0; 16]);
        let mut data = hex::decode("080000000001").unwrap();
        let tag = key.encrypt(&[0; 12], &mut data).unwrap();
        assert_eq!(hex::encode(&data), "0b88dace60b7");
        assert_eq!(hex::encode(tag), "207f594ef8a7950f1036e4575ed9e92b");
        key.decrypt(&[0; 12], &tag, &mut data).unwrap();
        assert_eq!(hex::encode(data), "080000000001");
    }
}
