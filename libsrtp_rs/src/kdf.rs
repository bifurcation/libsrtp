use crate::crypto::{CipherInstance, CipherTypeID, CryptoKernel};
use crate::srtp::Error;
use num_enum::IntoPrimitive;

#[repr(u8)]
#[derive(Copy, Clone, Debug, IntoPrimitive)]
pub enum KdfLabel {
    RtpEncryption = 0x00,
    RtpMsgAuth = 0x01,
    RtpSalt = 0x02,
    RtcpEncryption = 0x03,
    RtcpMsgAuth = 0x04,
    RtcpSalt = 0x05,
    RtpHeaderEncryption = 0x06,
    RtpHeaderSalt = 0x07,
}

pub struct KDF {
    salt: [u8; 16],
    cipher: CipherInstance,
}

impl KDF {
    pub fn cipher_type(rtp: CipherTypeID, rtcp: CipherTypeID) -> CipherTypeID {
        match (rtp, rtcp) {
            (CipherTypeID::Null, _) => CipherTypeID::AesIcm128,
            (CipherTypeID::AesIcm128, _) => CipherTypeID::AesIcm128,
            (CipherTypeID::AesGcm128, _) => CipherTypeID::AesIcm128,
            (_, CipherTypeID::Null) => CipherTypeID::AesIcm128,
            (_, CipherTypeID::AesIcm128) => CipherTypeID::AesIcm128,
            (_, CipherTypeID::AesGcm128) => CipherTypeID::AesIcm128,
            _ => CipherTypeID::AesIcm256,
        }
    }

    pub fn new(
        kernel: &CryptoKernel,
        cipher_id: CipherTypeID,
        key: &[u8],
        salt: &[u8],
    ) -> Result<Self, Error> {
        let mut kdf = KDF {
            salt: [0; 16],
            cipher: kernel.cipher(cipher_id, key, salt)?,
        };

        kdf.salt[..salt.len()].copy_from_slice(salt);
        Ok(kdf)
    }

    pub fn generate(&self, label: KdfLabel, buffer: &mut [u8]) -> Result<(), Error> {
        let mut inst = self.cipher.try_borrow_mut().map_err(|_| Error::Fail)?;
        let op = inst.start();

        let mut nonce = self.salt;
        let label_u8: u8 = label.into();
        nonce[7] ^= label_u8;

        buffer.fill(0);
        op.encrypt(&nonce, &[], buffer, buffer.len())?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_kdf() -> Result<(), Error> {
        let kdf_key = hex!("e1f97a0d3e018be0d64fa32c06de4139");
        let kdf_salt = hex!("0ec675ad498afeebb6960b3aabe6");
        let test_keys: [(KdfLabel, &[u8]); 8] = [
            (
                KdfLabel::RtpEncryption,
                &hex!("c61e7a93744f39ee10734afe3ff7a087"),
            ),
            (KdfLabel::RtpSalt, &hex!("30cbbc08863d8c85d49db34a9ae1")),
            (
                KdfLabel::RtpMsgAuth,
                &hex!("cebe321f6ff7716b6fd4ab49af256a15"),
            ),
            (
                KdfLabel::RtpHeaderEncryption,
                &hex!("549752054d6fb708622c4a2e596a1b93"),
            ),
            (
                KdfLabel::RtpHeaderSalt,
                &hex!("ab01818174c40d39a3781f7c2d27"),
            ),
            (
                KdfLabel::RtcpEncryption,
                &hex!("4c1aa45a81f73d61c800bbb00fbb1eaa"),
            ),
            (KdfLabel::RtcpSalt, &hex!("9581c7ad87b3e530bf3e4454a8b3")),
            (
                KdfLabel::RtcpMsgAuth,
                &hex!("8d54534feb49ae8e7993a6bd0b844fc3"),
            ),
        ];

        // Initialize the KDF
        let kernel = CryptoKernel::default()?;
        let kdf = KDF::new(&kernel, CipherTypeID::AesIcm128, &kdf_key, &kdf_salt)?;

        // Verify proper derivation
        for (label, ref_val) in test_keys {
            let mut gen_val = vec![0u8; ref_val.len()];
            kdf.generate(label, &mut gen_val)?;
            assert_eq!(gen_val, ref_val);
        }
        Ok(())
    }
}
