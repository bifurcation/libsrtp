use crate::crypto_kernel::constants;
use crate::crypto_kernel::{Cipher, CipherTypeID, CryptoKernel};
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
    cipher: Box<dyn Cipher>,
}

impl KDF {
    pub fn cipher_type(rtp: CipherTypeID, rtcp: CipherTypeID) -> CipherTypeID {
        if rtp.key_size() <= constants::AES_128_KEY_LEN
            && rtcp.key_size() <= constants::AES_128_KEY_LEN
        {
            CipherTypeID::AesIcm128
        } else {
            CipherTypeID::AesIcm256
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

        if salt.len() != constants::SALT_LEN {
            return Err(Error::BadParam);
        }

        kdf.salt[..constants::SALT_LEN].copy_from_slice(salt);
        Ok(kdf)
    }

    pub fn generate(&self, label: KdfLabel, buffer: &mut [u8]) -> Result<(), Error> {
        let mut nonce = self.salt;
        let label_u8: u8 = label.into();
        nonce[7] ^= label_u8;

        self.cipher.encrypt(&nonce, buffer, buffer.len())?;
        Ok(())
    }
}
