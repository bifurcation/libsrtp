use crate::crypto_kernel::constants;
use crate::crypto_kernel::{Cipher, CipherDirection, CipherTypeID, CryptoKernel};
use crate::srtp::Error;
use num_enum::IntoPrimitive;

#[repr(u8)]
#[derive(IntoPrimitive)]
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
    cipher: Box<dyn Cipher>,
}

impl KDF {
    pub fn new(kernel: &CryptoKernel, key: &[u8]) -> Result<Self, Error> {
        let cipher_id = match key.len() {
            constants::AES_ICM_128_KEY_LEN_WSALT => CipherTypeID::AesIcm128,
            // TODO constants::AES_ICM_192_KEY_LEN_WSALT => CipherTypeID::AesIcm192,
            constants::AES_ICM_256_KEY_LEN_WSALT => CipherTypeID::AesIcm256,
            _ => return Err(Error::BadParam),
        };

        let mut kdf = KDF {
            cipher: kernel.cipher(cipher_id, key.len(), 0)?,
        };

        kdf.cipher.init(key)?;
        Ok(kdf)
    }

    pub fn generate(&mut self, label: KdfLabel, value: &mut [u8]) -> Result<(), Error> {
        let mut iv = [0u8; 16];
        iv[7] = label.into();
        self.cipher.set_iv(&iv, CipherDirection::Encrypt)?;
        self.cipher.encrypt(value, value.len())?;
        Ok(())
    }
}
