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

const MAX_KDF_OUTPUT_SIZE: usize = 46;

pub struct KDF {
    iv: [u8; 16],
    buffer: [u8; MAX_KDF_OUTPUT_SIZE],
    cipher: Box<dyn Cipher>,
}

impl KDF {
    pub fn new(kernel: &CryptoKernel, key: &[u8]) -> Result<Self, Error> {
        let cipher_id = match key.len() {
            constants::AES_ICM_128_KEY_LEN_WSALT => CipherTypeID::AesIcm128,
            constants::AES_ICM_192_KEY_LEN_WSALT => CipherTypeID::AesIcm192,
            constants::AES_ICM_256_KEY_LEN_WSALT => CipherTypeID::AesIcm256,
            _ => return Err(Error::BadParam),
        };

        let mut kdf = KDF {
            iv: [0; 16],
            buffer: [0; MAX_KDF_OUTPUT_SIZE],
            cipher: kernel.cipher(cipher_id, key.len(), 0)?,
        };

        kdf.cipher.init(key)?;
        Ok(kdf)
    }

    pub fn generate(&mut self, label: KdfLabel, size: usize) -> Result<&[u8], Error> {
        if size > self.buffer.len() {
            return Err(Error::BadParam);
        }

        let output = &mut self.buffer[..size];
        output.fill(0);

        self.iv[7] = label.into();
        println!("iv: {:02x?}", &self.iv);
        self.cipher.set_iv(&self.iv, CipherDirection::Encrypt)?;
        self.cipher.encrypt(output, output.len())?;
        Ok(output)
    }
}
