use super::CipherTypeID;
use super::ExtensionCipherTypeID;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesKeySize {
    Aes128 = 16,
    Aes192 = 24,
    Aes256 = 32,
}

impl AesKeySize {
    pub fn as_usize(&self) -> usize {
        match self {
            AesKeySize::Aes128 => AES_128_KEY_LEN,
            AesKeySize::Aes192 => AES_192_KEY_LEN,
            AesKeySize::Aes256 => AES_256_KEY_LEN,
        }
    }

    pub fn as_icm_id(&self) -> CipherTypeID {
        match self {
            AesKeySize::Aes128 => CipherTypeID::AesIcm128,
            AesKeySize::Aes192 => CipherTypeID::AesIcm192,
            AesKeySize::Aes256 => CipherTypeID::AesIcm256,
        }
    }

    pub fn as_gcm_id(&self) -> CipherTypeID {
        match self {
            AesKeySize::Aes128 => CipherTypeID::AesGcm128,
            AesKeySize::Aes192 => panic!("Invalid GCM key size"),
            AesKeySize::Aes256 => CipherTypeID::AesGcm256,
        }
    }

    pub fn as_stream_icm_id(&self) -> ExtensionCipherTypeID {
        match self {
            AesKeySize::Aes128 => ExtensionCipherTypeID::AesIcm128,
            AesKeySize::Aes192 => ExtensionCipherTypeID::AesIcm192,
            AesKeySize::Aes256 => ExtensionCipherTypeID::AesIcm256,
        }
    }
}

impl Into<usize> for AesKeySize {
    fn into(self) -> usize {
        self.as_usize()
    }
}

pub const NULL_CIPHER_SALT_LEN: usize = 0;
pub const SALT_LEN: usize = 14;
pub const AEAD_SALT_LEN: usize = 12;

pub const NULL_CIPHER_KEY_LEN: usize = 0;
pub const AES_128_KEY_LEN: usize = 16;
pub const AES_192_KEY_LEN: usize = 24;
pub const AES_256_KEY_LEN: usize = 32;

pub const NULL_AUTH_KEY_LEN: usize = 0;
pub const HMAC_SHA1_KEY_LEN: usize = 20;

pub const AES_ICM_128_KEY_LEN_WSALT: usize = SALT_LEN + AES_128_KEY_LEN;
pub const AES_ICM_256_KEY_LEN_WSALT: usize = SALT_LEN + AES_256_KEY_LEN;

pub const AES_GCM_128_KEY_LEN_WSALT: usize = AEAD_SALT_LEN + AES_128_KEY_LEN;
pub const AES_GCM_256_KEY_LEN_WSALT: usize = AEAD_SALT_LEN + AES_256_KEY_LEN;

pub const NULL_CIPHER_NONCE_SIZE: usize = 0;
pub const AES_ICM_NONCE_SIZE: usize = 16;
pub const AES_GCM_NONCE_SIZE: usize = 12;
