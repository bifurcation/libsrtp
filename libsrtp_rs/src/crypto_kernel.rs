use crate::crypto_test;
use crate::srtp::Error;
use std::any::Any;
use std::collections::HashMap;
use std::ops::Range;

use crate::aes_gcm::NativeAesGcm;
use crate::aes_icm::NativeAesIcm;
use crate::hmac::NativeHMAC;
use crate::null_auth::NullAuth;
use crate::null_cipher::NullCipher;
use crate::replay::ExtendedSequenceNumber;

//
// Constants
//
pub mod constants {
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
    pub const AES_ICM_192_KEY_LEN_WSALT: usize = SALT_LEN + AES_192_KEY_LEN;
    pub const AES_ICM_256_KEY_LEN_WSALT: usize = SALT_LEN + AES_256_KEY_LEN;

    pub const AES_GCM_128_KEY_LEN_WSALT: usize = AEAD_SALT_LEN + AES_128_KEY_LEN;
    pub const AES_GCM_192_KEY_LEN_WSALT: usize = AEAD_SALT_LEN + AES_192_KEY_LEN;
    pub const AES_GCM_256_KEY_LEN_WSALT: usize = AEAD_SALT_LEN + AES_256_KEY_LEN;

    pub const NULL_CIPHER_NONCE_SIZE: usize = 0;
    pub const AES_ICM_NONCE_SIZE: usize = 16;
    pub const AES_GCM_NONCE_SIZE: usize = 12;
}

//
// ExtensionCipher
//
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum ExtensionCipherTypeID {
    Null = 0,
    AesIcm128 = 1,
    AesIcm192 = 4,
    AesIcm256 = 5,
}

impl ExtensionCipherTypeID {
    pub fn key_size(&self) -> usize {
        match self {
            ExtensionCipherTypeID::Null => constants::NULL_CIPHER_KEY_LEN,
            ExtensionCipherTypeID::AesIcm128 => constants::AES_128_KEY_LEN,
            ExtensionCipherTypeID::AesIcm192 => constants::AES_192_KEY_LEN,
            ExtensionCipherTypeID::AesIcm256 => constants::AES_256_KEY_LEN,
        }
    }

    pub fn nonce_size(&self) -> usize {
        match self {
            ExtensionCipherTypeID::Null => constants::NULL_CIPHER_NONCE_SIZE,
            ExtensionCipherTypeID::AesIcm128 => constants::AES_ICM_NONCE_SIZE,
            ExtensionCipherTypeID::AesIcm192 => constants::AES_ICM_NONCE_SIZE,
            ExtensionCipherTypeID::AesIcm256 => constants::AES_ICM_NONCE_SIZE,
        }
    }

    pub fn salt_size(&self) -> usize {
        match self {
            ExtensionCipherTypeID::Null => constants::NULL_CIPHER_SALT_LEN,
            ExtensionCipherTypeID::AesIcm128 => constants::SALT_LEN,
            ExtensionCipherTypeID::AesIcm192 => constants::SALT_LEN,
            ExtensionCipherTypeID::AesIcm256 => constants::SALT_LEN,
        }
    }
}

pub trait ExtensionCipher {
    fn xtn_id(&self) -> ExtensionCipherTypeID;
    fn rtp_xtn_header_iv(
        &self,
        ssrc: u32,
        ext_seq_num: ExtendedSequenceNumber,
        nonce: &mut [u8],
    ) -> Result<usize, Error>;
    fn init(&mut self, iv: &[u8]) -> Result<(), Error>;
    fn xor_key(&mut self, buffer: &mut [u8], range: Range<usize>) -> Result<(), Error>;

    fn clone_inner(&self) -> Box<dyn ExtensionCipher>;
}

impl Clone for Box<dyn ExtensionCipher> {
    fn clone(&self) -> Box<dyn ExtensionCipher> {
        self.clone_inner()
    }
}

pub trait ExtensionCipherType {
    // XXX(RLB) These names are slightly awkward, but they avoid overlap  with the corresponding
    // methods on CipherType when the same type implements both traits.
    fn xtn_id(&self) -> ExtensionCipherTypeID;
    fn xtn_create(&self, key: &[u8], salt: &[u8]) -> Result<Box<dyn ExtensionCipher>, Error>;
}

//
// Cipher
//
#[repr(u32)]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum CipherTypeID {
    Null = 0,
    AesIcm128 = 1,
    AesIcm192 = 4,
    AesIcm256 = 5,
    AesGcm128 = 6,
    AesGcm256 = 7,
}

impl CipherTypeID {
    pub fn key_size(&self) -> usize {
        match self {
            CipherTypeID::Null => constants::NULL_CIPHER_KEY_LEN,
            CipherTypeID::AesIcm128 => constants::AES_128_KEY_LEN,
            CipherTypeID::AesIcm192 => constants::AES_192_KEY_LEN,
            CipherTypeID::AesIcm256 => constants::AES_256_KEY_LEN,
            CipherTypeID::AesGcm128 => constants::AES_128_KEY_LEN,
            CipherTypeID::AesGcm256 => constants::AES_256_KEY_LEN,
        }
    }

    pub fn nonce_size(&self) -> usize {
        match self {
            CipherTypeID::Null => constants::NULL_CIPHER_NONCE_SIZE,
            CipherTypeID::AesIcm128 => constants::AES_ICM_NONCE_SIZE,
            CipherTypeID::AesIcm192 => constants::AES_ICM_NONCE_SIZE,
            CipherTypeID::AesIcm256 => constants::AES_ICM_NONCE_SIZE,
            CipherTypeID::AesGcm128 => constants::AES_GCM_NONCE_SIZE,
            CipherTypeID::AesGcm256 => constants::AES_GCM_NONCE_SIZE,
        }
    }

    pub fn salt_size(&self) -> usize {
        match self {
            CipherTypeID::Null => constants::NULL_CIPHER_SALT_LEN,
            CipherTypeID::AesIcm128 => constants::SALT_LEN,
            CipherTypeID::AesIcm192 => constants::SALT_LEN,
            CipherTypeID::AesIcm256 => constants::SALT_LEN,
            CipherTypeID::AesGcm128 => constants::AEAD_SALT_LEN,
            CipherTypeID::AesGcm256 => constants::AEAD_SALT_LEN,
        }
    }

    pub fn extension_header_cipher_type(&self) -> ExtensionCipherTypeID {
        match self {
            CipherTypeID::Null => ExtensionCipherTypeID::Null,
            CipherTypeID::AesIcm128 => ExtensionCipherTypeID::AesIcm128,
            CipherTypeID::AesIcm192 => ExtensionCipherTypeID::AesIcm192,
            CipherTypeID::AesIcm256 => ExtensionCipherTypeID::AesIcm256,
            CipherTypeID::AesGcm128 => ExtensionCipherTypeID::AesIcm128,
            CipherTypeID::AesGcm256 => ExtensionCipherTypeID::AesIcm256,
        }
    }
}

pub trait Cipher {
    fn id(&self) -> CipherTypeID;

    fn rtp_nonce(
        &self,
        ssrc: u32,
        ext_seq_num: ExtendedSequenceNumber,
        nonce: &mut [u8],
    ) -> Result<usize, Error>;
    fn rtcp_nonce(&self, ssrc: u32, index: u32, nonce: &mut [u8]) -> Result<usize, Error>;

    fn encrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut [u8],
        pt_size: usize,
    ) -> Result<usize, Error>;
    fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut [u8],
        ct_size: usize, // TODO(RLB) Delete ct_size
    ) -> Result<usize, Error>;

    // XXX(RLB): These methods are required to support cloning of SRTP streams.  Right now, Cipher
    // objects are not suitable for shared usage (Rc / Arc) because (a) doing anything with them
    // requires mutation and (b) the encryption process is multi-stage, and would lead to
    // inconsistent states if interrupted mid-stream.
    //
    // What we should do instead is simplify this API so that mutability is no longer required, and
    // then use Rc<dyn Cipher> instead of Box<dyn Cipher> in consumers. Roughly:
    //
    //   fn encrypt(&self, iv: &[u8], aad: &[u8], buf: &mut [u8], pt_size: usize)
    //   fn decrypt(&self, iv: &[u8], aad: &[u8], buf: &mut [u8], ct_size: usize)
    fn clone_inner(&self) -> Box<dyn Cipher>;
}

impl Clone for Box<dyn Cipher> {
    fn clone(&self) -> Box<dyn Cipher> {
        self.clone_inner()
    }
}

pub trait CipherType {
    fn id(&self) -> CipherTypeID;
    fn create(&self, key: &[u8], salt: &[u8]) -> Result<Box<dyn Cipher>, Error>;
}

//
// Auth
//
#[repr(u32)]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum AuthTypeID {
    Null = 0,
    HmacSha1 = 3,
}

impl AuthTypeID {
    pub fn key_size(&self) -> usize {
        match self {
            AuthTypeID::Null => constants::NULL_AUTH_KEY_LEN,
            AuthTypeID::HmacSha1 => constants::HMAC_SHA1_KEY_LEN,
        }
    }
}

pub trait Auth {
    fn tag_size(&self) -> usize;
    fn prefix_size(&self) -> usize;
    fn start(&mut self) -> Result<(), Error>;
    fn update(&mut self, update: &[u8]) -> Result<(), Error>;
    fn compute(&mut self, message: &[u8], tag: &mut [u8]) -> Result<(), Error>;

    // XXX(RLB): See the screed in Cipher above
    fn clone_inner(&self) -> Box<dyn Auth>;
    fn as_any(&self) -> &dyn Any;
    fn equals(&self, other: &Box<dyn Auth>) -> bool;
}

pub trait AuthType {
    fn id(&self) -> AuthTypeID;
    fn create(&self, key: &[u8], tag_size: usize) -> Result<Box<dyn Auth>, Error>;
}

impl Clone for Box<dyn Auth> {
    fn clone(&self) -> Box<dyn Auth> {
        self.clone_inner()
    }
}

//
// Kernel
//
pub struct CryptoKernel {
    xtn_cipher_types: HashMap<ExtensionCipherTypeID, Box<dyn ExtensionCipherType>>,
    cipher_types: HashMap<CipherTypeID, Box<dyn CipherType>>,
    auth_types: HashMap<AuthTypeID, Box<dyn AuthType>>,
}

impl CryptoKernel {
    pub fn new() -> CryptoKernel {
        CryptoKernel {
            xtn_cipher_types: HashMap::new(),
            cipher_types: HashMap::new(),
            auth_types: HashMap::new(),
        }
    }

    // XXX(RLB) We might not want this once we have crypto agility, but it's handy to have for now.
    pub fn default() -> Result<CryptoKernel, Error> {
        let mut kernel = CryptoKernel::new();

        // Extension cipher types
        kernel.load_xtn_cipher_type(Box::new(NullCipher {}))?;
        kernel.load_xtn_cipher_type(Box::new(NativeAesIcm::new(constants::AesKeySize::Aes128)))?;
        kernel.load_xtn_cipher_type(Box::new(NativeAesIcm::new(constants::AesKeySize::Aes192)))?;
        kernel.load_xtn_cipher_type(Box::new(NativeAesIcm::new(constants::AesKeySize::Aes256)))?;

        // Cipher types
        kernel.load_cipher_type(Box::new(NullCipher {}))?;
        kernel.load_cipher_type(Box::new(NativeAesIcm::new(constants::AesKeySize::Aes128)))?;
        kernel.load_cipher_type(Box::new(NativeAesIcm::new(constants::AesKeySize::Aes192)))?;
        kernel.load_cipher_type(Box::new(NativeAesIcm::new(constants::AesKeySize::Aes256)))?;
        kernel.load_cipher_type(Box::new(NativeAesGcm::new(constants::AesKeySize::Aes128)?))?;
        kernel.load_cipher_type(Box::new(NativeAesGcm::new(constants::AesKeySize::Aes256)?))?;

        // Auth types
        kernel.load_auth_type(Box::new(NullAuth {}))?;
        kernel.load_auth_type(Box::new(NativeHMAC {}))?;
        Ok(kernel)
    }

    pub fn load_xtn_cipher_type(&mut self, ect: Box<dyn ExtensionCipherType>) -> Result<(), Error> {
        crypto_test::xtn_cipher(ect.as_ref())?;
        self.xtn_cipher_types.insert(ect.xtn_id(), ect);
        Ok(())
    }

    pub fn load_cipher_type(&mut self, ct: Box<dyn CipherType>) -> Result<(), Error> {
        crypto_test::cipher(ct.as_ref())?;
        self.cipher_types.insert(ct.id(), ct);
        Ok(())
    }

    pub fn load_auth_type(&mut self, at: Box<dyn AuthType>) -> Result<(), Error> {
        crypto_test::auth(at.as_ref())?;
        self.auth_types.insert(at.id(), at);
        Ok(())
    }

    pub fn xtn_cipher(
        &self,
        id: ExtensionCipherTypeID,
        key: &[u8],
        salt: &[u8],
    ) -> Result<Box<dyn ExtensionCipher>, Error> {
        match self.xtn_cipher_types.get(&id) {
            Some(cipher_type) => cipher_type.xtn_create(key, salt),
            _ => Err(Error::Fail),
        }
    }

    pub fn cipher(
        &self,
        id: CipherTypeID,
        key: &[u8],
        salt: &[u8],
    ) -> Result<Box<dyn Cipher>, Error> {
        match self.cipher_types.get(&id) {
            Some(cipher_type) => cipher_type.create(key, salt),
            _ => Err(Error::Fail),
        }
    }

    pub fn auth(
        &self,
        id: AuthTypeID,
        key: &[u8],
        tag_size: usize,
    ) -> Result<Box<dyn Auth>, Error> {
        match self.auth_types.get(&id) {
            Some(auth_type) => auth_type.create(key, tag_size),
            _ => Err(Error::Fail),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_load_native_types() -> Result<(), Error> {
        let _ = CryptoKernel::default()?;
        Ok(())
    }
}
