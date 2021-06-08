use crate::crypto_test;
use crate::srtp::Error;
use num_enum::{IntoPrimitive, TryFromPrimitive}; // only for C interface
use std::any::Any;
use std::collections::HashMap;

//
// Constants
//
pub mod constants {
    pub const SALT_LEN: usize = 14;
    pub const AEAD_SALT_LEN: usize = 12;

    pub const AES_128_KEY_LEN: usize = 16;
    pub const AES_192_KEY_LEN: usize = 24;
    pub const AES_256_KEY_LEN: usize = 32;

    pub const AES_ICM_128_KEY_LEN_WSALT: usize = SALT_LEN + AES_128_KEY_LEN;
    pub const AES_ICM_192_KEY_LEN_WSALT: usize = SALT_LEN + AES_192_KEY_LEN;
    pub const AES_ICM_256_KEY_LEN_WSALT: usize = SALT_LEN + AES_256_KEY_LEN;
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

pub const fn is_aead(id: CipherTypeID) -> bool {
    match id {
        CipherTypeID::Null => false,
        CipherTypeID::AesIcm128 => false,
        CipherTypeID::AesIcm192 => false,
        CipherTypeID::AesIcm256 => false,
        CipherTypeID::AesGcm128 => true,
        CipherTypeID::AesGcm256 => true,
    }
}

#[repr(u32)] // only for C interface
#[derive(Copy, Clone, TryFromPrimitive, IntoPrimitive)] // only for C interface
pub enum CipherDirection {
    Encrypt = 0,
    Decrypt = 1,
    Any = 2,
}

pub trait Cipher {
    fn key_size(&self) -> usize;
    fn iv_size(&self) -> usize;
    fn init(&mut self, key: &[u8]) -> Result<(), Error>;
    fn set_aad(&mut self, _aad: &[u8]) -> Result<(), Error>;
    fn set_iv(&mut self, iv: &[u8], direction: CipherDirection) -> Result<(), Error>;
    fn encrypt(&mut self, buf: &mut [u8], pt_size: usize) -> Result<usize, Error>;
    fn decrypt(&mut self, buf: &mut [u8], ct_size: usize) -> Result<usize, Error>;
    fn get_tag(&mut self, tag: &mut [u8]) -> Result<usize, Error>;

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
    fn create(&self, key_len: usize, out_len: usize) -> Result<Box<dyn Cipher>, Error>;
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

pub trait Auth {
    fn key_size(&self) -> usize;
    fn tag_size(&self) -> usize;
    fn prefix_size(&self) -> usize;
    fn init(&mut self, key: &[u8]) -> Result<(), Error>;
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
    fn create(&self, key_len: usize, out_len: usize) -> Result<Box<dyn Auth>, Error>;
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
    cipher_types: HashMap<CipherTypeID, Box<dyn CipherType>>,
    auth_types: HashMap<AuthTypeID, Box<dyn AuthType>>,
}

impl CryptoKernel {
    pub fn new() -> CryptoKernel {
        CryptoKernel {
            cipher_types: HashMap::new(),
            auth_types: HashMap::new(),
        }
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

    pub fn cipher(
        &self,
        id: CipherTypeID,
        key_len: usize,
        tag_len: usize,
    ) -> Result<Box<dyn Cipher>, Error> {
        match self.cipher_types.get(&id) {
            Some(cipher_type) => cipher_type.create(key_len, tag_len),
            _ => Err(Error::Fail),
        }
    }

    pub fn auth(
        &self,
        id: AuthTypeID,
        key_len: usize,
        tag_len: usize,
    ) -> Result<Box<dyn Auth>, Error> {
        match self.auth_types.get(&id) {
            Some(auth_type) => auth_type.create(key_len, tag_len),
            _ => Err(Error::Fail),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::aes::KeySize;
    use crate::aes_icm::NativeAesIcm;
    use crate::hmac::NativeHMAC;
    use crate::null_auth::NullAuth;
    use crate::null_cipher::NullCipher;

    #[test]
    fn test_load_native_types() -> Result<(), Error> {
        let mut kernel = CryptoKernel::new();

        // Cipher types
        kernel.load_cipher_type(Box::new(NullCipher {}))?;
        kernel.load_cipher_type(Box::new(NativeAesIcm::new(KeySize::Aes128)))?;
        kernel.load_cipher_type(Box::new(NativeAesIcm::new(KeySize::Aes256)))?;

        // Auth types
        kernel.load_auth_type(Box::new(NullAuth {}))?;
        kernel.load_auth_type(Box::new(NativeHMAC {}))?;

        Ok(())
    }
}
