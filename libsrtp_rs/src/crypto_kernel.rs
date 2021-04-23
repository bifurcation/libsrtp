use crate::crypto_test;
use crate::srtp::Error;
use std::collections::HashMap;

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

pub enum CipherDirection {
    Encrypt,
    Decrypt,
    Any,
}

pub trait Cipher {
    fn init(&mut self, key: &[u8]) -> Result<(), Error>;
    fn set_aad(&mut self, _aad: &[u8]) -> Result<(), Error>;
    fn set_iv(&mut self, iv: &[u8], direction: CipherDirection) -> Result<(), Error>;
    fn encrypt(&mut self, buf: &mut [u8], pt_size: &mut usize) -> Result<(), Error>;
    fn get_tag(&mut self, _tag: &mut [u8]) -> Result<(), Error>;
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
    fn init(&mut self, key: &[u8]) -> Result<(), Error>;
    fn update(&mut self, update: &[u8]) -> Result<(), Error>;
    fn compute(&mut self, message: &[u8], tag: &mut [u8]) -> Result<(), Error>;
}

pub trait AuthType {
    fn id(&self) -> AuthTypeID;
    fn create(&self, key_len: usize, out_len: usize) -> Result<Box<dyn Auth>, Error>;
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
    use crate::aes_icm::{KeySize, NativeAesIcm};
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
