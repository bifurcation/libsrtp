use crate::replay::ExtendedSequenceNumber;
use crate::srtp::Error;
use std::cell::RefCell;
use std::collections::HashMap;
use std::ops::Range;
use std::ops::{Deref, DerefMut};
use std::rc::Rc;

//
// Submodules
//
pub(crate) mod constants;

pub(crate) mod aes_gcm;
pub(crate) mod aes_icm;
pub(crate) mod hmac_sha1;
pub(crate) mod null_auth;
pub(crate) mod null_cipher;
mod self_test;

#[cfg(feature = "openssl-crypto")]
mod openssl_common;

use self::aes_gcm::AesGcm;
use self::aes_icm::AesIcm;
use self::hmac_sha1::HmacSha1;
use self::null_auth::NullAuth;
use self::null_cipher::NullCipher;

pub(crate) fn xor_eq(a: &mut [u8], b: &[u8]) {
    for (b1, b2) in a.iter_mut().zip(b.iter()) {
        *b1 ^= *b2;
    }
}

//
// Operations and Instances
//

// Crypto objects in libsrtp are stateful, so they need to be reset between operations.
pub trait Reset {
    fn reset(&mut self);
}

// Operation just represents a wrapper around a resettable crypto object that uses RAII to make
// sure the object is reset at the end of the operation's scope.
pub struct Operation<'a, T: Reset> {
    val: &'a mut T,
}

impl<'a, T: Reset> Deref for Operation<'a, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        self.val
    }
}

impl<'a, T: Reset> DerefMut for Operation<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.val
    }
}

impl<'a, T: Reset> Drop for Operation<'a, T> {
    fn drop(&mut self) {
        self.val.reset();
    }
}

pub struct Instance<T: Reset> {
    val: T,
}

// An Instance represents an instantiation of a crypto object with a given key, which will be
// reused across multiple operations.  The Instance object is mainly used to produce Operations
// that expose the underlying object.
impl<T> Instance<T>
where
    T: Reset,
{
    pub fn new(val: T) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self { val: val }))
    }

    pub fn start<'b>(&'b mut self) -> Operation<'b, T> {
        Operation { val: &mut self.val }
    }
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

pub trait ExtensionCipher: Reset {
    fn xtn_id(&self) -> ExtensionCipherTypeID;

    fn init(&mut self, ssrc: u32, ext_seq_num: ExtendedSequenceNumber) -> Result<(), Error>;

    // buffer[0..(range.end-range.start)] ^= keystream[range]
    fn xor_key(&mut self, buffer: &mut [u8], range: Range<usize>) -> Result<(), Error>;
}

impl Reset for Box<dyn ExtensionCipher> {
    fn reset(&mut self) {
        self.deref_mut().reset()
    }
}

pub type ExtensionCipherInstance = Rc<RefCell<Instance<Box<dyn ExtensionCipher>>>>;

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

pub trait Cipher: Reset {
    fn id(&self) -> CipherTypeID;
    fn overhead(&self) -> usize;

    fn rtp_nonce(
        &self,
        ssrc: u32,
        ext_seq_num: ExtendedSequenceNumber,
        nonce: &mut [u8],
    ) -> Result<usize, Error>;
    fn rtcp_nonce(&self, ssrc: u32, index: u32, nonce: &mut [u8]) -> Result<usize, Error>;

    // XXX(RLB) Note: `aad: &[&[u8]]` to allow for SRTCP's discontiguous AAD
    fn encrypt(
        &self,
        nonce: &[u8],
        aad: &[&[u8]],
        buf: &mut [u8],
        pt_size: usize,
    ) -> Result<usize, Error>;
    fn decrypt(&self, nonce: &[u8], aad: &[&[u8]], buf: &mut [u8]) -> Result<usize, Error>;
}

impl Reset for Box<dyn Cipher> {
    fn reset(&mut self) {
        self.deref_mut().reset()
    }
}

pub type CipherInstance = Rc<RefCell<Instance<Box<dyn Cipher>>>>;

pub trait Overhead {
    fn overhead(&self) -> Result<usize, Error>;
}

impl Overhead for CipherInstance {
    fn overhead(&self) -> Result<usize, Error> {
        let mut inst = self.try_borrow_mut().map_err(|_| Error::Fail)?;
        let op = inst.start();
        Ok(op.overhead())
    }
}

pub trait CipherType {
    fn id(&self) -> CipherTypeID;
    fn create(&self, key: &[u8], salt: &[u8]) -> Result<Box<dyn Cipher>, Error>;
    fn clone(&self) -> Box<dyn CipherType>;
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

pub trait Auth: Reset {
    fn tag_size(&self) -> usize;

    // Note:
    // * `&mut self` to allow for internal mutability of a MAC instance
    // * `inputs: &[&[u8]]` to allow for SRTP's disaggregated auth input
    fn compute(&mut self, inputs: &[&[u8]], tag: &mut [u8]) -> Result<(), Error>;

    // This method allows us to expose the crypto libraries' constant-time equality checking
    // methods, so that we don't have to have our own.
    fn constant_time_eq(&self, tag_a: &[u8], tag_b: &[u8]) -> bool;
}

impl Reset for Box<dyn Auth> {
    fn reset(&mut self) {
        self.deref_mut().reset()
    }
}

pub type AuthInstance = Rc<RefCell<Instance<Box<dyn Auth>>>>;

pub trait TagSize {
    fn tag_size(&self) -> Result<usize, Error>;
}

impl TagSize for AuthInstance {
    fn tag_size(&self) -> Result<usize, Error> {
        let mut inst = self.try_borrow_mut().map_err(|_| Error::Fail)?;
        let op = inst.start();
        Ok(op.tag_size())
    }
}

pub trait AuthType {
    fn id(&self) -> AuthTypeID;
    fn create(&self, key: &[u8], tag_size: usize) -> Result<Box<dyn Auth>, Error>;
    fn clone(&self) -> Box<dyn AuthType>;
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
        kernel.load_xtn_cipher_type(Box::new(AesIcm::new(constants::AesKeySize::Aes128)?))?;
        kernel.load_xtn_cipher_type(Box::new(AesIcm::new(constants::AesKeySize::Aes192)?))?;
        kernel.load_xtn_cipher_type(Box::new(AesIcm::new(constants::AesKeySize::Aes256)?))?;

        // Cipher types
        kernel.load_cipher_type(Box::new(NullCipher {}))?;
        kernel.load_cipher_type(Box::new(AesIcm::new(constants::AesKeySize::Aes128)?))?;
        kernel.load_cipher_type(Box::new(AesIcm::new(constants::AesKeySize::Aes192)?))?;
        kernel.load_cipher_type(Box::new(AesIcm::new(constants::AesKeySize::Aes256)?))?;
        kernel.load_cipher_type(Box::new(AesGcm::new(constants::AesKeySize::Aes128)?))?;
        kernel.load_cipher_type(Box::new(AesGcm::new(constants::AesKeySize::Aes256)?))?;

        // Auth types
        kernel.load_auth_type(Box::new(NullAuth {}))?;
        kernel.load_auth_type(Box::new(HmacSha1 {}))?;
        Ok(kernel)
    }

    pub fn load_xtn_cipher_type(&mut self, ect: Box<dyn ExtensionCipherType>) -> Result<(), Error> {
        self_test::xtn_cipher(ect.as_ref())?;
        self.xtn_cipher_types.insert(ect.xtn_id(), ect);
        Ok(())
    }

    pub fn load_cipher_type(&mut self, ct: Box<dyn CipherType>) -> Result<(), Error> {
        self_test::cipher(ct.as_ref())?;
        self.cipher_types.insert(ct.id(), ct);
        Ok(())
    }

    pub fn load_auth_type(&mut self, at: Box<dyn AuthType>) -> Result<(), Error> {
        self_test::auth(at.as_ref())?;
        self.auth_types.insert(at.id(), at);
        Ok(())
    }

    pub fn xtn_cipher(
        &self,
        id: ExtensionCipherTypeID,
        key: &[u8],
        salt: &[u8],
    ) -> Result<ExtensionCipherInstance, Error> {
        let cipher_type = self.xtn_cipher_types.get(&id).ok_or(Error::Fail)?;
        let cipher = cipher_type.xtn_create(key, salt)?;
        Ok(Instance::new(cipher))
    }

    pub fn cipher(
        &self,
        id: CipherTypeID,
        key: &[u8],
        salt: &[u8],
    ) -> Result<CipherInstance, Error> {
        let cipher_type = self.cipher_types.get(&id).ok_or(Error::Fail)?;
        let cipher = cipher_type.create(key, salt)?;
        Ok(Instance::new(cipher))
    }

    pub fn auth(&self, id: AuthTypeID, key: &[u8], tag_size: usize) -> Result<AuthInstance, Error> {
        let auth_type = self.auth_types.get(&id).ok_or(Error::Fail)?;
        let auth = auth_type.create(key, tag_size)?;
        Ok(Instance::new(auth))
    }

    #[cfg(feature = "cffi")]
    pub fn cipher_type(&self, id: CipherTypeID) -> Result<Box<dyn CipherType>, Error> {
        let cipher_type = self.cipher_types.get(&id).ok_or(Error::Fail)?;
        Ok(cipher_type.deref().clone())
    }

    #[cfg(feature = "cffi")]
    pub fn auth_type(&self, id: AuthTypeID) -> Result<Box<dyn AuthType>, Error> {
        let auth_type = self.auth_types.get(&id).ok_or(Error::Fail)?;
        Ok(auth_type.deref().clone())
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
