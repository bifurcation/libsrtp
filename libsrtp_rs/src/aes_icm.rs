// XXX(RLB) RustCrypto offers AES-CTR implementations, but not for 16-bit counters.  If that
// changes in the future, we should remove the CTR internals here.

use crate::crypto_kernel::constants::AesKeySize;
use crate::crypto_kernel::{Cipher, CipherType, CipherTypeID};
use crate::replay::ExtendedSequenceNumber;
use crate::srtp::Error;
use aes::cipher::{
    generic_array::{typenum::U16, GenericArray},
    BlockCipher, BlockEncrypt, NewBlockCipher,
};
use aes::{Aes128, Aes192, Aes256};
use ctr::cipher::{NewCipher, StreamCipher};
use ctr::Ctr128BE;
use std::marker::PhantomData;

fn xor_eq(a: &mut [u8], b: &[u8]) {
    for (b1, b2) in a.iter_mut().zip(b.iter()) {
        *b1 ^= *b2;
    }
}

#[derive(Clone)]
struct Context<C>
where
    C: Clone + BlockEncrypt + BlockCipher<BlockSize = U16> + NewBlockCipher + 'static,
{
    key_size: AesKeySize,
    key: [u8; 32],
    salt: [u8; 14],
    phantom: PhantomData<C>,
}

impl<C> Context<C>
where
    C: Clone + BlockEncrypt + BlockCipher<BlockSize = U16> + NewBlockCipher + 'static,
{
    fn new(key_size: AesKeySize, key: &[u8], salt: &[u8]) -> Result<Self, Error> {
        let id = key_size.as_icm_id();
        if key.len() != id.key_size() || salt.len() != id.salt_size() {
            return Err(Error::BadParam);
        }

        let mut ctx = Context {
            key_size: key_size,
            key: Default::default(),
            salt: Default::default(),
            phantom: PhantomData,
        };

        ctx.key_mut().copy_from_slice(key);
        ctx.salt.copy_from_slice(salt);
        Ok(ctx)
    }

    fn key(&self) -> &[u8] {
        let key_size = self.id().key_size();
        &self.key[..key_size]
    }

    fn key_mut(&mut self) -> &mut [u8] {
        let key_size = self.id().key_size();
        &mut self.key[..key_size]
    }
}

impl<C> Cipher for Context<C>
where
    C: Clone + BlockEncrypt + BlockCipher<BlockSize = U16> + NewBlockCipher + 'static,
{
    fn id(&self) -> CipherTypeID {
        self.key_size.as_icm_id()
    }

    fn rtp_nonce(
        &self,
        ssrc: u32,
        ext_seq_num: ExtendedSequenceNumber,
        nonce: &mut [u8],
    ) -> Result<usize, Error> {
        Err(Error::Fail) // TODO
    }

    fn rtcp_nonce(&self, ssrc: u32, index: u32, nonce: &mut [u8]) -> Result<usize, Error> {
        Err(Error::Fail) // TODO
    }

    fn encrypt(
        &self,
        nonce: &[u8],
        _aad: &[u8],
        buf: &mut [u8],
        pt_size: usize,
    ) -> Result<usize, Error> {
        let key = GenericArray::from_slice(self.key());
        Ctr128BE::<C>::new(&key, nonce.into())
            .try_apply_keystream(&mut buf[..pt_size])
            .map(|_| pt_size)
            .map_err(|_| Error::CipherFail)
    }

    fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut [u8],
        ct_size: usize,
    ) -> Result<usize, Error> {
        self.encrypt(nonce, aad, buf, ct_size)
    }

    fn clone_inner(&self) -> Box<dyn Cipher> {
        let clone = (*self).clone();
        Box::new(clone)
    }
}

pub struct NativeAesIcm {
    key_size: AesKeySize,
}

impl NativeAesIcm {
    pub fn new(key_size: AesKeySize) -> Self {
        NativeAesIcm { key_size: key_size }
    }
}

impl CipherType for NativeAesIcm {
    fn id(&self) -> CipherTypeID {
        self.key_size.as_icm_id()
    }

    fn create(&self, key: &[u8], salt: &[u8]) -> Result<Box<dyn Cipher>, Error> {
        Ok(match self.key_size {
            AesKeySize::Aes128 => Box::new(Context::<Aes128>::new(self.key_size, key, salt)?),
            AesKeySize::Aes192 => Box::new(Context::<Aes192>::new(self.key_size, key, salt)?),
            AesKeySize::Aes256 => Box::new(Context::<Aes256>::new(self.key_size, key, salt)?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_test;

    #[test]
    fn test_aes_icm_128() -> Result<(), Error> {
        let cipher_type = NativeAesIcm::new(AesKeySize::Aes128);
        assert_eq!(cipher_type.id(), CipherTypeID::AesIcm128);

        let tests_passed = crypto_test::cipher(&cipher_type)?;
        assert!(tests_passed > 0);

        Ok(())
    }

    #[test]
    fn test_aes_icm_192() -> Result<(), Error> {
        let cipher_type = NativeAesIcm::new(AesKeySize::Aes192);
        assert_eq!(cipher_type.id(), CipherTypeID::AesIcm192);

        let tests_passed = crypto_test::cipher(&cipher_type)?;
        assert!(tests_passed > 0);

        Ok(())
    }

    #[test]
    fn test_aes_icm_256() -> Result<(), Error> {
        let cipher_type = NativeAesIcm::new(AesKeySize::Aes256);
        assert_eq!(cipher_type.id(), CipherTypeID::AesIcm256);

        let tests_passed = crypto_test::cipher(&cipher_type)?;
        assert!(tests_passed > 0);

        Ok(())
    }
}
