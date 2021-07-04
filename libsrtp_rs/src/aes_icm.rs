// XXX(RLB) RustCrypto offers AES-CTR implementations, but not for 16-bit counters.  If that
// changes in the future, we should remove the CTR internals here.

use crate::crypto_kernel::constants;
use crate::crypto_kernel::constants::AesKeySize;
use crate::crypto_kernel::{Cipher, CipherDirection, CipherType, CipherTypeID};
use crate::srtp::Error;
use aes::cipher::{generic_array::typenum::U16, BlockCipher, BlockEncrypt, NewBlockCipher};
use aes::{Aes128, Aes192, Aes256};
use ctr::cipher::{NewCipher, StreamCipher};
use ctr::Ctr128BE;

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
    cipher: Option<Ctr128BE<C>>,
}

impl<C> Context<C>
where
    C: Clone + BlockEncrypt + BlockCipher<BlockSize = U16> + NewBlockCipher + 'static,
{
    fn new(key_size: AesKeySize) -> Self {
        Context {
            key_size: key_size,
            key: [0; 32],
            salt: [0; 14],
            cipher: None,
        }
    }
}

impl<C> Cipher for Context<C>
where
    C: Clone + BlockEncrypt + BlockCipher<BlockSize = U16> + NewBlockCipher + 'static,
{
    fn key_size(&self) -> usize {
        self.key_size.icm_with_salt()
    }

    fn iv_size(&self) -> usize {
        16
    }

    fn init(&mut self, key: &[u8]) -> Result<(), Error> {
        let key_size_with_salt = self.key_size.icm_with_salt();
        if key.len() != key_size_with_salt {
            return Err(Error::BadParam);
        }

        let base_key_len = key_size_with_salt - constants::SALT_LEN;
        self.key[..base_key_len].copy_from_slice(&key[..base_key_len]);
        self.salt.fill(0);
        self.salt.copy_from_slice(&key[base_key_len..]);

        Ok(())
    }

    fn set_aad(&mut self, _aad: &[u8]) -> Result<(), Error> {
        Ok(())
    }

    fn set_iv(&mut self, iv: &[u8], _direction: CipherDirection) -> Result<(), Error> {
        if iv.len() != self.iv_size() {
            return Err(Error::BadParam);
        }

        // Nonce = (salt << 16) ^ iv
        let mut nonce = [0u8; 16];
        nonce[0..self.salt.len()].copy_from_slice(&self.salt);
        xor_eq(&mut nonce, &iv);

        let key_size = self.key_size.icm_with_salt() - constants::SALT_LEN;
        let key = &self.key[..key_size];
        let cipher = Ctr128BE::new(key.into(), (&nonce).into());
        self.cipher = Some(cipher);

        Ok(())
    }

    fn encrypt(&mut self, buf: &mut [u8], pt_size: usize) -> Result<usize, Error> {
        self.cipher
            .as_mut()
            .ok_or(Error::BadParam)?
            .try_apply_keystream(&mut buf[..pt_size])
            .map(|_| pt_size)
            .map_err(|_| Error::CipherFail)
    }

    fn decrypt(&mut self, buf: &mut [u8], ct_size: usize) -> Result<usize, Error> {
        self.encrypt(buf, ct_size)
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
        match self.key_size {
            AesKeySize::Aes128 => CipherTypeID::AesIcm128,
            AesKeySize::Aes192 => CipherTypeID::AesIcm192,
            AesKeySize::Aes256 => CipherTypeID::AesIcm256,
        }
    }

    fn create(&self, key_len: usize, _tag_len: usize) -> Result<Box<dyn Cipher>, Error> {
        if key_len != self.key_size.icm_with_salt() {
            return Err(Error::BadParam);
        }

        // XXX(RLB): It seems like we should fail on this case, but the SRTP layer seems to think
        // we should allow non-zero tag sizes
        /*
        if tag_len != 0 {
            return Err(Error::BadParam);
        }
        */

        Ok(match self.key_size {
            AesKeySize::Aes128 => Box::new(Context::<Aes128>::new(self.key_size)),
            AesKeySize::Aes192 => Box::new(Context::<Aes192>::new(self.key_size)),
            AesKeySize::Aes256 => Box::new(Context::<Aes256>::new(self.key_size)),
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
