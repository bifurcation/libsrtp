use crate::crypto_kernel::constants::AesKeySize;
use crate::crypto_kernel::{Cipher, CipherType, CipherTypeID};
use crate::replay::ExtendedSequenceNumber;
use crate::srtp::Error;
use aes_gcm::aead::{generic_array::GenericArray, AeadInPlace, NewAead};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Key, Nonce};

#[derive(Clone)]
struct Context<C> {
    key_size: AesKeySize,
    cipher: C,
    salt: [u8; 12],
}

impl<C> Context<C>
where
    C: NewAead,
{
    const SALT_SIZE: usize = 12;
    const NONCE_SIZE: usize = 12;
    const TAG_SIZE: usize = 16;

    fn new(key_size: AesKeySize, key: &[u8], salt: &[u8]) -> Result<Self, Error> {
        if key.len() != key_size.into() || salt.len() != Self::SALT_SIZE {
            return Err(Error::BadParam);
        }

        let mut ctx = Context {
            key_size: key_size,
            cipher: C::new(Key::from_slice(key)),
            salt: [0; 12],
        };

        ctx.salt.copy_from_slice(salt);
        Ok(ctx)
    }
}

impl<C> Cipher for Context<C>
where
    C: Clone + AeadInPlace + NewAead + 'static,
{
    fn id(&self) -> CipherTypeID {
        self.key_size.as_gcm_id()
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
        aad: &[u8],
        buf: &mut [u8],
        pt_size: usize,
    ) -> Result<usize, Error> {
        let ct_size = pt_size + Self::TAG_SIZE;
        if buf.len() < ct_size {
            return Err(Error::BadParam);
        }

        let nonce = Nonce::from_slice(&nonce);
        let tag = self
            .cipher
            .encrypt_in_place_detached(nonce, aad, &mut buf[..pt_size])
            .map_err(|_| Error::CipherFail)?;

        buf[pt_size..ct_size].copy_from_slice(&tag);
        Ok(ct_size)
    }

    fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut [u8],
        ct_size: usize,
    ) -> Result<usize, Error> {
        if ct_size < Self::TAG_SIZE {
            return Err(Error::BadParam);
        }

        let pt_size = ct_size - Self::TAG_SIZE;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&buf[pt_size..ct_size]);
        let tag = GenericArray::from_slice(&tag);

        let nonce = Nonce::from_slice(&nonce);
        self.cipher
            .decrypt_in_place_detached(nonce, aad, &mut buf[..pt_size], tag)
            .map_err(|_| Error::AuthFail)?;
        buf[pt_size..].fill(0);
        Ok(pt_size)
    }

    fn clone_inner(&self) -> Box<dyn Cipher> {
        Box::new(self.clone())
    }
}

pub struct NativeAesGcm {
    key_size: AesKeySize,
}

impl NativeAesGcm {
    pub fn new(key_size: AesKeySize) -> Result<Self, Error> {
        if key_size == AesKeySize::Aes192 {
            return Err(Error::BadParam);
        }

        Ok(NativeAesGcm { key_size: key_size })
    }
}

impl CipherType for NativeAesGcm {
    fn id(&self) -> CipherTypeID {
        self.key_size.as_gcm_id()
    }

    fn create(&self, key: &[u8], salt: &[u8]) -> Result<Box<dyn Cipher>, Error> {
        match self.key_size {
            AesKeySize::Aes128 => Ok(Box::new(Context::<Aes128Gcm>::new(
                self.key_size,
                key,
                salt,
            )?)),
            AesKeySize::Aes192 => Err(Error::BadParam),
            AesKeySize::Aes256 => Ok(Box::new(Context::<Aes256Gcm>::new(
                self.key_size,
                key,
                salt,
            )?)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_test;

    #[test]
    fn test_aes_gcm_128() -> Result<(), Error> {
        let cipher_type = NativeAesGcm::new(AesKeySize::Aes128)?;
        assert_eq!(cipher_type.id(), CipherTypeID::AesGcm128);

        let tests_passed = crypto_test::cipher(&cipher_type)?;
        assert!(tests_passed > 0);

        Ok(())
    }

    #[test]
    fn test_aes_gcm_256() -> Result<(), Error> {
        let cipher_type = NativeAesGcm::new(AesKeySize::Aes256)?;
        assert_eq!(cipher_type.id(), CipherTypeID::AesGcm256);

        let tests_passed = crypto_test::cipher(&cipher_type)?;
        assert!(tests_passed > 0);

        Ok(())
    }
}
