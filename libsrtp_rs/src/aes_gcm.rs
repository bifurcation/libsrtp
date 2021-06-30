// XXX(RLB) RustCrypto offers AES-CTR implementations, but not for 16-bit counters.  If that
// changes in the future, we should remove the CTR internals here.

use crate::crypto_kernel::constants;
use crate::crypto_kernel::constants::AesKeySize;
use crate::crypto_kernel::{Cipher, CipherDirection, CipherType, CipherTypeID};
use crate::srtp::Error;
use aes_gcm::aead::{generic_array::GenericArray, AeadInPlace, NewAead};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Key, Nonce};

#[derive(Clone)]
struct Context<C> {
    key_size: AesKeySize,
    cipher: Option<C>,

    // XXX(RLB): For the moment, we have to cache these on the cipher object.  If we refacter to a
    // more single-shot API, then we can get rid of these fields.  In a related vein, the presence
    // of fields like these introduces the risk of state desynchronization, which is part of why
    // Cipher isn't safe for use in an Rc.
    nonce: [u8; 12],
    aad: [u8; 512],
    aad_size: usize,
}

impl<C> Context<C> {
    const NONCE_SIZE: usize = 12;
    const TAG_SIZE: usize = 16;
    const MAX_AAD_SIZE: usize = 512;

    fn new(key_size: AesKeySize) -> Self {
        Context {
            key_size: key_size,
            cipher: None,
            nonce: [0; 12],
            aad: [0; 512],
            aad_size: 0,
        }
    }
}

impl<C> Cipher for Context<C>
where
    C: Clone + AeadInPlace + NewAead + 'static,
{
    fn key_size(&self) -> usize {
        self.key_size.gcm_with_salt()
    }

    fn iv_size(&self) -> usize {
        Self::NONCE_SIZE
    }

    fn init(&mut self, key: &[u8]) -> Result<(), Error> {
        let key_size_with_salt = self.key_size.gcm_with_salt();
        if key.len() != key_size_with_salt {
            return Err(Error::BadParam);
        }

        let base_key_size = key_size_with_salt - constants::AEAD_SALT_LEN;
        let base_key = Key::from_slice(&key[..base_key_size]);

        self.cipher = Some(C::new(base_key));
        Ok(())
    }

    fn set_aad(&mut self, aad: &[u8]) -> Result<(), Error> {
        let aad_size = aad.len();
        if aad_size > Self::MAX_AAD_SIZE {
            return Err(Error::BadParam);
        }

        self.aad.fill(0);
        self.aad[..aad_size].copy_from_slice(aad);
        self.aad_size = aad_size;
        Ok(())
    }

    fn set_iv(&mut self, iv: &[u8], _direction: CipherDirection) -> Result<(), Error> {
        if iv.len() != self.nonce.len() {
            return Err(Error::BadParam);
        }

        self.nonce.copy_from_slice(iv);
        Ok(())
    }

    fn encrypt(&mut self, buf: &mut [u8], pt_size: usize) -> Result<usize, Error> {
        let ct_size = pt_size + Self::TAG_SIZE;
        if buf.len() < ct_size {
            println!("err {:?} < {:?}", buf.len(), ct_size);
            return Err(Error::BadParam);
        }

        let cipher = self.cipher.as_ref().ok_or(Error::CipherFail)?;
        let nonce = Nonce::from_slice(&self.nonce);
        let aad = &self.aad[..self.aad_size];
        let tag = cipher
            .encrypt_in_place_detached(nonce, aad, &mut buf[..pt_size])
            .map_err(|_| Error::CipherFail)?;

        buf[pt_size..ct_size].copy_from_slice(&tag);
        Ok(ct_size)
    }

    fn decrypt(&mut self, buf: &mut [u8], ct_size: usize) -> Result<usize, Error> {
        if ct_size < Self::TAG_SIZE {
            return Err(Error::BadParam);
        }

        let pt_size = ct_size - Self::TAG_SIZE;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&buf[pt_size..ct_size]);

        let cipher = self.cipher.as_ref().ok_or(Error::CipherFail)?;
        let nonce = Nonce::from_slice(&self.nonce);
        let aad = &self.aad[..self.aad_size];
        let tag = GenericArray::from_slice(&tag);
        cipher
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
        match self.key_size {
            AesKeySize::Aes128 => CipherTypeID::AesGcm128,
            AesKeySize::Aes192 => panic!("Unsupported key size"),
            AesKeySize::Aes256 => CipherTypeID::AesGcm256,
        }
    }

    fn create(&self, key_len: usize, _tag_len: usize) -> Result<Box<dyn Cipher>, Error> {
        if key_len != self.key_size.gcm_with_salt() {
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
            AesKeySize::Aes128 => Box::new(Context::<Aes128Gcm>::new(self.key_size)),
            AesKeySize::Aes192 => panic!("Unsupported key size"),
            AesKeySize::Aes256 => Box::new(Context::<Aes256Gcm>::new(self.key_size)),
        })
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
