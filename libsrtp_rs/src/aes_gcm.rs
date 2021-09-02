use crate::crypto_kernel::constants::AesKeySize;
use crate::crypto_kernel::{Cipher, CipherType, CipherTypeID, Reset};
use crate::replay::ExtendedSequenceNumber;
use crate::srtp::Error;
use crate::util::xor_eq;
use aes_gcm::aead::{generic_array::GenericArray, AeadInPlace, NewAead};
use aes_gcm::{AeadCore, Aes128Gcm, Aes256Gcm, Key, Nonce};

#[derive(Clone)]
struct Context<C>
where
    C: AeadCore,
{
    key_size: AesKeySize,
    cipher: C,
    salt: [u8; 12],
    aad: [u8; 512],
    aad_size: usize,
    nonce: Option<Nonce<C::NonceSize>>,
}

impl<C> Reset for Context<C>
where
    C: AeadCore,
{
    fn reset(&mut self) {
        self.aad.fill(0);
        self.aad_size = 0;
        self.nonce = None;
    }
}

impl<C> Context<C>
where
    C: AeadCore + NewAead,
{
    const SALT_SIZE: usize = 12;
    const TAG_SIZE: usize = 16;
    const MAX_AAD_SIZE: usize = 512;

    fn new(key_size: AesKeySize, key: &[u8], salt: &[u8]) -> Result<Self, Error> {
        if key.len() != key_size.into() || salt.len() != Self::SALT_SIZE {
            return Err(Error::BadParam);
        }

        let mut ctx = Context {
            key_size: key_size,
            cipher: C::new(Key::from_slice(key)),
            salt: [0; 12],
            aad: [0; 512],
            aad_size: 0,
            nonce: None,
        };

        ctx.salt.copy_from_slice(salt);
        Ok(ctx)
    }
}

impl<C> Cipher for Context<C>
where
    C: Clone + AeadCore + AeadInPlace + NewAead + 'static,
{
    fn id(&self) -> CipherTypeID {
        self.key_size.as_gcm_id()
    }

    fn overhead(&self) -> usize {
        Self::TAG_SIZE
    }

    // https://datatracker.ietf.org/doc/html/rfc7714#section-8.3
    //
    //   0  0  0  0  0  0  0  0  0  0  1  1
    //   0  1  2  3  4  5  6  7  8  9  0  1
    // +--+--+--+--+--+--+--+--+--+--+--+--+
    // |00|00|    SSRC   |     ROC   | SEQ |---+
    // +--+--+--+--+--+--+--+--+--+--+--+--+   |
    //                                         |
    // +--+--+--+--+--+--+--+--+--+--+--+--+   |
    // |         Encryption Salt           |->(+)
    // +--+--+--+--+--+--+--+--+--+--+--+--+   |
    //                                         |
    // +--+--+--+--+--+--+--+--+--+--+--+--+   |
    // |       Initialization Vector       |<--+
    // +--+--+--+--+--+--+--+--+--+--+--+--+
    fn rtp_nonce(
        &self,
        ssrc: u32,
        ext_seq_num: ExtendedSequenceNumber,
        nonce: &mut [u8],
    ) -> Result<usize, Error> {
        if nonce.len() != self.id().salt_size() {
            return Err(Error::BadParam);
        }

        nonce.fill(0);
        nonce[2..6].copy_from_slice(&ssrc.to_be_bytes());
        nonce[6..12].copy_from_slice(&ext_seq_num.to_be_bytes()[2..]);
        xor_eq(nonce, &self.salt);
        Ok(self.salt.len())
    }

    // https://datatracker.ietf.org/doc/html/rfc7714#section-9.1
    //
    //   0  1  2  3  4  5  6  7  8  9 10 11
    // +--+--+--+--+--+--+--+--+--+--+--+--+
    // |00|00|    SSRC   |00|00|0+SRTCP Idx|---+
    // +--+--+--+--+--+--+--+--+--+--+--+--+   |
    //                                         |
    // +--+--+--+--+--+--+--+--+--+--+--+--+   |
    // |         Encryption Salt           |->(+)
    // +--+--+--+--+--+--+--+--+--+--+--+--+   |
    //                                         |
    // +--+--+--+--+--+--+--+--+--+--+--+--+   |
    // |       Initialization Vector       |<--+
    // +--+--+--+--+--+--+--+--+--+--+--+--+
    fn rtcp_nonce(&self, ssrc: u32, index: u32, nonce: &mut [u8]) -> Result<usize, Error> {
        self.rtp_nonce(ssrc, index.into(), nonce)
    }

    fn add_aad(&mut self, aad: &[u8]) -> Result<(), Error> {
        let new_aad_size = self.aad_size + aad.len();
        if new_aad_size > Self::MAX_AAD_SIZE {
            return Err(Error::CipherFail);
        }

        self.aad[self.aad_size..new_aad_size].copy_from_slice(aad);
        self.aad_size = new_aad_size;
        Ok(())
    }

    fn set_nonce(&mut self, nonce: &[u8]) -> Result<(), Error> {
        self.nonce = Some(Nonce::clone_from_slice(&nonce));
        Ok(())
    }

    fn encrypt(&self, buf: &mut [u8], pt_size: usize) -> Result<usize, Error> {
        let ct_size = pt_size + Self::TAG_SIZE;
        if buf.len() < ct_size {
            return Err(Error::BadParam);
        }

        let nonce = self.nonce.as_ref().ok_or(Error::BadParam)?;
        let aad = &self.aad[..self.aad_size];
        let tag = self
            .cipher
            .encrypt_in_place_detached(nonce, aad, &mut buf[..pt_size])
            .map_err(|_| Error::CipherFail)?;

        buf[pt_size..ct_size].copy_from_slice(&tag);
        Ok(ct_size)
    }

    fn decrypt(&self, buf: &mut [u8]) -> Result<usize, Error> {
        let ct_size = buf.len();
        if ct_size < Self::TAG_SIZE {
            return Err(Error::BadParam);
        }

        let pt_size = ct_size - Self::TAG_SIZE;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&buf[pt_size..]);
        let tag = GenericArray::from_slice(&tag);

        let nonce = self.nonce.as_ref().ok_or(Error::BadParam)?;
        let aad = &self.aad[..self.aad_size];

        self.cipher
            .decrypt_in_place_detached(nonce, aad, &mut buf[..pt_size], tag)
            .map_err(|_| Error::AuthFail)?;
        buf[pt_size..].fill(0);
        Ok(pt_size)
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

    fn clone(&self) -> Box<dyn CipherType> {
        Box::new(NativeAesGcm {
            key_size: self.key_size,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_test;
    use hex_literal::hex;

    #[test]
    fn test_128() -> Result<(), Error> {
        let cipher_type = NativeAesGcm::new(AesKeySize::Aes128)?;
        assert_eq!(cipher_type.id(), CipherTypeID::AesGcm128);

        let tests_passed = crypto_test::cipher(&cipher_type)?;
        assert!(tests_passed > 0);

        Ok(())
    }

    #[test]
    fn test_256() -> Result<(), Error> {
        let cipher_type = NativeAesGcm::new(AesKeySize::Aes256)?;
        assert_eq!(cipher_type.id(), CipherTypeID::AesGcm256);

        let tests_passed = crypto_test::cipher(&cipher_type)?;
        assert!(tests_passed > 0);

        Ok(())
    }

    #[test]
    fn test_rtp_example() -> Result<(), Error> {
        let key = hex!("238c882f36f000301573e69383502d9d");
        let salt = hex!("f2fee04070fc3f65d706e2e4");
        let ssrc: u32 = 0xcafebabe;
        let ext_seq_num: ExtendedSequenceNumber = 0x0000001234;
        // f2fee04070fc3f65d706e2e4 ^ 0000cafebabe000000001234
        let expected_nonce: [u8; 12] = hex!("f2fe2abeca423f65d706f0d0");
        let aad = hex!(
            "900f1234decafbadcafebabebede00061712e0205bfa949b1c220000c830bb46732778d9929aab00"
        );
        let pt = [0xab; 16];
        let ct = hex!("0eca0cf95ee955b26cd3d288b49f6ca9f4b1b759719eb5bc113b9ff1d40cd25a");

        let cipher_type = NativeAesGcm::new(AesKeySize::Aes128)?;
        let mut cipher = cipher_type.create(&key, &salt)?;

        // Verify correct nonce formation
        let mut nonce: [u8; 12] = Default::default();
        cipher.rtp_nonce(ssrc, ext_seq_num, &mut nonce)?;
        assert_eq!(nonce, expected_nonce);

        // Verify correct encryption
        let mut enc_buffer = [0u8; 32];
        enc_buffer[..pt.len()].copy_from_slice(&pt);

        cipher.reset();
        cipher.add_aad(&aad)?;
        cipher.set_nonce(&nonce)?;
        let ct_size = cipher.encrypt(&mut enc_buffer, pt.len())?;
        assert_eq!(ct_size, ct.len());
        assert_eq!(enc_buffer, ct);

        // Verify correct decryption
        cipher.reset();
        cipher.add_aad(&aad)?;
        cipher.set_nonce(&nonce)?;
        let pt_size = cipher.decrypt(&mut enc_buffer)?;
        assert_eq!(pt_size, pt.len());
        assert_eq!(&enc_buffer[..pt_size], &pt);

        Ok(())
    }

    #[test]
    fn test_rtcp_example() {
        // TODO
    }
}
