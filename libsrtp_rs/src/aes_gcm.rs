use crate::crypto_kernel::constants::AesKeySize;
use crate::crypto_kernel::{Cipher, CipherType, CipherTypeID};
use crate::replay::ExtendedSequenceNumber;
use crate::srtp::Error;
use crate::util::xor_eq;
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
        let key: [u8; 16] = [
            0x23, 0x8c, 0x88, 0x2f, 0x36, 0xf0, 0x00, 0x30, 0x15, 0x73, 0xe6, 0x93, 0x83, 0x50,
            0x2d, 0x9d,
        ];
        let salt: [u8; 12] = [
            0xf2, 0xfe, 0xe0, 0x40, 0x70, 0xfc, 0x3f, 0x65, 0xd7, 0x06, 0xe2, 0xe4,
        ];
        let ssrc: u32 = 0xcafebabe;
        let ext_seq_num: ExtendedSequenceNumber = 0x0000001234;
        let expected_nonce: [u8; 12] = [
            // f2fee04070fc3f65d706e2e4 ^ 0000cafebabe000000001234
            0xf2, 0xfe, 0x2a, 0xbe, 0xca, 0x42, 0x3f, 0x65, 0xd7, 0x06, 0xf0, 0xd0,
        ];
        let aad: [u8; 40] = [
            0x90, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0xbe, 0xde,
            0x00, 0x06, 0x17, 0x12, 0xe0, 0x20, 0x5b, 0xfa, 0x94, 0x9b, 0x1c, 0x22, 0x00, 0x00,
            0xc8, 0x30, 0xbb, 0x46, 0x73, 0x27, 0x78, 0xd9, 0x92, 0x9a, 0xab, 0x00,
        ];
        let pt: [u8; 16] = [0xab; 16];
        let ct: [u8; 32] = [
            0x0e, 0xca, 0x0c, 0xf9, 0x5e, 0xe9, 0x55, 0xb2, 0x6c, 0xd3, 0xd2, 0x88, 0xb4, 0x9f,
            0x6c, 0xa9, 0xf4, 0xb1, 0xb7, 0x59, 0x71, 0x9e, 0xb5, 0xbc, 0x11, 0x3b, 0x9f, 0xf1,
            0xd4, 0x0c, 0xd2, 0x5a,
        ];

        let cipher_type = NativeAesGcm::new(AesKeySize::Aes128)?;
        let cipher = cipher_type.create(&key, &salt)?;

        // Verify correct nonce formation
        let mut nonce: [u8; 12] = Default::default();
        cipher.rtp_nonce(ssrc, ext_seq_num, &mut nonce)?;
        assert_eq!(nonce, expected_nonce);

        // Verify correct encryption
        let mut enc_buffer = [0u8; 32];
        enc_buffer[..pt.len()].copy_from_slice(&pt);
        let ct_size = cipher.encrypt(&nonce, &aad, &mut enc_buffer, pt.len())?;
        assert_eq!(ct_size, ct.len());
        assert_eq!(enc_buffer, ct);

        // Verify correct decryption
        let pt_size = cipher.decrypt(&nonce, &aad, &mut enc_buffer, ct.len())?;
        assert_eq!(pt_size, pt.len());
        assert_eq!(&enc_buffer[..pt_size], &pt);

        Ok(())
    }

    #[test]
    fn test_rtcp_example() {
        // TODO
    }
}
