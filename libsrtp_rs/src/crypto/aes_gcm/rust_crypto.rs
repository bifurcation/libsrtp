#![cfg(feature = "rust-crypto")]
use crate::crypto::constants::AesKeySize;
use crate::crypto::{xor_eq, Cipher, CipherType, CipherTypeID, Reset};
use crate::replay::ExtendedSequenceNumber;
use crate::srtp::Error;
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
    /*
    aad: [u8; 512],
    aad_size: usize,
    nonce: Option<Nonce<C::NonceSize>>,
    */
}

impl<C> Reset for Context<C>
where
    C: AeadCore,
{
    fn reset(&mut self) {
        /*
        self.aad.fill(0);
        self.aad_size = 0;
        self.nonce = None;
        */
    }
}

impl<C> Context<C>
where
    C: AeadCore + NewAead,
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

    fn encrypt(
        &self,
        nonce_in: &[u8],
        aad_in: &[&[u8]],
        buf: &mut [u8],
        pt_size: usize,
    ) -> Result<usize, Error> {
        let ct_size = pt_size + Self::TAG_SIZE;
        if buf.len() < ct_size {
            return Err(Error::BadParam);
        }

        // Assemble AAD
        let mut aad_buf = [0u8; 512];
        let mut aad_size = 0;
        for elem in aad_in {
            let new_aad_size = aad_size + elem.len();
            if new_aad_size > aad_buf.len() {
                return Err(Error::BadParam);
            }

            aad_buf[aad_size..new_aad_size].copy_from_slice(elem);
            aad_size = new_aad_size
        }

        // Encrypt in-place
        let nonce = Nonce::clone_from_slice(nonce_in);
        let aad = &aad_buf[..aad_size];
        let tag = self
            .cipher
            .encrypt_in_place_detached(&nonce, aad, &mut buf[..pt_size])
            .map_err(|_| Error::CipherFail)?;

        buf[pt_size..ct_size].copy_from_slice(&tag);
        Ok(ct_size)
    }

    fn decrypt(&self, nonce_in: &[u8], aad_in: &[&[u8]], buf: &mut [u8]) -> Result<usize, Error> {
        let ct_size = buf.len();
        if ct_size < Self::TAG_SIZE {
            return Err(Error::BadParam);
        }

        // Assemble AAD
        let mut aad_buf = [0u8; 512];
        let mut aad_size = 0;
        for elem in aad_in {
            let new_aad_size = aad_size + elem.len();
            if new_aad_size > aad_buf.len() {
                return Err(Error::BadParam);
            }

            aad_buf[aad_size..new_aad_size].copy_from_slice(elem);
            aad_size = new_aad_size;
        }

        // Decrypt in place
        let pt_size = ct_size - Self::TAG_SIZE;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&buf[pt_size..]);
        let tag = GenericArray::from_slice(&tag);

        let nonce = Nonce::clone_from_slice(nonce_in);
        let aad = &aad_buf[..aad_size];
        self.cipher
            .decrypt_in_place_detached(&nonce, aad, &mut buf[..pt_size], tag)
            .map_err(|e| {
                println!("Error: {:?}", e);
                Error::AuthFail
            })?;
        buf[pt_size..].fill(0);
        Ok(pt_size)
    }
}

pub struct AesGcm {
    key_size: AesKeySize,
}

impl AesGcm {
    pub fn new(key_size: AesKeySize) -> Result<Self, Error> {
        if key_size == AesKeySize::Aes192 {
            return Err(Error::BadParam);
        }

        Ok(AesGcm { key_size: key_size })
    }
}

impl CipherType for AesGcm {
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
        Box::new(AesGcm {
            key_size: self.key_size,
        })
    }
}
