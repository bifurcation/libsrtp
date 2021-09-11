#![cfg(feature = "openssl-crypto")]
use crate::crypto::constants::AesKeySize;
use crate::crypto::{xor_eq, Cipher, CipherType, CipherTypeID, Reset};
use crate::replay::ExtendedSequenceNumber;
use crate::srtp::Error;

use openssl::symm;
use openssl::symm::{Crypter, Mode};

fn val_or_fail<T, E>(result: Result<T, E>) -> Result<T, Error> {
    result.map_err(|_| Error::CipherFail)
}

struct Context {
    key_size: AesKeySize,
    cipher: symm::Cipher,
    key: [u8; 32],
    salt: [u8; 12],
    nonce: Option<[u8; 12]>,
    aad: [u8; 512],
    aad_size: usize,
}

impl Reset for Context {
    fn reset(&mut self) {
        self.nonce = None;
        self.aad.fill(0);
        self.aad_size = 0;
    }
}

impl Context {
    const SALT_SIZE: usize = 12;
    const TAG_SIZE: usize = 16;
    const MAX_AAD_SIZE: usize = 512;

    fn new(key_size: AesKeySize, key: &[u8], salt: &[u8]) -> Result<Self, Error> {
        if key.len() != key_size.into() || salt.len() != Self::SALT_SIZE {
            return Err(Error::BadParam);
        }

        let cipher = match key_size {
            AesKeySize::Aes128 => symm::Cipher::aes_128_gcm(),
            AesKeySize::Aes192 => symm::Cipher::aes_192_gcm(),
            AesKeySize::Aes256 => symm::Cipher::aes_256_gcm(),
        };

        let mut ctx = Context {
            key_size: key_size,
            cipher: cipher,
            key: [0; 32],
            salt: [0; 12],
            nonce: None,
            aad: [0; 512],
            aad_size: 0,
        };

        ctx.key[..key.len()].copy_from_slice(key);
        ctx.salt.copy_from_slice(salt);
        Ok(ctx)
    }

    fn key(&self) -> &[u8] {
        let key_size: usize = self.key_size.into();
        &self.key[..key_size]
    }

    fn aad(&self) -> &[u8] {
        &self.aad[..self.aad_size]
    }
}

impl Cipher for Context {
    fn id(&self) -> CipherTypeID {
        self.key_size.as_gcm_id()
    }

    fn overhead(&self) -> usize {
        Self::TAG_SIZE
    }

    fn salt(&self) -> Vec<u8> {
        self.salt.clone().into()
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
        let mut nonce_copy = [0u8; Self::SALT_SIZE];
        nonce_copy.copy_from_slice(nonce);
        self.nonce = Some(nonce_copy);
        Ok(())
    }

    fn encrypt(&mut self, buf: &mut [u8], pt_size: usize) -> Result<usize, Error> {
        let ct_size = pt_size + Self::TAG_SIZE;
        if buf.len() < ct_size {
            return Err(Error::BadParam);
        }

        let nonce = self.nonce.as_ref().ok_or(Error::BadParam)?;
        let mut crypter = val_or_fail(Crypter::new(
            self.cipher,
            Mode::Encrypt,
            self.key(),
            Some(nonce),
        ))?;

        val_or_fail(crypter.aad_update(self.aad()))?;
        let count = unsafe {
            // XXX(RLB) OpenSSL is fine with encrypting in place, but the Rust interface makes it
            // impossible to do safely.  Note that we over-size the slice (ct_size) because the
            // Rust wrapper checks that the output has a block size more than the input.
            let out_ptr: *mut u8 = buf.as_mut_ptr();
            let out = std::slice::from_raw_parts_mut(out_ptr, pt_size + Self::TAG_SIZE);
            val_or_fail(crypter.update(buf, out))?
        };
        if count != pt_size {
            return Err(Error::CipherFail);
        }

        val_or_fail(crypter.finalize(&mut []))?;
        val_or_fail(crypter.get_tag(&mut buf[pt_size..ct_size]))?;
        Ok(ct_size)
    }

    fn decrypt(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let ct_size = buf.len();
        if ct_size < Self::TAG_SIZE {
            return Err(Error::BadParam);
        }
        let pt_size = ct_size - Self::TAG_SIZE;

        let nonce = self.nonce.as_ref().ok_or(Error::BadParam)?;
        let mut crypter = val_or_fail(Crypter::new(
            self.cipher,
            Mode::Decrypt,
            self.key(),
            Some(nonce),
        ))?;

        val_or_fail(crypter.set_tag(&buf[pt_size..]))?;
        val_or_fail(crypter.aad_update(self.aad()))?;

        let count = unsafe {
            // XXX(RLB) See comments above.
            let out_ptr: *mut u8 = buf.as_mut_ptr();
            let out = std::slice::from_raw_parts_mut(out_ptr, ct_size + Self::TAG_SIZE);
            val_or_fail(crypter.update(buf, out))?
        };
        if count != pt_size {
            return Err(Error::CipherFail);
        }

        val_or_fail(crypter.finalize(&mut []))?;
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
            AesKeySize::Aes128 => Ok(Box::new(Context::new(self.key_size, key, salt)?)),
            AesKeySize::Aes192 => Err(Error::BadParam),
            AesKeySize::Aes256 => Ok(Box::new(Context::new(self.key_size, key, salt)?)),
        }
    }

    fn clone(&self) -> Box<dyn CipherType> {
        Box::new(AesGcm {
            key_size: self.key_size,
        })
    }
}
