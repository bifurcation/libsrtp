#![cfg(feature = "openssl-crypto")]
use super::{constants, make_rtp_nonce};
use crate::crypto::constants::AesKeySize;
use crate::crypto::openssl_common::EvpCipherContext;
use crate::crypto::{Cipher, CipherType, CipherTypeID, Reset};
use crate::replay::ExtendedSequenceNumber;
use crate::srtp::Error;

struct Context {
    id: CipherTypeID,
    ctx: EvpCipherContext,
    salt: [u8; constants::SALT_SIZE],
}

impl Reset for Context {
    fn reset(&mut self) {
        // The context is automatically reset on set_nonce; there is no notion of reset without a
        // new nonce.
    }
}

impl Context {
    fn new(id: CipherTypeID, key: &[u8], salt: &[u8]) -> Result<Self, Error> {
        if key.len() != id.key_size() || salt.len() != constants::SALT_SIZE {
            return Err(Error::BadParam);
        }

        let mut ctx = Context {
            id: id,
            ctx: unsafe { EvpCipherContext::new(id, key)? },
            salt: [0; 12],
        };

        ctx.salt.copy_from_slice(salt);
        Ok(ctx)
    }
}

impl Cipher for Context {
    fn id(&self) -> CipherTypeID {
        self.id
    }

    fn overhead(&self) -> usize {
        constants::TAG_SIZE
    }

    fn rtp_nonce(
        &self,
        ssrc: u32,
        ext_seq_num: ExtendedSequenceNumber,
        nonce: &mut [u8],
    ) -> Result<usize, Error> {
        make_rtp_nonce(&self.salt, ssrc, ext_seq_num, nonce)
    }

    fn rtcp_nonce(&self, ssrc: u32, index: u32, nonce: &mut [u8]) -> Result<usize, Error> {
        self.rtp_nonce(ssrc, index.into(), nonce)
    }

    fn encrypt(
        &self,
        nonce: &[u8],
        aad: &[&[u8]],
        buf: &mut [u8],
        pt_size: usize,
    ) -> Result<usize, Error> {
        let ct_size = pt_size + constants::TAG_SIZE;
        if buf.len() < ct_size {
            return Err(Error::BadParam);
        }

        unsafe {
            self.ctx.set_nonce(nonce, true)?;
            for elem in aad {
                self.ctx.set_aad(elem)?;
            }

            self.ctx.encrypt(buf, pt_size, constants::TAG_SIZE)
        }
    }

    fn decrypt(&self, nonce: &[u8], aad: &[&[u8]], buf: &mut [u8]) -> Result<usize, Error> {
        if buf.len() < constants::TAG_SIZE {
            return Err(Error::BadParam);
        }
        let pt_size = buf.len() - constants::TAG_SIZE;

        unsafe {
            // The order of these operations matters to OpenSSL.  In particular, `set_tag` must
            // come before `set_aad`.
            self.ctx.set_nonce(nonce, false)?;
            self.ctx.set_tag(&buf[pt_size..])?;
            for elem in aad {
                self.ctx.set_aad(elem)?;
            }

            self.ctx.decrypt(&mut buf[..pt_size])
        }
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
            AesKeySize::Aes128 => Ok(Box::new(Context::new(self.id(), key, salt)?)),
            AesKeySize::Aes192 => Err(Error::BadParam),
            AesKeySize::Aes256 => Ok(Box::new(Context::new(self.id(), key, salt)?)),
        }
    }

    fn clone(&self) -> Box<dyn CipherType> {
        Box::new(AesGcm {
            key_size: self.key_size,
        })
    }
}
