#![cfg(feature = "openssl-crypto")]

use super::{constants, make_rtp_nonce};
use crate::crypto::constants::AesKeySize;
use crate::crypto::openssl_common::EvpCipherContext;
use crate::crypto::{
    Cipher, CipherType, CipherTypeID, ExtensionCipher, ExtensionCipherType, ExtensionCipherTypeID,
    Reset,
};
use crate::replay::ExtendedSequenceNumber;
use crate::srtp::Error;
use std::ops::Range;

struct Context {
    id: CipherTypeID,
    key_size: AesKeySize,
    ctx: EvpCipherContext,
    salt: [u8; constants::SALT_SIZE],
    encrypted_so_far: usize,
}

impl Reset for Context {
    fn reset(&mut self) {
        // The context is automatically reset on set_nonce; there is no notion of reset without a
        // new nonce.
        self.encrypted_so_far = 0;
    }
}

impl Context {
    fn new(id: CipherTypeID, key_size: AesKeySize, key: &[u8], salt: &[u8]) -> Result<Self, Error> {
        if key.len() != id.key_size() || salt.len() != constants::SALT_SIZE {
            return Err(Error::BadParam);
        }

        let mut ctx = Context {
            id: id,
            key_size: key_size,
            ctx: unsafe { EvpCipherContext::new(id, key)? },
            salt: [0; constants::SALT_SIZE],
            encrypted_so_far: 0,
        };

        ctx.salt.copy_from_slice(salt);
        Ok(ctx)
    }
}

impl ExtensionCipher for Context {
    fn xtn_id(&self) -> ExtensionCipherTypeID {
        self.key_size.as_stream_icm_id()
    }

    fn init(&mut self, ssrc: u32, ext_seq_num: ExtendedSequenceNumber) -> Result<(), Error> {
        let mut nonce = [0u8; constants::NONCE_SIZE];
        make_rtp_nonce(&self.salt, ssrc, ext_seq_num, &mut nonce)?;

        unsafe { self.ctx.set_nonce(&nonce, true)? };

        Ok(())
    }

    fn xor_key(&mut self, buffer: &mut [u8], range: Range<usize>) -> Result<(), Error> {
        if range.is_empty() {
            return Ok(());
        }

        // Skip the bytes between the end of the last encryption and the start of the current one
        if range.start < self.encrypted_so_far {
            return Err(Error::BadParam);
        }

        let mut skip_buf = [0u8; 256];
        let skip = range.start - self.encrypted_so_far;
        if skip > skip_buf.len() {
            return Err(Error::BadParam);
        }

        let skip_pt = &mut skip_buf[..skip];
        unsafe { self.ctx.encrypt(skip_pt, skip, 0)? };
        self.encrypted_so_far += skip;

        // Encrypt the buffer itself
        let size = range.end - range.start;
        if buffer.len() < size {
            return Err(Error::BadParam);
        }

        let pt = &mut buffer[..size];
        unsafe { self.ctx.encrypt(pt, size, 0)? };
        self.encrypted_so_far += size;
        Ok(())
    }
}

impl Cipher for Context {
    fn id(&self) -> CipherTypeID {
        self.id
    }

    fn overhead(&self) -> usize {
        0
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
        _aad: &[&[u8]],
        buf: &mut [u8],
        pt_size: usize,
    ) -> Result<usize, Error> {
        unsafe {
            self.ctx.set_nonce(nonce, true)?;
            self.ctx.encrypt(buf, pt_size, 0)
        }
    }

    fn decrypt(&self, nonce: &[u8], _aad: &[&[u8]], buf: &mut [u8]) -> Result<usize, Error> {
        unsafe {
            self.ctx.set_nonce(nonce, false)?;
            self.ctx.decrypt(buf)
        }
    }
}

pub struct AesIcm {
    key_size: AesKeySize,
}

impl AesIcm {
    pub fn new(key_size: AesKeySize) -> Result<Self, Error> {
        Ok(AesIcm { key_size: key_size })
    }
}

impl ExtensionCipherType for AesIcm {
    fn xtn_id(&self) -> ExtensionCipherTypeID {
        self.key_size.as_stream_icm_id()
    }

    fn xtn_create(&self, key: &[u8], salt: &[u8]) -> Result<Box<dyn ExtensionCipher>, Error> {
        Ok(Box::new(Context::new(self.id(), self.key_size, key, salt)?))
    }
}

impl CipherType for AesIcm {
    fn id(&self) -> CipherTypeID {
        self.key_size.as_icm_id()
    }

    fn create(&self, key: &[u8], salt: &[u8]) -> Result<Box<dyn Cipher>, Error> {
        Ok(Box::new(Context::new(self.id(), self.key_size, key, salt)?))
    }

    fn clone(&self) -> Box<dyn CipherType> {
        Box::new(AesIcm {
            key_size: self.key_size,
        })
    }
}
