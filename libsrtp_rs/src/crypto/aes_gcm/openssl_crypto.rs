#![cfg(feature = "openssl-crypto")]
use crate::crypto::constants::AesKeySize;
use crate::crypto::{xor_eq, Cipher, CipherType, CipherTypeID, Reset};
use crate::replay::ExtendedSequenceNumber;
use crate::srtp::Error;

use openssl_sys::*;
use std::os::raw::{c_int, c_void};

// Conveniences for dealing with pointers and errors
fn non_null<T>(ptr: *mut T) -> Result<*mut T, Error> {
    if ptr.is_null() {
        Err(Error::Fail)
    } else {
        Ok(ptr)
    }
}

fn require1(rv: c_int) -> Result<(), Error> {
    if rv != 1 {
        Err(Error::Fail)
    } else {
        Ok(())
    }
}

// This is a simple RAII wrapper around EVP_CIPHER_CTX.
struct EvpCipherContext {
    ctx: *mut EVP_CIPHER_CTX,
}

impl Drop for EvpCipherContext {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            unsafe { EVP_CIPHER_CTX_free(self.ctx) };
        }
    }
}

impl EvpCipherContext {
    unsafe fn new(key_size: AesKeySize, key: &[u8]) -> Result<Self, Error> {
        let ctx = non_null(EVP_CIPHER_CTX_new())?;

        let evp = match key_size {
            AesKeySize::Aes128 => EVP_aes_128_gcm(),
            AesKeySize::Aes192 => EVP_aes_192_gcm(),
            AesKeySize::Aes256 => EVP_aes_256_gcm(),
        };

        require1(EVP_CipherInit_ex(
            ctx,
            evp,
            std::ptr::null_mut(),
            key.as_ptr(),
            std::ptr::null(),
            0,
        ))?;

        Ok(Self { ctx: ctx })
    }

    unsafe fn set_nonce(&self, nonce: &[u8], encrypt: bool) -> Result<(), Error> {
        let direction = if encrypt { 1 } else { 0 };

        require1(EVP_CIPHER_CTX_ctrl(
            self.ctx,
            EVP_CTRL_GCM_SET_IVLEN,
            12,
            std::ptr::null_mut(),
        ))?;

        require1(EVP_CipherInit_ex(
            self.ctx,
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            nonce.as_ptr(),
            direction,
        ))
    }

    unsafe fn set_tag(&self, tag: &[u8]) -> Result<(), Error> {
        require1(EVP_CIPHER_CTX_ctrl(
            self.ctx,
            EVP_CTRL_GCM_SET_TAG,
            tag.len() as c_int,
            tag.as_ptr() as *mut c_void,
        ))
    }

    unsafe fn set_aad(&self, aad: &[u8]) -> Result<(), Error> {
        let mut out_size: c_int = 0;
        require1(EVP_CipherUpdate(
            self.ctx,
            std::ptr::null_mut(),
            &mut out_size,
            aad.as_ptr(),
            aad.len() as c_int,
        ))
    }

    unsafe fn encrypt(
        &self,
        pt: &mut [u8],
        pt_size: usize,
        tag_size: usize,
    ) -> Result<usize, Error> {
        let tag_end = pt_size + tag_size;

        let mut out_size: c_int = pt_size as i32;
        require1(EVP_CipherUpdate(
            self.ctx,
            pt.as_mut_ptr(),
            &mut out_size,
            pt.as_ptr(),
            pt_size as c_int,
        ))?;
        require1(EVP_CipherFinal(
            self.ctx,
            std::ptr::null_mut(),
            &mut out_size,
        ))?;
        require1(EVP_CIPHER_CTX_ctrl(
            self.ctx,
            EVP_CTRL_GCM_GET_TAG,
            tag_size as c_int,
            (&mut pt[pt_size..tag_end]).as_mut_ptr() as *mut c_void,
        ))?;
        Ok(pt_size + tag_size)
    }

    unsafe fn decrypt(&self, ct: &mut [u8]) -> Result<usize, Error> {
        let mut out_size: c_int = ct.len() as i32;
        require1(EVP_CipherUpdate(
            self.ctx,
            ct.as_mut_ptr(),
            &mut out_size,
            ct.as_ptr(),
            out_size,
        ))?;
        require1(EVP_CipherFinal(
            self.ctx,
            std::ptr::null_mut(),
            &mut out_size,
        ))?;
        Ok(ct.len())
    }
    /*

    EVP_CipherInit_ex(c->ctx, evp, NULL, key, NULL, 0);

    // Set IV
    EVP_CIPHER_CTX_ctrl(c->ctx, EVP_CTRL_GCM_SET_IVLEN, 12, 0);
    EVP_CipherInit_ex(c->ctx, NULL, NULL, NULL, iv,
                       (c->dir == srtp_direction_encrypt ? 1 : 0));

    // Set AAD
    if (c->dir == srtp_direction_decrypt) {
        /*
         * Set dummy tag, OpenSSL requires the Tag to be set before
         * processing AAD
         */

        /*
         * OpenSSL never write to address pointed by the last parameter of
         * EVP_CIPHER_CTX_ctrl while EVP_CTRL_GCM_SET_TAG (in reality,
         * OpenSSL copy its content to the context), so we can make
         * aad read-only in this function and all its wrappers.
         */
        unsigned char dummy_tag[GCM_AUTH_TAG_LEN];
        memset(dummy_tag, 0x0, GCM_AUTH_TAG_LEN);
        if (!EVP_CIPHER_CTX_ctrl(c->ctx, EVP_CTRL_GCM_SET_TAG, c->tag_len,
                                 &dummy_tag)) {
            return (srtp_err_status_algo_fail);
        }
    }

    rv = EVP_Cipher(c->ctx, NULL, aad, aad_len);

    // Encrypt
    EVP_Cipher(c->ctx, buf, buf, *enc_len);
    EVP_Cipher(c->ctx, NULL, NULL, 0);
    if (!EVP_CIPHER_CTX_ctrl(c->ctx, EVP_CTRL_GCM_GET_TAG, c->tag_len, buf)) {
        return (srtp_err_status_algo_fail);
    }

    // Dealloc
    EVP_CIPHER_CTX_free(ctx);

    */
}

///////////
///////////
///////////

struct Context {
    key_size: AesKeySize,
    ctx: EvpCipherContext,
    key: [u8; Self::MAX_KEY_SIZE],
    salt: [u8; Self::SALT_SIZE],
}

impl Reset for Context {
    fn reset(&mut self) {
        self.ctx = unsafe { EvpCipherContext::new(self.key_size, self.key()).unwrap() };
    }
}

impl Context {
    const MAX_KEY_SIZE: usize = 32;
    const SALT_SIZE: usize = 12;
    const TAG_SIZE: usize = 16;

    fn new(key_size: AesKeySize, key: &[u8], salt: &[u8]) -> Result<Self, Error> {
        if key.len() != key_size.into() || salt.len() != Self::SALT_SIZE {
            return Err(Error::BadParam);
        }

        let mut ctx = Context {
            key_size: key_size,
            ctx: unsafe { EvpCipherContext::new(key_size, key)? },
            key: [0; 32],
            salt: [0; 12],
        };

        ctx.key[..key.len()].copy_from_slice(key);
        ctx.salt.copy_from_slice(salt);
        Ok(ctx)
    }

    fn key(&self) -> &[u8] {
        let key_size: usize = self.key_size.into();
        &self.key[..key_size]
    }
}

impl Cipher for Context {
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
        nonce: &[u8],
        aad: &[&[u8]],
        buf: &mut [u8],
        pt_size: usize,
    ) -> Result<usize, Error> {
        let ct_size = pt_size + Self::TAG_SIZE;
        if buf.len() < ct_size {
            return Err(Error::BadParam);
        }

        unsafe {
            self.ctx.set_nonce(nonce, true)?;
            for elem in aad {
                self.ctx.set_aad(elem)?;
            }

            self.ctx.encrypt(buf, pt_size, Self::TAG_SIZE)
        }
    }

    fn decrypt(&self, nonce: &[u8], aad: &[&[u8]], buf: &mut [u8]) -> Result<usize, Error> {
        if buf.len() < Self::TAG_SIZE {
            return Err(Error::BadParam);
        }
        let pt_size = buf.len() - Self::TAG_SIZE;

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
