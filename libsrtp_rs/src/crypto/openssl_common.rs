#![cfg(feature = "openssl-crypto")]

use crate::crypto::CipherTypeID;
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

// This is a simple RAII wrapper around EVP_CIPHER_CTX that provides a slightly nicer interface to
// the underlying OpenSSL primitives.
pub struct EvpCipherContext {
    ctx: *mut EVP_CIPHER_CTX,
    gcm: bool,
}

impl Drop for EvpCipherContext {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            unsafe { EVP_CIPHER_CTX_free(self.ctx) };
        }
    }
}

impl EvpCipherContext {
    pub unsafe fn new(id: CipherTypeID, key: &[u8]) -> Result<Self, Error> {
        let ctx = non_null(EVP_CIPHER_CTX_new())?;

        let evp = match id {
            CipherTypeID::Null => return Err(Error::BadParam),
            CipherTypeID::AesIcm128 => EVP_aes_128_ctr(),
            CipherTypeID::AesIcm192 => EVP_aes_192_ctr(),
            CipherTypeID::AesIcm256 => EVP_aes_256_ctr(),
            CipherTypeID::AesGcm128 => EVP_aes_128_gcm(),
            CipherTypeID::AesGcm256 => EVP_aes_256_gcm(),
        };

        let gcm = match id {
            CipherTypeID::AesGcm128 | CipherTypeID::AesGcm256 => true,
            _ => false,
        };

        require1(EVP_CipherInit_ex(
            ctx,
            evp,
            std::ptr::null_mut(),
            key.as_ptr(),
            std::ptr::null(),
            0,
        ))?;

        Ok(Self { ctx: ctx, gcm: gcm })
    }

    pub unsafe fn set_nonce(&self, nonce: &[u8], encrypt: bool) -> Result<(), Error> {
        let direction = if encrypt { 1 } else { 0 };

        if self.gcm {
            require1(EVP_CIPHER_CTX_ctrl(
                self.ctx,
                EVP_CTRL_GCM_SET_IVLEN,
                12,
                std::ptr::null_mut(),
            ))?;
        }

        require1(EVP_CipherInit_ex(
            self.ctx,
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            nonce.as_ptr(),
            direction,
        ))
    }

    pub unsafe fn set_tag(&self, tag: &[u8]) -> Result<(), Error> {
        require1(EVP_CIPHER_CTX_ctrl(
            self.ctx,
            EVP_CTRL_GCM_SET_TAG,
            tag.len() as c_int,
            tag.as_ptr() as *mut c_void,
        ))
    }

    pub unsafe fn set_aad(&self, aad: &[u8]) -> Result<(), Error> {
        let mut out_size: c_int = 0;
        require1(EVP_CipherUpdate(
            self.ctx,
            std::ptr::null_mut(),
            &mut out_size,
            aad.as_ptr(),
            aad.len() as c_int,
        ))
    }

    pub unsafe fn encrypt(
        &self,
        pt: &mut [u8],
        pt_size: usize,
        tag_size: usize,
    ) -> Result<usize, Error> {
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

        if self.gcm {
            let tag_end = pt_size + tag_size;
            require1(EVP_CIPHER_CTX_ctrl(
                self.ctx,
                EVP_CTRL_GCM_GET_TAG,
                tag_size as c_int,
                (&mut pt[pt_size..tag_end]).as_mut_ptr() as *mut c_void,
            ))?;
        }

        Ok(pt_size + tag_size)
    }

    pub unsafe fn decrypt(&self, ct: &mut [u8]) -> Result<usize, Error> {
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
}
