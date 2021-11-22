#![cfg(feature = "openssl-crypto")]
use super::super::{Auth, AuthType, AuthTypeID, Reset};
use crate::srtp::Error;

use openssl::memcmp;
use openssl_sys::{
    EVP_sha1, HMAC_CTX_free, HMAC_CTX_new, HMAC_Final, HMAC_Init_ex, HMAC_Update, HMAC_CTX,
};
use std::convert::TryInto;
use std::os::raw::{c_int, c_void};

const SHA1_DIGEST_SIZE: usize = 20;

struct Context {
    tag_size: usize,
    key: Vec<u8>,
    ctx: *mut HMAC_CTX,
}

impl Context {
    fn new(key: &[u8], tag_size: usize) -> Result<Self, Error> {
        let ctx = unsafe { HMAC_CTX_new() };
        if ctx.is_null() {
            return Err(Error::AllocFail);
        }

        Ok(Self {
            tag_size: tag_size,
            key: key.into(),
            ctx,
        })
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        self.key.fill(0);
        unsafe { HMAC_CTX_free(self.ctx) };
    }
}

impl Reset for Context {
    fn reset(&mut self) {}
}

impl Auth for Context {
    fn tag_size(&self) -> usize {
        self.tag_size
    }

    fn compute(&mut self, inputs: &[&[u8]], tag: &mut [u8]) -> Result<(), Error> {
        if tag.len() != self.tag_size {
            return Err(Error::BadParam);
        }

        // Initialize context
        let key = self.key.as_ptr() as *const c_void;
        let key_len: c_int = self.key.len().try_into().map_err(|_| Error::AuthFail)?;
        let rv = unsafe { HMAC_Init_ex(self.ctx, key, key_len, EVP_sha1(), std::ptr::null_mut()) };
        if rv == 0 {
            return Err(Error::AuthFail);
        }

        // Feed in inputs
        for input in inputs {
            let msg = input.as_ptr();
            let msg_len = input.len().try_into().map_err(|_| Error::AuthFail)?;
            let rv = unsafe { HMAC_Update(self.ctx, msg, msg_len) };
            if rv == 0 {
                return Err(Error::AuthFail);
            }
        }

        // Output hash value
        let mut out = [0u8; SHA1_DIGEST_SIZE];
        let tag_ptr = out.as_mut_ptr();
        let mut tag_len = out.len().try_into().map_err(|_| Error::AuthFail)?;
        let rv = unsafe { HMAC_Final(self.ctx, tag_ptr, &mut tag_len) };
        if rv == 0 {
            return Err(Error::AuthFail);
        }

        tag.copy_from_slice(&out[..tag.len()]);
        Ok(())
    }

    fn constant_time_eq(&self, tag_a: &[u8], tag_b: &[u8]) -> bool {
        memcmp::eq(tag_a, tag_b)
    }
}

pub struct HmacSha1;

impl AuthType for HmacSha1 {
    fn id(&self) -> AuthTypeID {
        AuthTypeID::HmacSha1
    }

    fn create(&self, key: &[u8], tag_size: usize) -> Result<Box<dyn Auth>, Error> {
        Ok(Box::new(Context::new(key, tag_size)?))
    }

    fn clone(&self) -> Box<dyn AuthType> {
        Box::new(HmacSha1)
    }
}
