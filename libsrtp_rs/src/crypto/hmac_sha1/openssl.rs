#![cfg(feature = "openssl-crypto")]
use super::super::{Auth, AuthType, AuthTypeID, Reset};
use crate::srtp::Error;

use openssl::hash::MessageDigest;
use openssl::memcmp;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;

// XXX(RLB) Crate `openssl` has an incremental `Signer` struct, but it holds a reference to the
// `PKey` that created it.  So to avoid needing to have a self-referential struct, we queue up
// data to be MAC'ed.
//
// The proper fix here is probably to have a separate "operation" struct that holds an external
// reference to the context.  So we would refactor from the current two-tier (AuthType, Auth)
// system to a three-tier (AuthType, Auth, AuthOperation) system.
struct Context {
    tag_size: usize,
    key: PKey<Private>,
}

impl Context {
    fn new(key: &[u8], tag_size: usize) -> Result<Self, Error> {
        Ok(Self {
            tag_size: tag_size,
            key: PKey::hmac(key).map_err(|_| Error::CipherFail)?,
        })
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

        let mut signer =
            Signer::new(MessageDigest::sha1(), &self.key).map_err(|_| Error::CipherFail)?;

        for input in inputs {
            signer.update(&input).map_err(|_| Error::CipherFail)?;
        }

        let mut digest = [0u8; 20];
        signer.sign(&mut digest).map_err(|_| Error::CipherFail)?;
        tag[..self.tag_size].copy_from_slice(&digest[..self.tag_size]);
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
