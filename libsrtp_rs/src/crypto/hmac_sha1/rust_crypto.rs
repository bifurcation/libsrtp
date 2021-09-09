#![cfg(feature = "rust-crypto")]
use super::super::{Auth, AuthType, AuthTypeID, Reset};
use crate::srtp::Error;
use constant_time_eq::constant_time_eq;
use hmac::{Hmac, Mac, NewMac};
use sha1::Sha1;

#[derive(Clone)]
struct Context {
    tag_size: usize,
    mac: Hmac<Sha1>,
}

impl Context {
    fn new(key: &[u8], tag_size: usize) -> Result<Self, Error> {
        Ok(Self {
            tag_size: tag_size,
            mac: Hmac::<Sha1>::new_from_slice(key).map_err(|_| Error::BadParam)?,
        })
    }
}

impl Reset for Context {
    fn reset(&mut self) {
        self.mac.reset();
    }
}

impl Auth for Context {
    fn tag_size(&self) -> usize {
        self.tag_size
    }

    fn prefix_size(&self) -> usize {
        0
    }

    fn start(&mut self) -> Result<(), Error> {
        self.mac.reset();
        Ok(())
    }

    fn update(&mut self, update: &[u8]) -> Result<(), Error> {
        self.mac.update(update);
        Ok(())
    }

    fn compute(&mut self, tag: &mut [u8]) -> Result<(), Error> {
        let digest = self.mac.finalize_reset().into_bytes();

        if tag.len() != self.tag_size {
            return Err(Error::BadParam);
        }

        tag[..self.tag_size].copy_from_slice(&digest[..self.tag_size]);
        Ok(())
    }

    fn constant_time_eq(&self, tag_a: &[u8], tag_b: &[u8]) -> bool {
        constant_time_eq(tag_a, tag_b)
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
