use crate::crypto_kernel::{Auth, AuthType, AuthTypeID};
use crate::srtp::Error;
use hmac::{Hmac, Mac, NewMac};
use sha1::Sha1;
use std::any::Any;

type HmacSha1 = Hmac<Sha1>;

#[derive(Clone)]
struct HMAC {
    key_size: usize,
    tag_size: usize,
    mac: Option<HmacSha1>,
}

impl HMAC {
    fn hmac(&mut self) -> Result<&mut HmacSha1, Error> {
        self.mac.as_mut().ok_or(Error::BadParam)
    }
}

impl Auth for HMAC {
    fn key_size(&self) -> usize {
        self.key_size
    }

    fn tag_size(&self) -> usize {
        self.tag_size
    }

    fn prefix_size(&self) -> usize {
        0
    }

    fn init(&mut self, key: &[u8]) -> Result<(), Error> {
        let mac = HmacSha1::new_from_slice(key).map_err(|_| Error::BadParam)?;
        self.mac = Some(mac);
        Ok(())
    }

    fn start(&mut self) -> Result<(), Error> {
        self.hmac()?.reset();
        Ok(())
    }

    fn update(&mut self, update: &[u8]) -> Result<(), Error> {
        self.hmac()?.update(update);
        Ok(())
    }

    fn compute(&mut self, message: &[u8], tag: &mut [u8]) -> Result<(), Error> {
        self.hmac()?.update(message);
        let digest = self.hmac()?.finalize_reset().into_bytes();

        if tag.len() < self.tag_size {
            return Err(Error::BadParam);
        }

        tag[..self.tag_size].copy_from_slice(&digest[..self.tag_size]);
        Ok(())
    }

    fn clone_inner(&self) -> Box<dyn Auth> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn equals(&self, other: &Box<dyn Auth>) -> bool {
        match other.as_any().downcast_ref::<HMAC>() {
            Some(_) => true,
            None => false,
        }
    }
}

pub struct NativeHMAC;

impl AuthType for NativeHMAC {
    fn id(&self) -> AuthTypeID {
        AuthTypeID::HmacSha1
    }

    fn create(&self, key_len: usize, out_len: usize) -> Result<Box<dyn Auth>, Error> {
        Ok(Box::new(HMAC {
            key_size: key_len,
            tag_size: out_len,
            mac: None,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_test;

    #[test]
    fn test_hmac() -> Result<(), Error> {
        let auth_type = NativeHMAC {};
        assert_eq!(auth_type.id(), AuthTypeID::HmacSha1);

        let tests_passed = crypto_test::auth(&auth_type)?;
        assert!(tests_passed > 0);

        Ok(())
    }
}
