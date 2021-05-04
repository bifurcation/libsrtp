use crate::crypto_kernel::{Auth, AuthType, AuthTypeID};
use crate::sha1;
use crate::srtp::Error;

struct HMAC {
    ipad: [u8; 64],
    opad: [u8; 64],
    ctx: sha1::Context,
}

impl Auth for HMAC {
    fn init(&mut self, key: &[u8]) -> Result<(), Error> {
        self.ipad.fill(0x36);
        self.opad.fill(0x5c);

        for i in 0..key.len() {
            self.ipad[i] ^= key[i];
            self.opad[i] ^= key[i];
        }

        self.ctx.reset();
        self.ctx.update(&self.ipad);
        Ok(())
    }

    fn start(&mut self) -> Result<(), Error> {
        self.ctx.reset();
        self.ctx.update(&self.ipad);
        Ok(())
    }

    fn update(&mut self, update: &[u8]) -> Result<(), Error> {
        self.ctx.update(update);
        Ok(())
    }

    fn compute(&mut self, message: &[u8], tag: &mut [u8]) -> Result<(), Error> {
        if tag.len() > sha1::OUTPUT_BYTES {
            return Err(Error::BadParam);
        }

        let mut inner_hash: [u8; sha1::OUTPUT_BYTES] = [0; sha1::OUTPUT_BYTES];
        self.ctx.update(&message);
        self.ctx.finalize(&mut inner_hash);

        let mut outer_hash: [u8; sha1::OUTPUT_BYTES] = [0; sha1::OUTPUT_BYTES];
        self.ctx.reset();
        self.ctx.update(&self.opad);
        self.ctx.update(&inner_hash);
        self.ctx.finalize(&mut outer_hash);

        tag.copy_from_slice(&outer_hash[..tag.len()]);
        Ok(())
    }
}

pub struct NativeHMAC;

impl AuthType for NativeHMAC {
    fn id(&self) -> AuthTypeID {
        AuthTypeID::HmacSha1
    }

    fn create(&self, key_len: usize, out_len: usize) -> Result<Box<dyn Auth>, Error> {
        if key_len > sha1::OUTPUT_BYTES || out_len > sha1::OUTPUT_BYTES {
            return Err(Error::BadParam);
        }

        Ok(Box::new(HMAC {
            ipad: [0; 64],
            opad: [0; 64],
            ctx: sha1::Context::new(),
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
