use crate::crypto_kernel::{Auth, AuthType, AuthTypeID};
use crate::sha1;
use crate::srtp::Error;

struct HMAC {
    opad: [u8; 64],
    ctx: sha1::Context,
}

impl Auth for HMAC {
    fn init(&mut self, key: &[u8]) -> Result<(), Error> {
        let mut ipad: [u8; 64] = [0x36; 64];
        self.opad = [0x5c; 64];

        for i in 0..key.len() {
            ipad[i] ^= key[i];
            self.opad[i] ^= key[i];
        }

        self.ctx.reset();
        self.ctx.update(&ipad);
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
            opad: [0; 64],
            ctx: sha1::Context::new(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac() -> Result<(), Error> {
        let key: [u8; 20] = [0x0b; 20];
        let data: [u8; 8] = [0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65]; // "Hi There"
        let expected_tag: [u8; 20] = [
            0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37,
            0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00,
        ];
        let mut actual_tag: [u8; 20] = [0; 20];

        // Instantiate
        let mut auth = NativeHMAC {}.create(key.len(), actual_tag.len())?;

        // One step
        auth.init(&key)?;
        auth.compute(&data, &mut actual_tag)?;
        assert_eq!(expected_tag, actual_tag);

        // Two step
        auth.init(&key)?;
        auth.update(&data)?;
        auth.compute(&[], &mut actual_tag)?;
        assert_eq!(expected_tag, actual_tag);
        Ok(())
    }
}
