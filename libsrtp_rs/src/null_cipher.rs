use crate::crypto_kernel::{Cipher, CipherDirection, CipherType, CipherTypeID};
use crate::srtp::Error;

struct Context;

impl Cipher for Context {
    fn key_size(&self) -> usize {
        0
    }

    fn iv_size(&self) -> usize {
        0
    }

    fn init(&mut self, key: &[u8]) -> Result<(), Error> {
        if key.len() != 0 {
            return Err(Error::BadParam);
        }

        Ok(())
    }

    fn set_aad(&mut self, _aad: &[u8]) -> Result<(), Error> {
        Err(Error::NoSuchOp)
    }

    fn set_iv(&mut self, _iv: &[u8], _direction: CipherDirection) -> Result<(), Error> {
        Ok(())
    }

    fn encrypt(&mut self, _buf: &mut [u8], pt_size: usize) -> Result<usize, Error> {
        Ok(pt_size)
    }

    fn decrypt(&mut self, _buf: &mut [u8], ct_size: usize) -> Result<usize, Error> {
        Ok(ct_size)
    }

    fn get_tag(&mut self, _tag: &mut [u8]) -> Result<usize, Error> {
        Err(Error::NoSuchOp)
    }

    fn clone_inner(&self) -> Box<dyn Cipher> {
        Box::new(Context {})
    }
}

pub struct NullCipher;

impl CipherType for NullCipher {
    fn id(&self) -> CipherTypeID {
        CipherTypeID::Null
    }

    fn create(&self, _key_len: usize, _tag_len: usize) -> Result<Box<dyn Cipher>, Error> {
        // XXX(RLB) It seems like we should do this check, but it is incompatible with SRTP tests.
        /*
        if key_len > 0 || tag_len > 0 {
            return Err(Error::BadParam);
        }
        */

        Ok(Box::new(Context {}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_test;

    #[test]
    fn test_null_cipher() -> Result<(), Error> {
        let cipher_type = NullCipher {};
        assert_eq!(cipher_type.id(), CipherTypeID::Null);

        let tests_passed = crypto_test::cipher(&cipher_type)?;
        assert!(tests_passed > 0);

        Ok(())
    }
}
