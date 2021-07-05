use crate::crypto_kernel::{Cipher, CipherType, CipherTypeID};
use crate::replay::ExtendedSequenceNumber;
use crate::srtp::Error;

struct Context;

impl Cipher for Context {
    fn id(&self) -> CipherTypeID {
        CipherTypeID::Null
    }

    fn rtp_nonce(
        &self,
        ssrc: u32,
        ext_seq_num: ExtendedSequenceNumber,
        nonce: &mut [u8],
    ) -> Result<usize, Error> {
        Ok(0)
    }
    fn rtcp_nonce(&self, ssrc: u32, index: u32, nonce: &mut [u8]) -> Result<usize, Error> {
        Ok(0)
    }

    fn encrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut [u8],
        pt_size: usize,
    ) -> Result<usize, Error> {
        Ok(pt_size)
    }

    fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut [u8],
        ct_size: usize,
    ) -> Result<usize, Error> {
        Ok(ct_size)
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

    fn create(&self, key: &[u8], salt: &[u8]) -> Result<Box<dyn Cipher>, Error> {
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
