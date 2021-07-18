use crate::crypto_kernel::{
    Cipher, CipherType, CipherTypeID, ExtensionCipher, ExtensionCipherType, ExtensionCipherTypeID,
};
use crate::replay::ExtendedSequenceNumber;
use crate::srtp::Error;
use std::ops::Range;

struct Context;

impl ExtensionCipher for Context {
    fn xtn_id(&self) -> ExtensionCipherTypeID {
        ExtensionCipherTypeID::Null
    }

    fn init(&mut self, _ssrc: u32, _ext_seq_num: ExtendedSequenceNumber) -> Result<(), Error> {
        Ok(())
    }

    fn xor_key(&mut self, _buffer: &mut [u8], _range: Range<usize>) -> Result<(), Error> {
        Ok(())
    }

    fn clone_inner(&self) -> Box<dyn ExtensionCipher> {
        Box::new(Context {})
    }
}

impl Cipher for Context {
    fn id(&self) -> CipherTypeID {
        CipherTypeID::Null
    }

    fn rtp_nonce(
        &self,
        _ssrc: u32,
        _ext_seq_num: ExtendedSequenceNumber,
        _nonce: &mut [u8],
    ) -> Result<usize, Error> {
        Ok(0)
    }
    fn rtcp_nonce(&self, _ssrc: u32, _index: u32, _nonce: &mut [u8]) -> Result<usize, Error> {
        Ok(0)
    }

    fn set_aad(&mut self, _aad: &[u8]) -> Result<(), Error> {
        Ok(())
    }

    fn encrypt(&self, _nonce: &[u8], _buf: &mut [u8], pt_size: usize) -> Result<usize, Error> {
        Ok(pt_size)
    }

    fn decrypt(&self, _nonce: &[u8], _buf: &mut [u8], ct_size: usize) -> Result<usize, Error> {
        Ok(ct_size)
    }

    fn clone_inner(&self) -> Box<dyn Cipher> {
        Box::new(Context {})
    }
}

pub struct NullCipher;

impl ExtensionCipherType for NullCipher {
    fn xtn_id(&self) -> ExtensionCipherTypeID {
        ExtensionCipherTypeID::Null
    }

    fn xtn_create(&self, _key: &[u8], _salt: &[u8]) -> Result<Box<dyn ExtensionCipher>, Error> {
        Ok(Box::new(Context {}))
    }
}

impl CipherType for NullCipher {
    fn id(&self) -> CipherTypeID {
        CipherTypeID::Null
    }

    fn create(&self, _key: &[u8], _salt: &[u8]) -> Result<Box<dyn Cipher>, Error> {
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

    #[test]
    fn test_null_cipher_xtn() -> Result<(), Error> {
        let cipher_type = NullCipher {};
        assert_eq!(cipher_type.xtn_id(), ExtensionCipherTypeID::Null);

        let tests_passed = crypto_test::xtn_cipher(&cipher_type)?;
        assert!(tests_passed > 0);

        Ok(())
    }
}
