// Define all implementations
mod openssl_crypto;
mod rust_crypto;

// Export the crypto that was actually built
#[cfg(feature = "rust-crypto")]
pub use rust_crypto::*;

#[cfg(feature = "openssl-crypto")]
pub use openssl_crypto::*;

// Shared code across implementations

use crate::crypto::xor_eq;
use crate::replay::ExtendedSequenceNumber;
use crate::srtp::Error;

mod constants {
    pub const SALT_SIZE: usize = 14;
    pub const NONCE_SIZE: usize = 16;
    pub const TAG_SIZE: usize = 0;
}

// https://datatracker.ietf.org/doc/html/rfc3711#section-4.1.1
//
// IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)
//
// In more graphical notation:
//
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |00|00|00|00|    SSRC   |     ROC   | SEQ |00|00|
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
fn make_rtp_nonce(
    salt: &[u8],
    ssrc: u32,
    ext_seq_num: ExtendedSequenceNumber,
    nonce: &mut [u8],
) -> Result<usize, Error> {
    if nonce.len() != constants::NONCE_SIZE {
        return Err(Error::BadParam);
    }

    nonce.fill(0);
    nonce[4..8].copy_from_slice(&ssrc.to_be_bytes());
    nonce[8..14].copy_from_slice(&ext_seq_num.to_be_bytes()[2..]);
    xor_eq(&mut nonce[..14], salt);
    Ok(nonce.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        constants::AesKeySize, self_test, CipherType, CipherTypeID, Error, ExtendedSequenceNumber,
        ExtensionCipherType, ExtensionCipherTypeID,
    };
    use hex_literal::hex;
    use std::ops::Range;

    #[test]
    fn test_aes_icm_128() -> Result<(), Error> {
        let cipher_type: Box<dyn CipherType> = Box::new(AesIcm::new(AesKeySize::Aes128)?);
        assert_eq!(cipher_type.id(), CipherTypeID::AesIcm128);

        let tests_passed = self_test::cipher(cipher_type.as_ref())?;
        assert!(tests_passed > 0);

        Ok(())
    }

    #[test]
    fn test_aes_icm_192() -> Result<(), Error> {
        let cipher_type: Box<dyn CipherType> = Box::new(AesIcm::new(AesKeySize::Aes192)?);
        assert_eq!(cipher_type.id(), CipherTypeID::AesIcm192);

        let tests_passed = self_test::cipher(cipher_type.as_ref())?;
        assert!(tests_passed > 0);

        Ok(())
    }

    #[test]
    fn test_aes_icm_256() -> Result<(), Error> {
        let cipher_type: Box<dyn CipherType> = Box::new(AesIcm::new(AesKeySize::Aes256)?);
        assert_eq!(cipher_type.id(), CipherTypeID::AesIcm256);

        let tests_passed = self_test::cipher(cipher_type.as_ref())?;
        assert!(tests_passed > 0);

        Ok(())
    }

    #[test]
    fn test_aes_icm_128_xtn() -> Result<(), Error> {
        let cipher_type: Box<dyn ExtensionCipherType> = Box::new(AesIcm::new(AesKeySize::Aes128)?);
        assert_eq!(cipher_type.xtn_id(), ExtensionCipherTypeID::AesIcm128);

        let tests_passed = self_test::xtn_cipher(cipher_type.as_ref())?;
        assert!(tests_passed > 0);

        Ok(())
    }

    #[test]
    fn test_aes_icm_192_xtn() -> Result<(), Error> {
        let cipher_type: Box<dyn ExtensionCipherType> = Box::new(AesIcm::new(AesKeySize::Aes192)?);
        assert_eq!(cipher_type.xtn_id(), ExtensionCipherTypeID::AesIcm192);

        let tests_passed = self_test::xtn_cipher(cipher_type.as_ref())?;
        assert!(tests_passed > 0);

        Ok(())
    }

    #[test]
    fn test_aes_icm_256_xtn() -> Result<(), Error> {
        let cipher_type: Box<dyn ExtensionCipherType> = Box::new(AesIcm::new(AesKeySize::Aes256)?);
        assert_eq!(cipher_type.xtn_id(), ExtensionCipherTypeID::AesIcm256);

        let tests_passed = self_test::xtn_cipher(cipher_type.as_ref())?;
        assert!(tests_passed > 0);

        Ok(())
    }

    #[test]
    fn test_rtp_xtn_header_example() -> Result<(), Error> {
        let key = hex!("549752054d6fb708622c4a2e596a1b93");
        let salt = hex!("ab01818174c40d39a3781f7c2d27");
        let ssrc: u32 = 0xcafebabe;
        let ext_seq_num: ExtendedSequenceNumber = 0x0000001234;
        let ranges: &'static [Range<usize>] = &[1..9, 14..15, 16..23];
        let pt = hex!("17414273a475262748220000c8308e4655996386b395fb00");
        let ct = hex!("17588A9270F4E15E1C220000C8309546A994F0BC54789700");

        let cipher_type: Box<dyn ExtensionCipherType> = Box::new(AesIcm::new(AesKeySize::Aes128)?);
        let mut cipher = cipher_type.xtn_create(&key, &salt)?;

        // Verify correct encryption
        let mut encrypt_buffer = [0u8; 24];
        encrypt_buffer.copy_from_slice(&pt);
        cipher.init(ssrc, ext_seq_num)?;
        for r in ranges {
            cipher.xor_key(&mut encrypt_buffer[r.clone()], r.clone())?;
        }
        assert_eq!(encrypt_buffer, ct);

        Ok(())
    }

    #[test]
    fn test_rtp_example() -> Result<(), Error> {
        let key = hex!("c61e7a93744f39ee10734afe3ff7a087");
        let salt = hex!("30cbbc08863d8c85d49db34a9ae1");
        let ssrc: u32 = 0xcafebabe;
        let ext_seq_num: ExtendedSequenceNumber = 0x0000001234;
        // (30cbbc08863d8c85d49db34a9ae1 ^ 00000000cafebabe000000001234) || 0000
        let expected_nonce = hex!("30cbbc084cc3363bd49db34a88d50000");
        let aad = [];
        let pt = [0xab; 16];
        let ct = hex!("4e55dc4ce79978d88ca4d215949d2402");

        let cipher_type: Box<dyn CipherType> = Box::new(AesIcm::new(AesKeySize::Aes128)?);
        let mut cipher = cipher_type.create(&key, &salt)?;

        // Verify correct nonce formation
        let mut nonce: [u8; 16] = Default::default();
        cipher.rtp_nonce(ssrc, ext_seq_num, &mut nonce)?;
        assert_eq!(nonce, expected_nonce);

        // Verify correct encryption
        let mut enc_buffer = [0u8; 16];
        enc_buffer[..pt.len()].copy_from_slice(&pt);
        let ct_size = cipher.encrypt(&nonce, &[&aad], &mut enc_buffer, pt.len())?;
        assert_eq!(ct_size, ct.len());
        assert_eq!(enc_buffer, ct);

        // Verify correct decryption
        cipher.reset();
        let pt_size = cipher.decrypt(&nonce, &[&aad], &mut enc_buffer)?;
        assert_eq!(pt_size, pt.len());
        assert_eq!(&enc_buffer[..pt_size], &pt);

        Ok(())
    }

    #[test]
    fn test_rtcp_example() {
        // TODO
    }
}
