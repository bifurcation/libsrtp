// Define all implementations
mod openssl_crypto;
mod rust_crypto;

// Export the crypto that was actually built
#[cfg(feature = "rust-crypto")]
pub use rust_crypto::*;

#[cfg(feature = "openssl-crypto")]
pub use openssl_crypto::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        constants::AesKeySize, self_test, CipherType, CipherTypeID, Error, ExtendedSequenceNumber,
    };
    use hex_literal::hex;

    #[test]
    fn test_128() -> Result<(), Error> {
        let cipher_type = AesGcm::new(AesKeySize::Aes128)?;
        assert_eq!(cipher_type.id(), CipherTypeID::AesGcm128);

        let tests_passed = self_test::cipher(&cipher_type)?;
        assert!(tests_passed > 0);

        Ok(())
    }

    #[test]
    fn test_256() -> Result<(), Error> {
        let cipher_type = AesGcm::new(AesKeySize::Aes256)?;
        assert_eq!(cipher_type.id(), CipherTypeID::AesGcm256);

        let tests_passed = self_test::cipher(&cipher_type)?;
        assert!(tests_passed > 0);

        Ok(())
    }

    #[test]
    fn test_rtp_example() -> Result<(), Error> {
        let key = hex!("238c882f36f000301573e69383502d9d");
        let salt = hex!("f2fee04070fc3f65d706e2e4");
        let ssrc: u32 = 0xcafebabe;
        let ext_seq_num: ExtendedSequenceNumber = 0x0000001234;
        // f2fee04070fc3f65d706e2e4 ^ 0000cafebabe000000001234
        let expected_nonce: [u8; 12] = hex!("f2fe2abeca423f65d706f0d0");
        let aad = hex!(
            "900f1234decafbadcafebabebede00061712e0205bfa949b1c220000c830bb46732778d9929aab00"
        );
        let pt = [0xab; 16];
        let ct = hex!("0eca0cf95ee955b26cd3d288b49f6ca9f4b1b759719eb5bc113b9ff1d40cd25a");

        let cipher_type = AesGcm::new(AesKeySize::Aes128)?;
        let mut cipher = cipher_type.create(&key, &salt)?;

        // Verify correct nonce formation
        let mut nonce: [u8; 12] = Default::default();
        cipher.rtp_nonce(ssrc, ext_seq_num, &mut nonce)?;
        assert_eq!(nonce, expected_nonce);

        // Verify correct encryption
        let mut enc_buffer = [0u8; 32];
        enc_buffer[..pt.len()].copy_from_slice(&pt);

        cipher.reset();
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
