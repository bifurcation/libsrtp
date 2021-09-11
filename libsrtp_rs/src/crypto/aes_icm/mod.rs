use super::constants::AesKeySize;
use super::{
    xor_eq, Cipher, CipherType, CipherTypeID, ExtensionCipher, ExtensionCipherType,
    ExtensionCipherTypeID, Reset,
};
use crate::replay::ExtendedSequenceNumber;
use crate::srtp::Error;
use std::ops::Range;

use aes::cipher::{
    generic_array::{typenum::U16, GenericArray},
    BlockCipher, BlockEncrypt, NewBlockCipher,
};
use aes::{Aes128, Aes192, Aes256};
use ctr::cipher::{NewCipher, StreamCipher, StreamCipherSeek};
use ctr::Ctr128BE;

#[derive(Clone)]
struct Context<C>
where
    C: Clone + BlockEncrypt + BlockCipher<BlockSize = U16> + NewBlockCipher + 'static,
{
    key_size: AesKeySize,
    key: [u8; 32],
    salt: [u8; 14],
    cipher: Option<Ctr128BE<C>>,
}

impl<C> Reset for Context<C>
where
    C: Clone + BlockEncrypt + BlockCipher<BlockSize = U16> + NewBlockCipher + 'static,
{
    fn reset(&mut self) {
        self.cipher = None;
    }
}

impl<C> Context<C>
where
    C: Clone + BlockEncrypt + BlockCipher<BlockSize = U16> + NewBlockCipher + 'static,
{
    const NONCE_SIZE: usize = 16;

    fn new(key_size: AesKeySize, key: &[u8], salt: &[u8]) -> Result<Self, Error> {
        let id = key_size.as_icm_id();
        if key.len() != id.key_size() || salt.len() != id.salt_size() {
            return Err(Error::BadParam);
        }

        let mut ctx = Context {
            key_size: key_size,
            key: Default::default(),
            salt: Default::default(),
            cipher: None,
        };

        ctx.key_mut().copy_from_slice(key);
        ctx.salt.copy_from_slice(salt);
        Ok(ctx)
    }

    fn key(&self) -> &[u8] {
        let key_size = self.key_size.as_usize();
        &self.key[..key_size]
    }

    fn key_mut(&mut self) -> &mut [u8] {
        let key_size = self.key_size.as_usize();
        &mut self.key[..key_size]
    }

    // Placed up here because it is used for both SRTP encryption and extension header encryption.
    //
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
        &self,
        ssrc: u32,
        ext_seq_num: ExtendedSequenceNumber,
        nonce: &mut [u8],
    ) -> Result<usize, Error> {
        if nonce.len() != Self::NONCE_SIZE {
            return Err(Error::BadParam);
        }

        nonce.fill(0);
        nonce[4..8].copy_from_slice(&ssrc.to_be_bytes());
        nonce[8..14].copy_from_slice(&ext_seq_num.to_be_bytes()[2..]);
        xor_eq(&mut nonce[..14], &self.salt);
        Ok(nonce.len())
    }
}

impl<C> ExtensionCipher for Context<C>
where
    C: Clone + BlockEncrypt + BlockCipher<BlockSize = U16> + NewBlockCipher + 'static,
{
    fn xtn_id(&self) -> ExtensionCipherTypeID {
        self.key_size.as_stream_icm_id()
    }

    fn init(&mut self, ssrc: u32, ext_seq_num: ExtendedSequenceNumber) -> Result<(), Error> {
        let mut iv = [0u8; 16];
        self.make_rtp_nonce(ssrc, ext_seq_num, &mut iv[..Self::NONCE_SIZE])?;

        let iv = GenericArray::from_slice(&iv);
        let key = GenericArray::from_slice(self.key());
        self.cipher = Some(Ctr128BE::new(&key, iv.into()));
        Ok(())
    }

    fn xor_key(&mut self, buffer: &mut [u8], range: Range<usize>) -> Result<(), Error> {
        if range.is_empty() {
            return Ok(());
        }

        let size = range.end - range.start;
        if buffer.len() < size {
            return Err(Error::BadParam);
        }

        let cipher = self.cipher.as_mut().ok_or(Error::CipherFail)?;
        cipher
            .try_seek(range.start)
            .map_err(|_| Error::CipherFail)?;
        cipher
            .try_apply_keystream(&mut buffer[..size])
            .map_err(|_| Error::CipherFail)?;
        Ok(())
    }
}

impl<C> Cipher for Context<C>
where
    C: Clone + BlockEncrypt + BlockCipher<BlockSize = U16> + NewBlockCipher + 'static,
{
    fn id(&self) -> CipherTypeID {
        self.key_size.as_icm_id()
    }

    fn overhead(&self) -> usize {
        0
    }

    fn salt(&self) -> Vec<u8> {
        self.salt.clone().into()
    }

    fn rtp_nonce(
        &self,
        ssrc: u32,
        ext_seq_num: ExtendedSequenceNumber,
        nonce: &mut [u8],
    ) -> Result<usize, Error> {
        self.make_rtp_nonce(ssrc, ext_seq_num, nonce)
    }

    // In the case of SRTCP, the SSRC of the first header of the compound
    // packet MUST be used, i SHALL be the 31-bit SRTCP index...
    fn rtcp_nonce(&self, ssrc: u32, index: u32, nonce: &mut [u8]) -> Result<usize, Error> {
        self.rtp_nonce(ssrc, index.into(), nonce)
    }

    fn add_aad(&mut self, _aad: &[u8]) -> Result<(), Error> {
        Ok(())
    }

    fn set_nonce(&mut self, nonce: &[u8]) -> Result<(), Error> {
        let iv = GenericArray::from_slice(&nonce);
        let key = GenericArray::from_slice(self.key());
        self.cipher = Some(Ctr128BE::new(&key, iv.into()));
        Ok(())
    }

    fn encrypt_one(
        &mut self,
        nonce: &[u8],
        _aad: &[&[u8]],
        buf: &mut [u8],
        pt_size: usize,
    ) -> Result<usize, Error> {
        let iv = GenericArray::from_slice(&nonce);
        let key = GenericArray::from_slice(self.key());
        Ctr128BE::<C>::new(&key, iv.into())
            .try_apply_keystream(&mut buf[..pt_size])
            .map(|_| pt_size)
            .map_err(|_| Error::CipherFail)
    }

    fn decrypt_one(&mut self, nonce: &[u8], aad: &[&[u8]], buf: &mut [u8]) -> Result<usize, Error> {
        self.encrypt_one(nonce, aad, buf, buf.len())
    }

    fn encrypt(&mut self, buf: &mut [u8], pt_size: usize) -> Result<usize, Error> {
        self.cipher
            .as_mut()
            .ok_or(Error::CipherFail)?
            .try_apply_keystream(&mut buf[..pt_size])
            .map(|_| pt_size)
            .map_err(|_| Error::CipherFail)
    }

    fn decrypt(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.encrypt(buf, buf.len())
    }
}

pub struct AesIcm {
    key_size: AesKeySize,
}

impl AesIcm {
    pub fn new(key_size: AesKeySize) -> Self {
        AesIcm { key_size: key_size }
    }
}

impl ExtensionCipherType for AesIcm {
    fn xtn_id(&self) -> ExtensionCipherTypeID {
        self.key_size.as_stream_icm_id()
    }

    fn xtn_create(&self, key: &[u8], salt: &[u8]) -> Result<Box<dyn ExtensionCipher>, Error> {
        Ok(match self.key_size {
            AesKeySize::Aes128 => Box::new(Context::<Aes128>::new(self.key_size, key, salt)?),
            AesKeySize::Aes192 => Box::new(Context::<Aes192>::new(self.key_size, key, salt)?),
            AesKeySize::Aes256 => Box::new(Context::<Aes256>::new(self.key_size, key, salt)?),
        })
    }
}

impl CipherType for AesIcm {
    fn id(&self) -> CipherTypeID {
        self.key_size.as_icm_id()
    }

    fn create(&self, key: &[u8], salt: &[u8]) -> Result<Box<dyn Cipher>, Error> {
        Ok(match self.key_size {
            AesKeySize::Aes128 => Box::new(Context::<Aes128>::new(self.key_size, key, salt)?),
            AesKeySize::Aes192 => Box::new(Context::<Aes192>::new(self.key_size, key, salt)?),
            AesKeySize::Aes256 => Box::new(Context::<Aes256>::new(self.key_size, key, salt)?),
        })
    }

    fn clone(&self) -> Box<dyn CipherType> {
        Box::new(AesIcm {
            key_size: self.key_size,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::self_test;
    use hex_literal::hex;

    #[test]
    fn test_aes_icm_128() -> Result<(), Error> {
        let cipher_type: Box<dyn CipherType> = Box::new(AesIcm::new(AesKeySize::Aes128));
        assert_eq!(cipher_type.id(), CipherTypeID::AesIcm128);

        let tests_passed = self_test::cipher(cipher_type.as_ref())?;
        assert!(tests_passed > 0);

        Ok(())
    }

    #[test]
    fn test_aes_icm_192() -> Result<(), Error> {
        let cipher_type: Box<dyn CipherType> = Box::new(AesIcm::new(AesKeySize::Aes192));
        assert_eq!(cipher_type.id(), CipherTypeID::AesIcm192);

        let tests_passed = self_test::cipher(cipher_type.as_ref())?;
        assert!(tests_passed > 0);

        Ok(())
    }

    #[test]
    fn test_aes_icm_256() -> Result<(), Error> {
        let cipher_type: Box<dyn CipherType> = Box::new(AesIcm::new(AesKeySize::Aes256));
        assert_eq!(cipher_type.id(), CipherTypeID::AesIcm256);

        let tests_passed = self_test::cipher(cipher_type.as_ref())?;
        assert!(tests_passed > 0);

        Ok(())
    }

    #[test]
    fn test_aes_icm_128_xtn() -> Result<(), Error> {
        let cipher_type: Box<dyn ExtensionCipherType> = Box::new(AesIcm::new(AesKeySize::Aes128));
        assert_eq!(cipher_type.xtn_id(), ExtensionCipherTypeID::AesIcm128);

        let tests_passed = self_test::xtn_cipher(cipher_type.as_ref())?;
        assert!(tests_passed > 0);

        Ok(())
    }

    #[test]
    fn test_aes_icm_192_xtn() -> Result<(), Error> {
        let cipher_type: Box<dyn ExtensionCipherType> = Box::new(AesIcm::new(AesKeySize::Aes192));
        assert_eq!(cipher_type.xtn_id(), ExtensionCipherTypeID::AesIcm192);

        let tests_passed = self_test::xtn_cipher(cipher_type.as_ref())?;
        assert!(tests_passed > 0);

        Ok(())
    }

    #[test]
    fn test_aes_icm_256_xtn() -> Result<(), Error> {
        let cipher_type: Box<dyn ExtensionCipherType> = Box::new(AesIcm::new(AesKeySize::Aes256));
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

        let cipher_type: Box<dyn ExtensionCipherType> = Box::new(AesIcm::new(AesKeySize::Aes128));
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

        let cipher_type: Box<dyn CipherType> = Box::new(AesIcm::new(AesKeySize::Aes128));
        let mut cipher = cipher_type.create(&key, &salt)?;

        // Verify correct nonce formation
        let mut nonce: [u8; 16] = Default::default();
        cipher.rtp_nonce(ssrc, ext_seq_num, &mut nonce)?;
        assert_eq!(nonce, expected_nonce);

        // Verify correct encryption
        let mut enc_buffer = [0u8; 16];
        enc_buffer[..pt.len()].copy_from_slice(&pt);
        let ct_size = cipher.encrypt_one(&nonce, &[&aad], &mut enc_buffer, pt.len())?;
        assert_eq!(ct_size, ct.len());
        assert_eq!(enc_buffer, ct);

        // Verify correct decryption
        cipher.reset();
        let pt_size = cipher.decrypt_one(&nonce, &[&aad], &mut enc_buffer)?;
        assert_eq!(pt_size, pt.len());
        assert_eq!(&enc_buffer[..pt_size], &pt);

        Ok(())
    }

    #[test]
    fn test_rtcp_example() {
        // TODO
    }
}
