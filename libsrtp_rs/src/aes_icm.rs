use crate::crypto_kernel::constants::AesKeySize;
use crate::crypto_kernel::{
    Cipher, CipherType, CipherTypeID, ExtensionCipher, ExtensionCipherType, ExtensionCipherTypeID,
};
use crate::replay::ExtendedSequenceNumber;
use crate::srtp::Error;
use crate::util::xor_eq;
use aes::cipher::{
    generic_array::{typenum::U16, GenericArray},
    BlockCipher, BlockEncrypt, NewBlockCipher,
};
use aes::{Aes128, Aes192, Aes256};
use ctr::cipher::{NewCipher, StreamCipher, StreamCipherSeek};
use ctr::Ctr128BE;
use std::ops::Range;

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
        println!("iv: {:02x?}", iv);

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

    fn clone_inner(&self) -> Box<dyn ExtensionCipher> {
        Box::new(self.clone())
    }
}

impl<C> Cipher for Context<C>
where
    C: Clone + BlockEncrypt + BlockCipher<BlockSize = U16> + NewBlockCipher + 'static,
{
    fn id(&self) -> CipherTypeID {
        self.key_size.as_icm_id()
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

    fn set_aad(&mut self, _aad: &[u8]) -> Result<(), Error> {
        Ok(())
    }

    fn encrypt(&self, nonce: &[u8], buf: &mut [u8], pt_size: usize) -> Result<usize, Error> {
        let key = GenericArray::from_slice(self.key());
        Ctr128BE::<C>::new(&key, nonce.into())
            .try_apply_keystream(&mut buf[..pt_size])
            .map(|_| pt_size)
            .map_err(|_| Error::CipherFail)
    }

    fn decrypt(&self, nonce: &[u8], buf: &mut [u8], ct_size: usize) -> Result<usize, Error> {
        self.encrypt(nonce, buf, ct_size)
    }

    fn clone_inner(&self) -> Box<dyn Cipher> {
        Box::new(self.clone())
    }
}

pub struct NativeAesIcm {
    key_size: AesKeySize,
}

impl NativeAesIcm {
    pub fn new(key_size: AesKeySize) -> Self {
        NativeAesIcm { key_size: key_size }
    }
}

impl ExtensionCipherType for NativeAesIcm {
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

impl CipherType for NativeAesIcm {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_test;

    #[test]
    fn test_aes_icm_128() -> Result<(), Error> {
        let cipher_type: Box<dyn CipherType> = Box::new(NativeAesIcm::new(AesKeySize::Aes128));
        assert_eq!(cipher_type.id(), CipherTypeID::AesIcm128);

        let tests_passed = crypto_test::cipher(cipher_type.as_ref())?;
        assert!(tests_passed > 0);

        Ok(())
    }

    #[test]
    fn test_aes_icm_192() -> Result<(), Error> {
        let cipher_type: Box<dyn CipherType> = Box::new(NativeAesIcm::new(AesKeySize::Aes192));
        assert_eq!(cipher_type.id(), CipherTypeID::AesIcm192);

        let tests_passed = crypto_test::cipher(cipher_type.as_ref())?;
        assert!(tests_passed > 0);

        Ok(())
    }

    #[test]
    fn test_aes_icm_256() -> Result<(), Error> {
        let cipher_type: Box<dyn CipherType> = Box::new(NativeAesIcm::new(AesKeySize::Aes256));
        assert_eq!(cipher_type.id(), CipherTypeID::AesIcm256);

        let tests_passed = crypto_test::cipher(cipher_type.as_ref())?;
        assert!(tests_passed > 0);

        Ok(())
    }

    #[test]
    fn test_aes_icm_128_xtn() -> Result<(), Error> {
        let cipher_type: Box<dyn ExtensionCipherType> =
            Box::new(NativeAesIcm::new(AesKeySize::Aes128));
        assert_eq!(cipher_type.xtn_id(), ExtensionCipherTypeID::AesIcm128);

        let tests_passed = crypto_test::xtn_cipher(cipher_type.as_ref())?;
        assert!(tests_passed > 0);

        Ok(())
    }

    #[test]
    fn test_aes_icm_192_xtn() -> Result<(), Error> {
        let cipher_type: Box<dyn ExtensionCipherType> =
            Box::new(NativeAesIcm::new(AesKeySize::Aes192));
        assert_eq!(cipher_type.xtn_id(), ExtensionCipherTypeID::AesIcm192);

        let tests_passed = crypto_test::xtn_cipher(cipher_type.as_ref())?;
        assert!(tests_passed > 0);

        Ok(())
    }

    #[test]
    fn test_aes_icm_256_xtn() -> Result<(), Error> {
        let cipher_type: Box<dyn ExtensionCipherType> =
            Box::new(NativeAesIcm::new(AesKeySize::Aes256));
        assert_eq!(cipher_type.xtn_id(), ExtensionCipherTypeID::AesIcm256);

        let tests_passed = crypto_test::xtn_cipher(cipher_type.as_ref())?;
        assert!(tests_passed > 0);

        Ok(())
    }

    #[test]
    fn test_rtp_xtn_header_example() -> Result<(), Error> {
        let key: [u8; 16] = [
            0x54, 0x97, 0x52, 0x05, 0x4d, 0x6f, 0xb7, 0x08, 0x62, 0x2c, 0x4a, 0x2e, 0x59, 0x6a,
            0x1b, 0x93,
        ];
        let salt: [u8; 14] = [
            0xab, 0x01, 0x81, 0x81, 0x74, 0xc4, 0x0d, 0x39, 0xa3, 0x78, 0x1f, 0x7c, 0x2d, 0x27,
        ];
        let ssrc: u32 = 0xcafebabe;
        let ext_seq_num: ExtendedSequenceNumber = 0x0000001234;
        let ranges: &'static [Range<usize>] = &[1..9, 14..15, 16..23];
        let pt: &'static [u8] = &[
            0x17, 0x41, 0x42, 0x73, 0xa4, 0x75, 0x26, 0x27, 0x48, 0x22, 0x00, 0x00, 0xc8, 0x30,
            0x8e, 0x46, 0x55, 0x99, 0x63, 0x86, 0xb3, 0x95, 0xfb, 0x00,
        ];
        let ct: &'static [u8] = &[
            0x17, 0x58, 0x8A, 0x92, 0x70, 0xF4, 0xE1, 0x5E, 0x1C, 0x22, 0x00, 0x00, 0xC8, 0x30,
            0x95, 0x46, 0xA9, 0x94, 0xF0, 0xBC, 0x54, 0x78, 0x97, 0x00,
        ];

        let cipher_type: Box<dyn ExtensionCipherType> =
            Box::new(NativeAesIcm::new(AesKeySize::Aes128));
        let mut cipher = cipher_type.xtn_create(&key, &salt)?;

        // Verify correct encryption
        let mut encrypt_buffer = [0u8; 24];
        encrypt_buffer.copy_from_slice(pt);
        cipher.init(ssrc, ext_seq_num)?;
        for r in ranges {
            cipher.xor_key(&mut encrypt_buffer[r.clone()], r.clone())?;
        }
        println!("enc_buf:   {:02x?}", encrypt_buffer);
        println!("ct:        {:02x?}", ct);
        assert_eq!(encrypt_buffer, ct);

        Ok(())
    }

    #[test]
    fn test_rtp_example() -> Result<(), Error> {
        let key: [u8; 16] = [
            0xc6, 0x1e, 0x7a, 0x93, 0x74, 0x4f, 0x39, 0xee, 0x10, 0x73, 0x4a, 0xfe, 0x3f, 0xf7,
            0xa0, 0x87,
        ];
        let salt: [u8; 14] = [
            0x30, 0xcb, 0xbc, 0x08, 0x86, 0x3d, 0x8c, 0x85, 0xd4, 0x9d, 0xb3, 0x4a, 0x9a, 0xe1,
        ];
        let ssrc: u32 = 0xcafebabe;
        let ext_seq_num: ExtendedSequenceNumber = 0x0000001234;
        let expected_nonce: [u8; 16] = [
            // 30cbbc08863d8c85d49db34a9ae1 ^ 00000000cafebabe000000001234 || 0000
            0x30, 0xcb, 0xbc, 0x08, 0x4c, 0xc3, 0x36, 0x3b, 0xd4, 0x9d, 0xb3, 0x4a, 0x88, 0xd5,
            0x00, 0x00,
        ];
        let aad = [];
        let pt: [u8; 16] = [0xab; 16];
        let ct: [u8; 16] = [
            0x4e, 0x55, 0xdc, 0x4c, 0xe7, 0x99, 0x78, 0xd8, 0x8c, 0xa4, 0xd2, 0x15, 0x94, 0x9d,
            0x24, 0x02,
        ];

        let cipher_type: Box<dyn CipherType> = Box::new(NativeAesIcm::new(AesKeySize::Aes128));
        let mut cipher = cipher_type.create(&key, &salt)?;

        // Verify correct nonce formation
        let mut nonce: [u8; 16] = Default::default();
        cipher.rtp_nonce(ssrc, ext_seq_num, &mut nonce)?;
        assert_eq!(nonce, expected_nonce);

        // Verify correct encryption
        let mut enc_buffer = [0u8; 16];
        enc_buffer[..pt.len()].copy_from_slice(&pt);
        cipher.set_aad(&aad)?;
        let ct_size = cipher.encrypt(&nonce, &mut enc_buffer, pt.len())?;
        assert_eq!(ct_size, ct.len());
        assert_eq!(enc_buffer, ct);

        // Verify correct decryption
        cipher.set_aad(&aad)?;
        let pt_size = cipher.decrypt(&nonce, &mut enc_buffer, ct.len())?;
        assert_eq!(pt_size, pt.len());
        assert_eq!(&enc_buffer[..pt_size], &pt);

        Ok(())
    }

    #[test]
    fn test_rtcp_example() {
        // TODO
    }
}
