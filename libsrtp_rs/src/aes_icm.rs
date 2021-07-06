// XXX(RLB) RustCrypto offers AES-CTR implementations, but not for 16-bit counters.  If that
// changes in the future, we should remove the CTR internals here.

use crate::crypto_kernel::constants::AesKeySize;
use crate::crypto_kernel::{Cipher, CipherType, CipherTypeID};
use crate::replay::ExtendedSequenceNumber;
use crate::srtp::Error;
use aes::cipher::{
    generic_array::{typenum::U16, GenericArray},
    BlockCipher, BlockEncrypt, NewBlockCipher,
};
use aes::{Aes128, Aes192, Aes256};
use ctr::cipher::{NewCipher, StreamCipher};
use ctr::Ctr128BE;
use std::marker::PhantomData;

fn xor_eq(a: &mut [u8], b: &[u8]) {
    for (b1, b2) in a.iter_mut().zip(b.iter()) {
        *b1 ^= *b2;
    }
}

#[derive(Clone)]
struct Context<C>
where
    C: Clone + BlockEncrypt + BlockCipher<BlockSize = U16> + NewBlockCipher + 'static,
{
    key_size: AesKeySize,
    key: [u8; 32],
    salt: [u8; 14],
    phantom: PhantomData<C>,
}

impl<C> Context<C>
where
    C: Clone + BlockEncrypt + BlockCipher<BlockSize = U16> + NewBlockCipher + 'static,
{
    fn new(key_size: AesKeySize, key: &[u8], salt: &[u8]) -> Result<Self, Error> {
        let id = key_size.as_icm_id();
        if key.len() != id.key_size() || salt.len() != id.salt_size() {
            return Err(Error::BadParam);
        }

        let mut ctx = Context {
            key_size: key_size,
            key: Default::default(),
            salt: Default::default(),
            phantom: PhantomData,
        };

        ctx.key_mut().copy_from_slice(key);
        ctx.salt.copy_from_slice(salt);
        Ok(ctx)
    }

    fn key(&self) -> &[u8] {
        let key_size = self.id().key_size();
        &self.key[..key_size]
    }

    fn key_mut(&mut self) -> &mut [u8] {
        let key_size = self.id().key_size();
        &mut self.key[..key_size]
    }
}

impl<C> Cipher for Context<C>
where
    C: Clone + BlockEncrypt + BlockCipher<BlockSize = U16> + NewBlockCipher + 'static,
{
    fn id(&self) -> CipherTypeID {
        self.key_size.as_icm_id()
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
    fn rtp_nonce(
        &self,
        ssrc: u32,
        ext_seq_num: ExtendedSequenceNumber,
        nonce: &mut [u8],
    ) -> Result<usize, Error> {
        if nonce.len() != self.id().nonce_size() {
            return Err(Error::BadParam);
        }

        nonce.fill(0);
        nonce[4..8].copy_from_slice(&ssrc.to_be_bytes());
        nonce[8..14].copy_from_slice(&ext_seq_num.to_be_bytes()[2..]);
        xor_eq(&mut nonce[..14], &self.salt);
        Ok(nonce.len())
    }

    // In the case of SRTCP, the SSRC of the first header of the compound
    // packet MUST be used, i SHALL be the 31-bit SRTCP index...
    fn rtcp_nonce(&self, ssrc: u32, index: u32, nonce: &mut [u8]) -> Result<usize, Error> {
        self.rtp_nonce(ssrc, index.into(), nonce)
    }

    fn encrypt(
        &self,
        nonce: &[u8],
        _aad: &[u8],
        buf: &mut [u8],
        pt_size: usize,
    ) -> Result<usize, Error> {
        let key = GenericArray::from_slice(self.key());
        Ctr128BE::<C>::new(&key, nonce.into())
            .try_apply_keystream(&mut buf[..pt_size])
            .map(|_| pt_size)
            .map_err(|_| Error::CipherFail)
    }

    fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut [u8],
        ct_size: usize,
    ) -> Result<usize, Error> {
        self.encrypt(nonce, aad, buf, ct_size)
    }

    fn clone_inner(&self) -> Box<dyn Cipher> {
        let clone = (*self).clone();
        Box::new(clone)
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
        let cipher_type = NativeAesIcm::new(AesKeySize::Aes128);
        assert_eq!(cipher_type.id(), CipherTypeID::AesIcm128);

        let tests_passed = crypto_test::cipher(&cipher_type)?;
        assert!(tests_passed > 0);

        Ok(())
    }

    #[test]
    fn test_aes_icm_192() -> Result<(), Error> {
        let cipher_type = NativeAesIcm::new(AesKeySize::Aes192);
        assert_eq!(cipher_type.id(), CipherTypeID::AesIcm192);

        let tests_passed = crypto_test::cipher(&cipher_type)?;
        assert!(tests_passed > 0);

        Ok(())
    }

    #[test]
    fn test_aes_icm_256() -> Result<(), Error> {
        let cipher_type = NativeAesIcm::new(AesKeySize::Aes256);
        assert_eq!(cipher_type.id(), CipherTypeID::AesIcm256);

        let tests_passed = crypto_test::cipher(&cipher_type)?;
        assert!(tests_passed > 0);

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

        let cipher_type = NativeAesIcm::new(AesKeySize::Aes128);
        let cipher = cipher_type.create(&key, &salt)?;

        // Verify correct nonce formation
        let mut nonce: [u8; 16] = Default::default();
        cipher.rtp_nonce(ssrc, ext_seq_num, &mut nonce)?;
        assert_eq!(nonce, expected_nonce);

        // Verify correct encryption
        let mut enc_buffer = [0u8; 16];
        enc_buffer[..pt.len()].copy_from_slice(&pt);
        let ct_size = cipher.encrypt(&nonce, &aad, &mut enc_buffer, pt.len())?;
        assert_eq!(ct_size, ct.len());
        assert_eq!(enc_buffer, ct);

        // Verify correct decryption
        let pt_size = cipher.decrypt(&nonce, &aad, &mut enc_buffer, ct.len())?;
        assert_eq!(pt_size, pt.len());
        assert_eq!(&enc_buffer[..pt_size], &pt);

        Ok(())
    }

    #[test]
    fn test_rtcp_example() {
        // TODO
    }
}
