#![cfg(feature = "rust-crypto")]
use super::{constants, make_rtp_nonce};
use crate::crypto::constants::AesKeySize;
use crate::crypto::{
    Cipher, CipherType, CipherTypeID, ExtensionCipher, ExtensionCipherType, ExtensionCipherTypeID,
    Reset,
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
    salt: [u8; constants::SALT_SIZE],
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
}

impl<C> ExtensionCipher for Context<C>
where
    C: Clone + BlockEncrypt + BlockCipher<BlockSize = U16> + NewBlockCipher + 'static,
{
    fn xtn_id(&self) -> ExtensionCipherTypeID {
        self.key_size.as_stream_icm_id()
    }

    fn init(&mut self, ssrc: u32, ext_seq_num: ExtendedSequenceNumber) -> Result<(), Error> {
        let mut nonce = [0u8; constants::NONCE_SIZE];
        make_rtp_nonce(&self.salt, ssrc, ext_seq_num, &mut nonce)?;

        let key = GenericArray::from_slice(self.key());
        let nonce = GenericArray::from_slice(&nonce);
        self.cipher = Some(Ctr128BE::new(&key, nonce.into()));
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

    fn rtp_nonce(
        &self,
        ssrc: u32,
        ext_seq_num: ExtendedSequenceNumber,
        nonce: &mut [u8],
    ) -> Result<usize, Error> {
        make_rtp_nonce(&self.salt, ssrc, ext_seq_num, nonce)
    }

    // In the case of SRTCP, the SSRC of the first header of the compound
    // packet MUST be used, i SHALL be the 31-bit SRTCP index...
    fn rtcp_nonce(&self, ssrc: u32, index: u32, nonce: &mut [u8]) -> Result<usize, Error> {
        self.rtp_nonce(ssrc, index.into(), nonce)
    }

    fn encrypt(
        &self,
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

    fn decrypt(&self, nonce: &[u8], aad: &[&[u8]], buf: &mut [u8]) -> Result<usize, Error> {
        self.encrypt(nonce, aad, buf, buf.len())
    }
}

pub struct AesIcm {
    key_size: AesKeySize,
}

impl AesIcm {
    pub fn new(key_size: AesKeySize) -> Result<Self, Error> {
        Ok(AesIcm { key_size: key_size })
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
