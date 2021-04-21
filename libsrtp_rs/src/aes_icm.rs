use crate::aes;
use crate::crypto_kernel::{Cipher, CipherType, CipherTypeID};
use crate::srtp::Error;

// integer counter mode works as follows:
//
// 16 bits
// <----->
// +------+------+------+------+------+------+------+------+
// |           nonce           |    packet index    |  ctr |---+
// +------+------+------+------+------+------+------+------+   |
//                                                             |
// +------+------+------+------+------+------+------+------+   v
// |                      salt                      |000000|->(+)
// +------+------+------+------+------+------+------+------+   |
//                                                             |
//                                                        +---------+
//							  | encrypt |
//							  +---------+
//							       |
// +------+------+------+------+------+------+------+------+   |
// |                    keystream block                    |<--+
// +------+------+------+------+------+------+------+------+
//
// All fields are big-endian
//
// ctr is the block counter, which increments from zero for
// each packet (16 bits wide)
//
// packet index is distinct for each packet (48 bits wide)
//
// nonce can be distinct across many uses of the same key, or
// can be a fixed value per key, or can be per-packet randomness
// (64 bits)

#[derive(Debug, Clone, Copy)]
pub enum KeySize {
    Aes128 = 16,
    Aes256 = 32,
}

fn xor_eq(a: &mut [u8], b: &[u8]) {
    for (b1, b2) in a.iter_mut().zip(b.iter()) {
        *b1 ^= *b2;
    }
}

struct Context {
    counter: u16,
    salt_block: [u8; 16],
    counter_block: [u8; 16],
    buffer: [u8; 16],
    expanded_key: Option<aes::EncryptionKey>,
    bytes_in_buffer: usize,
    key_size: usize,
}

impl Cipher for Context {}

impl Context {
    fn new(key_size: KeySize) -> Self {
        Context {
            counter: 0,
            salt_block: [0; 16],
            counter_block: [0; 16],
            buffer: [0; 16],
            expanded_key: None,
            bytes_in_buffer: 0,
            key_size: match key_size {
                KeySize::Aes128 => constants::AES_ICM_128_KEY_LEN_WSALT,
                KeySize::Aes256 => constants::AES_ICM_256_KEY_LEN_WSALT,
            },
        }
    }

    fn advance(&mut self) {
        let enc = self.expanded_key.as_ref().unwrap();

        self.counter_block[14..].copy_from_slice(&self.counter.to_be_bytes());
        self.buffer = self.counter_block;
        enc.encrypt(&mut self.buffer);
        self.bytes_in_buffer = self.buffer.len();
        self.counter += 1;
    }

    fn init(&mut self, key: &[u8]) -> Result<(), Error> {
        if key.len() != self.key_size {
            return Err(Error::BadParam);
        }

        self.counter = 0;

        let base_key_len = self.key_size - constants::SALT_LEN;
        let copy_len = constants::SALT_LEN;
        let salt = &key[base_key_len..];

        self.salt_block.fill(0);
        self.salt_block[..copy_len].copy_from_slice(salt);

        self.counter_block.fill(0);
        self.counter_block[..copy_len].copy_from_slice(salt);

        self.buffer.fill(0);
        self.bytes_in_buffer = 0;

        self.expanded_key = Some(aes::EncryptionKey::new(key)?);
        Ok(())
    }

    fn set_aad(&mut self, _aad: &[u8]) -> Result<(), Error> {
        Err(Error::NoSuchOp)
    }

    fn set_iv(&mut self, iv: &[u8]) -> Result<(), Error> {
        if iv.len() != self.counter_block.len() {
            return Err(Error::BadParam);
        }

        self.counter_block.copy_from_slice(&iv);
        xor_eq(&mut self.counter_block, &self.salt_block);
        Ok(())
    }

    fn encrypt(&mut self, buf: &mut [u8], pt_size: &mut usize) -> Result<(), Error> {
        if self.expanded_key.is_none() {
            return Err(Error::CipherFail);
        }

        let bytes_to_encrypt: usize = *pt_size;
        if bytes_to_encrypt > 0xffff - (self.counter as usize) {
            return Err(Error::Terminus);
        }

        // Special case for small buffers
        if bytes_to_encrypt <= self.bytes_in_buffer {
            let key_start = 16 - self.bytes_in_buffer;
            let key_end = key_start + bytes_to_encrypt;
            xor_eq(&mut buf, &self.buffer[key_start..key_end]);
            self.bytes_in_buffer -= bytes_to_encrypt;
            return Ok(());
        }

        let key_start = 16 - self.bytes_in_buffer;
        xor_eq(&mut buf[..self.bytes_in_buffer], &self.buffer[key_start..]);

        let mut buf_start = self.bytes_in_buffer;
        let mut buf_end = buf_start + 16;
        while buf_start + 16 <= bytes_to_encrypt {
            self.advance();
            xor_eq(&mut buf[buf_start..buf_end], &self.buffer);

            buf_start = buf_end;
            buf_end = buf_start + 16;
        }

        if buf_start < bytes_to_encrypt {
            let tail_size = bytes_to_encrypt - buf_start;
            xor_eq(&mut buf[buf_start..], &self.buffer[..tail_size]);
            self.bytes_in_buffer -= tail_size;
        }

        Ok(())
    }

    fn get_tag(&mut self, _tag: &mut [u8]) -> Result<(), Error> {
        Err(Error::NoSuchOp)
    }
}

pub struct NativeAesIcm {
    key_size: KeySize,
}

impl NativeAesIcm {
    fn new(key_size: KeySize) -> Self {
        NativeAesIcm { key_size: key_size }
    }
}

impl CipherType for NativeAesIcm {
    fn id(&self) -> CipherTypeID {
        match self.key_size {
            KeySize::Aes128 => CipherTypeID::AesIcm128,
            KeySize::Aes256 => CipherTypeID::AesGcm256,
        }
    }

    fn create(&self, key_len: usize, tag_len: usize) -> Result<Box<dyn Cipher>, Error> {
        let correct_key_len = match self.key_size {
            KeySize::Aes128 => constants::AES_ICM_128_KEY_LEN_WSALT,
            KeySize::Aes256 => constants::AES_ICM_256_KEY_LEN_WSALT,
        };
        if key_len != correct_key_len || tag_len != 0 {
            return Err(Error::BadParam);
        }

        Ok(Box::new(Context::new(self.key_size)))
    }
}

mod constants {
    pub const SALT_LEN: usize = 14;
    pub const AEAD_SALT_LEN: usize = 12;

    pub const AES_128_KEY_LEN: usize = 16;
    pub const AES_256_KEY_LEN: usize = 32;

    pub const AES_ICM_128_KEY_LEN_WSALT: usize = SALT_LEN + AES_128_KEY_LEN;
    pub const AES_ICM_256_KEY_LEN_WSALT: usize = SALT_LEN + AES_256_KEY_LEN;
}
