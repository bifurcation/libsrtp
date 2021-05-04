use crate::aes;
use crate::crypto_kernel::constants;
use crate::crypto_kernel::{Cipher, CipherDirection, CipherType, CipherTypeID};
use crate::srtp::Error;

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

impl Context {
    fn new(key_size: aes::KeySize) -> Self {
        Context {
            counter: 0,
            salt_block: [0; 16],
            counter_block: [0; 16],
            buffer: [0; 16],
            expanded_key: None,
            bytes_in_buffer: 0,
            key_size: match key_size {
                aes::KeySize::Aes128 => constants::AES_ICM_128_KEY_LEN_WSALT,
                aes::KeySize::Aes256 => constants::AES_ICM_256_KEY_LEN_WSALT,
            },
        }
    }

    fn reset(&mut self) {
        self.counter = 0;
        self.buffer.fill(0);
        self.bytes_in_buffer = 0;
        self.counter_block.fill(0);
    }

    fn advance(&mut self) {
        let enc = self.expanded_key.as_ref().unwrap();

        self.counter_block[14..].copy_from_slice(&self.counter.to_be_bytes());
        self.buffer.copy_from_slice(&self.counter_block);
        enc.encrypt(&mut self.buffer);
        self.bytes_in_buffer = self.buffer.len();
        self.counter += 1;
    }
}

impl Cipher for Context {
    fn key_size(&self) -> usize {
        self.key_size
    }

    fn iv_size(&self) -> usize {
        self.counter_block.len()
    }

    fn init(&mut self, key: &[u8]) -> Result<(), Error> {
        if key.len() != self.key_size {
            return Err(Error::BadParam);
        }

        self.reset();

        let base_key_len = self.key_size - constants::SALT_LEN;
        let copy_len = constants::SALT_LEN;
        let base_key = &key[..base_key_len];
        let salt = &key[base_key_len..];

        self.salt_block.fill(0);
        self.salt_block[..copy_len].copy_from_slice(salt);

        self.counter_block[..copy_len].copy_from_slice(salt);

        self.expanded_key = Some(aes::EncryptionKey::new(base_key)?);
        Ok(())
    }

    fn set_aad(&mut self, _aad: &[u8]) -> Result<(), Error> {
        Err(Error::NoSuchOp)
    }

    fn set_iv(&mut self, iv: &[u8], _direction: CipherDirection) -> Result<(), Error> {
        if iv.len() != self.counter_block.len() {
            return Err(Error::BadParam);
        }

        self.reset();
        self.counter_block.copy_from_slice(&iv);
        xor_eq(&mut self.counter_block, &self.salt_block);
        Ok(())
    }

    fn encrypt(&mut self, buf: &mut [u8], pt_size: usize) -> Result<usize, Error> {
        if pt_size > buf.len() {
            return Err(Error::BadParam);
        }

        if self.expanded_key.is_none() {
            return Err(Error::CipherFail);
        }

        if pt_size > 0xffff - (self.counter as usize) {
            return Err(Error::Terminus);
        }

        // Special case for small buffers
        if pt_size <= self.bytes_in_buffer {
            let key_start = 16 - self.bytes_in_buffer;
            let key_end = key_start + pt_size;
            xor_eq(buf, &self.buffer[key_start..key_end]);
            self.bytes_in_buffer -= pt_size;
            return Ok(pt_size);
        }

        let key_start = 16 - self.bytes_in_buffer;
        xor_eq(&mut buf[..self.bytes_in_buffer], &self.buffer[key_start..]);

        let mut buf_start = self.bytes_in_buffer;
        let mut buf_end = buf_start + 16;
        while buf_start + 16 <= pt_size {
            self.advance();
            xor_eq(&mut buf[buf_start..buf_end], &self.buffer);

            buf_start = buf_end;
            buf_end = buf_start + 16;
        }

        if buf_start < pt_size {
            self.advance();
            let tail_size = pt_size - buf_start;
            xor_eq(&mut buf[buf_start..], &self.buffer[..tail_size]);
            self.bytes_in_buffer = self.buffer.len() - tail_size;
        } else {
            self.bytes_in_buffer = 0;
        }

        Ok(pt_size)
    }

    fn decrypt(&mut self, buf: &mut [u8], ct_size: usize) -> Result<usize, Error> {
        self.encrypt(buf, ct_size)
    }

    fn get_tag(&mut self, _tag: &mut [u8]) -> Result<usize, Error> {
        Err(Error::NoSuchOp)
    }
}

pub struct NativeAesIcm {
    key_size: aes::KeySize,
}

impl NativeAesIcm {
    pub fn new(key_size: aes::KeySize) -> Self {
        NativeAesIcm { key_size: key_size }
    }
}

impl CipherType for NativeAesIcm {
    fn id(&self) -> CipherTypeID {
        match self.key_size {
            aes::KeySize::Aes128 => CipherTypeID::AesIcm128,
            aes::KeySize::Aes256 => CipherTypeID::AesIcm256,
        }
    }

    fn create(&self, key_len: usize, _tag_len: usize) -> Result<Box<dyn Cipher>, Error> {
        let correct_key_len = match self.key_size {
            aes::KeySize::Aes128 => constants::AES_ICM_128_KEY_LEN_WSALT,
            aes::KeySize::Aes256 => constants::AES_ICM_256_KEY_LEN_WSALT,
        };
        if key_len != correct_key_len {
            return Err(Error::BadParam);
        }

        // XXX(RLB): It seems like we should fail on this case, but the SRTP layer seems to think
        // we should allow non-zero tag sizes
        /*
        if tag_len != 0 {
            return Err(Error::BadParam);
        }
        */

        Ok(Box::new(Context::new(self.key_size)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_test;

    #[test]
    fn test_aes_icm_128() -> Result<(), Error> {
        let cipher_type = NativeAesIcm::new(aes::KeySize::Aes128);
        assert_eq!(cipher_type.id(), CipherTypeID::AesIcm128);

        let tests_passed = crypto_test::cipher(&cipher_type)?;
        assert!(tests_passed > 0);

        Ok(())
    }

    #[test]
    fn test_aes_icm_256() -> Result<(), Error> {
        let cipher_type = NativeAesIcm::new(aes::KeySize::Aes256);
        assert_eq!(cipher_type.id(), CipherTypeID::AesIcm256);

        let tests_passed = crypto_test::cipher(&cipher_type)?;
        assert!(tests_passed > 0);

        Ok(())
    }
}
