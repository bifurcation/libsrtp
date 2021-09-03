use crate::srtp::Error;
use aes::{Aes128, Aes192, Aes256, Block, BlockEncrypt, NewBlockCipher};
use std::os::raw::c_int;

// XXX(RLB) These methods in C expect `ctx` to have type srtp_aes_expanded_key_t, whereas here we
// use Box<Aes>.  The important thing here is that whatever type we use for `ctx` has smaller size
// than srtp_aes_expanded_key_t, so that it fits in the memory allocated by the caller.

pub enum Aes {
    Aes128(Aes128),
    Aes192(Aes192),
    Aes256(Aes256),
}

impl Aes {
    fn new(key: &[u8]) -> Result<Aes, Error> {
        Ok(match key.len() {
            16 => Aes::Aes128(Aes128::new_from_slice(key).unwrap()),
            24 => Aes::Aes192(Aes192::new_from_slice(key).unwrap()),
            32 => Aes::Aes256(Aes256::new_from_slice(key).unwrap()),
            _ => return Err(Error::BadParam),
        })
    }

    fn encrypt(&self, block: &mut [u8]) {
        let block = Block::from_mut_slice(block);
        match self {
            Aes::Aes128(cipher) => cipher.encrypt_block(block),
            Aes::Aes192(cipher) => cipher.encrypt_block(block),
            Aes::Aes256(cipher) => cipher.encrypt_block(block),
        };
    }
}

#[no_mangle]
pub extern "C" fn srtp_aes_encrypt(pt: *mut u8, key: *const Box<Aes>) {
    let cipher = unsafe { key.read() };
    let pt_slice = unsafe { std::slice::from_raw_parts_mut(pt, 16) };
    cipher.encrypt(pt_slice);
}

#[no_mangle]
pub extern "C" fn srtp_aes_expand_encryption_key(
    key_ptr: *const u8,
    key_len: c_int,
    expanded: *mut Box<Aes>,
) -> Error {
    let key = unsafe { std::slice::from_raw_parts(key_ptr, key_len as usize) };
    let cipher = match Aes::new(key) {
        Ok(x) => x,
        Err(err) => return err,
    };
    unsafe { expanded.write(Box::new(cipher)) };
    Error::Ok
}
