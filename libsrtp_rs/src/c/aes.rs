use crate::aes::EncryptionKey;
use crate::srtp::Error;
use std::os::raw::c_int;

#[no_mangle]
pub extern "C" fn srtp_aes_encrypt(pt: *mut u8, key: *const EncryptionKey) {
    let pt_slice = unsafe { std::slice::from_raw_parts_mut(pt, 16) };
    let key_ref = unsafe { key.as_ref().unwrap() };
    key_ref.encrypt(pt_slice);
}

#[no_mangle]
pub extern "C" fn srtp_aes_expand_encryption_key(
    key: *const u8,
    key_len: c_int,
    expanded: *mut EncryptionKey,
) -> Error {
    unsafe {
        let key_slice = std::slice::from_raw_parts(key, key_len as usize);
        expanded.write(match EncryptionKey::new(key_slice) {
            Ok(x) => x,
            Err(err) => return err,
        })
    };
    Error::Ok
}
