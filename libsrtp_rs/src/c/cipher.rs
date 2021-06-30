// Because this is a C interface file, matching C names is more ergonomic than being rustic
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

use crate::aes_icm::NativeAesIcm;
use crate::c::err::srtp_debug_module_t;
use crate::c::{just_error, zero_and_drop};
use crate::crypto_kernel::constants::AesKeySize;
use crate::crypto_kernel::{Cipher, CipherDirection, CipherType, CipherTypeID};
use crate::null_cipher::NullCipher;
use crate::srtp::Error;
use cpu_time::ThreadTime;
use cstr::cstr;
use rand::RngCore;
use std::convert::TryFrom;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_uint};

//
// Types
//
pub type srtp_cipher_type_id_t = u32;

pub type srtp_cipher_direction_t = c_uint;
pub type srtp_cipher_pointer_t = *mut srtp_cipher_t;

pub type srtp_cipher_alloc_func_t =
    Option<extern "C" fn(cp: *mut srtp_cipher_pointer_t, key_len: c_int, tag_len: c_int) -> Error>;

pub type srtp_cipher_dealloc_func_t = Option<extern "C" fn(cp: srtp_cipher_pointer_t) -> Error>;

pub type srtp_cipher_init_func_t =
    Option<extern "C" fn(state: *mut Box<dyn Cipher>, key: *const u8) -> Error>;

pub type srtp_cipher_set_aad_func_t =
    Option<extern "C" fn(state: *mut Box<dyn Cipher>, aad: *const u8, aad_len: u32) -> Error>;

pub type srtp_cipher_encrypt_func_t = Option<
    extern "C" fn(
        state: *mut Box<dyn Cipher>,
        buffer: *mut u8,
        octets_to_encrypt: *mut c_uint,
    ) -> Error,
>;

pub type srtp_cipher_decrypt_func_t = Option<
    extern "C" fn(
        state: *mut Box<dyn Cipher>,
        buffer: *mut u8,
        octets_to_decrypt: *mut c_uint,
    ) -> Error,
>;

pub type srtp_cipher_set_iv_func_t = Option<
    extern "C" fn(
        state: *mut Box<dyn Cipher>,
        iv: *mut u8,
        direction: srtp_cipher_direction_t,
    ) -> Error,
>;

pub type srtp_cipher_get_tag_func_t =
    Option<unsafe extern "C" fn(state: *mut Box<dyn Cipher>, tag: *mut u8, len: *mut u32) -> Error>;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct srtp_cipher_test_case_t {
    pub key_length_octets: c_int,
    pub key: *const u8,
    pub idx: *mut u8,
    pub plaintext_length_octets: c_uint,
    pub plaintext: *const u8,
    pub ciphertext_length_octets: c_uint,
    pub ciphertext: *const u8,
    pub aad_length_octets: c_int,
    pub aad: *const u8,
    pub tag_length_octets: c_int,
    pub next_test_case: *const srtp_cipher_test_case_t,
}

unsafe impl Sync for srtp_cipher_test_case_t {}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct srtp_cipher_type_t {
    pub alloc: srtp_cipher_alloc_func_t,
    pub dealloc: srtp_cipher_dealloc_func_t,
    pub init: srtp_cipher_init_func_t,
    pub set_aad: srtp_cipher_set_aad_func_t,
    pub encrypt: srtp_cipher_encrypt_func_t,
    pub decrypt: srtp_cipher_decrypt_func_t,
    pub set_iv: srtp_cipher_set_iv_func_t,
    pub get_tag: srtp_cipher_get_tag_func_t,
    pub description: *const c_char,
    pub test_data: *const srtp_cipher_test_case_t,
    pub id: srtp_cipher_type_id_t,
}

unsafe impl Sync for srtp_cipher_type_t {}

#[repr(C)]
#[derive(Debug)]
pub struct srtp_cipher_t {
    pub type_: *const srtp_cipher_type_t,
    pub state: *mut Box<dyn Cipher>,
    pub key_len: c_int,
    pub algorithm: c_int,
}

impl Drop for srtp_cipher_t {
    fn drop(&mut self) {
        // Take ownership of the Box<dyn Cipher> so that it gets dropped
        let _ = unsafe { self.state.read() };
        self.state = std::ptr::null_mut();
    }
}

//
// Debug module
//

static srtp_mod_cipher_name: &CStr = cstr!("cipher");

#[no_mangle]
pub static srtp_mod_cipher: srtp_debug_module_t = srtp_debug_module_t {
    on: 0,
    name: srtp_mod_cipher_name.as_ptr(),
};

//
// Utility functions
//

fn cipher_alloc(
    cipher_type: &dyn CipherType,
    srtp_cipher_type: *const srtp_cipher_type_t,
    cp: *mut srtp_cipher_pointer_t,
    key_len: c_int,
    tag_len: c_int,
) -> Error {
    let cipher = match cipher_type.create(key_len as usize, tag_len as usize) {
        Ok(x) => Box::new(x),
        Err(err) => return err,
    };

    let srtp_cipher = Box::new(srtp_cipher_t {
        type_: srtp_cipher_type,
        state: Box::into_raw(cipher),
        key_len: key_len,
        algorithm: CipherTypeID::Null as c_int,
    });
    unsafe { cp.write(Box::into_raw(srtp_cipher)) };
    Error::Ok
}

extern "C" fn cipher_init(state: *mut Box<dyn Cipher>, key: *const u8) -> Error {
    let cipher = unsafe { state.as_mut().unwrap() };
    let key_slice = unsafe { std::slice::from_raw_parts(key, cipher.key_size()) };
    just_error(cipher.init(key_slice))
}

extern "C" fn cipher_set_aad(state: *mut Box<dyn Cipher>, aad: *const u8, aad_len: u32) -> Error {
    let cipher = unsafe { state.as_mut().unwrap() };
    let aad_slice = unsafe { std::slice::from_raw_parts(aad, aad_len as usize) };
    just_error(cipher.set_aad(aad_slice))
}

extern "C" fn cipher_encrypt(
    state: *mut Box<dyn Cipher>,
    buffer: *mut u8,
    octets_to_encrypt: *mut c_uint,
) -> Error {
    let cipher = unsafe { state.as_mut().unwrap() };
    let buf_size = unsafe { octets_to_encrypt.read() as usize };
    let buf_slice = unsafe { std::slice::from_raw_parts_mut(buffer, buf_size) };

    match cipher.encrypt(buf_slice, buf_size) {
        Ok(len) => {
            unsafe { octets_to_encrypt.write(len as c_uint) };
            Error::Ok
        }
        Err(err) => err,
    }
}

extern "C" fn cipher_decrypt(
    state: *mut Box<dyn Cipher>,
    buffer: *mut u8,
    octets_to_decrypt: *mut c_uint,
) -> Error {
    let cipher = unsafe { state.as_mut().unwrap() };
    let buf_size = unsafe { octets_to_decrypt.read() as usize };
    let buf_slice = unsafe { std::slice::from_raw_parts_mut(buffer, buf_size) };

    match cipher.decrypt(buf_slice, buf_size) {
        Ok(len) => {
            unsafe { octets_to_decrypt.write(len as c_uint) };
            Error::Ok
        }
        Err(err) => err,
    }
}

extern "C" fn cipher_set_iv(
    state: *mut Box<dyn Cipher>,
    iv: *mut u8,
    direction: srtp_cipher_direction_t,
) -> Error {
    let cipher = unsafe { state.as_mut().unwrap() };
    let iv_slice = unsafe { std::slice::from_raw_parts(iv, cipher.iv_size()) };
    let dir = match CipherDirection::try_from(direction) {
        Ok(x) => x,
        Err(_err) => return Error::BadParam,
    };
    just_error(cipher.set_iv(iv_slice, dir))
}

extern "C" fn cipher_get_tag(state: *mut Box<dyn Cipher>, tag: *mut u8, len: *mut u32) -> Error {
    Error::Ok
}

//
// Null Cipher implementation
//

extern "C" fn null_alloc(cp: *mut srtp_cipher_pointer_t, key_len: c_int, tag_len: c_int) -> Error {
    let cipher_type = NullCipher {};
    cipher_alloc(&cipher_type, &srtp_null_cipher, cp, key_len, tag_len)
}

static srtp_null_cipher_test_case: srtp_cipher_test_case_t = srtp_cipher_test_case_t {
    key_length_octets: 0,
    key: std::ptr::null(),
    idx: std::ptr::null_mut(),
    plaintext_length_octets: 0,
    plaintext: std::ptr::null(),
    ciphertext_length_octets: 0,
    ciphertext: std::ptr::null(),
    aad_length_octets: 0,
    aad: std::ptr::null(),
    tag_length_octets: 0,
    next_test_case: std::ptr::null(),
};

static srtp_null_cipher_description: &CStr = cstr!("null cipher");

#[no_mangle]
pub static srtp_null_cipher: srtp_cipher_type_t = srtp_cipher_type_t {
    alloc: Some(null_alloc),
    dealloc: Some(zero_and_drop::<srtp_cipher_t>),
    init: Some(cipher_init),
    set_aad: Some(cipher_set_aad),
    encrypt: Some(cipher_encrypt),
    decrypt: Some(cipher_decrypt),
    set_iv: Some(cipher_set_iv),
    get_tag: Some(cipher_get_tag),
    description: srtp_null_cipher_description.as_ptr(),
    test_data: &srtp_null_cipher_test_case,
    id: CipherTypeID::Null as srtp_cipher_type_id_t,
};

//
// AES-ICM-128 implementation
//

extern "C" fn aes_icm_128_alloc(
    cp: *mut srtp_cipher_pointer_t,
    key_len: c_int,
    tag_len: c_int,
) -> Error {
    let cipher_type = NativeAesIcm::new(AesKeySize::Aes128);
    cipher_alloc(&cipher_type, &srtp_aes_icm_128, cp, key_len, tag_len)
}

static srtp_aes_icm_128_key: [u8; 30] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
];

static srtp_aes_icm_128_iv: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

static srtp_aes_icm_128_pt: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

static srtp_aes_icm_128_ct: [u8; 32] = [
    0xe0, 0x3e, 0xad, 0x09, 0x35, 0xc9, 0x5e, 0x80, 0xe1, 0x66, 0xb1, 0x6d, 0xd9, 0x2b, 0x4e, 0xb4,
    0xd2, 0x35, 0x13, 0x16, 0x2b, 0x02, 0xd0, 0xf7, 0x2a, 0x43, 0xa2, 0xfe, 0x4a, 0x5f, 0x97, 0xab,
];

static srtp_aes_icm_128_test_case: srtp_cipher_test_case_t = srtp_cipher_test_case_t {
    key_length_octets: srtp_aes_icm_128_key.len() as c_int,
    key: srtp_aes_icm_128_key.as_ptr(),
    idx: srtp_aes_icm_128_iv.as_ptr() as *mut u8,
    plaintext_length_octets: srtp_aes_icm_128_pt.len() as c_uint,
    plaintext: srtp_aes_icm_128_pt.as_ptr(),
    ciphertext_length_octets: srtp_aes_icm_128_ct.len() as c_uint,
    ciphertext: srtp_aes_icm_128_ct.as_ptr(),
    aad_length_octets: 0,
    aad: std::ptr::null(),
    tag_length_octets: 0,
    next_test_case: std::ptr::null(),
};

static srtp_aes_icm_128_description: &CStr = cstr!("AES-128 integer counter mode");

#[no_mangle]
pub static srtp_aes_icm_128: srtp_cipher_type_t = srtp_cipher_type_t {
    alloc: Some(aes_icm_128_alloc),
    dealloc: Some(zero_and_drop::<srtp_cipher_t>),
    init: Some(cipher_init),
    set_aad: Some(cipher_set_aad),
    encrypt: Some(cipher_encrypt),
    decrypt: Some(cipher_decrypt),
    set_iv: Some(cipher_set_iv),
    get_tag: Some(cipher_get_tag),
    description: srtp_aes_icm_128_description.as_ptr(),
    test_data: &srtp_aes_icm_128_test_case,
    id: CipherTypeID::AesIcm128 as srtp_cipher_type_id_t,
};

static srtp_mod_aes_icm_name: &CStr = cstr!("aes icm");

#[no_mangle]
pub static srtp_mod_aes_icm: srtp_debug_module_t = srtp_debug_module_t {
    on: 0,
    name: srtp_mod_aes_icm_name.as_ptr(),
};

//
// AES-ICM-128 implementation
//

extern "C" fn aes_icm_256_alloc(
    cp: *mut srtp_cipher_pointer_t,
    key_len: c_int,
    tag_len: c_int,
) -> Error {
    let cipher_type = NativeAesIcm::new(AesKeySize::Aes256);
    cipher_alloc(&cipher_type, &srtp_aes_icm_256, cp, key_len, tag_len)
}

static srtp_aes_icm_256_key: [u8; 46] = [
    0x57, 0xf8, 0x2f, 0xe3, 0x61, 0x3f, 0xd1, 0x70, 0xa8, 0x5e, 0xc9, 0x3c, 0x40, 0xb1, 0xf0, 0x92,
    0x2e, 0xc4, 0xcb, 0x0d, 0xc0, 0x25, 0xb5, 0x82, 0x72, 0x14, 0x7c, 0xc4, 0x38, 0x94, 0x4a, 0x98,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
];

static srtp_aes_icm_256_iv: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

static srtp_aes_icm_256_pt: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

static srtp_aes_icm_256_ct: [u8; 32] = [
    0x92, 0xbd, 0xd2, 0x8a, 0x93, 0xc3, 0xf5, 0x25, 0x11, 0xc6, 0x77, 0xd0, 0x8b, 0x55, 0x15, 0xa4,
    0x9d, 0xa7, 0x1b, 0x23, 0x78, 0xa8, 0x54, 0xf6, 0x70, 0x50, 0x75, 0x6d, 0xed, 0x16, 0x5b, 0xac,
];

static srtp_aes_icm_256_test_case: srtp_cipher_test_case_t = srtp_cipher_test_case_t {
    key_length_octets: srtp_aes_icm_256_key.len() as c_int,
    key: srtp_aes_icm_256_key.as_ptr(),
    idx: srtp_aes_icm_256_iv.as_ptr() as *mut u8,
    plaintext_length_octets: srtp_aes_icm_256_pt.len() as c_uint,
    plaintext: srtp_aes_icm_256_pt.as_ptr(),
    ciphertext_length_octets: srtp_aes_icm_256_ct.len() as c_uint,
    ciphertext: srtp_aes_icm_256_ct.as_ptr(),
    aad_length_octets: 0,
    aad: std::ptr::null(),
    tag_length_octets: 0,
    next_test_case: std::ptr::null(),
};

static srtp_aes_icm_256_description: &CStr = cstr!("AES-256 integer counter mode");

#[no_mangle]
pub static srtp_aes_icm_256: srtp_cipher_type_t = srtp_cipher_type_t {
    alloc: Some(aes_icm_256_alloc),
    dealloc: Some(zero_and_drop::<srtp_cipher_t>),
    init: Some(cipher_init),
    set_aad: Some(cipher_set_aad),
    encrypt: Some(cipher_encrypt),
    decrypt: Some(cipher_decrypt),
    set_iv: Some(cipher_set_iv),
    get_tag: Some(cipher_get_tag),
    description: srtp_aes_icm_256_description.as_ptr(),
    test_data: &srtp_aes_icm_256_test_case,
    id: CipherTypeID::AesIcm256 as srtp_cipher_type_id_t,
};

//
// Cipher Methods
//
#[no_mangle]
pub extern "C" fn srtp_cipher_get_key_length(c: *const srtp_cipher_t) -> c_int {
    unsafe { c.as_ref().unwrap().key_len }
}

#[no_mangle]
pub extern "C" fn srtp_cipher_type_self_test(ct: *const srtp_cipher_type_t) -> Error {
    let ct_ref = unsafe { ct.as_ref().unwrap() };
    srtp_cipher_type_test(ct, ct_ref.test_data)
}

#[no_mangle]
pub extern "C" fn srtp_cipher_type_test(
    _ct: *const srtp_cipher_type_t,
    _test_data: *const srtp_cipher_test_case_t,
) -> Error {
    Error::Ok // TODO
}

#[no_mangle]
pub extern "C" fn srtp_cipher_bits_per_second(
    c: *mut srtp_cipher_t,
    octets_in_buffer: c_int,
    num_trials: c_int,
) -> u64 {
    let mut enc_vec = vec![0u8; octets_in_buffer as usize];
    let enc_buf = enc_vec.as_mut_slice();

    let mut nonce = [0u8; 16];
    let timer = ThreadTime::now();
    for i in 0..(num_trials as u32) {
        nonce[12..].copy_from_slice(&i.to_be_bytes());

        let direction: u32 = CipherDirection::Encrypt.into();
        let err = srtp_cipher_set_iv(c, nonce.as_mut_ptr(), direction as i32);
        if err != Error::Ok {
            return 0;
        }

        let mut enc_buf_len = enc_buf.len() as u32;
        let err = srtp_cipher_encrypt(c, enc_buf.as_mut_ptr(), &mut enc_buf_len);
        if err != Error::Ok {
            return 0;
        }
    }

    let elapsed = timer.elapsed().as_secs_f64();
    if elapsed == 0.0 {
        return 0;
    }

    let n_octets = (num_trials as f64) * (octets_in_buffer as f64) * 8.0;
    (n_octets / elapsed) as u64
}

#[no_mangle]
extern "C" fn srtp_cipher_type_alloc(
    ct: *const srtp_cipher_type_t,
    c: *mut *mut srtp_cipher_t,
    key_len: c_int,
    tlen: c_int,
) -> Error {
    let ct_ref = unsafe { ct.as_ref().unwrap() };
    ct_ref.alloc.unwrap()(c, key_len, tlen)
}

#[no_mangle]
pub extern "C" fn srtp_cipher_dealloc(c: *mut srtp_cipher_t) -> Error {
    zero_and_drop(c)
}

#[no_mangle]
pub extern "C" fn srtp_cipher_init(c: *mut srtp_cipher_t, key: *const u8) -> Error {
    let c_ref = unsafe { c.as_ref().unwrap() };
    cipher_init(c_ref.state, key)
}

#[no_mangle]
pub extern "C" fn srtp_cipher_set_iv(
    c: *mut srtp_cipher_t,
    iv: *mut u8,
    direction: c_int,
) -> Error {
    let c_ref = unsafe { c.as_ref().unwrap() };
    cipher_set_iv(c_ref.state, iv, direction as srtp_cipher_direction_t)
}

#[no_mangle]
pub extern "C" fn srtp_cipher_output(
    c: *mut srtp_cipher_t,
    buffer: *mut u8,
    num_octets_to_output: *mut u32,
) -> Error {
    let c_ref = unsafe { c.as_ref().unwrap() };
    unsafe { std::ptr::write_bytes(buffer, 0, num_octets_to_output.read() as usize) };
    cipher_encrypt(c_ref.state, buffer, num_octets_to_output)
}

#[no_mangle]
pub extern "C" fn srtp_cipher_encrypt(
    c: *mut srtp_cipher_t,
    buffer: *mut u8,
    num_octets_to_output: *mut u32,
) -> Error {
    let c_ref = unsafe { c.as_ref().unwrap() };
    cipher_encrypt(c_ref.state, buffer, num_octets_to_output)
}

#[no_mangle]
pub extern "C" fn srtp_cipher_decrypt(
    c: *mut srtp_cipher_t,
    buffer: *mut u8,
    num_octets_to_output: *mut u32,
) -> Error {
    let c_ref = unsafe { c.as_ref().unwrap() };
    cipher_decrypt(c_ref.state, buffer, num_octets_to_output)
}

#[no_mangle]
pub extern "C" fn srtp_cipher_get_tag(
    c: *mut srtp_cipher_t,
    buffer: *mut u8,
    tag_len: *mut u32,
) -> Error {
    let c_ref = unsafe { c.as_ref().unwrap() };
    cipher_get_tag(c_ref.state, buffer, tag_len)
}

#[no_mangle]
pub extern "C" fn srtp_cipher_set_aad(
    c: *mut srtp_cipher_t,
    aad: *const u8,
    aad_len: u32,
) -> Error {
    let c_ref = unsafe { c.as_ref().unwrap() };
    cipher_set_aad(c_ref.state, aad, aad_len)
}

#[no_mangle]
pub extern "C" fn srtp_cipher_rand_for_tests(dest: *mut u8, len: u32) {
    let mut dest_slice = unsafe { std::slice::from_raw_parts_mut(dest, len as usize) };
    rand::thread_rng().fill_bytes(&mut dest_slice);
}

#[no_mangle]
pub extern "C" fn srtp_cipher_rand_u32_for_tests() -> u32 {
    rand::random()
}

//
// Manufacture srtp_cipher_t from Cipher
//

extern "C" fn drop_type_then_drop_cipher(c: *mut srtp_cipher_t) -> Error {
    // Take over ownership of the type object so that gets freed
    let c_ref = unsafe { c.as_ref().unwrap() };
    let _ = unsafe { Box::from_raw(c_ref.type_ as *mut srtp_cipher_type_t) };
    zero_and_drop(c)
}

// Ciphers not implemented as static types
static srtp_aes_icm_192_description: &CStr = cstr!("aes icm 192");
static srtp_aes_gcm_128_description: &CStr = cstr!("aes gcm 128");
static srtp_aes_gcm_256_description: &CStr = cstr!("aes gcm 256");

pub fn make_cipher_t(id: CipherTypeID, c: Box<dyn Cipher>) -> srtp_cipher_t {
    let description = match id {
        CipherTypeID::Null => srtp_null_cipher_description.as_ptr(),
        CipherTypeID::AesIcm128 => srtp_aes_icm_128_description.as_ptr(),
        CipherTypeID::AesIcm192 => srtp_aes_icm_192_description.as_ptr(),
        CipherTypeID::AesIcm256 => srtp_aes_icm_256_description.as_ptr(),
        CipherTypeID::AesGcm128 => srtp_aes_gcm_128_description.as_ptr(),
        CipherTypeID::AesGcm256 => srtp_aes_gcm_256_description.as_ptr(),
    };

    let cipher_type = Box::new(srtp_cipher_type_t {
        alloc: None,
        dealloc: Some(drop_type_then_drop_cipher),
        init: Some(cipher_init),
        set_aad: Some(cipher_set_aad),
        encrypt: Some(cipher_encrypt),
        decrypt: Some(cipher_decrypt),
        set_iv: Some(cipher_set_iv),
        get_tag: Some(cipher_get_tag),
        description: description,
        test_data: std::ptr::null(),
        id: id as srtp_cipher_type_id_t,
    });

    let key_size = c.key_size() as c_int;
    srtp_cipher_t {
        type_: Box::into_raw(cipher_type),
        state: Box::into_raw(Box::new(c)),
        key_len: key_size,
        algorithm: id as c_int,
    }
}
