#![allow(non_snake_case)]

use crate::aes;
use crate::aes_icm::NativeAesIcm;
use crate::crypto_kernel::{Cipher, CipherDirection, CipherType, CipherTypeID};
use crate::null_cipher::NullCipher;
use crate::srtp::Error;
use cstr::cstr;
use num_enum::TryFromPrimitive;
use std::convert::TryFrom;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_uint, c_void};

pub type srtp_cipher_type_id_t = u32;

pub type srtp_cipher_direction_t = c_uint;
pub type srtp_cipher_pointer_t = *mut srtp_cipher_t;

pub type srtp_cipher_alloc_func_t = Option<
    unsafe extern "C" fn(cp: *mut srtp_cipher_pointer_t, key_len: c_int, tag_len: c_int) -> Error,
>;

pub type srtp_cipher_dealloc_func_t =
    Option<unsafe extern "C" fn(cp: srtp_cipher_pointer_t) -> Error>;

pub type srtp_cipher_init_func_t =
    Option<unsafe extern "C" fn(state: *mut Box<dyn Cipher>, key: *const u8) -> Error>;

pub type srtp_cipher_set_aad_func_t = Option<
    unsafe extern "C" fn(state: *mut Box<dyn Cipher>, aad: *const u8, aad_len: u32) -> Error,
>;

pub type srtp_cipher_encrypt_func_t = Option<
    unsafe extern "C" fn(
        state: *mut Box<dyn Cipher>,
        buffer: *mut u8,
        octets_to_encrypt: *mut c_uint,
    ) -> Error,
>;

pub type srtp_cipher_decrypt_func_t = Option<
    unsafe extern "C" fn(
        state: *mut Box<dyn Cipher>,
        buffer: *mut u8,
        octets_to_decrypt: *mut c_uint,
    ) -> Error,
>;

pub type srtp_cipher_set_iv_func_t = Option<
    unsafe extern "C" fn(
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

#[test]
fn bindgen_test_layout_srtp_cipher_test_case_t() {
    assert_eq!(
        ::std::mem::size_of::<srtp_cipher_test_case_t>(),
        88usize,
        concat!("Size of: ", stringify!(srtp_cipher_test_case_t))
    );
    assert_eq!(
        ::std::mem::align_of::<srtp_cipher_test_case_t>(),
        8usize,
        concat!("Alignment of ", stringify!(srtp_cipher_test_case_t))
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<srtp_cipher_test_case_t>())).key_length_octets as *const _
                as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_cipher_test_case_t),
            "::",
            stringify!(key_length_octets)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_cipher_test_case_t>())).key as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_cipher_test_case_t),
            "::",
            stringify!(key)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_cipher_test_case_t>())).idx as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_cipher_test_case_t),
            "::",
            stringify!(idx)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<srtp_cipher_test_case_t>())).plaintext_length_octets as *const _
                as usize
        },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_cipher_test_case_t),
            "::",
            stringify!(plaintext_length_octets)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<srtp_cipher_test_case_t>())).plaintext as *const _ as usize
        },
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_cipher_test_case_t),
            "::",
            stringify!(plaintext)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<srtp_cipher_test_case_t>())).ciphertext_length_octets as *const _
                as usize
        },
        40usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_cipher_test_case_t),
            "::",
            stringify!(ciphertext_length_octets)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<srtp_cipher_test_case_t>())).ciphertext as *const _ as usize
        },
        48usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_cipher_test_case_t),
            "::",
            stringify!(ciphertext)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<srtp_cipher_test_case_t>())).aad_length_octets as *const _
                as usize
        },
        56usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_cipher_test_case_t),
            "::",
            stringify!(aad_length_octets)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_cipher_test_case_t>())).aad as *const _ as usize },
        64usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_cipher_test_case_t),
            "::",
            stringify!(aad)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<srtp_cipher_test_case_t>())).tag_length_octets as *const _
                as usize
        },
        72usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_cipher_test_case_t),
            "::",
            stringify!(tag_length_octets)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<srtp_cipher_test_case_t>())).next_test_case as *const _ as usize
        },
        80usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_cipher_test_case_t),
            "::",
            stringify!(next_test_case)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct srtp_cipher_type_t {
    pub alloc: srtp_cipher_alloc_func_t,
    pub dealloc: srtp_cipher_dealloc_func_t,
    pub init: srtp_cipher_init_func_t,
    pub set_aad: srtp_cipher_set_aad_func_t,
    pub encrypt: srtp_cipher_encrypt_func_t,
    pub decrypt: srtp_cipher_encrypt_func_t,
    pub set_iv: srtp_cipher_set_iv_func_t,
    pub get_tag: srtp_cipher_get_tag_func_t,
    pub description: *const c_char,
    pub test_data: *const srtp_cipher_test_case_t,
    pub id: srtp_cipher_type_id_t,
}

unsafe impl Sync for srtp_cipher_type_t {}

#[test]
fn bindgen_test_layout_srtp_cipher_type_t() {
    assert_eq!(
        ::std::mem::size_of::<srtp_cipher_type_t>(),
        88usize,
        concat!("Size of: ", stringify!(srtp_cipher_type_t))
    );
    assert_eq!(
        ::std::mem::align_of::<srtp_cipher_type_t>(),
        8usize,
        concat!("Alignment of ", stringify!(srtp_cipher_type_t))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_cipher_type_t>())).alloc as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_cipher_type_t),
            "::",
            stringify!(alloc)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_cipher_type_t>())).dealloc as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_cipher_type_t),
            "::",
            stringify!(dealloc)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_cipher_type_t>())).init as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_cipher_type_t),
            "::",
            stringify!(init)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_cipher_type_t>())).set_aad as *const _ as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_cipher_type_t),
            "::",
            stringify!(set_aad)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_cipher_type_t>())).encrypt as *const _ as usize },
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_cipher_type_t),
            "::",
            stringify!(encrypt)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_cipher_type_t>())).decrypt as *const _ as usize },
        40usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_cipher_type_t),
            "::",
            stringify!(decrypt)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_cipher_type_t>())).set_iv as *const _ as usize },
        48usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_cipher_type_t),
            "::",
            stringify!(set_iv)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_cipher_type_t>())).get_tag as *const _ as usize },
        56usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_cipher_type_t),
            "::",
            stringify!(get_tag)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_cipher_type_t>())).description as *const _ as usize },
        64usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_cipher_type_t),
            "::",
            stringify!(description)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_cipher_type_t>())).test_data as *const _ as usize },
        72usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_cipher_type_t),
            "::",
            stringify!(test_data)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_cipher_type_t>())).id as *const _ as usize },
        80usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_cipher_type_t),
            "::",
            stringify!(id)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct srtp_cipher_t {
    pub type_: *const srtp_cipher_type_t,
    pub state: *mut Box<dyn Cipher>,
    pub key_len: c_int,
    pub algorithm: c_int,
}
#[test]
fn bindgen_test_layout_srtp_cipher_t() {
    assert_eq!(
        ::std::mem::size_of::<srtp_cipher_t>(),
        24usize,
        concat!("Size of: ", stringify!(srtp_cipher_t))
    );
    assert_eq!(
        ::std::mem::align_of::<srtp_cipher_t>(),
        8usize,
        concat!("Alignment of ", stringify!(srtp_cipher_t))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_cipher_t>())).type_ as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_cipher_t),
            "::",
            stringify!(type_)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_cipher_t>())).state as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_cipher_t),
            "::",
            stringify!(state)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_cipher_t>())).key_len as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_cipher_t),
            "::",
            stringify!(key_len)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_cipher_t>())).algorithm as *const _ as usize },
        20usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_cipher_t),
            "::",
            stringify!(algorithm)
        )
    );
}

extern "C" fn zero_and_drop<T>(p: *mut T) -> Error {
    unsafe {
        let mut zero = std::mem::MaybeUninit::<T>::zeroed();
        std::ptr::swap(p, zero.as_mut_ptr());

        // Since `zero` now holds the contents of `p`, which is presumed valid, we tell the
        // compiler to assume it's initialized.  As a result, resources owned by `p` will get
        // cleaned up when `zero` is dropped.
        zero.assume_init();
    }

    Error::Ok
}

fn just_error(result: Result<(), Error>) -> Error {
    match result {
        Ok(_) => Error::Ok,
        Err(err) => err,
    }
}

extern "C" fn cipher_alloc(
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
        Err(err) => return Error::BadParam,
    };
    just_error(cipher.set_iv(iv_slice, dir))
}

extern "C" fn cipher_get_tag(state: *mut Box<dyn Cipher>, tag: *mut u8, len: *mut u32) -> Error {
    let cipher = unsafe { state.as_mut().unwrap() };
    let tag_size = unsafe { len.read() as usize };
    let tag_slice = unsafe { std::slice::from_raw_parts_mut(tag, tag_size) };

    match cipher.get_tag(tag_slice) {
        Ok(len_out) => {
            unsafe { len.write(len_out as c_uint) };
            Error::Ok
        }
        Err(err) => err,
    }
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
    let cipher_type = NativeAesIcm::new(aes::KeySize::Aes128);
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

//
// AES-ICM-128 implementation
//

extern "C" fn aes_icm_256_alloc(
    cp: *mut srtp_cipher_pointer_t,
    key_len: c_int,
    tag_len: c_int,
) -> Error {
    let cipher_type = NativeAesIcm::new(aes::KeySize::Aes256);
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

/*
extern "C" {
    pub fn srtp_cipher_get_key_length(c: *const srtp_cipher_t) -> c_int;
}
extern "C" {
    pub fn srtp_cipher_type_self_test(ct: *const srtp_cipher_type_t) -> Error;
}
extern "C" {
    pub fn srtp_cipher_type_test(
        ct: *const srtp_cipher_type_t,
        test_data: *const srtp_cipher_test_case_t,
    ) -> Error;
}
extern "C" {
    pub fn srtp_cipher_bits_per_second(
        c: *mut srtp_cipher_t,
        octets_in_buffer: c_int,
        num_trials: c_int,
    ) -> u64;
}
extern "C" {
    pub fn srtp_cipher_type_alloc(
        ct: *const srtp_cipher_type_t,
        c: *mut *mut srtp_cipher_t,
        key_len: c_int,
        tlen: c_int,
    ) -> Error;
}
extern "C" {
    pub fn srtp_cipher_dealloc(c: *mut srtp_cipher_t) -> Error;
}
extern "C" {
    pub fn srtp_cipher_init(c: *mut srtp_cipher_t, key: *const u8) -> Error;
}
extern "C" {
    pub fn srtp_cipher_set_iv(
        c: *mut srtp_cipher_t,
        iv: *mut u8,
        direction: c_int,
    ) -> Error;
}
extern "C" {
    pub fn srtp_cipher_output(
        c: *mut srtp_cipher_t,
        buffer: *mut u8,
        num_octets_to_output: *mut u32,
    ) -> Error;
}
extern "C" {
    pub fn srtp_cipher_encrypt(
        c: *mut srtp_cipher_t,
        buffer: *mut u8,
        num_octets_to_output: *mut u32,
    ) -> Error;
}
extern "C" {
    pub fn srtp_cipher_decrypt(
        c: *mut srtp_cipher_t,
        buffer: *mut u8,
        num_octets_to_output: *mut u32,
    ) -> Error;
}
extern "C" {
    pub fn srtp_cipher_get_tag(
        c: *mut srtp_cipher_t,
        buffer: *mut u8,
        tag_len: *mut u32,
    ) -> Error;
}
extern "C" {
    pub fn srtp_cipher_set_aad(
        c: *mut srtp_cipher_t,
        aad: *const u8,
        aad_len: u32,
    ) -> Error;
}
extern "C" {
    pub fn srtp_replace_cipher_type(
        ct: *const srtp_cipher_type_t,
        id: srtp_cipher_type_id_t,
    ) -> Error;
}
*/
