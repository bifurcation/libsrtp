// Because this is a C interface file, matching C names is more ergonomic than being rustic
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

use crate::c::err::srtp_debug_module_t;
use crate::c::{just_error, zero_and_drop};
use crate::crypto_kernel::{Auth, AuthType, AuthTypeID};
use crate::hmac::NativeHMAC;
use crate::null_auth::NullAuth;
use crate::srtp::Error;
use cstr::cstr;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

pub type srtp_auth_type_id_t = c_int;

pub type srtp_auth_pointer_t = *mut srtp_auth_t;

pub type srtp_auth_alloc_func =
    Option<extern "C" fn(ap: *mut srtp_auth_pointer_t, key_len: c_int, out_len: c_int) -> Error>;

pub type srtp_auth_dealloc_func = Option<extern "C" fn(ap: srtp_auth_pointer_t) -> Error>;

pub type srtp_auth_init_func =
    Option<extern "C" fn(state: *mut Box<dyn Auth>, key: *const u8, key_len: c_int) -> Error>;

pub type srtp_auth_compute_func = Option<
    extern "C" fn(
        state: *mut Box<dyn Auth>,
        buffer: *const u8,
        octets_to_auth: c_int,
        tag_len: c_int,
        tag: *mut u8,
    ) -> Error,
>;

pub type srtp_auth_update_func = Option<
    extern "C" fn(state: *mut Box<dyn Auth>, buffer: *const u8, octets_to_auth: c_int) -> Error,
>;

pub type srtp_auth_start_func = Option<extern "C" fn(state: *mut Box<dyn Auth>) -> Error>;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct srtp_auth_test_case_t {
    pub key_length_octets: c_int,
    pub key: *const u8,
    pub data_length_octets: c_int,
    pub data: *const u8,
    pub tag_length_octets: c_int,
    pub tag: *const u8,
    pub next_test_case: *const srtp_auth_test_case_t,
}

unsafe impl Sync for srtp_auth_test_case_t {}

#[test]
fn bindgen_test_layout_srtp_auth_test_case_t() {
    assert_eq!(
        ::std::mem::size_of::<srtp_auth_test_case_t>(),
        56usize,
        concat!("Size of: ", stringify!(srtp_auth_test_case_t))
    );
    assert_eq!(
        ::std::mem::align_of::<srtp_auth_test_case_t>(),
        8usize,
        concat!("Alignment of ", stringify!(srtp_auth_test_case_t))
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<srtp_auth_test_case_t>())).key_length_octets as *const _ as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_auth_test_case_t),
            "::",
            stringify!(key_length_octets)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_auth_test_case_t>())).key as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_auth_test_case_t),
            "::",
            stringify!(key)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<srtp_auth_test_case_t>())).data_length_octets as *const _
                as usize
        },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_auth_test_case_t),
            "::",
            stringify!(data_length_octets)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_auth_test_case_t>())).data as *const _ as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_auth_test_case_t),
            "::",
            stringify!(data)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<srtp_auth_test_case_t>())).tag_length_octets as *const _ as usize
        },
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_auth_test_case_t),
            "::",
            stringify!(tag_length_octets)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_auth_test_case_t>())).tag as *const _ as usize },
        40usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_auth_test_case_t),
            "::",
            stringify!(tag)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<srtp_auth_test_case_t>())).next_test_case as *const _ as usize
        },
        48usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_auth_test_case_t),
            "::",
            stringify!(next_test_case)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct srtp_auth_type_t {
    pub alloc: srtp_auth_alloc_func,
    pub dealloc: srtp_auth_dealloc_func,
    pub init: srtp_auth_init_func,
    pub compute: srtp_auth_compute_func,
    pub update: srtp_auth_update_func,
    pub start: srtp_auth_start_func,
    pub description: *const c_char,
    pub test_data: *const srtp_auth_test_case_t,
    pub id: srtp_auth_type_id_t,
}

unsafe impl Sync for srtp_auth_type_t {}

#[test]
fn bindgen_test_layout_srtp_auth_type_t() {
    assert_eq!(
        ::std::mem::size_of::<srtp_auth_type_t>(),
        72usize,
        concat!("Size of: ", stringify!(srtp_auth_type_t))
    );
    assert_eq!(
        ::std::mem::align_of::<srtp_auth_type_t>(),
        8usize,
        concat!("Alignment of ", stringify!(srtp_auth_type_t))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_auth_type_t>())).alloc as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_auth_type_t),
            "::",
            stringify!(alloc)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_auth_type_t>())).dealloc as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_auth_type_t),
            "::",
            stringify!(dealloc)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_auth_type_t>())).init as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_auth_type_t),
            "::",
            stringify!(init)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_auth_type_t>())).compute as *const _ as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_auth_type_t),
            "::",
            stringify!(compute)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_auth_type_t>())).update as *const _ as usize },
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_auth_type_t),
            "::",
            stringify!(update)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_auth_type_t>())).start as *const _ as usize },
        40usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_auth_type_t),
            "::",
            stringify!(start)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_auth_type_t>())).description as *const _ as usize },
        48usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_auth_type_t),
            "::",
            stringify!(description)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_auth_type_t>())).test_data as *const _ as usize },
        56usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_auth_type_t),
            "::",
            stringify!(test_data)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_auth_type_t>())).id as *const _ as usize },
        64usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_auth_type_t),
            "::",
            stringify!(id)
        )
    );
}
#[repr(C)]
#[derive(Debug)]
pub struct srtp_auth_t {
    pub type_: *const srtp_auth_type_t,
    pub state: *mut Box<dyn Auth>,
    pub out_len: c_int,
    pub key_len: c_int,
    pub prefix_len: c_int,
}

unsafe impl Sync for srtp_auth_t {}

impl Drop for srtp_auth_t {
    fn drop(&mut self) {
        let _ = unsafe { self.state.read() };
        self.state = std::ptr::null_mut();
    }
}

#[test]
fn bindgen_test_layout_srtp_auth_t() {
    assert_eq!(
        ::std::mem::size_of::<srtp_auth_t>(),
        32usize,
        concat!("Size of: ", stringify!(srtp_auth_t))
    );
    assert_eq!(
        ::std::mem::align_of::<srtp_auth_t>(),
        8usize,
        concat!("Alignment of ", stringify!(srtp_auth_t))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_auth_t>())).type_ as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_auth_t),
            "::",
            stringify!(type_)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_auth_t>())).state as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_auth_t),
            "::",
            stringify!(state)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_auth_t>())).out_len as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_auth_t),
            "::",
            stringify!(out_len)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_auth_t>())).key_len as *const _ as usize },
        20usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_auth_t),
            "::",
            stringify!(key_len)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<srtp_auth_t>())).prefix_len as *const _ as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(srtp_auth_t),
            "::",
            stringify!(prefix_len)
        )
    );
}

//
// Debug module
//

static srtp_mod_auth_name: &CStr = cstr!("auth func");

#[no_mangle]
pub static srtp_mod_auth: srtp_debug_module_t = srtp_debug_module_t {
    on: 0,
    name: srtp_mod_auth_name.as_ptr(),
};

//
// Utility functions
//

fn auth_alloc(
    auth_type: &dyn AuthType,
    srtp_auth_type: *const srtp_auth_type_t,
    ap: *mut srtp_auth_pointer_t,
    key_len: c_int,
    out_len: c_int,
    prefix_len: c_int,
) -> Error {
    let auth = match auth_type.create(key_len as usize, out_len as usize) {
        Ok(x) => Box::new(x),
        Err(err) => return err,
    };

    let srtp_auth = Box::new(srtp_auth_t {
        type_: srtp_auth_type,
        state: Box::into_raw(auth),
        out_len: out_len,
        key_len: key_len,
        prefix_len: prefix_len,
    });
    unsafe { ap.write(Box::into_raw(srtp_auth)) };
    Error::Ok
}

extern "C" fn auth_init(state: *mut Box<dyn Auth>, key: *const u8, key_len: c_int) -> Error {
    let auth = unsafe { state.as_mut().unwrap() };
    let key_slice = unsafe { std::slice::from_raw_parts(key, key_len as usize) };
    just_error(auth.init(key_slice))
}

extern "C" fn auth_compute(
    state: *mut Box<dyn Auth>,
    buffer: *const u8,
    octets_to_auth: c_int,
    tag_len: c_int,
    tag: *mut u8,
) -> Error {
    let auth = unsafe { state.as_mut().unwrap() };
    let buffer_slice = unsafe { std::slice::from_raw_parts(buffer, octets_to_auth as usize) };
    let tag_slice = unsafe { std::slice::from_raw_parts_mut(tag, tag_len as usize) };
    just_error(auth.compute(buffer_slice, tag_slice))
}

extern "C" fn auth_update(
    state: *mut Box<dyn Auth>,
    buffer: *const u8,
    octets_to_auth: c_int,
) -> Error {
    let auth = unsafe { state.as_mut().unwrap() };
    let buf_slice = unsafe { std::slice::from_raw_parts(buffer, octets_to_auth as usize) };
    just_error(auth.update(buf_slice))
}

extern "C" fn auth_start(state: *mut Box<dyn Auth>) -> Error {
    let auth = unsafe { state.as_mut().unwrap() };
    just_error(auth.start())
}

//
// Null Auth
//

extern "C" fn null_alloc(ap: *mut srtp_auth_pointer_t, key_len: c_int, out_len: c_int) -> Error {
    let auth_type = NullAuth {};
    auth_alloc(&auth_type, &srtp_null_auth, ap, key_len, out_len, out_len)
}

static srtp_null_auth_test_case: srtp_auth_test_case_t = srtp_auth_test_case_t {
    key_length_octets: 0,
    key: std::ptr::null(),
    data_length_octets: 0,
    data: std::ptr::null(),
    tag_length_octets: 0,
    tag: std::ptr::null(),
    next_test_case: std::ptr::null(),
};

static srtp_null_auth_description: &CStr = cstr!("null authentication function");

#[no_mangle]
pub static srtp_null_auth: srtp_auth_type_t = srtp_auth_type_t {
    alloc: Some(null_alloc),
    dealloc: Some(zero_and_drop::<srtp_auth_t>),
    init: Some(auth_init),
    compute: Some(auth_compute),
    update: Some(auth_update),
    start: Some(auth_start),
    description: srtp_null_auth_description.as_ptr(),
    test_data: &srtp_null_auth_test_case,
    id: AuthTypeID::Null as srtp_auth_type_id_t,
};

//
// HMAC Auth
//
extern "C" fn hmac_alloc(ap: *mut srtp_auth_pointer_t, key_len: c_int, out_len: c_int) -> Error {
    let auth_type = NativeHMAC {};
    auth_alloc(&auth_type, &srtp_hmac, ap, key_len, out_len, 0)
}

static srtp_hmac_key: [u8; 20] = [
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b,
];

static srtp_hmac_data: [u8; 8] = [0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65];

static srtp_hmac_tag: [u8; 20] = [
    0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e,
    0xf1, 0x46, 0xbe, 0x00,
];

static srtp_hmac_test_case: srtp_auth_test_case_t = srtp_auth_test_case_t {
    key_length_octets: 20,
    key: srtp_hmac_key.as_ptr(),
    data_length_octets: 8,
    data: srtp_hmac_data.as_ptr(),
    tag_length_octets: 20,
    tag: srtp_hmac_tag.as_ptr(),
    next_test_case: std::ptr::null(),
};

static srtp_hmac_description: &CStr = cstr!("hmac sha-1 authentication function");

#[no_mangle]
pub static srtp_hmac: srtp_auth_type_t = srtp_auth_type_t {
    alloc: Some(hmac_alloc),
    dealloc: Some(zero_and_drop::<srtp_auth_t>),
    init: Some(auth_init),
    compute: Some(auth_compute),
    update: Some(auth_update),
    start: Some(auth_start),
    description: srtp_hmac_description.as_ptr(),
    test_data: &srtp_hmac_test_case,
    id: AuthTypeID::HmacSha1 as srtp_auth_type_id_t,
};

static srtp_mod_hmac_name: &CStr = cstr!("hmac sha-1");

#[no_mangle]
pub static srtp_mod_hmac: srtp_debug_module_t = srtp_debug_module_t {
    on: 0,
    name: srtp_mod_hmac_name.as_ptr(),
};

//
// Auth methods
//

#[no_mangle]
pub extern "C" fn srtp_auth_type_alloc(
    at: *const srtp_auth_type_t,
    ap: *mut srtp_auth_pointer_t,
    key_len: c_int,
    out_len: c_int,
) -> Error {
    let at_ref = unsafe { at.as_ref().unwrap() };
    at_ref.alloc.unwrap()(ap, key_len, out_len)
}

#[no_mangle]
pub extern "C" fn srtp_auth_dealloc(a: *mut srtp_auth_t) -> Error {
    zero_and_drop(a)
}

#[no_mangle]
pub extern "C" fn srtp_auth_init(a: *mut srtp_auth_t, key: *const u8) -> Error {
    let a_ref = unsafe { a.as_ref().unwrap() };
    auth_init(a_ref.state, key, a_ref.key_len)
}

#[no_mangle]
pub extern "C" fn srtp_auth_start(a: *mut srtp_auth_t) -> Error {
    let a_ref = unsafe { a.as_ref().unwrap() };
    auth_start(a_ref.state)
}

#[no_mangle]
pub extern "C" fn srtp_auth_update(
    a: *mut srtp_auth_t,
    buffer: *const u8,
    octets_to_auth: c_int,
) -> Error {
    let a_ref = unsafe { a.as_ref().unwrap() };
    auth_update(a_ref.state, buffer, octets_to_auth)
}

#[no_mangle]
pub extern "C" fn srtp_auth_compute(
    a: *mut srtp_auth_t,
    buffer: *const u8,
    octets_to_auth: c_int,
    tag: *mut u8,
) -> Error {
    let a_ref = unsafe { a.as_ref().unwrap() };
    auth_compute(a_ref.state, buffer, octets_to_auth, a_ref.out_len, tag)
}

#[no_mangle]
pub extern "C" fn srtp_auth_get_key_length(a: *const srtp_auth_t) -> c_int {
    unsafe { a.as_ref().unwrap().key_len }
}

#[no_mangle]
pub extern "C" fn srtp_auth_get_tag_length(a: *const srtp_auth_t) -> c_int {
    unsafe { a.as_ref().unwrap().out_len }
}

#[no_mangle]
pub extern "C" fn srtp_auth_get_prefix_length(a: *const srtp_auth_t) -> c_int {
    unsafe { a.as_ref().unwrap().prefix_len }
}

#[no_mangle]
pub extern "C" fn srtp_auth_type_self_test(at: *const srtp_auth_type_t) -> Error {
    let at_ref = unsafe { at.as_ref().unwrap() };
    srtp_auth_type_test(at, at_ref.test_data)
}

#[no_mangle]
pub extern "C" fn srtp_auth_type_test(
    _at: *const srtp_auth_type_t,
    _test_data: *const srtp_auth_test_case_t,
) -> Error {
    Error::Ok // TODO
}
