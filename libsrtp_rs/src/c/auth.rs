// Because this is a C interface file, matching C names is more ergonomic than being rustic
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

use crate::c::err::srtp_debug_module_t;
use crate::c::{just_error, zero_and_drop};
use crate::crypto::hmac_sha1::HmacSha1;
use crate::crypto::null_auth::NullAuth;
use crate::crypto::{Auth, AuthType, AuthTypeID};
use crate::srtp::Error;
use cstr::cstr;
use hex_literal::hex;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

pub struct SrtpAuthState {
    auth_type: Box<dyn AuthType>,
    tag_size: usize,
    auth: Option<Box<dyn Auth>>,
}

pub type srtp_auth_type_id_t = c_int;

pub type srtp_auth_alloc_func =
    Option<extern "C" fn(ap: *mut *mut srtp_auth_t, key_len: c_int, out_len: c_int) -> Error>;

pub type srtp_auth_dealloc_func = Option<extern "C" fn(ap: *mut srtp_auth_t) -> Error>;

pub type srtp_auth_init_func =
    Option<extern "C" fn(state: *mut SrtpAuthState, key: *const u8, key_len: c_int) -> Error>;

pub type srtp_auth_compute_func = Option<
    extern "C" fn(
        state: *mut SrtpAuthState,
        buffer: *const u8,
        octets_to_auth: c_int,
        tag_len: c_int,
        tag: *mut u8,
    ) -> Error,
>;

pub type srtp_auth_update_func = Option<
    extern "C" fn(state: *mut SrtpAuthState, buffer: *const u8, octets_to_auth: c_int) -> Error,
>;

pub type srtp_auth_start_func = Option<extern "C" fn(state: *mut SrtpAuthState) -> Error>;

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

#[repr(C)]
#[derive(Debug)]
pub struct srtp_auth_t {
    pub type_: *const srtp_auth_type_t,
    pub state: *mut SrtpAuthState,
    pub out_len: c_int,
    pub key_len: c_int,
    pub prefix_len: c_int,
}

unsafe impl Sync for srtp_auth_t {}

impl Drop for srtp_auth_t {
    fn drop(&mut self) {
        if self.state.is_null() {
            return;
        }

        let _ = unsafe { self.state.read() };
        self.state = std::ptr::null_mut();
    }
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
    auth_type: Box<dyn AuthType>,
    srtp_auth_type: *const srtp_auth_type_t,
    ap: *mut *mut srtp_auth_t,
    key_len: c_int,
    out_len: c_int,
    prefix_len: c_int,
) -> Error {
    let state = Box::new(SrtpAuthState {
        auth_type: auth_type,
        tag_size: out_len as usize,
        auth: None,
    });

    let srtp_auth = Box::new(srtp_auth_t {
        type_: srtp_auth_type,
        state: Box::into_raw(state),
        out_len: out_len,
        key_len: key_len,
        prefix_len: prefix_len,
    });
    unsafe { ap.write(Box::into_raw(srtp_auth)) };
    Error::Ok
}

extern "C" fn auth_init(
    state_ptr: *mut SrtpAuthState,
    key_ptr: *const u8,
    key_len: c_int,
) -> Error {
    let state = unsafe { state_ptr.as_mut().unwrap() };
    let key = unsafe { std::slice::from_raw_parts(key_ptr, key_len as usize) };

    match state.auth_type.create(key, state.tag_size) {
        Err(err) => err,
        Ok(auth) => {
            state.auth = Some(auth);
            Error::Ok
        }
    }
}

extern "C" fn auth_compute(
    state_ptr: *mut SrtpAuthState,
    buffer_ptr: *const u8,
    octets_to_auth: c_int,
    tag_len: c_int,
    tag_ptr: *mut u8,
) -> Error {
    let state = unsafe { state_ptr.as_mut().unwrap() };
    let buffer = unsafe { std::slice::from_raw_parts(buffer_ptr, octets_to_auth as usize) };
    let tag = unsafe { std::slice::from_raw_parts_mut(tag_ptr, tag_len as usize) };

    let auth = state.auth.as_mut().unwrap();
    match auth.update(buffer) {
        Ok(_) => {}
        Err(err) => return err,
    };

    just_error(auth.compute(tag))
}

extern "C" fn auth_update(
    state_ptr: *mut SrtpAuthState,
    buffer_ptr: *const u8,
    octets_to_auth: c_int,
) -> Error {
    let state = unsafe { state_ptr.as_mut().unwrap() };
    let buf_slice = unsafe { std::slice::from_raw_parts(buffer_ptr, octets_to_auth as usize) };
    just_error(state.auth.as_mut().unwrap().update(buf_slice))
}

extern "C" fn auth_start(state_ptr: *mut SrtpAuthState) -> Error {
    let state = unsafe { state_ptr.as_mut().unwrap() };
    state.auth.as_mut().unwrap().reset();
    Error::Ok
}

//
// Null Auth
//

extern "C" fn null_alloc(ap: *mut *mut srtp_auth_t, key_len: c_int, out_len: c_int) -> Error {
    let auth_type = Box::new(NullAuth {});
    auth_alloc(auth_type, &srtp_null_auth, ap, key_len, out_len, out_len)
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
extern "C" fn hmac_alloc(ap: *mut *mut srtp_auth_t, key_len: c_int, out_len: c_int) -> Error {
    let auth_type = Box::new(HmacSha1 {});
    auth_alloc(auth_type, &srtp_hmac, ap, key_len, out_len, 0)
}

static srtp_hmac_key: [u8; 20] = [0x0bu8; 20];
static srtp_hmac_data: [u8; 8] = hex!("4869205468657265");
static srtp_hmac_tag: [u8; 20] = hex!("b617318655057264e28bc0b6fb378c8ef146be00");

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
    ap: *mut *mut srtp_auth_t,
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

//
// Manufacture srtp_auth_t from Auth
//

extern "C" fn drop_type_then_drop_auth(c: *mut srtp_auth_t) -> Error {
    // Take over ownership of the type object so that gets freed, since srtp_auth_t::drop doesn't
    // do this (in order to allow for references to static auth types
    let c_ref = unsafe { c.as_ref().unwrap() };
    let _ = unsafe { Box::from_raw(c_ref.type_ as *mut srtp_auth_type_t) };
    zero_and_drop(c)
}

pub fn make_auth_t(at: Box<dyn AuthType>, key_len: c_int, tag_len: c_int) -> srtp_auth_t {
    let description = match at.id() {
        AuthTypeID::Null => srtp_null_auth_description.as_ptr(),
        AuthTypeID::HmacSha1 => srtp_hmac_description.as_ptr(),
    };

    let auth_type = Box::new(srtp_auth_type_t {
        alloc: None,
        dealloc: Some(drop_type_then_drop_auth),
        init: Some(auth_init),
        compute: Some(auth_compute),
        update: Some(auth_update),
        start: Some(auth_start),
        description: description,
        test_data: std::ptr::null(),
        id: at.id() as srtp_auth_type_id_t,
    });

    let state = SrtpAuthState {
        auth_type: at,
        tag_size: tag_len as usize,
        auth: None,
    };

    srtp_auth_t {
        type_: Box::into_raw(auth_type),
        state: Box::into_raw(Box::new(state)),
        key_len: key_len,
        out_len: tag_len,
        prefix_len: 0,
    }
}
