// Because this is a C interface file, matching C names is more ergonomic than being rustic
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

use crate::c::auth::{make_auth_t, srtp_auth_t};
use crate::c::cipher::{make_cipher_t, srtp_cipher_t};
use crate::c::err::{srtp_debug_module_t, srtp_err_reporting_init};
use crate::crypto_kernel::{AuthTypeID, CipherTypeID, CryptoKernel};
use crate::srtp::Error;
use std::os::raw::{c_char, c_int};

pub static mut singleton_kernel: Option<CryptoKernel> = None;

#[no_mangle]
pub extern "C" fn srtp_crypto_kernel_init() -> Error {
    // If we're already in the secure state, but we've been asked to re-initialize, re-run the self
    // tests and return the results.
    if let Some(_) = unsafe { &singleton_kernel } {
        return srtp_crypto_kernel_status();
    }

    let status = srtp_err_reporting_init();
    if status != Error::Ok {
        return status;
    }

    // Initialize the kernel
    let kernel = match CryptoKernel::default() {
        Ok(x) => x,
        Err(err) => return err,
    };

    unsafe { singleton_kernel = Some(kernel) };

    srtp_crypto_kernel_status()
}

#[no_mangle]
pub extern "C" fn srtp_crypto_kernel_shutdown() -> Error {
    // Trigger drop of the singleton kernel
    unsafe { singleton_kernel = None };
    Error::Ok
}

#[no_mangle]
pub extern "C" fn srtp_crypto_kernel_status() -> Error {
    // TODO Run self-tests on installed ciphers
    Error::Ok
}

#[no_mangle]
pub extern "C" fn srtp_crypto_kernel_alloc_cipher(
    id: CipherTypeID,
    cp: *mut *mut srtp_cipher_t,
    _key_len: c_int,
    tag_len: c_int,
) -> Error {
    if let None = unsafe { &singleton_kernel } {
        return Error::InitFail;
    }

    let cipher_type = match unsafe { singleton_kernel.as_ref().unwrap().cipher_type(id) } {
        Ok(x) => x,
        Err(err) => return err,
    };

    // Disallow truncated GCM
    // XXX(RLB) We can't enforce a general requirement that tag_len == id.tag_size() because
    // the libsrtp policy struct conflates the AEAD tag size with the external MAC tag size.
    match id {
        CipherTypeID::AesGcm128 | CipherTypeID::AesGcm256 => {
            if tag_len != 16 {
                return Error::BadParam;
            }
        }
        _ => {}
    };

    let cipher = make_cipher_t(cipher_type);
    let cipher_ptr = Box::into_raw(Box::new(cipher));
    unsafe { cp.write(cipher_ptr) };
    Error::Ok
}

#[no_mangle]
pub extern "C" fn srtp_crypto_kernel_alloc_auth(
    id: AuthTypeID,
    ap: *mut *mut srtp_auth_t,
    key_len: c_int,
    tag_len: c_int,
) -> Error {
    if let None = unsafe { &singleton_kernel } {
        return Error::InitFail;
    }

    let auth_type = match unsafe { singleton_kernel.as_ref().unwrap().auth_type(id) } {
        Ok(x) => x,
        Err(err) => return err,
    };

    let auth = make_auth_t(auth_type, key_len, tag_len);
    let auth_ptr = Box::into_raw(Box::new(auth));
    unsafe { ap.write(auth_ptr) };
    Error::Ok
}

// TODO(RLB): Allow application-defined cipher/auth types

//
// Debug modules
//

// XXX(RLB) Debug logging is not implemented right now, so the debug module methods on the crypto
// kernel are just stubs.

#[no_mangle]
pub extern "C" fn srtp_crypto_kernel_list_debug_modules() -> Error {
    Error::Ok
}

#[no_mangle]
pub extern "C" fn srtp_crypto_kernel_load_debug_module(_new_dm: *mut srtp_debug_module_t) -> Error {
    Error::Ok
}

#[no_mangle]
pub extern "C" fn srtp_crypto_kernel_set_debug_module(
    _mod_name: *const c_char,
    _v: c_int,
) -> Error {
    Error::Ok
}
