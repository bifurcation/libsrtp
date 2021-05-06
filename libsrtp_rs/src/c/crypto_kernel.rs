// Because this is a C interface file, matching C names is more ergonomic than being rustic
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

use crate::c::auth::{make_auth_t, srtp_auth_t};
use crate::c::cipher::{make_cipher_t, srtp_cipher_t};
use crate::c::err::{srtp_debug_module_t, srtp_err_reporting_init};
use crate::srtp::Error;
use std::os::raw::{c_char, c_int};

use crate::aes::KeySize;
use crate::aes_icm::NativeAesIcm;
use crate::crypto_kernel::{AuthTypeID, CipherTypeID, CryptoKernel};
use crate::hmac::NativeHMAC;
use crate::null_auth::NullAuth;
use crate::null_cipher::NullCipher;

static mut singleton_kernel: Option<CryptoKernel> = None;

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
    let mut kernel = CryptoKernel::new();

    // Cipher types
    if let Err(err) = kernel.load_cipher_type(Box::new(NullCipher {})) {
        return err;
    }
    if let Err(err) = kernel.load_cipher_type(Box::new(NativeAesIcm::new(KeySize::Aes128))) {
        return err;
    }
    if let Err(err) = kernel.load_cipher_type(Box::new(NativeAesIcm::new(KeySize::Aes256))) {
        return err;
    }

    // Auth types
    if let Err(err) = kernel.load_auth_type(Box::new(NullAuth {})) {
        return err;
    }
    if let Err(err) = kernel.load_auth_type(Box::new(NativeHMAC {})) {
        return err;
    }

    unsafe { singleton_kernel = Some(kernel) };

    srtp_crypto_kernel_status()
}

#[no_mangle]
pub extern "C" fn srtp_crypto_kernel_shutdown() -> Error {
    // Trigger GC on the singleton kernel
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
    key_len: c_int,
    tag_len: c_int,
) -> Error {
    if let None = unsafe { &singleton_kernel } {
        return Error::InitFail;
    }

    let cipher_result = unsafe {
        singleton_kernel
            .as_ref()
            .unwrap()
            .cipher(id, key_len as usize, tag_len as usize)
    };

    let cipher = match cipher_result {
        Ok(x) => x,
        Err(err) => return err,
    };

    let srtp_cipher = make_cipher_t(id, cipher);

    let cipher_ptr = Box::into_raw(Box::new(srtp_cipher));
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

    let auth_result = unsafe {
        singleton_kernel
            .as_ref()
            .unwrap()
            .auth(id, key_len as usize, tag_len as usize)
    };

    let auth = match auth_result {
        Ok(x) => x,
        Err(err) => return err,
    };

    let srtp_auth = make_auth_t(id, auth);

    let auth_ptr = Box::into_raw(Box::new(srtp_auth));
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
