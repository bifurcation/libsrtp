use crate::key_limit::*;
use crate::replay::ExtendedSequenceNumber;
use crate::srtp::Error;

#[no_mangle]
pub extern "C" fn srtp_key_limit_set(
    key: *mut KeyLimitContext,
    s: ExtendedSequenceNumber,
) -> Error {
    match unsafe { key.as_mut().unwrap().set(s) } {
        Ok(_) => Error::Ok,
        Err(err) => err,
    }
}

#[no_mangle]
pub extern "C" fn srtp_key_limit_clone(
    original: *mut KeyLimitContext,
    new_key: *mut *mut KeyLimitContext,
) -> Error {
    if original.is_null() {
        return Error::BadParam;
    }

    let mut new_context = Box::new(KeyLimitContext::new());
    unsafe {
        *new_context = original.read();
        new_key.write(Box::into_raw(new_context))
    };
    Error::Ok
}

#[no_mangle]
pub extern "C" fn srtp_key_limit_check(key: *const KeyLimitContext) -> Error {
    match unsafe { key.as_ref().unwrap().check() } {
        Ok(_) => Error::Ok,
        Err(err) => err,
    }
}

#[no_mangle]
pub extern "C" fn srtp_key_limit_update(key: *mut KeyLimitContext) -> KeyEvent {
    unsafe { key.as_mut().unwrap().update() }
}
