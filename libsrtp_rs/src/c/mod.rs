mod aes;
mod alloc;
mod auth;
mod cipher;
mod crypto_kernel;
mod err;
mod key_limit;
mod replay;
mod sha1;
mod srtp;

use crate::srtp::Error;

fn just_error(result: Result<(), Error>) -> Error {
    match result {
        Ok(_) => Error::Ok,
        Err(err) => err,
    }
}

extern "C" fn zero_and_drop<T>(p: *mut T) -> Error {
    if p.is_null() {
        return Error::Ok;
    }

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
