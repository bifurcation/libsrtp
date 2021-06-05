pub mod aes;
pub mod alloc;
pub mod auth;
pub mod cipher;
pub mod crypto_kernel;
pub mod err;
pub mod key_limit;
pub mod replay;
pub mod sha1;
pub mod srtp;

use crate::srtp::Error;

fn just_error(result: Result<(), Error>) -> Error {
    match result {
        Ok(_) => Error::Ok,
        Err(err) => err,
    }
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
