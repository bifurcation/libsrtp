use std::os::raw::{c_char, c_int, c_void};

#[repr(C)]
pub struct DebugModule {
    enabled: c_int,
    name: *const c_char,
}

unsafe impl Sync for DebugModule {}

pub static MOD_NAME: &str = "alloc\0";

#[no_mangle]
pub static srtp_mod_alloc: DebugModule = DebugModule {
    enabled: 0,
    name: MOD_NAME.as_ptr() as *const c_char,
};

#[no_mangle]
pub extern "C" fn srtp_crypto_alloc(size: usize) -> *mut c_void {
    if size == 0 {
        return std::ptr::null_mut();
    }

    unsafe { libc::malloc(size) }
}

#[no_mangle]
pub extern "C" fn srtp_crypto_free(ptr: *mut c_void) {
    unsafe { libc::free(ptr) }
}
