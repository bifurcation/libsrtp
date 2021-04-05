use crate::sha1;

use std::convert::TryFrom;
use std::os::raw::c_int;
use std::slice;

#[no_mangle]
pub extern "C" fn srtp_sha1_init(ctx: *mut sha1::Context) {
    unsafe {
        *ctx = sha1::Context::new();
    }
}

#[no_mangle]
pub extern "C" fn srtp_sha1_update(
    ctx: *mut sha1::Context,
    msg_ptr: *const u8,
    octets_in_msg: c_int,
) {
    unsafe {
        let msg_size = usize::try_from(octets_in_msg as i32).unwrap();
        let msg = slice::from_raw_parts(msg_ptr, msg_size);
        (*ctx).update(&msg);
    }
}

#[no_mangle]
pub extern "C" fn srtp_sha1_final(ctx: *mut sha1::Context, output_ptr: *mut u32) {
    unsafe {
        let output_slice = slice::from_raw_parts(output_ptr, 5);
        let mut output_array = <[u32; 5]>::try_from(output_slice).unwrap();
        (*ctx).finalize(&mut output_array);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_c() {
        // Simply verify that this runs without panicking
        let mut ctx = sha1::Context::new();
        let ctx_ptr: *mut sha1::Context = &mut ctx;

        let msg: [u8; 4] = [1, 2, 3, 4];
        let msg_len: c_int = 4;
        let mut output: [u32; 5] = [0; 5];

        srtp_sha1_init(ctx_ptr);
        srtp_sha1_update(ctx_ptr, msg.as_ptr(), msg_len);
        srtp_sha1_final(ctx_ptr, output.as_mut_ptr());
    }
}
