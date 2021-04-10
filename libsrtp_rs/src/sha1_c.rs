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
        let output_u8 = output_ptr as *mut u8;
        let mut output_slice = slice::from_raw_parts_mut(output_u8, 20);
        (*ctx).finalize(&mut output_slice);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_c() -> Result<(), hex::FromHexError> {
        let mut ctx = sha1::Context::new();
        let ctx_ptr: *mut sha1::Context = &mut ctx;

        let msg: [u8; 4] = [0x9f, 0xc3, 0xfe, 0x08];
        let msg_len: c_int = 4;
        let mut actual_output_u32: [u32; 5] = [0; 5];
        let expected_output = hex::decode("16a0ff84fcc156fd5d3ca3a744f20a232d172253")?;

        srtp_sha1_init(ctx_ptr);
        srtp_sha1_update(ctx_ptr, msg.as_ptr(), msg_len);
        srtp_sha1_final(ctx_ptr, actual_output_u32.as_mut_ptr());

        let actual_output: &[u8; 20] = unsafe { std::mem::transmute(&actual_output_u32) };
        assert_eq!(expected_output, actual_output);

        Ok(())
    }
}
