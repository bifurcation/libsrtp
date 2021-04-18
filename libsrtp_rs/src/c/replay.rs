use crate::replay;
use crate::replay::ExtSeqNum;
use crate::srtp;

#[no_mangle]
pub extern "C" fn srtp_rdb_init(rdb: *mut replay::ReplayDB) -> srtp::Error {
    unsafe { *rdb = replay::ReplayDB::new() };
    srtp::Error::Ok
}

#[no_mangle]
pub extern "C" fn srtp_rdb_check(rdb: *const replay::ReplayDB, rdb_index: u32) -> srtp::Error {
    match unsafe { (*rdb).check(rdb_index) } {
        Ok(_) => srtp::Error::Ok,
        Err(err) => err,
    }
}

#[no_mangle]
pub extern "C" fn srtp_rdb_add_index(rdb: *mut replay::ReplayDB, rdb_index: u32) -> srtp::Error {
    match unsafe { (*rdb).add(rdb_index) } {
        Ok(_) => srtp::Error::Ok,
        Err(err) => err,
    }
}

#[no_mangle]
pub extern "C" fn srtp_rdb_increment(rdb: *mut replay::ReplayDB) -> srtp::Error {
    match unsafe { (*rdb).increment() } {
        Ok(_) => srtp::Error::Ok,
        Err(err) => err,
    }
}

#[no_mangle]
pub extern "C" fn srtp_rdb_get_value(rdb: *const replay::ReplayDB) -> u32 {
    unsafe { (*rdb).get_value() }
}

#[no_mangle]
pub extern "C" fn srtp_rdbx_init(
    rdbx: *mut replay::ExtendedReplayDB,
    ws: ::std::os::raw::c_ulong,
) -> srtp::Error {
    let rdbx_rs = match replay::ExtendedReplayDB::new(ws as usize) {
        Ok(rdbx_rs) => rdbx_rs,
        Err(err) => return err,
    };

    unsafe { rdbx.write(rdbx_rs) };
    srtp::Error::Ok
}

#[no_mangle]
pub extern "C" fn srtp_rdbx_dealloc(rdbx: *mut replay::ExtendedReplayDB) -> srtp::Error {
    unsafe {
        let mut zero = std::mem::MaybeUninit::<replay::ExtendedReplayDB>::zeroed();
        std::ptr::swap(rdbx, zero.as_mut_ptr());

        // Since `zero` now holds the contents of `rdbx`, which is presumed valid, we tell the
        // compiler to assume it's initialized.  As a result, resources owned by `rdbx` will get
        // cleaned up when `zero` is dropped.
        zero.assume_init();
    }

    srtp::Error::Ok
}

#[no_mangle]
pub extern "C" fn srtp_rdbx_estimate_index(
    rdbx: *const replay::ExtendedReplayDB,
    guess: *mut replay::ExtendedSequenceNumber,
    s: replay::SequenceNumber,
) -> i32 {
    let (my_guess, delta) = unsafe { (*rdbx).estimate(s) };
    unsafe { *guess = my_guess };
    delta
}

#[no_mangle]
pub extern "C" fn srtp_rdbx_check(
    rdbx: *const replay::ExtendedReplayDB,
    difference: ::std::os::raw::c_int,
) -> srtp::Error {
    let rv = unsafe { (*rdbx).check(difference as i32) };
    match rv {
        Ok(_) => srtp::Error::Ok,
        Err(err) => err,
    }
}

#[no_mangle]
pub extern "C" fn srtp_rdbx_add_index(
    rdbx: *mut replay::ExtendedReplayDB,
    delta: ::std::os::raw::c_int,
) -> srtp::Error {
    let rv = unsafe { (*rdbx).add(delta as i32) };
    match rv {
        Ok(_) => srtp::Error::Ok,
        Err(err) => err,
    }
}

#[no_mangle]
pub extern "C" fn srtp_rdbx_set_roc(
    rdbx: *mut replay::ExtendedReplayDB,
    roc: replay::RolloverCounter,
) -> srtp::Error {
    let rv = unsafe { (*rdbx).set_roc(roc) };
    match rv {
        Ok(_) => srtp::Error::Ok,
        Err(err) => err,
    }
}

#[no_mangle]
pub extern "C" fn srtp_rdbx_get_packet_index(
    rdbx: *const replay::ExtendedReplayDB,
) -> replay::ExtendedSequenceNumber {
    unsafe { (*rdbx).packet_index() }
}

#[no_mangle]
pub extern "C" fn srtp_rdbx_get_window_size(
    rdbx: *const replay::ExtendedReplayDB,
) -> ::std::os::raw::c_ulong {
    unsafe { (*rdbx).window_size() as ::std::os::raw::c_ulong }
}

#[no_mangle]
pub extern "C" fn srtp_index_init(pi: *mut replay::ExtendedSequenceNumber) {
    unsafe { *pi = 0 };
}

#[no_mangle]
pub extern "C" fn srtp_index_advance(
    pi: *mut replay::ExtendedSequenceNumber,
    s: replay::SequenceNumber,
) {
    unsafe { *pi += s as replay::ExtendedSequenceNumber };
}

#[no_mangle]
pub extern "C" fn srtp_index_guess(
    local: *const replay::ExtendedSequenceNumber,
    guess: *mut replay::ExtendedSequenceNumber,
    s: replay::SequenceNumber,
) -> i32 {
    let (my_guess, delta) = unsafe { (*local).estimate(s) };
    unsafe { *guess = my_guess };
    delta
}

#[no_mangle]
pub extern "C" fn srtp_rdbx_get_roc(
    rdbx: *const replay::ExtendedReplayDB,
) -> replay::RolloverCounter {
    unsafe { (*rdbx).roc() }
}

#[no_mangle]
pub extern "C" fn srtp_rdbx_set_roc_seq(
    rdbx: *mut replay::ExtendedReplayDB,
    roc: replay::RolloverCounter,
    seq: replay::SequenceNumber,
) -> srtp::Error {
    let rv = unsafe { (*rdbx).set_roc_seq(roc, seq) };
    match rv {
        Ok(_) => srtp::Error::Ok,
        Err(err) => err,
    }
}
