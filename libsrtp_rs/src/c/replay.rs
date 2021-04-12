use crate::replay;
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
