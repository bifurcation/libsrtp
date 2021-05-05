// Because this is a C interface file, matching C names is more ergonomic than being rustic
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

use crate::srtp::Error;
use std::os::raw::{c_char, c_int};

#[repr(C)]
pub enum ErrorReportingLevel {
    Error = 0,
    Warning = 1,
    Info = 2,
    Debug = 3,
}

#[no_mangle]
pub extern "C" fn srtp_err_reporting_init() -> Error {
    // TODO(RLB): Implement file-based logging
    Error::Ok
}

pub type srtp_err_report_handler_func_t =
    Option<extern "C" fn(level: ErrorReportingLevel, msg: *const c_char)>;

static mut srtp_err_report_handler: srtp_err_report_handler_func_t = None;

#[no_mangle]
pub extern "C" fn srtp_install_err_report_handler(func: srtp_err_report_handler_func_t) -> Error {
    unsafe {
        srtp_err_report_handler = func;
    }
    Error::Ok
}

#[no_mangle]
pub unsafe extern "C" fn srtp_err_report(_level: ErrorReportingLevel, _format: *const c_char) {
    // XXX(RLB): C-Variadic functions are unstable in Rust, so we can only implement a stub version
    // of this function right now.
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct srtp_debug_module_t {
    pub on: c_int,
    pub name: *const c_char,
}

unsafe impl Sync for srtp_debug_module_t {}
