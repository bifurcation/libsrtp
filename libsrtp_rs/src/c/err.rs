// Because this is a C interface file, matching C names is more ergonomic than being rustic
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

use std::os::raw::{c_char, c_int};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct srtp_debug_module_t {
    pub on: c_int,
    pub name: *const c_char,
}

unsafe impl Sync for srtp_debug_module_t {}
