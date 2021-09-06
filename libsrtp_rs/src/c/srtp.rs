// Because this is a C interface file, matching C names is more ergonomic than being rustic
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

use crate::c::crypto_kernel::{
    singleton_kernel, srtp_crypto_kernel_init, srtp_crypto_kernel_shutdown,
};
use crate::c::{just_error, zero_and_drop};
use crate::crypto_kernel::{AuthTypeID, CipherTypeID};
use crate::policy::{CryptoPolicy, MasterKey, Policy, ProfileID, SecurityServices, Ssrc};
use crate::replay::RolloverCounter;
use crate::srtp::{Context, Error};
use cstr::cstr;
use std::convert::TryInto;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_uchar, c_uint, c_ulong, c_void};

//
// Profile
//

#[no_mangle]
pub extern "C" fn srtp_profile_get_master_key_length(profile: ProfileID) -> c_uint {
    profile.master_key_size() as c_uint
}

#[no_mangle]
pub extern "C" fn srtp_profile_get_master_salt_length(profile: ProfileID) -> c_uint {
    profile.master_salt_size() as c_uint
}

//
// Policy
//

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct srtp_crypto_policy_t {
    pub cipher_type: CipherTypeID,
    pub cipher_key_len: c_int,
    pub auth_type: AuthTypeID,
    pub auth_key_len: c_int,
    pub auth_tag_len: c_int,
    pub sec_serv: SecurityServices,
}

impl Into<CryptoPolicy> for srtp_crypto_policy_t {
    fn into(self) -> CryptoPolicy {
        CryptoPolicy {
            cipher_type: self.cipher_type,
            cipher_key_len: self.cipher_key_len as usize,
            auth_type: self.auth_type,
            auth_key_len: self.auth_key_len as usize,
            auth_tag_len: self.auth_tag_len as usize,
            sec_serv: self.sec_serv,
        }
    }
}

impl From<CryptoPolicy> for srtp_crypto_policy_t {
    fn from(cp: CryptoPolicy) -> srtp_crypto_policy_t {
        srtp_crypto_policy_t {
            cipher_type: cp.cipher_type,
            cipher_key_len: cp.cipher_key_len as c_int,
            auth_type: cp.auth_type,
            auth_key_len: cp.auth_key_len as c_int,
            auth_tag_len: cp.auth_tag_len as c_int,
            sec_serv: cp.sec_serv,
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum SsrcType {
    Undefined = 0,
    Specific = 1,
    Inbound = 2,
    Outbound = 3,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct srtp_ssrc_t {
    pub type_: SsrcType,
    pub value: c_uint,
}

impl Into<Ssrc> for srtp_ssrc_t {
    fn into(self) -> Ssrc {
        match self.type_ {
            SsrcType::Undefined => panic!("Invalid ssrc"),
            SsrcType::Specific => Ssrc::Any(self.value),
            SsrcType::Inbound => Ssrc::AnyInbound,
            SsrcType::Outbound => Ssrc::AnyOutbound,
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct srtp_master_key_t {
    pub key: *mut c_uchar,
    pub mki_id: *mut c_uchar,
    pub mki_size: c_uint,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct srtp_policy_t {
    pub ssrc: srtp_ssrc_t,
    pub rtp: srtp_crypto_policy_t,
    pub rtcp: srtp_crypto_policy_t,
    pub key: *mut c_uchar,
    pub keys: *mut *mut srtp_master_key_t,
    pub num_master_keys: c_ulong,
    pub deprecated_ekt: *mut c_void,
    pub window_size: c_ulong,
    pub allow_repeat_tx: c_int,
    pub enc_xtn_hdr: *mut c_int,
    pub enc_xtn_hdr_count: c_int,
    pub next: *mut srtp_policy_t,
}

fn split_key_for_cipher<'a>(key_ptr: *mut c_uchar, id: CipherTypeID) -> (&'a [u8], &'a [u8]) {
    let key_size = id.key_size();
    let salt_size = id.salt_size();

    let salt_ptr = unsafe { key_ptr.offset(key_size as isize) };

    let key = unsafe { std::slice::from_raw_parts(key_ptr, key_size) };
    let salt = unsafe { std::slice::from_raw_parts(salt_ptr, salt_size) };
    (key, salt)
}

fn master_key_for_cipher(mk: &srtp_master_key_t, id: CipherTypeID) -> MasterKey {
    let (key, salt) = split_key_for_cipher(mk.key, id);
    let id = unsafe { std::slice::from_raw_parts(mk.mki_id, mk.mki_size as usize) };
    MasterKey {
        key: key.into(),
        salt: salt.into(),
        id: id.into(),
    }
}

impl Into<Policy> for srtp_policy_t {
    fn into(self) -> Policy {
        let have_key = self.key.is_null();
        let num_master_keys = if have_key {
            1usize
        } else {
            self.num_master_keys as usize
        };
        let num_xtn_hdr = self.enc_xtn_hdr_count as usize;

        let mut policy = Policy {
            ssrc: self.ssrc.into(),
            rtp: self.rtp.into(),
            rtcp: self.rtcp.into(),
            keys: Vec::with_capacity(num_master_keys),
            window_size: self.window_size as usize,
            allow_repeat_tx: (self.allow_repeat_tx != 0),
            xtn_headers_to_encrypt: Vec::with_capacity(num_xtn_hdr),
        };

        // Import master keys
        if have_key {
            let (key, salt) = split_key_for_cipher(self.key, self.rtp.cipher_type);
            policy.keys.push(MasterKey {
                key: key.into(),
                salt: salt.into(),
                id: vec![],
            });
        } else {
            let id = self.rtp.cipher_type;
            let mks = unsafe { std::slice::from_raw_parts(self.keys, num_master_keys) };
            for mk in mks {
                let mk_ref = unsafe { mk.as_ref().unwrap() };
                policy.keys.push(master_key_for_cipher(mk_ref, id));
            }
        }

        // Copy in extension headers to encrypt
        if !self.enc_xtn_hdr.is_null() && num_xtn_hdr > 0 {
            let hdrs = unsafe { std::slice::from_raw_parts(self.enc_xtn_hdr, num_xtn_hdr) };
            let mut hdrs: Vec<u8> = hdrs.iter().map(|x| (*x).try_into().unwrap()).collect();
            policy.xtn_headers_to_encrypt.append(&mut hdrs);
        }

        policy
    }
}

fn assign_crypto_policy(p: *mut srtp_crypto_policy_t, cp: CryptoPolicy) {
    unsafe { p.write(cp.into()) };
}

#[no_mangle]
extern "C" fn srtp_crypto_policy_set_rtp_default(p: *mut srtp_crypto_policy_t) {
    assign_crypto_policy(p, CryptoPolicy::RTP_DEFAULT);
}

#[no_mangle]
extern "C" fn srtp_crypto_policy_set_rtcp_default(p: *mut srtp_crypto_policy_t) {
    assign_crypto_policy(p, CryptoPolicy::RTCP_DEFAULT);
}

#[no_mangle]
extern "C" fn srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(p: *mut srtp_crypto_policy_t) {
    assign_crypto_policy(p, CryptoPolicy::AES_CM_128_HMAC_SHA1_32);
}

#[no_mangle]
extern "C" fn srtp_crypto_policy_set_aes_cm_128_null_auth(p: *mut srtp_crypto_policy_t) {
    assign_crypto_policy(p, CryptoPolicy::AES_CM_128_NULL_AUTH);
}

#[no_mangle]
extern "C" fn srtp_crypto_policy_set_null_cipher_hmac_sha1_80(p: *mut srtp_crypto_policy_t) {
    assign_crypto_policy(p, CryptoPolicy::AES_CM_128_HMAC_SHA1_80);
}

#[no_mangle]
extern "C" fn srtp_crypto_policy_set_null_cipher_hmac_null(p: *mut srtp_crypto_policy_t) {
    assign_crypto_policy(p, CryptoPolicy::NULL_CIPHER_NULL_AUTH);
}

#[no_mangle]
extern "C" fn srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(p: *mut srtp_crypto_policy_t) {
    assign_crypto_policy(p, CryptoPolicy::AES_CM_256_HMAC_SHA1_80);
}

#[no_mangle]
extern "C" fn srtp_crypto_policy_set_aes_cm_256_hmac_sha1_32(p: *mut srtp_crypto_policy_t) {
    assign_crypto_policy(p, CryptoPolicy::AES_CM_256_HMAC_SHA1_32);
}

#[no_mangle]
extern "C" fn srtp_crypto_policy_set_aes_cm_256_null_auth(p: *mut srtp_crypto_policy_t) {
    assign_crypto_policy(p, CryptoPolicy::AES_CM_256_NULL_AUTH);
}

#[no_mangle]
extern "C" fn srtp_crypto_policy_set_aes_cm_192_hmac_sha1_80(p: *mut srtp_crypto_policy_t) {
    assign_crypto_policy(p, CryptoPolicy::AES_CM_192_HMAC_SHA1_80);
}

#[no_mangle]
extern "C" fn srtp_crypto_policy_set_aes_cm_192_hmac_sha1_32(p: *mut srtp_crypto_policy_t) {
    assign_crypto_policy(p, CryptoPolicy::AES_CM_192_HMAC_SHA1_32);
}

#[no_mangle]
extern "C" fn srtp_crypto_policy_set_aes_cm_192_null_auth(p: *mut srtp_crypto_policy_t) {
    assign_crypto_policy(p, CryptoPolicy::AES_CM_192_NULL_AUTH);
}

#[no_mangle]
extern "C" fn srtp_crypto_policy_set_aes_gcm_128_8_auth(_p: *mut srtp_crypto_policy_t) {
    panic!("Truncated GCM ciphersuites are not supported");
}

#[no_mangle]
extern "C" fn srtp_crypto_policy_set_aes_gcm_256_8_auth(_p: *mut srtp_crypto_policy_t) {
    panic!("Truncated GCM ciphersuites are not supported");
}

#[no_mangle]
extern "C" fn srtp_crypto_policy_set_aes_gcm_128_8_only_auth(_p: *mut srtp_crypto_policy_t) {
    panic!("Truncated GCM ciphersuites are not supported");
}

#[no_mangle]
extern "C" fn srtp_crypto_policy_set_aes_gcm_256_8_only_auth(_p: *mut srtp_crypto_policy_t) {
    panic!("Truncated GCM ciphersuites are not supported");
}

#[no_mangle]
extern "C" fn srtp_crypto_policy_set_aes_gcm_128_16_auth(p: *mut srtp_crypto_policy_t) {
    assign_crypto_policy(p, CryptoPolicy::AES_GCM_128);
}

#[no_mangle]
extern "C" fn srtp_crypto_policy_set_aes_gcm_256_16_auth(p: *mut srtp_crypto_policy_t) {
    assign_crypto_policy(p, CryptoPolicy::AES_GCM_256);
}

#[no_mangle]
extern "C" fn srtp_crypto_policy_set_from_profile_for_rtp(
    policy_ptr: *mut srtp_crypto_policy_t,
    profile: ProfileID,
) -> Error {
    assign_crypto_policy(policy_ptr, CryptoPolicy::from_profile_rtp(profile));
    Error::Ok
}

#[no_mangle]
extern "C" fn srtp_crypto_policy_set_from_profile_for_rtcp(
    policy_ptr: *mut srtp_crypto_policy_t,
    profile: ProfileID,
) -> Error {
    assign_crypto_policy(policy_ptr, CryptoPolicy::from_profile_rtcp(profile));
    Error::Ok
}

//
// Srtp
//

pub type srtp_t = *mut Context;

fn read_policy_list(policy: *const srtp_policy_t) -> Vec<Policy> {
    let mut policies: Vec<Policy> = Vec::new();
    let mut policy_ptr = policy;
    while !policy_ptr.is_null() {
        let policy_val = unsafe { policy_ptr.read() };
        policies.push(policy_val.into());
        policy_ptr = policy_val.next;
    }
    policies
}

#[no_mangle]
pub extern "C" fn srtp_create(session_ptr: *mut srtp_t, policy_ptr: *const srtp_policy_t) -> Error {
    // Read the linked list of policies into a Vec
    let policies = read_policy_list(policy_ptr);

    // Get a reference to the singleton kernel, failing if not initialized
    let kernel = match unsafe { singleton_kernel.as_ref() } {
        Some(x) => x,
        None => return Error::Fail,
    };

    // Allocate a Context
    let ctx = match Context::new(kernel, &policies) {
        Ok(x) => x,
        Err(err) => return err,
    };

    let ctx_ptr = Box::into_raw(Box::new(ctx));
    unsafe { session_ptr.write(ctx_ptr) };
    Error::Ok
}

#[no_mangle]
pub extern "C" fn srtp_add_stream(session_ptr: srtp_t, policy_ptr: *const srtp_policy_t) -> Error {
    let session = unsafe { session_ptr.as_mut().unwrap() };
    let policy = unsafe { policy_ptr.read() };

    let kernel = match unsafe { singleton_kernel.as_ref() } {
        Some(x) => x,
        None => return Error::Fail,
    };

    just_error(session.add_stream(kernel, &policy.into()))
}

#[no_mangle]
pub extern "C" fn srtp_remove_stream(session_ptr: srtp_t, ssrc: c_uint) -> Error {
    let session = unsafe { session_ptr.as_mut().unwrap() };
    just_error(session.remove_stream(ssrc as u32))
}

#[no_mangle]
pub extern "C" fn srtp_update(session_ptr: srtp_t, policy: *const srtp_policy_t) -> Error {
    let session = unsafe { session_ptr.as_mut().unwrap() };
    let policies = read_policy_list(policy);
    let kernel = match unsafe { singleton_kernel.as_ref() } {
        Some(x) => x,
        None => return Error::Fail,
    };

    just_error(session.update(kernel, &policies))
}

#[no_mangle]
pub extern "C" fn srtp_update_stream(session_ptr: srtp_t, policy: *const srtp_policy_t) -> Error {
    let session = unsafe { session_ptr.as_mut().unwrap() };
    let policy: Policy = unsafe { policy.read().into() };
    let kernel = match unsafe { singleton_kernel.as_ref() } {
        Some(x) => x,
        None => return Error::Fail,
    };

    just_error(session.update_stream(kernel, &policy))
}

#[no_mangle]
pub extern "C" fn srtp_dealloc(s: srtp_t) -> Error {
    zero_and_drop(s)
}

#[no_mangle]
pub extern "C" fn srtp_protect(
    session_ptr: srtp_t,
    buf_ptr: *mut c_void,
    len_ptr: *mut c_int,
) -> Error {
    srtp_protect_mki(session_ptr, buf_ptr, len_ptr, 0, 0)
}

#[no_mangle]
pub extern "C" fn srtp_protect_mki(
    session_ptr: srtp_t,
    buf_ptr: *mut c_void,
    len_ptr: *mut c_int,
    use_mki: c_uint,
    mki_index: c_uint,
) -> Error {
    let session = unsafe { session_ptr.as_mut().unwrap() };
    let use_mki = use_mki != 0;
    let mki_index = mki_index as usize;

    // Assume that the buffer has MAX_TRAILER_SIZE bytes remaining
    const SRTP_MAX_TRAILER_LEN: usize = 144;
    let pt_size = unsafe { len_ptr.read() as usize };
    let buf_ptr = buf_ptr.cast::<u8>();
    let buf_size = pt_size + SRTP_MAX_TRAILER_LEN;
    let buf = unsafe { std::slice::from_raw_parts_mut(buf_ptr, buf_size) };
    let ct_size = match session.srtp_protect_mki(buf, pt_size, use_mki, mki_index) {
        Ok(x) => x,
        Err(err) => return err,
    };

    unsafe { len_ptr.write(ct_size as c_int) };
    Error::Ok
}

#[no_mangle]
pub extern "C" fn srtp_unprotect(
    session_ptr: srtp_t,
    buf_ptr: *mut c_void,
    len_ptr: *mut c_int,
) -> Error {
    srtp_unprotect_mki(session_ptr, buf_ptr, len_ptr, 0)
}

#[no_mangle]
pub extern "C" fn srtp_unprotect_mki(
    session_ptr: srtp_t,
    buf_ptr: *mut c_void,
    len_ptr: *mut c_int,
    use_mki: c_uint,
) -> Error {
    let session = unsafe { session_ptr.as_mut().unwrap() };
    let use_mki = use_mki != 0;

    // Assume that the buffer has MAX_TRAILER_SIZE bytes remaining
    const SRTP_MAX_TRAILER_LEN: usize = 144;
    let ct_size = unsafe { len_ptr.read() as usize };
    let buf_ptr = buf_ptr.cast::<u8>();
    let buf = unsafe { std::slice::from_raw_parts_mut(buf_ptr, ct_size) };
    let pt_size = match session.srtp_unprotect_mki(buf, use_mki) {
        Ok(x) => x,
        Err(err) => return err,
    };

    unsafe { len_ptr.write(pt_size as c_int) };
    Error::Ok
}

#[no_mangle]
pub extern "C" fn srtp_protect_rtcp(
    session_ptr: srtp_t,
    buf_ptr: *mut c_void,
    len_ptr: *mut c_int,
) -> Error {
    srtp_protect_rtcp_mki(session_ptr, buf_ptr, len_ptr, 0, 0)
}

#[no_mangle]
pub extern "C" fn srtp_protect_rtcp_mki(
    session_ptr: srtp_t,
    buf_ptr: *mut c_void,
    len_ptr: *mut c_int,
    use_mki: c_uint,
    mki_index: c_uint,
) -> Error {
    let session = unsafe { session_ptr.as_mut().unwrap() };
    let use_mki = use_mki != 0;
    let mki_index = mki_index as usize;

    // Assume that the buffer has MAX_TRAILER_SIZE bytes remaining
    const SRTP_MAX_TRAILER_LEN: usize = 144;
    let pt_size = unsafe { len_ptr.read() as usize };
    let buf_ptr = buf_ptr.cast::<u8>();
    let buf_size = pt_size + SRTP_MAX_TRAILER_LEN;
    let buf = unsafe { std::slice::from_raw_parts_mut(buf_ptr, buf_size) };
    let ct_size = match session.srtcp_protect_mki(buf, pt_size, use_mki, mki_index) {
        Ok(x) => x,
        Err(err) => return err,
    };

    unsafe { len_ptr.write(ct_size as c_int) };
    Error::Ok
}

#[no_mangle]
pub extern "C" fn srtp_unprotect_rtcp(
    session_ptr: srtp_t,
    buf_ptr: *mut c_void,
    len_ptr: *mut c_int,
) -> Error {
    srtp_unprotect_rtcp_mki(session_ptr, buf_ptr, len_ptr, 0)
}

#[no_mangle]
pub extern "C" fn srtp_unprotect_rtcp_mki(
    session_ptr: srtp_t,
    buf_ptr: *mut c_void,
    len_ptr: *mut c_int,
    use_mki: c_uint,
) -> Error {
    let session = unsafe { session_ptr.as_mut().unwrap() };
    let use_mki = use_mki != 0;

    // Assume that the buffer has MAX_TRAILER_SIZE bytes remaining
    const SRTP_MAX_TRAILER_LEN: usize = 144;
    let ct_size = unsafe { len_ptr.read() as usize };
    let buf_ptr = buf_ptr.cast::<u8>();
    let buf = unsafe { std::slice::from_raw_parts_mut(buf_ptr, ct_size) };
    let pt_size = match session.srtcp_unprotect_mki(buf, use_mki) {
        Ok(x) => x,
        Err(err) => return err,
    };

    unsafe { len_ptr.write(pt_size as c_int) };
    Error::Ok
}

#[no_mangle]
pub extern "C" fn srtp_set_user_data(_session_ptr: srtp_t, _data: *mut c_void) {
    // TODO
}

#[no_mangle]
pub extern "C" fn srtp_get_user_data(_session_ptr: srtp_t) -> *mut c_void {
    std::ptr::null_mut() // TODO
}

#[no_mangle]
pub extern "C" fn srtp_get_protect_trailer_length(
    session_ptr: srtp_t,
    use_mki: u32,
    mki_index: u32,
    len_ptr: *mut u32,
) -> Error {
    let session = unsafe { session_ptr.as_mut().unwrap() };
    let use_mki = use_mki != 0;
    let mki_index = mki_index as usize;

    let trailer_size = match session.srtp_trailer_size(use_mki, mki_index) {
        Ok(x) => x,
        Err(err) => return err,
    };
    unsafe { len_ptr.write(trailer_size as u32) };
    Error::Ok
}

#[no_mangle]
pub extern "C" fn srtp_get_protect_rtcp_trailer_length(
    session_ptr: srtp_t,
    use_mki: u32,
    mki_index: u32,
    len_ptr: *mut u32,
) -> Error {
    let session = unsafe { session_ptr.as_mut().unwrap() };
    let use_mki = use_mki != 0;
    let mki_index = mki_index as usize;

    let trailer_size = match session.srtcp_trailer_size(use_mki, mki_index) {
        Ok(x) => x,
        Err(err) => return err,
    };
    unsafe { len_ptr.write(trailer_size as u32) };
    Error::Ok
}

#[no_mangle]
pub extern "C" fn srtp_set_stream_roc(session_ptr: srtp_t, ssrc: u32, roc: u32) -> Error {
    let session = unsafe { session_ptr.as_mut().unwrap() };
    just_error(session.set_stream_roc(ssrc, roc as RolloverCounter))
}

#[no_mangle]
extern "C" fn srtp_get_stream_roc(session_ptr: srtp_t, ssrc: u32, roc_ptr: *mut u32) -> Error {
    let session = unsafe { session_ptr.as_mut().unwrap() };
    let roc = match session.get_stream_roc(ssrc) {
        Ok(x) => x,
        Err(err) => return err,
    };
    unsafe { roc_ptr.write(roc) };
    Error::Ok
}

//
// Event Reporting
//
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum Event {
    SsrcCollision = 0,
    KeySoftLimit = 1,
    KeyHardLimit = 2,
    PacketIndexLimit = 3,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct srtp_event_data_t {
    pub session: srtp_t,
    pub ssrc: u32,
    pub event: Event,
}

pub type srtp_event_handler_func_t = Option<unsafe extern "C" fn(data: *mut srtp_event_data_t)>;

#[no_mangle]
pub extern "C" fn srtp_install_event_handler(_func: srtp_event_handler_func_t) -> Error {
    // TODO(RLB): It's not totally clear how to handle this without having crate::srtp::Context
    // depend on global state.  Maybe we could have a global list of outstanding contexts and use
    // that to update the contexts when the event handler changes.  For example, we might have
    // srtp_create() return something like `*mut Rc<RefCell<Context>>`, where another copy of the
    // Rc is held in global state.
    Error::Ok
}

//
// Logging
//

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum LogLevel {
    Error = 0,
    Warning = 1,
    Info = 2,
    Debug = 3,
}

pub type srtp_log_handler_func_t =
    Option<unsafe extern "C" fn(level: LogLevel, msg: *const c_char, data: *mut c_void)>;

#[no_mangle]
pub extern "C" fn srtp_install_log_handler(
    _func: srtp_log_handler_func_t,
    _data: *mut c_void,
) -> Error {
    // TODO(RLB): This should probably be handled with other debug logging.  The approach there
    // seems likely to use the global CryptoKernel to store debug modules and their state.  If
    // that's the case, we could also load this here.  Otherwise, we might need some secondary
    // global state alongside the crypto kernel.
    Error::Ok
}

//
// Misc
//

#[no_mangle]
pub extern "C" fn srtp_init() -> Error {
    let status = srtp_crypto_kernel_init();
    if status != Error::Ok {
        return status;
    }

    // TODO Load SRTP debug module into the crypto kernel

    Error::Ok
}

#[no_mangle]
pub extern "C" fn srtp_shutdown() -> Error {
    srtp_crypto_kernel_shutdown()
}

#[no_mangle]
pub extern "C" fn srtp_get_version_string() -> *const c_char {
    const VERSION_STRING: &CStr = cstr!("libsrtp_rs 0.0.1");
    VERSION_STRING.as_ptr()
}

#[no_mangle]
pub extern "C" fn srtp_get_version() -> c_uint {
    0 // TODO
}

#[no_mangle]
pub extern "C" fn srtp_set_debug_module(_mod_name: *const c_char, _v: c_int) -> Error {
    Error::Ok // TODO
}

#[no_mangle]
pub extern "C" fn srtp_list_debug_modules() -> Error {
    Error::Ok // TODO
}

#[no_mangle]
pub extern "C" fn srtp_append_salt_to_key(
    key: *mut c_uchar,
    bytes_in_key: c_uint,
    salt: *mut c_uchar,
    bytes_in_salt: c_uint,
) {
    unsafe {
        let salt_dst = key.offset(bytes_in_key as isize);
        std::ptr::copy_nonoverlapping(salt_dst, salt, bytes_in_salt as usize);
    }
}
