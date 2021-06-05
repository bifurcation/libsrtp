// Because this is a C interface file, matching C names is more ergonomic than being rustic
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

use crate::crypto_kernel::{AuthTypeID, CipherTypeID};
use crate::srtp::Error;
use std::os::raw::{c_char, c_int, c_uchar, c_uint, c_ulong, c_void};

pub const SRTP_MAX_KEY_LEN: u32 = 64;
pub const SRTP_MAX_TAG_LEN: u32 = 16;
pub const SRTP_MAX_MKI_LEN: u32 = 128;
pub const SRTP_MAX_TRAILER_LEN: u32 = 144;
pub const SRTP_MAX_NUM_MASTER_KEYS: u32 = 16;
pub const SRTP_SALT_LEN: u32 = 14;
pub const SRTP_AEAD_SALT_LEN: u32 = 12;
pub const SRTP_AES_128_KEY_LEN: u32 = 16;
pub const SRTP_AES_192_KEY_LEN: u32 = 24;
pub const SRTP_AES_256_KEY_LEN: u32 = 32;
pub const SRTP_AES_ICM_128_KEY_LEN_WSALT: u32 = 30;
pub const SRTP_AES_ICM_192_KEY_LEN_WSALT: u32 = 38;
pub const SRTP_AES_ICM_256_KEY_LEN_WSALT: u32 = 46;
pub const SRTP_AES_GCM_128_KEY_LEN_WSALT: u32 = 28;
pub const SRTP_AES_GCM_192_KEY_LEN_WSALT: u32 = 36;
pub const SRTP_AES_GCM_256_KEY_LEN_WSALT: u32 = 44;
pub const SRTCP_E_BIT: u32 = 2147483648;
pub const SRTCP_E_BYTE_BIT: u32 = 128;
pub const SRTCP_INDEX_MASK: u32 = 2147483647;

//
// Profile
//

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum ProfileID {
    Reserved = 0,
    Aes128CmSha180 = 1,
    Aes128CmSha132 = 2,
    NullSha180 = 5,
    NullSha132 = 6,
    AeadAes128Gcm = 7,
    AeadAes256Gcm = 8,
}

extern "C" {
    pub fn srtp_profile_get_master_key_length(profile: ProfileID) -> c_uint;
    pub fn srtp_profile_get_master_salt_length(profile: ProfileID) -> c_uint;
}

//
// Policy
//

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum SecurityServices {
    None = 0,
    Conf = 1,
    Auth = 2,
    ConfAndAUth = 3,
}

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

extern "C" {
    pub fn srtp_crypto_policy_set_rtp_default(p: *mut srtp_crypto_policy_t);
    pub fn srtp_crypto_policy_set_rtcp_default(p: *mut srtp_crypto_policy_t);
    pub fn srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(p: *mut srtp_crypto_policy_t);
    pub fn srtp_crypto_policy_set_aes_cm_128_null_auth(p: *mut srtp_crypto_policy_t);
    pub fn srtp_crypto_policy_set_null_cipher_hmac_sha1_80(p: *mut srtp_crypto_policy_t);
    pub fn srtp_crypto_policy_set_null_cipher_hmac_null(p: *mut srtp_crypto_policy_t);
    pub fn srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(p: *mut srtp_crypto_policy_t);
    pub fn srtp_crypto_policy_set_aes_cm_256_hmac_sha1_32(p: *mut srtp_crypto_policy_t);
    pub fn srtp_crypto_policy_set_aes_cm_256_null_auth(p: *mut srtp_crypto_policy_t);
    pub fn srtp_crypto_policy_set_aes_cm_192_hmac_sha1_80(p: *mut srtp_crypto_policy_t);
    pub fn srtp_crypto_policy_set_aes_cm_192_hmac_sha1_32(p: *mut srtp_crypto_policy_t);
    pub fn srtp_crypto_policy_set_aes_cm_192_null_auth(p: *mut srtp_crypto_policy_t);
    pub fn srtp_crypto_policy_set_aes_gcm_128_8_auth(p: *mut srtp_crypto_policy_t);
    pub fn srtp_crypto_policy_set_aes_gcm_256_8_auth(p: *mut srtp_crypto_policy_t);
    pub fn srtp_crypto_policy_set_aes_gcm_128_8_only_auth(p: *mut srtp_crypto_policy_t);
    pub fn srtp_crypto_policy_set_aes_gcm_256_8_only_auth(p: *mut srtp_crypto_policy_t);
    pub fn srtp_crypto_policy_set_aes_gcm_128_16_auth(p: *mut srtp_crypto_policy_t);
    pub fn srtp_crypto_policy_set_aes_gcm_256_16_auth(p: *mut srtp_crypto_policy_t);
    pub fn srtp_crypto_policy_set_from_profile_for_rtp(
        policy: *mut srtp_crypto_policy_t,
        profile: ProfileID,
    ) -> Error;
    pub fn srtp_crypto_policy_set_from_profile_for_rtcp(
        policy: *mut srtp_crypto_policy_t,
        profile: ProfileID,
    ) -> Error;
}

//
// Srtp
//

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct srtp_ctx_t_ {
    _unused: [u8; 0],
}
pub type srtp_ctx_t = srtp_ctx_t_;

pub type srtp_t = *mut srtp_ctx_t;
extern "C" {
    pub fn srtp_create(session: *mut srtp_t, policy: *const srtp_policy_t) -> Error;
    pub fn srtp_add_stream(session: srtp_t, policy: *const srtp_policy_t) -> Error;
    pub fn srtp_remove_stream(session: srtp_t, ssrc: c_uint) -> Error;
    pub fn srtp_update(session: srtp_t, policy: *const srtp_policy_t) -> Error;
    pub fn srtp_update_stream(session: srtp_t, policy: *const srtp_policy_t) -> Error;
    pub fn srtp_dealloc(s: srtp_t) -> Error;

    pub fn srtp_protect(ctx: srtp_t, rtp_hdr: *mut c_void, len_ptr: *mut c_int) -> Error;
    pub fn srtp_protect_mki(
        ctx: *mut srtp_ctx_t,
        rtp_hdr: *mut c_void,
        pkt_octet_len: *mut c_int,
        use_mki: c_uint,
        mki_index: c_uint,
    ) -> Error;

    pub fn srtp_unprotect(ctx: srtp_t, srtp_hdr: *mut c_void, len_ptr: *mut c_int) -> Error;
    pub fn srtp_unprotect_mki(
        ctx: srtp_t,
        srtp_hdr: *mut c_void,
        len_ptr: *mut c_int,
        use_mki: c_uint,
    ) -> Error;

    pub fn srtp_protect_rtcp(
        ctx: srtp_t,
        rtcp_hdr: *mut c_void,
        pkt_octet_len: *mut c_int,
    ) -> Error;
    pub fn srtp_protect_rtcp_mki(
        ctx: srtp_t,
        rtcp_hdr: *mut c_void,
        pkt_octet_len: *mut c_int,
        use_mki: c_uint,
        mki_index: c_uint,
    ) -> Error;

    pub fn srtp_unprotect_rtcp(
        ctx: srtp_t,
        srtcp_hdr: *mut c_void,
        pkt_octet_len: *mut c_int,
    ) -> Error;
    pub fn srtp_unprotect_rtcp_mki(
        ctx: srtp_t,
        srtcp_hdr: *mut c_void,
        pkt_octet_len: *mut c_int,
        use_mki: c_uint,
    ) -> Error;

    pub fn srtp_set_user_data(ctx: srtp_t, data: *mut c_void);
    pub fn srtp_get_user_data(ctx: srtp_t) -> *mut c_void;
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
extern "C" {
    pub fn srtp_install_event_handler(func: srtp_event_handler_func_t) -> Error;
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
extern "C" {
    pub fn srtp_install_log_handler(func: srtp_log_handler_func_t, data: *mut c_void) -> Error;
}

//
// Misc
//

extern "C" {
    pub fn srtp_init() -> Error;
    pub fn srtp_shutdown() -> Error;

    pub fn srtp_get_version_string() -> *const c_char;
    pub fn srtp_get_version() -> c_uint;

    pub fn srtp_set_debug_module(mod_name: *const c_char, v: c_int) -> Error;
    pub fn srtp_list_debug_modules() -> Error;

    pub fn srtp_append_salt_to_key(
        key: *mut c_uchar,
        bytes_in_key: c_uint,
        salt: *mut c_uchar,
        bytes_in_salt: c_uint,
    );

    pub fn srtp_get_protect_trailer_length(
        session: srtp_t,
        use_mki: u32,
        mki_index: u32,
        length: *mut u32,
    ) -> Error;
    pub fn srtp_get_protect_rtcp_trailer_length(
        session: srtp_t,
        use_mki: u32,
        mki_index: u32,
        length: *mut u32,
    ) -> Error;

    pub fn srtp_set_stream_roc(session: srtp_t, ssrc: u32, roc: u32) -> Error;
    pub fn srtp_get_stream_roc(session: srtp_t, ssrc: u32, roc: *mut u32) -> Error;
}
