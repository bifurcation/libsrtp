use crate::crypto_kernel::*;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum SecurityServices {
    None = 0,
    Conf = 1,
    Auth = 2,
    ConfAndAuth = 3,
}

impl SecurityServices {
    pub fn confidentiality(&self) -> bool {
        match self {
            SecurityServices::None | SecurityServices::Auth => false,
            SecurityServices::Conf | SecurityServices::ConfAndAuth => true,
        }
    }

    pub fn authenticity(&self) -> bool {
        match self {
            SecurityServices::None | SecurityServices::Conf => false,
            SecurityServices::Auth | SecurityServices::ConfAndAuth => true,
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum ProfileID {
    Aes128CmSha180 = 1,
    Aes128CmSha132 = 2,
    NullSha180 = 5,
    NullSha132 = 6,
    AeadAes128Gcm = 7,
    AeadAes256Gcm = 8,
}

impl ProfileID {
    pub fn master_key_size(&self) -> usize {
        match self {
            ProfileID::Aes128CmSha180 => constants::AES_128_KEY_LEN,
            ProfileID::Aes128CmSha132 => constants::AES_128_KEY_LEN,
            ProfileID::NullSha180 => constants::AES_128_KEY_LEN,
            ProfileID::NullSha132 => constants::AES_128_KEY_LEN,
            ProfileID::AeadAes128Gcm => constants::AES_128_KEY_LEN,
            ProfileID::AeadAes256Gcm => constants::AES_256_KEY_LEN,
        }
    }

    pub fn master_salt_size(&self) -> usize {
        match self {
            ProfileID::Aes128CmSha180 => constants::SALT_LEN,
            ProfileID::Aes128CmSha132 => constants::SALT_LEN,
            ProfileID::NullSha180 => constants::SALT_LEN,
            ProfileID::NullSha132 => constants::SALT_LEN,
            ProfileID::AeadAes128Gcm => constants::AEAD_SALT_LEN,
            ProfileID::AeadAes256Gcm => constants::AEAD_SALT_LEN,
        }
    }
}

#[derive(Copy, Clone)]
pub struct CryptoPolicy {
    pub cipher_type: CipherTypeID,
    pub cipher_key_len: usize,
    pub auth_type: AuthTypeID,
    pub auth_key_len: usize,
    pub auth_tag_len: usize,
    pub sec_serv: SecurityServices,
}

impl CryptoPolicy {
    pub const RTP_DEFAULT: Self = Self::AES_CM_128_HMAC_SHA1_80;
    pub const RTCP_DEFAULT: Self = Self::AES_CM_128_HMAC_SHA1_80;

    // Should only be used for testing
    pub const NULL_CIPHER_NULL_AUTH: Self = Self {
        cipher_type: CipherTypeID::Null,
        cipher_key_len: 0,
        auth_type: AuthTypeID::Null,
        auth_key_len: 0,
        auth_tag_len: 0,
        sec_serv: SecurityServices::None,
    };

    // Corresponds to RFC 4568
    pub const NULL_CIPHER_HMAC_SHA1_32: Self = Self {
        cipher_type: CipherTypeID::Null,
        cipher_key_len: 0,
        auth_type: AuthTypeID::HmacSha1,
        auth_key_len: 20,
        auth_tag_len: 4,
        sec_serv: SecurityServices::None,
    };

    // Corresponds to RFC 4568
    pub const NULL_CIPHER_HMAC_SHA1_80: Self = Self {
        cipher_type: CipherTypeID::Null,
        cipher_key_len: 0,
        auth_type: AuthTypeID::HmacSha1,
        auth_key_len: 20,
        auth_tag_len: 10,
        sec_serv: SecurityServices::None,
    };

    // Corresponds to RFC 4568
    // note that this crypto policy is intended for SRTP, but not SRTCP
    pub const AES_CM_128_NULL_AUTH: Self = Self {
        cipher_type: CipherTypeID::AesIcm128,
        cipher_key_len: constants::AES_ICM_128_KEY_LEN_WSALT,
        auth_type: AuthTypeID::Null,
        auth_key_len: 0,
        auth_tag_len: 0,
        sec_serv: SecurityServices::Conf,
    };

    // Corresponds to RFC 4568
    // note that this crypto policy is intended for SRTP, but not SRTCP
    pub const AES_CM_128_HMAC_SHA1_32: Self = Self {
        cipher_type: CipherTypeID::AesIcm128,
        cipher_key_len: constants::AES_ICM_128_KEY_LEN_WSALT,
        auth_type: AuthTypeID::HmacSha1,
        auth_key_len: 20,
        auth_tag_len: 4,
        sec_serv: SecurityServices::ConfAndAuth,
    };

    // Corresponds to RFC 4568
    pub const AES_CM_128_HMAC_SHA1_80: Self = Self {
        cipher_type: CipherTypeID::AesIcm128,
        cipher_key_len: constants::AES_ICM_128_KEY_LEN_WSALT,
        auth_type: AuthTypeID::HmacSha1,
        auth_key_len: 20,
        auth_tag_len: 10,
        sec_serv: SecurityServices::ConfAndAuth,
    };

    pub const AES_CM_192_NULL_AUTH: Self = Self::NULL_CIPHER_NULL_AUTH; // TODO
    pub const AES_CM_192_HMAC_SHA1_32: Self = Self::NULL_CIPHER_NULL_AUTH; // TODO
    pub const AES_CM_192_HMAC_SHA1_80: Self = Self::NULL_CIPHER_NULL_AUTH; // TODO

    // Corresponds to RFC 4568
    // note that this crypto policy is intended for SRTP, but not SRTCP
    pub const AES_CM_256_NULL_AUTH: Self = Self {
        cipher_type: CipherTypeID::AesIcm256,
        cipher_key_len: constants::AES_ICM_256_KEY_LEN_WSALT,
        auth_type: AuthTypeID::Null,
        auth_key_len: 0,
        auth_tag_len: 0,
        sec_serv: SecurityServices::Conf,
    };

    // Corresponds to RFC 4568
    // note that this crypto policy is intended for SRTP, but not SRTCP
    pub const AES_CM_256_HMAC_SHA1_32: Self = Self {
        cipher_type: CipherTypeID::AesIcm256,
        cipher_key_len: constants::AES_ICM_256_KEY_LEN_WSALT,
        auth_type: AuthTypeID::HmacSha1,
        auth_key_len: 20,
        auth_tag_len: 4,
        sec_serv: SecurityServices::ConfAndAuth,
    };

    // Corresponds to RFC 4568
    pub const AES_CM_256_HMAC_SHA1_80: Self = Self {
        cipher_type: CipherTypeID::AesIcm256,
        cipher_key_len: constants::AES_ICM_256_KEY_LEN_WSALT,
        auth_type: AuthTypeID::HmacSha1,
        auth_key_len: 20,
        auth_tag_len: 10,
        sec_serv: SecurityServices::ConfAndAuth,
    };

    // Corresponds to RFC 7714
    pub const AES_GCM_128: Self = Self {
        cipher_type: CipherTypeID::AesGcm128,
        cipher_key_len: constants::AES_GCM_128_KEY_LEN_WSALT,
        auth_type: AuthTypeID::Null,
        auth_key_len: 0,
        auth_tag_len: 0,
        sec_serv: SecurityServices::ConfAndAuth,
    };

    // Corresponds to RFC 7714
    pub const AES_GCM_256: Self = Self {
        cipher_type: CipherTypeID::AesGcm256,
        cipher_key_len: constants::AES_GCM_256_KEY_LEN_WSALT,
        auth_type: AuthTypeID::Null,
        auth_key_len: 0,
        auth_tag_len: 0,
        sec_serv: SecurityServices::ConfAndAuth,
    };

    pub const fn from_profile_rtp(id: ProfileID) -> Self {
        match id {
            ProfileID::Aes128CmSha180 => Self::AES_CM_128_HMAC_SHA1_80,
            ProfileID::Aes128CmSha132 => Self::AES_CM_128_HMAC_SHA1_32,
            ProfileID::NullSha180 => Self::NULL_CIPHER_HMAC_SHA1_80,
            ProfileID::NullSha132 => Self::NULL_CIPHER_HMAC_SHA1_32,
            ProfileID::AeadAes128Gcm => Self::AES_GCM_128,
            ProfileID::AeadAes256Gcm => Self::AES_GCM_256,
        }
    }

    pub const fn from_profile_rtcp(id: ProfileID) -> Self {
        match id {
            ProfileID::Aes128CmSha180 => Self::AES_CM_128_HMAC_SHA1_80,
            ProfileID::Aes128CmSha132 => Self::AES_CM_128_HMAC_SHA1_32,
            ProfileID::NullSha180 => Self::NULL_CIPHER_HMAC_SHA1_80,
            // We do not honor the 32-bit auth tag request
            // since this is not compliant with RFC 3711
            ProfileID::NullSha132 => Self::NULL_CIPHER_HMAC_SHA1_80,
            ProfileID::AeadAes128Gcm => Self::AES_GCM_128,
            ProfileID::AeadAes256Gcm => Self::AES_GCM_256,
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

#[derive(Copy, Clone)]
pub struct Ssrc {
    pub type_: SsrcType,
    pub value: u32,
}

#[derive(Clone)]
pub struct MasterKey {
    pub key: Vec<u8>,
    pub salt: Vec<u8>,
    pub id: Vec<u8>,
}

pub type ExtensionHeaderId = u8;

#[derive(Clone)]
pub struct Policy {
    pub ssrc: Ssrc,
    pub rtp: CryptoPolicy,
    pub rtcp: CryptoPolicy,
    pub keys: Vec<MasterKey>,
    pub window_size: usize,
    pub allow_repeat_tx: bool,
    pub xtn_headers_to_encrypt: Vec<ExtensionHeaderId>,
}

impl Policy {
    pub fn validate_master_keys(&self) -> bool {
        !self.keys.is_empty()
    }
}
