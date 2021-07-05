use crate::crypto_kernel::*;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum SecurityServices {
    None = 0,
    Conf = 1,
    Auth = 2,
    ConfAndAuth = 3,
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
    fn master_key_size(&self) -> usize {
        match self {
            ProfileID::Aes128CmSha180 => constants::AES_128_KEY_LEN,
            ProfileID::Aes128CmSha132 => constants::AES_128_KEY_LEN,
            ProfileID::NullSha180 => constants::AES_128_KEY_LEN,
            ProfileID::NullSha132 => constants::AES_128_KEY_LEN,
            ProfileID::AeadAes128Gcm => constants::AES_128_KEY_LEN,
            ProfileID::AeadAes256Gcm => constants::AES_256_KEY_LEN,
        }
    }

    fn master_salt_size(&self) -> usize {
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

pub struct CryptoPolicy {
    pub cipher_type: CipherTypeID,
    pub cipher_key_len: usize,
    pub auth_type: AuthTypeID,
    pub auth_key_len: usize,
    pub auth_tag_len: usize,
    pub sec_serv: SecurityServices,
}

impl CryptoPolicy {
    pub fn rtp_default() -> Self {
        Self::aes_cm_128_hmac_sha1_80()
    }

    pub fn rtcp_default() -> Self {
        Self::aes_cm_128_hmac_sha1_80()
    }

    pub fn null_cipher_null_auth() -> Self {
        // Should only be used for testing
        Self {
            cipher_type: CipherTypeID::Null,
            cipher_key_len: 0,
            auth_type: AuthTypeID::Null,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: SecurityServices::None,
        }
    }

    pub fn null_cipher_hmac_sha1_32() -> Self {
        // Corresponds to RFC 4568
        Self {
            cipher_type: CipherTypeID::Null,
            cipher_key_len: 0,
            auth_type: AuthTypeID::HmacSha1,
            auth_key_len: 20,
            auth_tag_len: 4,
            sec_serv: SecurityServices::None,
        }
    }

    pub fn null_cipher_hmac_sha1_80() -> Self {
        // Corresponds to RFC 4568
        Self {
            cipher_type: CipherTypeID::Null,
            cipher_key_len: 0,
            auth_type: AuthTypeID::HmacSha1,
            auth_key_len: 20,
            auth_tag_len: 10,
            sec_serv: SecurityServices::None,
        }
    }

    pub fn aes_cm_128_null_auth() -> Self {
        // Corresponds to RFC 4568
        // note that this crypto policy is intended for SRTP, but not SRTCP
        Self {
            cipher_type: CipherTypeID::AesIcm128,
            cipher_key_len: constants::AES_ICM_128_KEY_LEN_WSALT,
            auth_type: AuthTypeID::Null,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: SecurityServices::Conf,
        }
    }

    pub fn aes_cm_128_hmac_sha1_32() -> Self {
        // Corresponds to RFC 4568
        // note that this crypto policy is intended for SRTP, but not SRTCP
        Self {
            cipher_type: CipherTypeID::AesIcm128,
            cipher_key_len: constants::AES_ICM_128_KEY_LEN_WSALT,
            auth_type: AuthTypeID::HmacSha1,
            auth_key_len: 20,
            auth_tag_len: 4,
            sec_serv: SecurityServices::ConfAndAuth,
        }
    }

    pub fn aes_cm_128_hmac_sha1_80() -> Self {
        // Corresponds to RFC 4568
        Self {
            cipher_type: CipherTypeID::AesIcm128,
            cipher_key_len: constants::AES_ICM_128_KEY_LEN_WSALT,
            auth_type: AuthTypeID::HmacSha1,
            auth_key_len: 20,
            auth_tag_len: 10,
            sec_serv: SecurityServices::ConfAndAuth,
        }
    }

    pub fn aes_cm_192_null_auth() -> Self {
        Self::null_cipher_null_auth() // TODO
    }

    pub fn aes_cm_192_hmac_sha1_32() -> Self {
        Self::null_cipher_null_auth() // TODO
    }

    pub fn aes_cm_192_hmac_sha1_80() -> Self {
        Self::null_cipher_null_auth() // TODO
    }

    pub fn aes_cm_256_null_auth() -> Self {
        // Corresponds to RFC 4568
        // note that this crypto policy is intended for SRTP, but not SRTCP
        Self {
            cipher_type: CipherTypeID::AesIcm256,
            cipher_key_len: constants::AES_ICM_256_KEY_LEN_WSALT,
            auth_type: AuthTypeID::Null,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: SecurityServices::Conf,
        }
    }

    pub fn aes_cm_256_hmac_sha1_32() -> Self {
        // Corresponds to RFC 4568
        // note that this crypto policy is intended for SRTP, but not SRTCP
        Self {
            cipher_type: CipherTypeID::AesIcm256,
            cipher_key_len: constants::AES_ICM_256_KEY_LEN_WSALT,
            auth_type: AuthTypeID::HmacSha1,
            auth_key_len: 20,
            auth_tag_len: 4,
            sec_serv: SecurityServices::ConfAndAuth,
        }
    }

    pub fn aes_cm_256_hmac_sha1_80() -> Self {
        // Corresponds to RFC 4568
        Self {
            cipher_type: CipherTypeID::AesIcm256,
            cipher_key_len: constants::AES_ICM_256_KEY_LEN_WSALT,
            auth_type: AuthTypeID::HmacSha1,
            auth_key_len: 20,
            auth_tag_len: 10,
            sec_serv: SecurityServices::ConfAndAuth,
        }
    }

    pub fn aes_gcm_128() -> Self {
        // Corresponds to RFC 7714
        Self {
            cipher_type: CipherTypeID::AesGcm128,
            cipher_key_len: constants::AES_GCM_128_KEY_LEN_WSALT,
            auth_type: AuthTypeID::Null,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: SecurityServices::ConfAndAuth,
        }
    }

    pub fn aes_gcm_256() -> Self {
        // Corresponds to RFC 7714
        Self {
            cipher_type: CipherTypeID::AesGcm256,
            cipher_key_len: constants::AES_GCM_256_KEY_LEN_WSALT,
            auth_type: AuthTypeID::Null,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: SecurityServices::ConfAndAuth,
        }
    }

    pub fn from_profile_rtp(id: ProfileID) -> Self {
        match id {
            ProfileID::Aes128CmSha180 => Self::aes_cm_128_hmac_sha1_80(),
            ProfileID::Aes128CmSha132 => Self::aes_cm_128_hmac_sha1_32(),
            ProfileID::NullSha180 => Self::null_cipher_hmac_sha1_80(),
            ProfileID::NullSha132 => Self::null_cipher_hmac_sha1_32(),
            ProfileID::AeadAes128Gcm => Self::aes_gcm_128(),
            ProfileID::AeadAes256Gcm => Self::aes_gcm_256(),
        }
    }

    pub fn from_profile_rtcp(id: ProfileID) -> Self {
        match id {
            ProfileID::Aes128CmSha180 => Self::aes_cm_128_hmac_sha1_80(),
            ProfileID::Aes128CmSha132 => Self::aes_cm_128_hmac_sha1_32(),
            ProfileID::NullSha180 => Self::null_cipher_hmac_sha1_80(),
            // We do not honor the 32-bit auth tag request
            // since this is not compliant with RFC 3711
            ProfileID::NullSha132 => Self::null_cipher_hmac_sha1_80(),
            ProfileID::AeadAes128Gcm => Self::aes_gcm_128(),
            ProfileID::AeadAes256Gcm => Self::aes_gcm_256(),
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

pub struct Ssrc {
    pub type_: SsrcType,
    pub value: u32,
}

pub struct MasterKey {
    pub key: Vec<u8>,
    pub salt: Vec<u8>,
    pub id: Vec<u8>,
}

pub type ExtensionHeaderId = u8;

pub struct Policy {
    pub ssrc: Ssrc,
    pub rtp: CryptoPolicy,
    pub rtcp: CryptoPolicy,
    pub keys: Vec<MasterKey>,
    pub window_size: usize,
    pub allow_repeat_tx: bool,
    pub enc_xtn_hdr: Vec<ExtensionHeaderId>,
}

impl Policy {
    pub fn validate_master_keys(&self) -> bool {
        self.keys.is_empty()
    }
}
