use crate::crypto_kernel::*;
use crate::kdf::*;
use crate::key_limit::*;
use crate::policy::*;
use crate::replay::*;
use std::collections::LinkedList;

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Ok = 0, // included for backward compatibility

    // TODO(RLB): During translation, we are promoting this as needed, to make sure we only end up with the set we need
    Fail = 1,       // unspecified failure
    BadParam = 2,   // unsupported parameter
    InitFail = 5,   // couldn't initialize
    Terminus = 6,   // can't process as much data as requested
    CipherFail = 8, // cipher failure
    ReplayFail = 9, // replay check failed (bad index)
    ReplayOld = 10, // replay check failed (index too old)
    AlgoFail = 11,  // algorithm failed test routine
    NoSuchOp = 12,  // unsupported operation
    KeyExpired = 15, // can't use key any more

                    /*
                    alloc_fail = 3,     // couldn't allocate memory
                    dealloc_fail = 4,   // couldn't deallocate properly
                    auth_fail = 7,      // authentication failure
                    no_ctx = 13,        // no appropriate context found
                    cant_check = 14,    // unable to perform desired validation
                    socket_err = 16,    // error in use of socket
                    signal_err = 17,    // error in use POSIX signals
                    nonce_bad = 18,     // nonce check failed
                    read_fail = 19,     // couldn't read data
                    write_fail = 20,    // couldn't write data
                    parse_err = 21,     // error parsing data
                    encode_err = 22,    // error encoding data
                    semaphore_err = 23, // error while using semaphores
                    pfkey_err = 24,     // error while using pfkey
                    bad_mki = 25,       // error MKI present in packet is invalid
                    pkt_idx_old = 26,   // packet index is too old to consider
                    pkt_idx_adv = 27,   // packet index advanced, reset needed
                    */
}

enum Direction {
    Unknown = 0,
    Sender = 1,
    Receiver = 2,
}

struct SessionKeys {
    rtp_cipher: Box<dyn Cipher>,
    rtp_xtn_hdr_cipher: Box<dyn Cipher>,
    rtp_auth: Box<dyn Auth>,
    rtcp_cipher: Box<dyn Cipher>,
    rtcp_auth: Box<dyn Auth>,

    salt: Vec<u8>,
    c_salt: Vec<u8>,
    mki_id: Vec<u8>,
    limit: KeyLimitContext,
}

fn base_key_size(id: CipherTypeID, key_size: usize) -> usize {
    match id {
        CipherTypeID::Null => key_size,
        CipherTypeID::AesIcm128 => key_size - constants::SALT_LEN,
        CipherTypeID::AesIcm192 => key_size - constants::SALT_LEN,
        CipherTypeID::AesIcm256 => key_size - constants::SALT_LEN,
        CipherTypeID::AesGcm128 => key_size - constants::AEAD_SALT_LEN,
        CipherTypeID::AesGcm256 => key_size - constants::AEAD_SALT_LEN,
    }
}

const MAX_SRTP_KEY_SIZE: usize = 46; // XXX

impl SessionKeys {
    fn new(
        kernel: &CryptoKernel,
        key: &MasterKey,
        rtp: &CryptoPolicy,
        rtcp: &CryptoPolicy,
    ) -> Result<Self, Error> {
        // Allocate ciphers
        let xtn_hdr_cipher_type = rtp.cipher_type;
        let xtn_hdr_key_len = rtp.cipher_key_len;
        // TODO(RLB) if GCM, use corresponding ICM

        let mut sk = SessionKeys {
            rtp_cipher: kernel.cipher(rtp.cipher_type, rtp.cipher_key_len, rtp.auth_tag_len)?,
            rtp_xtn_hdr_cipher: kernel.cipher(
                xtn_hdr_cipher_type,
                xtn_hdr_key_len,
                rtp.auth_tag_len,
            )?,
            rtp_auth: kernel.auth(rtp.auth_type, rtp.auth_key_len, rtp.auth_tag_len)?,
            rtcp_cipher: kernel.cipher(rtcp.cipher_type, rtcp.cipher_key_len, rtcp.auth_tag_len)?,
            rtcp_auth: kernel.auth(rtcp.auth_type, rtcp.auth_key_len, rtcp.auth_tag_len)?,

            salt: Vec::new(),
            c_salt: Vec::new(),
            mki_id: key.id.clone(),
            limit: KeyLimitContext::new(),
        };

        // Set up KDF
        let rtp_key_size = sk.rtp_cipher.key_size();
        let rtcp_key_size = sk.rtcp_cipher.key_size();
        let rtp_base_key_size = base_key_size(rtp.cipher_type, rtp_key_size);
        let rtcp_base_key_size = base_key_size(rtcp.cipher_type, rtcp_key_size);
        if key.key.len() != rtp_key_size {
            return Err(Error::BadParam);
        }

        let mut kdf_key_size = 30;
        if (rtp_key_size > kdf_key_size) || (rtcp_key_size > kdf_key_size) {
            // AES-CTR mode is always used for KDF
            // XXX(RLB) ???
            kdf_key_size = 46;
        }

        let mut kdf_key = [0u8; MAX_SRTP_KEY_SIZE];
        kdf_key[..key.key.len()].copy_from_slice(&key.key);
        let mut kdf = KDF::new(kernel, &kdf_key[..kdf_key_size])?;

        // Initialize RTP cipher
        let mut tmp_key = [0u8; MAX_SRTP_KEY_SIZE];
        kdf.generate(KdfLabel::RtpEncryption, &mut tmp_key[..rtp_base_key_size])?;
        kdf.generate(
            KdfLabel::RtpSalt,
            &mut tmp_key[rtp_base_key_size..rtp_key_size],
        )?;

        sk.rtp_cipher.init(&tmp_key[..rtp_key_size])?;
        sk.salt = tmp_key[rtp_base_key_size..rtp_key_size].to_vec();

        // Initialize RTP extension header cipher
        // TODO(RLB): This might require adaptation to use a different KDF for GCM ciphers (?)
        if xtn_hdr_cipher_type != rtp.cipher_type {
            return Err(Error::BadParam);
        }
        let xtn_hdr_key_size = sk.rtp_cipher.key_size();
        let xtn_hdr_base_key_size = base_key_size(xtn_hdr_cipher_type, xtn_hdr_key_size);

        tmp_key = [0u8; MAX_SRTP_KEY_SIZE];
        kdf.generate(
            KdfLabel::RtpHeaderEncryption,
            &mut tmp_key[..xtn_hdr_base_key_size],
        )?;
        kdf.generate(
            KdfLabel::RtpHeaderSalt,
            &mut tmp_key[xtn_hdr_base_key_size..xtn_hdr_key_size],
        )?;

        sk.rtp_xtn_hdr_cipher
            .init(&mut tmp_key[..xtn_hdr_key_size])?;

        // Initialize RTP authentication
        tmp_key = [0u8; MAX_SRTP_KEY_SIZE];
        {
            let auth_key = &mut tmp_key[..sk.rtp_auth.key_size()];
            kdf.generate(KdfLabel::RtpMsgAuth, auth_key)?;
            sk.rtp_auth.init(auth_key)?;
        }

        // Initialize RTCP encryption
        let mut tmp_key = [0u8; MAX_SRTP_KEY_SIZE];
        kdf.generate(KdfLabel::RtcpEncryption, &mut tmp_key[..rtcp_base_key_size])?;
        kdf.generate(
            KdfLabel::RtcpSalt,
            &mut tmp_key[rtcp_base_key_size..rtcp_key_size],
        )?;

        sk.rtcp_cipher.init(&tmp_key[..rtcp_key_size])?;
        sk.c_salt = tmp_key[rtcp_base_key_size..rtcp_key_size].to_vec();

        // Initialize RTCP authentication
        tmp_key = [0u8; MAX_SRTP_KEY_SIZE];
        {
            let auth_key = &mut tmp_key[..sk.rtcp_auth.key_size()];
            kdf.generate(KdfLabel::RtcpMsgAuth, auth_key)?;
            sk.rtcp_auth.init(auth_key)?;
        }

        Ok(sk)
    }
}

struct Stream {
    ssrc: u32,
    session_keys: Vec<SessionKeys>,
    rtp_rdbx: ExtendedReplayDB,
    rtp_rdb: ReplayDB,
    rtp_services: SecurityServices,
    rtcp_services: SecurityServices,
    direction: Direction,
    allow_repeat_tx: bool,
    enc_xtn_hdr: Vec<ExtensionHeaderId>,
    pending_roc: u32,
}

impl Stream {
    // XXX(RLB) This method combins srtp_stream_alloc and srtp_stream_init, since they are only
    // ever called together.
    fn new(kernel: &CryptoKernel, policy: &Policy) -> Result<Self, Error> {
        // Set up SessionKeys for each master key
        let mut session_keys = Vec::<SessionKeys>::new();
        if let Some(key) = &policy.key {
            let mk = MasterKey {
                key: key.clone(),
                id: vec![],
            };
            session_keys.push(SessionKeys::new(kernel, &mk, &policy.rtp, &policy.rtcp)?);
        } else {
            session_keys = Vec::<SessionKeys>::with_capacity(policy.keys.len());
            for mk in &policy.keys {
                session_keys.push(SessionKeys::new(kernel, &mk, &policy.rtp, &policy.rtcp)?);
            }
        };

        Ok(Stream {
            ssrc: policy.ssrc.value,
            session_keys: session_keys,
            rtp_rdbx: ExtendedReplayDB::new(policy.window_size)?,
            rtp_rdb: ReplayDB::new(),
            rtp_services: policy.rtp.sec_serv,
            rtcp_services: policy.rtp.sec_serv,
            direction: Direction::Unknown,
            allow_repeat_tx: policy.allow_repeat_tx,
            enc_xtn_hdr: policy.enc_xtn_hdr.clone(),
            pending_roc: 0,
        })
    }

    // TODO pub fn clone(ssrc: u32) -> Result<Self, Error>
}

pub struct Context {
    streams: LinkedList<Stream>,
    stream_template: Option<Stream>,
    // XXX(RLB) user_data: Box<dyn Any> ?
}

impl Context {
    pub fn new(kernel: &CryptoKernel, policies: &[Policy]) -> Result<Self, Error> {
        let mut ctx = Self {
            streams: LinkedList::new(),
            stream_template: None,
            // XXX(RLB) user
        };

        for p in policies {
            if let Err(err) = ctx.add_stream(kernel, p) {
                return Err(err);
            }
        }

        Ok(ctx)
    }

    pub fn add_stream(&mut self, kernel: &CryptoKernel, policy: &Policy) -> Result<(), Error> {
        let stream = match Stream::new(kernel, policy) {
            Ok(x) => x,
            Err(err) => return Err(err),
        };

        match policy.ssrc.type_ {
            SsrcType::Specific => {
                // SSRC-specific streams are added to the stream list
                self.streams.push_front(stream);
                Ok(())
            }
            SsrcType::Inbound | SsrcType::Outbound => {
                // A wildcard inbound or outbound policy sets the stream template.  If the template
                // is already set, then the policy set is inconsistent.
                if let Some(_) = self.stream_template {
                    return Err(Error::BadParam);
                }

                self.stream_template = Some(stream);
                Ok(())
            }
            _ => Err(Error::BadParam),
        }
    }

    fn get_stream(&self, ssrc: u32) -> Option<&Stream> {
        for stream in &self.streams {
            if stream.ssrc == ssrc {
                return Some(stream);
            }
        }
        None
    }

    // TODO remove_stream
    // TODO update
    // TODO update_stream

    // TODO srtp_protect
    // TODO srtp_protect_mki

    // TODO srtp_unprotect
    // TODO srtp_unprotect_mki

    // TODO srtcp_protect
    // TODO srtcp_protect_mki

    // TODO srtcp_unprotect
    // TODO srtcp_unprotect_mki
}
