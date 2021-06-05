use crate::crypto_kernel::*;
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

    salt: [u8; 0],   // XXX SRTP_AEAD_SALT_LEN
    c_salt: [u8; 0], // XXX SRTP_AEAD_SALT_LEN
    mki_id: Option<u8>,
    mki_size: usize,
    limit: KeyLimitContext,
}

struct Stream {
    ssrc: u32,
    session_keys: SessionKeys,
    num_master_keys: usize,
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
    fn new(kernel: &CryptoKernel, policy: &Policy) -> Result<Self, Error> {
        Err(Error::Fail) // TODO
    }
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
}
