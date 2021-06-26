use crate::crypto_kernel::*;
use crate::kdf::*;
use crate::key_limit::*;
use crate::policy::*;
use crate::replay::*;
use constant_time_eq::constant_time_eq;
use core::iter::Iterator;
use std::ops::Range;

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Ok = 0, // included for backward compatibility

    // TODO(RLB): During translation, we are promoting this as needed, to make sure we only end up with the set we need
    Fail = 1,        // unspecified failure
    BadParam = 2,    // unsupported parameter
    InitFail = 5,    // couldn't initialize
    Terminus = 6,    // can't process as much data as requested
    AuthFail = 7,    // authentication failure
    CipherFail = 8,  // cipher failure
    ReplayFail = 9,  // replay check failed (bad index)
    ReplayOld = 10,  // replay check failed (index too old)
    AlgoFail = 11,   // algorithm failed test routine
    NoSuchOp = 12,   // unsupported operation
    NoContext = 13,  // no appropriate context found
    KeyExpired = 15, // can't use key any more
    BadMki = 25,     // error MKI present in packet is invalid

                     /*
                     alloc_fail = 3,     // couldn't allocate memory
                     dealloc_fail = 4,   // couldn't deallocate properly
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
                     pkt_idx_old = 26,   // packet index is too old to consider
                     pkt_idx_adv = 27,   // packet index advanced, reset needed
                     */
}

#[derive(Clone, PartialEq, Eq)]
enum Direction {
    Unknown = 0,
    Sender = 1,
    Receiver = 2,
}

#[derive(Clone)]
pub struct SessionKeys {
    pub rtp_cipher: Box<dyn Cipher>,
    pub rtp_xtn_hdr_cipher: Box<dyn Cipher>,
    pub rtp_auth: Box<dyn Auth>,
    pub rtcp_cipher: Box<dyn Cipher>,
    pub rtcp_auth: Box<dyn Auth>,

    pub salt: Vec<u8>,
    pub c_salt: Vec<u8>,
    pub mki_id: Vec<u8>,
    pub limit: KeyLimitContext,
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

        let mut rtp_cipher =
            kernel.cipher(rtp.cipher_type, rtp.cipher_key_len, rtp.auth_tag_len)?;
        let mut rtp_xtn_hdr_cipher =
            kernel.cipher(xtn_hdr_cipher_type, xtn_hdr_key_len, rtp.auth_tag_len)?;
        let mut rtp_auth = kernel.auth(rtp.auth_type, rtp.auth_key_len, rtp.auth_tag_len)?;
        let mut rtcp_cipher =
            kernel.cipher(rtcp.cipher_type, rtcp.cipher_key_len, rtcp.auth_tag_len)?;
        let mut rtcp_auth = kernel.auth(rtcp.auth_type, rtcp.auth_key_len, rtcp.auth_tag_len)?;

        // Set up KDF
        let rtp_key_size = rtp_cipher.key_size();
        let rtcp_key_size = rtcp_cipher.key_size();
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

        rtp_cipher.init(&tmp_key[..rtp_key_size])?;
        let salt = tmp_key[rtp_base_key_size..rtp_key_size].to_vec();

        // Initialize RTP extension header cipher
        // TODO(RLB): This might require adaptation to use a different KDF for GCM ciphers (?)
        if xtn_hdr_cipher_type != rtp.cipher_type {
            return Err(Error::BadParam);
        }
        let xtn_hdr_key_size = rtp_cipher.key_size();
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

        rtp_xtn_hdr_cipher.init(&mut tmp_key[..xtn_hdr_key_size])?;

        // Initialize RTP authentication
        tmp_key = [0u8; MAX_SRTP_KEY_SIZE];
        {
            let auth_key = &mut tmp_key[..rtp_auth.key_size()];
            kdf.generate(KdfLabel::RtpMsgAuth, auth_key)?;
            rtp_auth.init(auth_key)?;
        }

        // Initialize RTCP encryption
        let mut tmp_key = [0u8; MAX_SRTP_KEY_SIZE];
        kdf.generate(KdfLabel::RtcpEncryption, &mut tmp_key[..rtcp_base_key_size])?;
        kdf.generate(
            KdfLabel::RtcpSalt,
            &mut tmp_key[rtcp_base_key_size..rtcp_key_size],
        )?;

        rtcp_cipher.init(&tmp_key[..rtcp_key_size])?;
        let c_salt = tmp_key[rtcp_base_key_size..rtcp_key_size].to_vec();

        // Initialize RTCP authentication
        tmp_key = [0u8; MAX_SRTP_KEY_SIZE];
        {
            let auth_key = &mut tmp_key[..rtcp_auth.key_size()];
            kdf.generate(KdfLabel::RtcpMsgAuth, auth_key)?;
            rtcp_auth.init(auth_key)?;
        }

        Ok(SessionKeys {
            rtp_cipher: rtp_cipher,
            rtp_xtn_hdr_cipher: rtp_xtn_hdr_cipher,
            rtp_auth: rtp_auth,
            rtcp_cipher: rtcp_cipher,
            rtcp_auth: rtcp_auth,

            salt: salt,
            c_salt: c_salt,
            mki_id: key.id.clone(),
            limit: KeyLimitContext::new(),
        })
    }
}

#[derive(Clone)]
struct Stream {
    ssrc: u32,
    session_keys: Vec<SessionKeys>,
    rtp_rdbx: ExtendedReplayDB,
    rtcp_rdb: ReplayDB,
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
            rtcp_rdb: ReplayDB::new(),
            rtp_services: policy.rtp.sec_serv,
            rtcp_services: policy.rtp.sec_serv,
            direction: Direction::Unknown,
            allow_repeat_tx: policy.allow_repeat_tx,
            enc_xtn_hdr: policy.enc_xtn_hdr.clone(),
            pending_roc: 0,
        })
    }

    pub fn same_crypto(&self, other: &Self) -> bool {
        self.session_keys[0]
            .rtp_auth
            .equals(&other.session_keys[0].rtp_auth)
    }

    pub fn clone_for_ssrc(&self, ssrc: u32) -> Result<Self, Error> {
        let mut stream = self.clone();

        // Set the SSRC to the one provided
        stream.ssrc = ssrc;

        // Re-initialize the replay databases
        stream.rtp_rdbx = ExtendedReplayDB::new(self.rtp_rdbx.window_size())?;
        stream.rtcp_rdb = ReplayDB::new();

        // Reset the pending ROC
        stream.pending_roc = 0;

        Ok(stream)
    }

    pub fn get_session_keys(
        &mut self,
        use_mki: bool,
        mki_index: usize,
    ) -> Option<&mut SessionKeys> {
        if !use_mki {
            return Some(&mut self.session_keys[0]);
        }

        if mki_index > self.session_keys.len() {
            return None;
        }

        Some(&mut self.session_keys[mki_index])
    }
}

pub struct Context {
    streams: Vec<Stream>,
    stream_template: Option<Stream>,
    // XXX(RLB) user_data: Box<dyn Any> ?
}

impl Context {
    pub fn new(kernel: &CryptoKernel, policies: &[Policy]) -> Result<Self, Error> {
        let mut ctx = Self {
            streams: Vec::new(),
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
        let stream = Stream::new(kernel, policy)?;

        match policy.ssrc.type_ {
            SsrcType::Specific => {
                // SSRC-specific streams are added to the stream list
                self.streams.push(stream);
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

    fn get_stream(&self, ssrc: u32) -> Option<usize> {
        for i in 0..self.streams.len() {
            if self.streams[i].ssrc == ssrc {
                return Some(i);
            }
        }
        None
    }

    pub fn remove_stream(&mut self, ssrc: u32) -> Result<(), Error> {
        match self.get_stream(ssrc) {
            Some(i) => {
                self.streams.remove(i);
                Ok(())
            }
            None => Err(Error::NoContext),
        }
    }

    pub fn update(&mut self, kernel: &CryptoKernel, policies: &[Policy]) -> Result<(), Error> {
        for p in policies {
            self.update_stream(kernel, p)?;
        }
        Ok(())
    }

    pub fn update_stream(&mut self, kernel: &CryptoKernel, policy: &Policy) -> Result<(), Error> {
        match policy.ssrc.type_ {
            SsrcType::Specific => self.update_specific_stream(kernel, policy),
            SsrcType::Inbound | SsrcType::Outbound => self.update_template_streams(kernel, policy),
            _ => Err(Error::BadParam),
        }
    }

    fn update_specific_stream(
        &mut self,
        kernel: &CryptoKernel,
        policy: &Policy,
    ) -> Result<(), Error> {
        let ssrc = policy.ssrc.value;
        let stream_index = self.get_stream(ssrc).ok_or(Error::BadParam)?;

        // Save the old extended seq
        let old_index = self.streams[stream_index].rtp_rdbx.packet_index();
        let old_rtcp_rdb = self.streams[stream_index].rtcp_rdb.clone();

        // Replace the stream with a fresh one
        self.remove_stream(ssrc)?;
        self.add_stream(kernel, policy)?;

        // Restore the old extended seq
        let stream_index = self.get_stream(ssrc).ok_or(Error::BadParam)?;

        self.streams[stream_index]
            .rtp_rdbx
            .set_packet_index(old_index);
        self.streams[stream_index].rtcp_rdb = old_rtcp_rdb;

        Ok(())
    }

    fn update_template_streams(
        &mut self,
        kernel: &CryptoKernel,
        policy: &Policy,
    ) -> Result<(), Error> {
        let stream_template = self.stream_template.as_ref().ok_or(Error::BadParam)?;

        // Initialize a new template stream
        let new_stream_template = Stream::new(kernel, policy)?;

        // Replace all old templated streams
        // XXX(RLB): We do this a bit differently than C libsrtp because we use a Vec instead of a
        // linked list.  Tracking the new stream indices and doing replaces directly means that we
        // avoid changing the Vec while we're iterating over it, and we avoid repeatedly changing
        // the size of the Vec.
        let mut new_streams = Vec::<(usize, Stream)>::new();
        for i in 0..self.streams.len() {
            let stream = &self.streams[i];
            if !stream.same_crypto(&stream_template) {
                continue;
            }

            let ssrc = stream.ssrc;
            let mut new_stream = new_stream_template.clone_for_ssrc(ssrc)?;
            new_stream
                .rtp_rdbx
                .set_packet_index(stream.rtp_rdbx.packet_index());
            new_stream.rtcp_rdb = stream.rtcp_rdb.clone();

            new_streams.push((i, new_stream));
        }

        self.stream_template = Some(new_stream_template);
        for (i, new_stream) in new_streams.drain(..) {
            self.streams[i] = new_stream;
        }

        Ok(())
    }

    fn srtp_protect(&mut self, pkt_data: &mut [u8], pkt_len: usize) -> Result<usize, Error> {
        self.srtp_protect_mki(pkt_data, pkt_len, false, 0)
    }

    fn srtp_protect_mki(
        &mut self,
        pkt_data: &mut [u8],
        pkt_len: usize,
        use_mki: bool,
        mki_index: usize,
    ) -> Result<usize, Error> {
        let mut pkt = SrtpPacket::new(pkt_data, pkt_len)?;

        // Find or create the correct stream
        let stream_index = match self.get_stream(pkt.header.ssrc) {
            Some(x) => x,
            None => {
                if self.stream_template.is_none() {
                    return Err(Error::NoContext);
                }

                let mut stream = self.stream_template.as_ref().unwrap().clone();
                stream.direction = Direction::Sender;
                self.streams.push(stream);
                self.streams.len() - 1
            }
        };
        let stream = &mut self.streams[stream_index];

        // Check that the stream is for sending traffic
        if stream.direction == Direction::Unknown {
            stream.direction = Direction::Sender
        } else if stream.direction != Direction::Sender {
            return Err(Error::Fail); // TODO report ssrc collision
        }

        // Look up the session keys by MKI
        let mut sk = match stream.get_session_keys(use_mki, mki_index) {
            Some(x) => x,
            None => return Err(Error::BadMki),
        };

        // Update the key usage limit
        match sk.limit.update() {
            KeyEvent::Normal => {}
            KeyEvent::SoftLimit => { /* TODO report soft limit */ }
            KeyEvent::HardLimit => {
                // TODO report hard limit
                return Err(Error::KeyExpired);
            }
        }

        // TODO estimate sequence number and form nonce
        let nonce = [0u8; 16];

        // Encrypt the headers
        for ext in pkt.extension() {
            // TODO encrypt header extension
        }

        // Encrypt the payload
        // TODO AEAD-ish
        let pt_size = pkt.payload_size();
        sk.rtp_cipher.set_iv(&nonce, CipherDirection::Encrypt)?;
        sk.rtp_cipher.set_aad(pkt.aad())?;
        let ct_size = sk.rtp_cipher.encrypt(pkt.payload(), pt_size)?;
        pkt.set_payload_size(ct_size);

        // Write the MKI
        pkt.append(sk.mki_id.len())?.copy_from_slice(&sk.mki_id);

        // Write the tag
        let mut tag = [0u8; 128]; // TODO fix some max size
        let tag_size = sk.rtp_auth.tag_size();
        sk.rtp_auth.compute(pkt.auth_data(), &mut tag)?;
        pkt.append(tag_size)?.copy_from_slice(&tag[..tag_size]);

        Ok(pkt.size()) // TODO
    }

    fn srtp_unprotect(&mut self, pkt_data: &mut [u8]) -> Result<usize, Error> {
        self.srtp_unprotect_mki(pkt_data, false)
    }

    fn srtp_unprotect_mki(&mut self, pkt_data: &mut [u8], use_mki: bool) -> Result<usize, Error> {
        let mut pkt = SrtpPacket::new(pkt_data, pkt_data.len())?;

        // Get or create the stream
        let stream = match self.get_stream(pkt.header.ssrc) {
            Some(x) => &mut self.streams[x],
            None => {
                if self.stream_template.is_none() {
                    return Err(Error::NoContext);
                }

                self.stream_template.as_mut().unwrap()
            }
        };

        // Verify that stream is for received traffic
        if stream.direction == Direction::Unknown {
            stream.direction = Direction::Receiver;
        }

        if stream.direction != Direction::Receiver {
            // TODO report SSRC collision
            return Err(Error::Fail);
        }

        // TODO estimate the sequence number and form the nonce
        let nonce = [0u8; 16];

        // Determine if MKI is being used and what session keys should be used
        let sk = if use_mki {
            pkt.find_mki(&mut stream.session_keys)
                .ok_or(Error::BadMki)?
        } else {
            &mut stream.session_keys[0]
        };

        // Verify the authentication tag
        let mut tag_buf = [0u8; 128]; // TODO fix some max size
        let tag_size = sk.rtp_auth.tag_size();
        let tag = &mut tag_buf[..tag_size];
        sk.rtp_auth.compute(pkt.auth_data(), tag)?;
        if !constant_time_eq(tag, pkt.last(tag_size)?) {
            return Err(Error::AuthFail);
        }

        // TODO update usage limits
        // TODO convert to real stream
        // TODO update replay DB

        // Strip the auth tag and MKI
        pkt.strip(tag_size)?;
        if use_mki {
            pkt.strip(sk.mki_id.len())?;
        }

        // Decrypt the headers
        for ext in pkt.extension() {
            // TODO encrypt header extension
        }

        // Decrypt the payload
        let ct_size = pkt.payload_size();
        sk.rtp_cipher.set_iv(&nonce, CipherDirection::Decrypt)?;
        sk.rtp_cipher.set_aad(pkt.aad())?;
        let pt_size = sk.rtp_cipher.decrypt(pkt.payload(), ct_size)?;
        pkt.set_payload_size(pt_size);

        Ok(pkt.size())
    }

    // TODO srtcp_protect
    // TODO srtcp_protect_mki

    // TODO srtcp_unprotect
    // TODO srtcp_unprotect_mki
}

struct RtpExtensionReader<'a> {
    data: &'a mut [u8],
}

impl<'a> RtpExtensionReader<'a> {
    fn get<'b>(&'b mut self, range: Range<usize>) -> &'b mut [u8] {
        &mut self.data[range]
    }
}

impl<'a> Iterator for RtpExtensionReader<'a> {
    type Item = Range<usize>;

    fn next(&mut self) -> Option<Self::Item> {
        None // TODO parse next extension
    }
}

struct SrtpHeader {
    ssrc: u32,
}

struct SrtpPacket {
    header: SrtpHeader,
}

impl SrtpPacket {
    fn new(data: &mut [u8], len: usize) -> Result<Self, Error> {
        Err(Error::Fail) // TODO
    }

    fn find_mki<'b>(
        &mut self,
        session_keys: &'b mut Vec<SessionKeys>,
    ) -> Option<&'b mut SessionKeys> {
        None // TODO
    }

    fn extension(&mut self) -> RtpExtensionReader {
        RtpExtensionReader { data: &mut [] } // TODO
    }

    fn aad<'b>(&'b self) -> &'b [u8] {
        &[] // TODO
    }

    fn auth_data<'b>(&'b self) -> &'b [u8] {
        &[] // TODO
    }

    fn payload<'b>(&'b mut self) -> &'b mut [u8] {
        &mut [] // TODO
    }

    fn payload_size(&self) -> usize {
        0 // TODO
    }

    fn set_payload_size(&mut self, size: usize) {
        // TODO
    }

    fn append<'b>(&'b mut self, size: usize) -> Result<&'b mut [u8], Error> {
        Err(Error::Fail) // TODO
    }

    fn last<'b>(&'b self, size: usize) -> Result<&'b [u8], Error> {
        Err(Error::Fail) // TODO
    }

    fn strip(&mut self, size: usize) -> Result<(), Error> {
        Err(Error::Fail) // TODO
    }

    fn size(&self) -> usize {
        0 // TODO
    }
}
