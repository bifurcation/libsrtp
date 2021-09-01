use crate::crypto_kernel::*;
use crate::kdf::*;
use crate::key_limit::*;
use crate::policy::*;
use crate::replay::*;
use crate::rtp_header::{SrtcpPacket, SrtpPacket};
use constant_time_eq::constant_time_eq;
use std::any::Any;
use std::rc::{Rc, Weak};

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
    ParseError = 21, // error parsing data
    BadMki = 25,     // error MKI present in packet is invalid
    PacketIndexOld = 26, // packet index is too old to consider

                     /*
                     alloc_fail = 3,     // couldn't allocate memory
                     dealloc_fail = 4,   // couldn't deallocate properly
                     cant_check = 14,    // unable to perform desired validation
                     socket_err = 16,    // error in use of socket
                     signal_err = 17,    // error in use POSIX signals
                     nonce_bad = 18,     // nonce check failed
                     read_fail = 19,     // couldn't read data
                     write_fail = 20,    // couldn't write data
                     encode_err = 22,    // error encoding data
                     semaphore_err = 23, // error while using semaphores
                     pfkey_err = 24,     // error while using pfkey
                     pkt_idx_adv = 27,   // packet index advanced, reset needed
                     */
}

struct CipherFactory<'a> {
    kernel: &'a CryptoKernel,
    kdf: &'a KDF,
}

impl<'a> CipherFactory<'a> {
    fn new(kernel: &'a CryptoKernel, kdf: &'a KDF) -> Self {
        Self {
            kernel: kernel,
            kdf: kdf,
        }
    }

    fn xtn_cipher(
        &self,
        xtn_cipher_type: ExtensionCipherTypeID,
        key_label: KdfLabel,
        salt_label: KdfLabel,
        salt_size: usize,
    ) -> Result<ExtensionCipherInstance, Error> {
        let mut key_buffer = [0u8; 32];
        let key = &mut key_buffer[..xtn_cipher_type.key_size()];
        self.kdf.generate(key_label, key)?;

        // XXX(RLB) This fiddling around with salt sizes is because the ciphers expect a fixed
        // size, but the CTR modes used together with GCM modes provide a shorter salt.  Instead of
        // actually using a shorter salt, we append zeros, which has the same effect.
        let mut salt_buffer = [0u8; 14];
        let salt = &mut salt_buffer[..xtn_cipher_type.salt_size()];
        self.kdf.generate(salt_label, &mut salt[..salt_size])?;

        self.kernel.xtn_cipher(xtn_cipher_type, key, salt)
    }

    fn cipher(
        &self,
        cipher_type: CipherTypeID,
        key_label: KdfLabel,
        salt_label: KdfLabel,
        salt_size: usize,
    ) -> Result<CipherInstance, Error> {
        let mut key_buffer = [0u8; 32];
        let key = &mut key_buffer[..cipher_type.key_size()];
        self.kdf.generate(key_label, key)?;

        // XXX(RLB) This fiddling around with salt sizes is because the ciphers expect a fixed
        // size, but the CTR modes used together with GCM modes provide a shorter salt.  Instead of
        // actually using a shorter salt, we append zeros, which has the same effect.
        let mut salt_buffer = [0u8; 14];
        let salt = &mut salt_buffer[..cipher_type.salt_size()];
        self.kdf.generate(salt_label, &mut salt[..salt_size])?;
        self.kernel.cipher(cipher_type, key, salt)
    }

    fn auth(
        &self,
        auth_type: AuthTypeID,
        key_label: KdfLabel,
        key_size: usize,
        tag_size: usize,
    ) -> Result<AuthInstance, Error> {
        let mut key_buffer = [0u8; 20];
        let key = &mut key_buffer[..key_size];
        self.kdf.generate(key_label, key)?;
        self.kernel.auth(auth_type, key, tag_size)
    }
}

#[derive(Clone)]
pub struct SessionKeys {
    pub rtp_cipher: CipherInstance,
    pub rtp_xtn_hdr_cipher: ExtensionCipherInstance,
    pub rtp_auth: AuthInstance,
    pub rtcp_cipher: CipherInstance,
    pub rtcp_auth: AuthInstance,

    pub mki_id: Vec<u8>,
    pub limit: KeyLimitContext,
}

impl SessionKeys {
    pub fn new(
        kernel: &CryptoKernel,
        key: &MasterKey,
        rtp: &CryptoPolicy,
        rtcp: &CryptoPolicy,
    ) -> Result<Self, Error> {
        // Set up a KDF and cipher factory
        // XXX(RLB) Apparently we can't use key.salt directly, because it its length is expected to
        // match the salt size for the RTP cipher.
        let kdf_cipher_type = KDF::cipher_type(rtp.cipher_type, rtcp.cipher_type);
        let mut kdf_salt = [0u8; 14];
        kdf_salt[..key.salt.len()].copy_from_slice(&key.salt);
        let kdf = KDF::new(kernel, kdf_cipher_type, &key.key, &kdf_salt)?;
        let factory = CipherFactory::new(kernel, &kdf);

        // Set up the RTP cipher
        let rtp_cipher = factory.cipher(
            rtp.cipher_type,
            KdfLabel::RtpEncryption,
            KdfLabel::RtpSalt,
            rtp.cipher_type.salt_size(),
        )?;

        // Set up the RTP extension header cipher
        let xtn_hdr_cipher = factory.xtn_cipher(
            rtp.cipher_type.extension_header_cipher_type(),
            KdfLabel::RtpHeaderEncryption,
            KdfLabel::RtpHeaderSalt,
            rtp.cipher_type.salt_size(),
        )?;

        // Set up RTP authentication
        let rtp_auth = factory.auth(
            rtp.auth_type,
            KdfLabel::RtpMsgAuth,
            rtp.auth_key_len,
            rtp.auth_tag_len,
        )?;

        // Set up the RTCP cipher
        let rtcp_cipher = factory.cipher(
            rtcp.cipher_type,
            KdfLabel::RtcpEncryption,
            KdfLabel::RtcpSalt,
            rtcp.cipher_type.salt_size(),
        )?;

        // Set up RTCP authentication
        let rtcp_auth = factory.auth(
            rtcp.auth_type,
            KdfLabel::RtcpMsgAuth,
            rtcp.auth_key_len,
            rtcp.auth_tag_len,
        )?;

        Ok(SessionKeys {
            rtp_cipher: rtp_cipher,
            rtp_xtn_hdr_cipher: xtn_hdr_cipher,
            rtp_auth: rtp_auth,
            rtcp_cipher: rtcp_cipher,
            rtcp_auth: rtcp_auth,

            mki_id: key.id.clone(),
            limit: KeyLimitContext::new(),
        })
    }

    fn check_key_usage_limit<F>(&mut self, event_handler: F) -> Result<(), Error>
    where
        F: Fn(Event),
    {
        match self.limit.update() {
            KeyEvent::Normal => Ok(()),
            KeyEvent::SoftLimit => {
                event_handler(Event::KeySoftLimit);
                Ok(())
            }
            KeyEvent::HardLimit => {
                event_handler(Event::KeyHardLimit);
                return Err(Error::KeyExpired);
            }
        }
    }

    fn srtp_add_auth(&mut self, pkt: &mut SrtpPacket, roc: RolloverCounter) -> Result<(), Error> {
        let mut inst = self.rtp_auth.try_borrow_mut().map_err(|_| Error::Fail)?;
        let mut op = inst.start();

        let mut tag_buf = [0u8; 128];
        let tag_size = op.tag_size();
        let tag = &mut tag_buf[..tag_size];

        op.update(pkt.auth_data())?;
        op.update(&roc.to_be_bytes())?;
        op.compute(tag)?;

        pkt.append(tag_size)?.copy_from_slice(tag);
        Ok(())
    }

    fn srtp_verify_auth(
        &mut self,
        pkt: &mut SrtpPacket,
        roc: RolloverCounter,
    ) -> Result<(), Error> {
        let mut inst = self.rtp_auth.try_borrow_mut().map_err(|_| Error::Fail)?;
        let mut op = inst.start();

        let mut tag_buf = [0u8; 128];
        let tag_size = op.tag_size();
        let tag = &mut tag_buf[..tag_size];

        op.update(pkt.auth_data())?;
        op.update(&roc.to_be_bytes())?;
        op.compute(tag)?;

        let pkt_tag = pkt.last(tag_size)?;
        if !constant_time_eq(tag, pkt_tag) {
            return Err(Error::AuthFail);
        }

        pkt.strip(tag_size)?;
        Ok(())
    }

    fn srtcp_add_auth(&mut self, pkt: &mut SrtcpPacket) -> Result<(), Error> {
        let mut inst = self.rtcp_auth.try_borrow_mut().map_err(|_| Error::Fail)?;
        let mut op = inst.start();

        let mut tag_buf = [0u8; 128];
        let tag_size = op.tag_size();
        let tag = &mut tag_buf[..tag_size];

        op.update(pkt.auth_data())?;
        op.compute(tag)?;

        pkt.append(tag_size)?.copy_from_slice(tag);
        Ok(())
    }

    fn srtcp_verify_auth(&mut self, pkt: &mut SrtcpPacket) -> Result<(), Error> {
        let mut inst = self.rtcp_auth.try_borrow_mut().map_err(|_| Error::Fail)?;
        let mut op = inst.start();

        let mut tag_buf = [0u8; 128];
        let tag_size = op.tag_size();
        let tag = &mut tag_buf[..tag_size];

        op.update(pkt.auth_data())?;
        op.compute(tag)?;

        if !constant_time_eq(tag, pkt.last(tag_size)?) {
            return Err(Error::AuthFail);
        }

        pkt.strip(tag_size)?;
        Ok(())
    }

    fn process_header_extension(
        &mut self,
        pkt: &mut SrtpPacket,
        index: ExtendedSequenceNumber,
        headers_to_encrypt: &Vec<u8>,
    ) -> Result<(), Error> {
        let mut inst = self
            .rtp_xtn_hdr_cipher
            .try_borrow_mut()
            .map_err(|_| Error::Fail)?;
        let mut op = inst.start();
        op.init(pkt.header.ssrc, index)?;
        pkt.extensions()?.apply(|ext| {
            if !headers_to_encrypt.contains(&ext.id) {
                return Ok(());
            }
            op.xor_key(ext.data, ext.range)
        })?;
        Ok(())
    }

    fn srtp_encrypt(
        &mut self,
        pkt: &mut SrtpPacket,
        index: ExtendedSequenceNumber,
    ) -> Result<(), Error> {
        let mut inst = self.rtp_cipher.try_borrow_mut().map_err(|_| Error::Fail)?;
        let mut op = inst.start();

        op.add_aad(pkt.aad())?;

        let mut nonce = [0u8; 16];
        let nonce_size = op.id().nonce_size();
        let nonce = &mut nonce[..nonce_size];
        op.rtp_nonce(pkt.header.ssrc, index, nonce)?;
        op.set_nonce(nonce)?;

        let pt_size = pkt.payload_size();
        let ct_size = op.encrypt(pkt.payload_for_encrypt(), pt_size)?;
        pkt.set_payload_size(ct_size)?;
        Ok(())
    }

    fn srtp_decrypt(
        &mut self,
        pkt: &mut SrtpPacket,
        index: ExtendedSequenceNumber,
    ) -> Result<(), Error> {
        let mut inst = self.rtp_cipher.try_borrow_mut().map_err(|_| Error::Fail)?;
        let mut op = inst.start();

        op.add_aad(pkt.aad())?;

        let mut nonce = [0u8; 16];
        let nonce_size = op.id().nonce_size();
        let nonce = &mut nonce[..nonce_size];
        op.rtp_nonce(pkt.header.ssrc, index, nonce)?;
        op.set_nonce(nonce)?;

        let pt_size = op.decrypt(pkt.payload_for_decrypt())?;
        pkt.set_payload_size(pt_size)?;
        Ok(())
    }

    fn srtcp_encrypt(
        &mut self,
        pkt: &mut SrtcpPacket,
        auth_only: bool,
        index: u32,
    ) -> Result<(), Error> {
        let mut inst = self.rtcp_cipher.try_borrow_mut().map_err(|_| Error::Fail)?;
        let mut op = inst.start();

        let (aad1, aad2) = pkt.aad(0)?;
        op.add_aad(aad1)?;
        op.add_aad(aad2)?;

        let mut nonce = [0u8; 16];
        let nonce_size = op.id().nonce_size();
        let nonce = &mut nonce[..nonce_size];
        op.rtcp_nonce(pkt.header.ssrc, index as u32, nonce)?;
        op.set_nonce(nonce)?;

        let pt_size = pkt.payload_size();
        let ct_size = if auth_only {
            let overhead = op.encrypt(pkt.payload_for_encrypt(true), 0)?;
            pt_size + overhead
        } else {
            op.encrypt(pkt.payload_for_encrypt(false), pt_size)?
        };

        pkt.set_payload_size(ct_size)?;
        Ok(())
    }

    fn srtcp_decrypt(
        &mut self,
        pkt: &mut SrtcpPacket,
        auth_only: bool,
        index: u32,
    ) -> Result<(), Error> {
        let mut inst = self.rtcp_cipher.try_borrow_mut().map_err(|_| Error::Fail)?;
        let mut op = inst.start();

        let overhead = op.overhead();
        let (aad1, aad2) = pkt.aad(overhead)?;
        op.add_aad(aad1)?;
        op.add_aad(aad2)?;

        let mut nonce = [0u8; 16];
        let nonce_size = op.id().nonce_size();
        let nonce = &mut nonce[..nonce_size];
        op.rtcp_nonce(pkt.header.ssrc, index, nonce)?;
        op.set_nonce(nonce)?;

        let ct_size = pkt.payload_size();
        let pt_size = if auth_only {
            let payload = pkt.payload_for_decrypt_tag_only(overhead)?;
            let remaining_tag = op.decrypt(payload)?;
            if remaining_tag != 0 {
                return Err(Error::BadParam);
            }

            ct_size - overhead
        } else {
            op.decrypt(pkt.payload_for_decrypt())?
        };

        pkt.set_payload_size(pt_size)?;
        Ok(())
    }
}

#[derive(Clone)]
struct Stream {
    ssrc: Ssrc,
    session_keys: Vec<SessionKeys>,
    rtp_rdbx: ExtendedReplayDB,
    rtcp_rdb: ReplayDB,
    rtp_services: SecurityServices,
    rtcp_services: SecurityServices,
    allow_repeat_tx: bool,
    xtn_headers_to_encrypt: Vec<ExtensionHeaderId>,
    pending_roc: Option<RolloverCounter>,
}

impl Stream {
    // XXX(RLB) This method combins srtp_stream_alloc and srtp_stream_init, since they are only
    // ever called together.
    fn new(kernel: &CryptoKernel, policy: &Policy) -> Result<Self, Error> {
        // Set up SessionKeys for each master key
        // XXX(RLB): Note that this deprecates the old policy interface, where you could just shove
        // in a key, instead of formatting it as a master key
        let mut session_keys = Vec::<SessionKeys>::with_capacity(policy.keys.len());
        for mk in &policy.keys {
            session_keys.push(SessionKeys::new(kernel, &mk, &policy.rtp, &policy.rtcp)?);
        }

        Ok(Stream {
            ssrc: policy.ssrc,
            session_keys: session_keys,
            rtp_rdbx: ExtendedReplayDB::new(policy.window_size)?,
            rtcp_rdb: ReplayDB::new(),
            rtp_services: policy.rtp.sec_serv,
            rtcp_services: policy.rtcp.sec_serv,
            allow_repeat_tx: policy.allow_repeat_tx,
            xtn_headers_to_encrypt: policy.xtn_headers_to_encrypt.clone(),
            pending_roc: None,
        })
    }

    pub fn same_crypto(&self, other: &Self) -> bool {
        Rc::ptr_eq(
            &self.session_keys[0].rtp_auth,
            &other.session_keys[0].rtp_auth,
        )
    }

    pub fn clone_for_ssrc(&self, ssrc: Ssrc) -> Result<Self, Error> {
        let mut stream = self.clone();

        // Set the SSRC to the one provided
        stream.ssrc = ssrc;

        // Re-initialize the replay databases
        stream.rtp_rdbx = ExtendedReplayDB::new(self.rtp_rdbx.window_size())?;
        stream.rtcp_rdb = ReplayDB::new();

        // Reset the pending ROC
        stream.pending_roc = None;

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

    pub fn estimate_packet_index(
        &self,
        seq: SequenceNumber,
    ) -> Result<(ExtendedSequenceNumber, i32, bool), Error> {
        if self.pending_roc.is_some() {
            let pending_roc = self.pending_roc.unwrap();
            let index = self.rtp_rdbx.packet_index();
            let estimate = ExtendedSequenceNumber::from_roc_seq(pending_roc, seq);
            let delta = ((estimate as i64) - (index as i64)) as i32;

            if self.rtp_rdbx.should_advance(estimate)? {
                return Ok((estimate, 0, true));
            }

            return Ok((estimate, delta, false));
        }

        let (estimate, delta) = self.rtp_rdbx.estimate(seq);
        Ok((estimate, delta, false))
    }

    pub fn srtp_protect(
        &mut self,
        pkt: &mut SrtpPacket,
        use_mki: bool,
        mki_index: usize,
        event_handler: EventHandler,
    ) -> Result<usize, Error> {
        // Estimate the packet index
        let (index, delta, advance_index) = self.estimate_packet_index(pkt.header.seq)?;
        if advance_index {
            // XXX(RLB) set_packet_index?
            self.rtp_rdbx.set_roc_seq(index.roc(), index.seq())?;
            self.pending_roc = None;
            self.rtp_rdbx.add(0)?;
        } else {
            match self.rtp_rdbx.check(delta) {
                Ok(_) => {}
                Err(Error::ReplayFail) if self.allow_repeat_tx => {}
                Err(err) => return Err(err),
            };
            self.rtp_rdbx.add(delta)?;
        }

        // Look up the session keys by MKI
        // XXX(RLB): These copies are needed to satisfy the borrow checker, since we hold on to the
        // sk reference to self.  It would be nice to have a more elegant approach.
        let ssrc = self.ssrc;
        let xtn_headers_to_encrypt = self.xtn_headers_to_encrypt.clone();
        let sk = match self.get_session_keys(use_mki, mki_index) {
            Some(x) => x,
            None => return Err(Error::BadMki),
        };

        // Update the key usage limit
        sk.check_key_usage_limit(|e| event_handler.handle(ssrc, e))?;

        // Encrypt the headers
        sk.process_header_extension(pkt, index, &xtn_headers_to_encrypt)?;

        // Encrypt the payload
        sk.srtp_encrypt(pkt, index)?;

        // Write the MKI if required
        if use_mki {
            pkt.append(sk.mki_id.len())?.copy_from_slice(&sk.mki_id);
        }

        // Write the tag
        sk.srtp_add_auth(pkt, index.roc())?;

        Ok(pkt.size())
    }

    pub fn srtp_unprotect(
        &mut self,
        pkt: &mut SrtpPacket,
        use_mki: bool,
        event_handler: EventHandler,
    ) -> Result<usize, Error> {
        // Estimate the sequence number
        let (index, delta, advance_index) = self.estimate_packet_index(pkt.header.seq)?;
        self.rtp_rdbx.check(delta)?;

        // Determine which session keys should be used
        let sk = if use_mki {
            pkt.find_mki(&mut self.session_keys).ok_or(Error::BadMki)?
        } else {
            pkt.find_tag(&self.session_keys[0])?;
            &mut self.session_keys[0]
        };

        // Verify and strip the authentication tag
        sk.srtp_verify_auth(pkt, index.roc())?;

        // Strip the MKI
        if use_mki {
            pkt.strip(sk.mki_id.len())?;
        }

        // Update the key usage limit
        let ssrc = self.ssrc;
        sk.check_key_usage_limit(|e| event_handler.handle(ssrc, e))?;

        // Decrypt the payload
        sk.srtp_decrypt(pkt, index)?;

        // Decrypt the headers
        sk.process_header_extension(pkt, index, &self.xtn_headers_to_encrypt)?;

        // Update the replay DB
        if advance_index {
            // XXX(RLB) set_packet_index?
            self.rtp_rdbx.set_roc_seq(index.roc(), index.seq())?;
            self.pending_roc = None;
            self.rtp_rdbx.add(0)?;
        } else {
            self.rtp_rdbx.add(delta)?;
        }

        Ok(pkt.size())
    }

    pub fn srtcp_protect(
        &mut self,
        pkt: &mut SrtcpPacket,
        use_mki: bool,
        mki_index: usize,
        event_handler: EventHandler,
    ) -> Result<usize, Error> {
        // Calculate the packet index
        let index = self.rtcp_rdb.increment()?;

        // Look up the session keys by MKI
        let ssrc = self.ssrc;
        let services = self.rtcp_services;
        let sk = match self.get_session_keys(use_mki, mki_index) {
            Some(x) => x,
            None => return Err(Error::BadMki),
        };

        // Set the RTCP trailer
        pkt.set_e_index(services, index)?;

        // Update the key usage limit
        sk.check_key_usage_limit(|e| event_handler.handle(ssrc, e))?;

        // Encrypt the payload if required
        let auth_only = !services.confidentiality();
        sk.srtcp_encrypt(pkt, auth_only, index)?;

        // Write the trailer
        pkt.append_trailer()?;

        // Write the MKI
        if use_mki {
            pkt.append(sk.mki_id.len())?.copy_from_slice(&sk.mki_id);
        }

        // Write the tag
        sk.srtcp_add_auth(pkt)?;

        Ok(pkt.size())
    }

    pub fn srtcp_unprotect(
        &mut self,
        pkt: &mut SrtcpPacket,
        use_mki: bool,
        event_handler: EventHandler,
    ) -> Result<usize, Error> {
        // Determine which session keys should be used
        let sk = if use_mki {
            pkt.find_mki(&mut self.session_keys).ok_or(Error::BadMki)?
        } else {
            pkt.find_tag(&self.session_keys[0])?;
            &mut self.session_keys[0]
        };

        // Read the sequence number from the trailer and check for replay
        // XXX(RLB) libsrtp accepts unencrypted RTCP packets even if the local security service
        // description specifies confidentiality.  It seems like we should check for:
        //
        //     if self.rtcp_services.confidentiality() && !trailer.e { /* fail */ }
        let trailer = pkt.parse_trailer()?;
        self.rtcp_rdb.check(trailer.index)?;

        // Verify and strip the authentication tag
        sk.srtcp_verify_auth(pkt)?;

        // Strip the MKI, and trailer
        if use_mki {
            pkt.strip(sk.mki_id.len())?;
        }
        pkt.strip_trailer()?;

        // Update the key usage limit
        let ssrc = self.ssrc;
        sk.check_key_usage_limit(|e| event_handler.handle(ssrc, e))?;

        // Decrypt the payload if required
        sk.srtcp_decrypt(pkt, !trailer.e, trailer.index)?;

        // Update the replay DB
        self.rtcp_rdb.add(trailer.index)?;

        Ok(pkt.size())
    }
}

pub type UserData = Option<Weak<dyn Any>>;

#[derive(Debug, Copy, Clone)]
pub enum Event {
    SsrcCollision,
    KeySoftLimit,
    KeyHardLimit,
    // XXX(RLB) event_packet_index_limit never emitted in C code
}

// XXX(RLB) Our version of EventData doesn't pass a reference to the Context, as in the C version.
// This would confuse the borrow checker, since whenever we're in a position to emit an event, we
// need to have a mutable borrow active.  A couple of options to clean this up:
//
// * Provide UserData in EventData
// * Refactor Context to hold RefCell<Stream> instead of Stream
pub struct EventData {
    pub ssrc: Ssrc,
    pub event: Event,
}

pub type EventHandlerFn = fn(data: &EventData);

#[derive(Copy, Clone, Default)]
pub struct EventHandler {
    handle_fn: Option<EventHandlerFn>,
}

impl EventHandler {
    pub fn set(&mut self, f: EventHandlerFn) {
        self.handle_fn = Some(f);
    }

    pub fn clear(&mut self) {
        self.handle_fn = None;
    }

    fn handle(&self, ssrc: Ssrc, event: Event) {
        self.handle_fn.map(|f| {
            f(&EventData {
                ssrc: ssrc,
                event: event,
            })
        });
    }
}

pub struct Context {
    streams: Vec<Stream>,
    stream_template: Option<Stream>,
    pub event_handler: EventHandler,

    // XXX(RLB): This is designed to mimic the pattern in the C implementation, which seems to hold
    // a weak reference, in the sense that a referenced user data object is not freed when the
    // srtp_t is freed.
    pub user_data: UserData,
}

impl Context {
    pub fn new(kernel: &CryptoKernel, policies: &[Policy]) -> Result<Self, Error> {
        let mut ctx = Self {
            streams: Default::default(),
            stream_template: Default::default(),
            event_handler: Default::default(),
            user_data: Default::default(),
        };

        for p in policies {
            if !p.validate_master_keys() {
                return Err(Error::BadParam);
            }

            ctx.add_stream(kernel, p)?;
        }

        Ok(ctx)
    }

    pub fn add_stream(&mut self, kernel: &CryptoKernel, policy: &Policy) -> Result<(), Error> {
        let stream = Stream::new(kernel, policy)?;

        match policy.ssrc {
            Ssrc::Inbound(_) | Ssrc::Outbound(_) | Ssrc::Any(_) => {
                // SSRC-specific streams are added to the stream list
                self.streams.push(stream);
                Ok(())
            }
            Ssrc::AnyInbound | Ssrc::AnyOutbound => {
                // A wildcard inbound or outbound policy sets the stream template.  If the template
                // is already set, then the policy set is inconsistent.
                if let Some(_) = self.stream_template {
                    return Err(Error::BadParam);
                }

                self.stream_template = Some(stream);
                Ok(())
            }
        }
    }

    fn get_stream(&mut self, ssrc: Ssrc) -> Option<usize> {
        for i in 0..self.streams.len() {
            if self.streams[i].ssrc.equal_or_generic(ssrc) {
                // XXX(RLB) If we don't need Any, we can use `==` above, remove this line, and
                // remove the &mut from the `self` reference.
                self.streams[i].ssrc = ssrc;
                return Some(i);
            }
        }
        None
    }

    pub fn remove_stream(&mut self, ssrc: Ssrc) -> Result<(), Error> {
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
        match policy.ssrc {
            Ssrc::Inbound(_) | Ssrc::Outbound(_) | Ssrc::Any(_) => {
                self.update_specific_stream(kernel, policy)
            }
            Ssrc::AnyInbound | Ssrc::AnyOutbound => self.update_template_streams(kernel, policy),
        }
    }

    pub fn update_specific_stream(
        &mut self,
        kernel: &CryptoKernel,
        policy: &Policy,
    ) -> Result<(), Error> {
        let ssrc = policy.ssrc;
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

    fn make_stream(&self, ssrc: Ssrc) -> Result<Stream, Error> {
        let stream_template = self.stream_template.as_ref().ok_or(Error::NoContext)?;
        Ok(stream_template.clone_for_ssrc(ssrc)?)
    }

    pub fn update_template_streams(
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

    pub fn srtp_protect(&mut self, pkt_data: &mut [u8], pkt_len: usize) -> Result<usize, Error> {
        self.srtp_protect_mki(pkt_data, pkt_len, false, 0)
    }

    pub fn srtp_protect_mki(
        &mut self,
        pkt_data: &mut [u8],
        pkt_len: usize,
        use_mki: bool,
        mki_index: usize,
    ) -> Result<usize, Error> {
        let mut pkt = SrtpPacket::new(pkt_data, pkt_len)?;

        // Find or create the correct stream
        let ssrc = Ssrc::Outbound(pkt.header.ssrc);
        let stream_index = match self.get_stream(ssrc) {
            Some(x) => x,
            None => {
                if self.stream_template.is_none() {
                    return Err(Error::NoContext);
                }

                let stream = self.make_stream(ssrc)?;
                self.streams.push(stream);
                self.streams.len() - 1
            }
        };
        let stream = &mut self.streams[stream_index];

        // Encrypt the packet
        stream.srtp_protect(&mut pkt, use_mki, mki_index, self.event_handler)
    }

    pub fn srtp_unprotect(&mut self, pkt_data: &mut [u8]) -> Result<usize, Error> {
        self.srtp_unprotect_mki(pkt_data, false)
    }

    pub fn srtp_unprotect_mki(
        &mut self,
        pkt_data: &mut [u8],
        use_mki: bool,
    ) -> Result<usize, Error> {
        let mut pkt = SrtpPacket::new(pkt_data, pkt_data.len())?;

        // Get or create the stream
        let ssrc = Ssrc::Inbound(pkt.header.ssrc);
        let stream_index = self.get_stream(ssrc);
        let mut new_stream = match stream_index {
            Some(_) => None,
            None => Some(self.make_stream(ssrc)?),
        };
        let stream = match stream_index {
            Some(i) => &mut self.streams[i],
            None => new_stream.as_mut().ok_or(Error::Fail)?,
        };

        // Attempt to authenticate and decrypt the packet
        let pt_size = stream.srtp_unprotect(&mut pkt, use_mki, self.event_handler)?;

        // If decryption succeeded with a new stream, keep the stream
        if let Some(new_stream) = new_stream {
            self.streams.push(new_stream);
        }

        Ok(pt_size)
    }

    pub fn srtcp_protect(&mut self, pkt_data: &mut [u8], pkt_len: usize) -> Result<usize, Error> {
        self.srtcp_protect_mki(pkt_data, pkt_len, false, 0)
    }

    pub fn srtcp_protect_mki(
        &mut self,
        pkt_data: &mut [u8],
        pkt_len: usize,
        use_mki: bool,
        mki_index: usize,
    ) -> Result<usize, Error> {
        let mut pkt = SrtcpPacket::new(pkt_data, pkt_len)?;

        // Find or create the correct stream
        let ssrc = Ssrc::Outbound(pkt.header.ssrc);
        let stream_index = match self.get_stream(ssrc) {
            Some(x) => x,
            None => {
                if self.stream_template.is_none() {
                    return Err(Error::NoContext);
                }

                let stream = self.make_stream(ssrc)?;
                self.streams.push(stream);
                self.streams.len() - 1
            }
        };
        let stream = &mut self.streams[stream_index];

        // Encrypt the packet
        stream.srtcp_protect(&mut pkt, use_mki, mki_index, self.event_handler)
    }

    pub fn srtcp_unprotect(&mut self, pkt_data: &mut [u8]) -> Result<usize, Error> {
        self.srtcp_unprotect_mki(pkt_data, false)
    }

    pub fn srtcp_unprotect_mki(
        &mut self,
        pkt_data: &mut [u8],
        use_mki: bool,
    ) -> Result<usize, Error> {
        let mut pkt = SrtcpPacket::new(pkt_data, pkt_data.len())?;

        // Get or create the stream
        let ssrc = Ssrc::Inbound(pkt.header.ssrc);
        let stream_index = self.get_stream(ssrc);
        let mut new_stream = match stream_index {
            Some(_) => None,
            None => Some(self.make_stream(ssrc)?),
        };
        let stream = match stream_index {
            Some(i) => &mut self.streams[i],
            None => new_stream.as_mut().ok_or(Error::Fail)?,
        };

        // Attempt to authenticate and decrypt the packet
        let pt_size = stream.srtcp_unprotect(&mut pkt, use_mki, self.event_handler)?;

        // If decryption succeeded with a new stream, keep the stream
        if let Some(new_stream) = new_stream {
            self.streams.push(new_stream);
        }

        Ok(pt_size)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_session_keys() -> Result<(), Error> {
        // Verify that keys are derived in the same way as libsrtp in C
        let kernel = CryptoKernel::default()?;
        let key = MasterKey {
            key: hex!("e1f97a0d3e018be0d64fa32c06de4139").into(),
            salt: hex!("0ec675ad498afeebb6960b3aabe6").into(),
            id: [].into(),
        };
        let rtp_policy = CryptoPolicy::RTP_DEFAULT;
        let rtcp_policy = CryptoPolicy::RTP_DEFAULT;

        let _ = SessionKeys::new(&kernel, &key, &rtp_policy, &rtcp_policy)?;
        // TODO verify that the keys are right

        Ok(())
    }

    #[test]
    fn test_session_keys_gcm() -> Result<(), Error> {
        // Verify that keys are derived in the same way as libsrtp in C
        let kernel = CryptoKernel::default()?;
        let key = MasterKey {
            key: hex!("e1f97a0d3e018be0d64fa32c06de4139").into(),
            salt: hex!("0ec675ad498afeebb6960b3aabe6").into(),
            id: [].into(),
        };
        let rtp_policy = CryptoPolicy::AES_GCM_128;
        let rtcp_policy = CryptoPolicy::AES_GCM_128;

        let _ = SessionKeys::new(&kernel, &key, &rtp_policy, &rtcp_policy)?;
        // TODO verify that the keys are right

        Ok(())
    }

    // Common parameters for validation tests
    const KEY: &'static [u8] = &hex!("e1f97a0d3e018be0d64fa32c06de4139");
    const SALT: &'static [u8] = &hex!("0ec675ad498afeebb6960b3aabe6");
    const AEAD_SALT: &'static [u8] = &hex!("0ec675ad498afeebb6960b3a");
    const MKI: &'static [u8] = &hex!("e1f97a0d");
    const SHORT_AUTH_KEY_POLICY: CryptoPolicy = CryptoPolicy {
        cipher_type: CipherTypeID::AesIcm128,
        cipher_key_len: constants::AES_ICM_128_KEY_LEN_WSALT,
        auth_type: AuthTypeID::HmacSha1,
        auth_key_len: 16,
        auth_tag_len: 10,
        sec_serv: SecurityServices::ConfAndAuth,
    };

    // RTP Validation tests
    struct RtpValidationTest {
        aead: bool,
        mki: bool,
        enc_ext: bool,
        ciphertext: &'static [u8],
    }

    impl RtpValidationTest {
        const PLAINTEXT: &'static [u8] = &hex![
            "
            900f1234decafbad
            cafebabebede0006
            17414273A4752627
            48220000C8308E46
            55996386B395FB00
            abababababababab
            abababababababab"
        ];
        const ENCRYPTED_HEADERS: [u8; 3] = [1, 3, 4];

        fn validate(&self) -> Result<(), Error> {
            let mut policy = Policy {
                ssrc: Ssrc::AnyOutbound,
                rtp: SHORT_AUTH_KEY_POLICY,
                rtcp: SHORT_AUTH_KEY_POLICY,
                keys: vec![MasterKey {
                    key: KEY.to_vec(),
                    salt: SALT.to_vec(),
                    id: MKI.to_vec(),
                }],
                window_size: 128,
                allow_repeat_tx: false,
                xtn_headers_to_encrypt: vec![],
            };

            if self.aead {
                policy.rtp = CryptoPolicy::AES_GCM_128;
                policy.rtcp = CryptoPolicy::AES_GCM_128;
                policy.keys[0].salt = AEAD_SALT.to_vec();
            }

            if self.enc_ext {
                policy.xtn_headers_to_encrypt = Self::ENCRYPTED_HEADERS.into();
            }

            let policies = [policy];

            let kernel = CryptoKernel::default()?;
            let mut ctx_send = Context::new(&kernel, &policies)?;
            let mut ctx_recv = Context::new(&kernel, &policies)?;

            let pt_size = Self::PLAINTEXT.len();
            let mut buffer = [0u8; 80];
            buffer[..pt_size].copy_from_slice(Self::PLAINTEXT);

            // Verify that encryption produces the correct ciphertext
            let ct_size = if self.mki {
                ctx_send.srtp_protect_mki(&mut buffer, pt_size, true, 0)?
            } else {
                ctx_send.srtp_protect(&mut buffer, pt_size)?
            };
            assert_eq!(self.ciphertext, &buffer[..ct_size]);

            // Verify that decryption succeeds on the ciphertext
            let pt_size = if self.mki {
                ctx_recv.srtp_unprotect_mki(&mut buffer[..ct_size], true)?
            } else {
                ctx_recv.srtp_unprotect(&mut buffer[..ct_size])?
            };
            assert_eq!(Self::PLAINTEXT, &mut buffer[..pt_size]);

            Ok(())
        }
    }

    const RTP_VALIDATION_TESTS: &[RtpValidationTest] = &[
        RtpValidationTest {
            aead: false,
            mki: false,
            enc_ext: false,
            ciphertext: &hex!(
                "900f1234decafbadcafebabebede000617414273a475262748220000c8308e46
                 55996386b395fb004e55dc4ce79978d88ca4d215949d24023f8b392545c2fbb0
                 c33c"
            ),
        },
        RtpValidationTest {
            aead: false,
            mki: true,
            enc_ext: false,
            ciphertext: &hex!(
                "900f1234decafbadcafebabebede000617414273a475262748220000c8308e46
                 55996386b395fb004e55dc4ce79978d88ca4d215949d2402e1f97a0d3f8b3925
                 45c2fbb0c33c"
            ),
        },
        RtpValidationTest {
            aead: false,
            mki: false,
            enc_ext: true,
            ciphertext: &hex!(
                "900f1234decafbadcafebabebede000617588a9270f4e15e1c220000c8309546
                 a994f0bc547897004e55dc4ce79978d88ca4d215949d24026e89a746e7607c5e
                 3ad2"
            ),
        },
        RtpValidationTest {
            aead: true,
            mki: false,
            enc_ext: false,
            ciphertext: &hex!(
                "900f1234decafbadcafebabebede000617414273a475262748220000c8308e46
                 55996386b395fb000eca0cf95ee955b26cd3d288b49f6ca9e0eb4eab09af2bae
                 f6804f141b9b02b0"
            ),
        },
        RtpValidationTest {
            aead: true,
            mki: true,
            enc_ext: false,
            ciphertext: &hex!(
                "900f1234decafbadcafebabebede000617414273a475262748220000c8308e46
                 55996386b395fb000eca0cf95ee955b26cd3d288b49f6ca9e0eb4eab09af2bae
                 f6804f141b9b02b0e1f97a0d"
            ),
        },
        RtpValidationTest {
            aead: true,
            mki: false,
            enc_ext: true,
            ciphertext: &hex!(
                "900f1234decafbadcafebabebede00061712e0205bfa949b1c220000c
                 830bb46732778d9929aab000eca0cf95ee955b26cd3d288b49f6ca9f4
                 b1b759719eb5bc113b9ff1d40cd25a"
            ),
        },
    ];

    #[test]
    fn test_rtp_validation() -> Result<(), Error> {
        for test in RTP_VALIDATION_TESTS {
            test.validate()?
        }
        Ok(())
    }

    // RTCP Validation tests
    struct RtcpValidationTest {
        aead: bool,
        mki: bool,
        auth_only: bool,
        ciphertext: &'static [u8],
    }

    impl RtcpValidationTest {
        const PLAINTEXT: &'static [u8] = &hex![
            "c80006f3cb200183ab03a1eb020b3a000094200000009e00009b8881ca0005f3
             cb2001010a6f757468616e6e656c00000000"
        ];

        fn validate(&self) -> Result<(), Error> {
            let mut policy = Policy {
                ssrc: Ssrc::AnyOutbound,
                rtp: SHORT_AUTH_KEY_POLICY,
                rtcp: SHORT_AUTH_KEY_POLICY,
                keys: vec![MasterKey {
                    key: KEY.to_vec(),
                    salt: SALT.to_vec(),
                    id: MKI.to_vec(),
                }],
                window_size: 128,
                allow_repeat_tx: false,
                xtn_headers_to_encrypt: vec![],
            };

            if self.aead {
                policy.rtcp = CryptoPolicy::AES_GCM_128;
                policy.keys[0].salt = AEAD_SALT.to_vec();
            }

            if self.auth_only {
                policy.rtcp.sec_serv = SecurityServices::Auth;
            }

            let policies = [policy];

            let kernel = CryptoKernel::default()?;
            let mut ctx_send = Context::new(&kernel, &policies)?;
            let mut ctx_recv = Context::new(&kernel, &policies)?;

            let pt_size = Self::PLAINTEXT.len();
            let mut buffer = [0u8; 80];
            buffer[..pt_size].copy_from_slice(Self::PLAINTEXT);

            // Verify that encryption produces the correct ciphertext
            let ct_size = if self.mki {
                ctx_send.srtcp_protect_mki(&mut buffer, pt_size, true, 0)?
            } else {
                ctx_send.srtcp_protect(&mut buffer, pt_size)?
            };

            assert_eq!(self.ciphertext, &buffer[..ct_size]);

            // Verify that decryption succeeds on the ciphertext
            let pt_size = if self.mki {
                ctx_recv.srtcp_unprotect_mki(&mut buffer[..ct_size], true)?
            } else {
                ctx_recv.srtcp_unprotect(&mut buffer[..ct_size])?
            };
            assert_eq!(Self::PLAINTEXT, &mut buffer[..pt_size]);

            Ok(())
        }
    }

    const RTCP_VALIDATION_TESTS: &[RtcpValidationTest] = &[
        RtcpValidationTest {
            aead: false,
            mki: false,
            auth_only: false,
            ciphertext: &hex!(
                "c80006f3cb200183d7b53de643149ee23197d69da86eb8b476dcf161580c9ae3
                 d8e26db3cffc5cb14ac1c94e3462f2a6469480000001243caf328e5bd739d438"
            ),
        },
        RtcpValidationTest {
            aead: false,
            mki: true,
            auth_only: false,
            ciphertext: &hex!(
                "c80006f3cb200183d7b53de643149ee23197d69da86eb8b476dcf161580c9ae3
                 d8e26db3cffc5cb14ac1c94e3462f2a6469480000001e1f97a0d243caf328e5b
                 d739d438"
            ),
        },
        RtcpValidationTest {
            aead: false,
            mki: false,
            auth_only: true,
            ciphertext: &hex!(
                "c80006f3cb200183ab03a1eb020b3a000094200000009e00009b8881ca0005f3
                 cb2001010a6f757468616e6e656c0000000000000001d7a9661ceb221a2ec208"
            ),
        },
        RtcpValidationTest {
            aead: true,
            mki: false,
            auth_only: false,
            ciphertext: &hex!(
                "c80006f3cb2001836e87f6bdcdb482b1997e0b097cae3c38df506b92692b408d
                 da5a40326902a488b6126e8d229a810cedec9de3e6e4876bc08e75eda2f7dc33
                 67a080000001"
            ),
        },
        RtcpValidationTest {
            aead: true,
            mki: true,
            auth_only: false,
            ciphertext: &hex!(
                "c80006f3cb2001836e87f6bdcdb482b1997e0b097cae3c38df506b92692b408d
                 da5a40326902a488b6126e8d229a810cedec9de3e6e4876bc08e75eda2f7dc33
                 67a080000001e1f97a0d"
            ),
        },
        RtcpValidationTest {
            aead: true,
            mki: false,
            auth_only: true,
            ciphertext: &hex!(
                "c80006f3cb200183ab03a1eb020b3a000094200000009e00009b8881ca0005f3
                 cb2001010a6f757468616e6e656c000000001963d61ae031b347f39bc3ad9fbb
                 64fc00000001"
            ),
        },
    ];

    #[test]
    fn test_rtcp_validation() -> Result<(), Error> {
        for test in RTCP_VALIDATION_TESTS {
            test.validate()?
        }
        Ok(())
    }
}
