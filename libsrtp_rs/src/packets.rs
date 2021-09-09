use crate::crypto::TagSize;
use crate::policy::SecurityServices;
use crate::srtp::{Error, SessionKeys};
use packed_struct::prelude::*;
use std::ops::Range;

pub trait PackedSize {
    const PACKED_SIZE: usize;
}

struct OffsetReader<'a> {
    data: &'a mut [u8],
    pos: usize,
}

impl<'a> OffsetReader<'a> {
    fn new(data: &'a mut [u8]) -> Self {
        Self { data: data, pos: 0 }
    }

    fn empty() -> Self {
        Self {
            data: &mut [],
            pos: 0,
        }
    }

    fn skip_zeros(&mut self) -> usize {
        let initial_pos = self.pos;
        while self.pos < self.data.len() && self.data[self.pos] == 0x00 {
            self.pos += 1;
        }
        self.pos - initial_pos
    }

    fn remaining(&self) -> usize {
        if self.pos >= self.data.len() {
            return 0;
        }

        self.data.len() - self.pos
    }

    fn read<'b>(&'b mut self, size: usize) -> Result<(&'b mut [u8], Range<usize>), Error> {
        let start = self.pos;
        let end = self.pos + size;
        if end > self.data.len() {
            return Err(Error::ParseError);
        }

        self.pos += size;
        Ok((&mut self.data[start..end], start..end))
    }

    fn unpack<T: PackedStruct + PackedSize>(&mut self) -> Result<T, Error> {
        let (val_data, _val_range) = self.read(T::PACKED_SIZE)?;
        let val = T::unpack_from_slice(val_data).or(Err(Error::ParseError))?;
        Ok(val)
    }

    fn close(self) -> usize {
        self.pos
    }
}

// https://datatracker.ietf.org/doc/html/rfc3711#section-3.1
//
//      0                   1                   2                   3
//      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<+
//     |V=2|P|X|  CC   |M|     PT      |       sequence number         | |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
//     |                           timestamp                           | |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
//     |           synchronization source (SSRC) identifier            | |
//     +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+ |
//     |            contributing source (CSRC) identifiers             | |
//     |                               ....                            | |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
//     |                   RTP extension (OPTIONAL)                    | |
//   +>+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
//   | |                          payload  ...                         | |
//   | |                               +-------------------------------+ |
//   | |                               | RTP padding   | RTP pad count | |
//   +>+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<+
//   | ~                     SRTP MKI (OPTIONAL)                       ~ |
//   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
//   | :                 authentication tag (RECOMMENDED)              : |
//   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
//   |                                                                   |
//   +- Encrypted Portion*                      Authenticated Portion ---+
#[derive(PackedStruct)]
#[packed_struct(bit_numbering = "msb0")]
pub struct RtpHeader {
    #[packed_field(bits = "0..2")]
    pub v: u8,

    #[packed_field(bits = "2")]
    pub p: u8,

    #[packed_field(bits = "3")]
    pub x: u8,

    #[packed_field(bits = "4..8")]
    pub cc: u8,

    #[packed_field(bits = "8")]
    pub m: u8,

    #[packed_field(bits = "9..16")]
    pub pt: u8,

    #[packed_field(endian = "msb")]
    pub seq: u16,

    #[packed_field(endian = "msb")]
    pub ts: u32,

    #[packed_field(endian = "msb")]
    pub ssrc: u32,
}

impl PackedSize for RtpHeader {
    const PACKED_SIZE: usize = 12;
}

// https://datatracker.ietf.org/doc/html/rfc3550#section-5.3.1
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |      defined by profile       |           length              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                        header extension                       |
//   |                             ....                              |
const ONE_BYTE_HEADER: u16 = 0xBEDE;
const TWO_BYTE_HEADER: u16 = 0x1000;
const TWO_BYTE_HEADER_MASK: u16 = 0xfff0;

#[derive(PackedStruct)]
#[packed_struct(bit_numbering = "msb0")]
pub struct RtpExtensionHeader {
    #[packed_field(endian = "msb")]
    defined_by_profile: u16,

    #[packed_field(endian = "msb")]
    length_u32: u16,
}

impl PackedSize for RtpExtensionHeader {
    const PACKED_SIZE: usize = 4;
}

// https://datatracker.ietf.org/doc/html/rfc5285#section-4.2
//
// "defined by profile" = 0xBEDE
//
//       0
//       0 1 2 3 4 5 6 7
//      +-+-+-+-+-+-+-+-+
//      |  ID   |  len  |
//      +-+-+-+-+-+-+-+-+
#[derive(PackedStruct)]
#[packed_struct(bit_numbering = "msb0")]
pub struct OneByteElementHeader {
    #[packed_field(bits = "0..4")]
    id: u8,

    #[packed_field(bits = "4..8")]
    length: u8,
}

impl PackedSize for OneByteElementHeader {
    const PACKED_SIZE: usize = 1;
}

// https://datatracker.ietf.org/doc/html/rfc5285#section-4.3
//
//       0                   1
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |         0x100         |appbits|
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//       0                   1
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |       ID      |     length    |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(PackedStruct)]
#[packed_struct(bit_numbering = "msb0")]
pub struct TwoByteElementHeader {
    #[packed_field(bits = "0..8")]
    id: u8,

    #[packed_field(bits = "8..16")]
    length: u8,
}

impl PackedSize for TwoByteElementHeader {
    const PACKED_SIZE: usize = 2;
}

// https://datatracker.ietf.org/doc/html/rfc3711#section-3.4
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<+
//   |V=2|P|    RC   |   PT=SR or RR   |             length          | |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
//   |                         SSRC of sender                        | |
// +>+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+ |
// | ~                          sender info                          ~ |
// | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
// | ~                         report block 1                        ~ |
// | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
// | ~                         report block 2                        ~ |
// | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
// | ~                              ...                              ~ |
// | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
// | |V=2|P|    SC   |  PT=SDES=202  |             length            | |
// | +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+ |
// | |                          SSRC/CSRC_1                          | |
// | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
// | ~                           SDES items                          ~ |
// | +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+ |
// | ~                              ...                              ~ |
// +>+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+ |
// | |E|                         SRTCP index                         | |
// | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<+
// | ~                     SRTCP MKI (OPTIONAL)                      ~ |
// | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
// | :                     authentication tag                        : |
// | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
// |                                                                   |
// +-- Encrypted Portion                    Authenticated Portion -----+
#[derive(PackedStruct, Debug)]
#[packed_struct(bit_numbering = "msb0")]
pub struct RtcpHeader {
    #[packed_field(bits = "0..2")]
    pub v: u8,

    #[packed_field(bits = "2")]
    pub p: u8,

    #[packed_field(bits = "3..8")]
    pub rc: u8,

    #[packed_field]
    pub pt: u8,

    #[packed_field(endian = "msb")]
    pub length: u16,

    #[packed_field(endian = "msb")]
    pub ssrc: u32,
}

impl PackedSize for RtcpHeader {
    const PACKED_SIZE: usize = 8;
}

// https://datatracker.ietf.org/doc/html/rfc3711#section-3.4
//
// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
// |E|                         SRTCP index                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(PackedStruct, Copy, Clone, Debug)]
#[packed_struct(bit_numbering = "msb0")]
pub struct SrtcpTrailer {
    #[packed_field(bits = "0")]
    pub e: bool,

    #[packed_field(endian = "msb", bits = "1..32")]
    pub index: u32,
}

impl PackedSize for SrtcpTrailer {
    const PACKED_SIZE: usize = 4;
}

#[repr(usize)]
#[derive(Copy, Clone)]
pub enum ElementHeaderSize {
    OneByte = 1,
    TwoByte = 2,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RtpExtensionElement<'a> {
    pub id: u8,
    pub range: Range<usize>,
    pub data: &'a mut [u8],
}

pub struct RtpExtensionReader<'a> {
    reader: OffsetReader<'a>,
    header_size: ElementHeaderSize,
}

impl<'a> RtpExtensionReader<'a> {
    pub fn new(
        maybe_header: Option<&RtpExtensionHeader>,
        data: &'a mut [u8],
    ) -> Result<Self, Error> {
        let header = match maybe_header {
            Some(header) => header,
            None => return Ok(Self::empty()),
        };

        let elem_header_size = match header.defined_by_profile {
            ONE_BYTE_HEADER => ElementHeaderSize::OneByte,
            x if (x & TWO_BYTE_HEADER_MASK) == TWO_BYTE_HEADER => ElementHeaderSize::TwoByte,
            _ => return Err(Error::BadParam),
        };

        Ok(RtpExtensionReader {
            reader: OffsetReader::new(data),
            header_size: elem_header_size,
        })
    }

    pub fn empty() -> Self {
        RtpExtensionReader {
            reader: OffsetReader::empty(),
            header_size: ElementHeaderSize::OneByte,
        }
    }

    // Effectively a fallible iterator interface that borrows internal data:
    //   Ok(Some(x)) - Next item is x
    //   Ok(None) - No more items
    //   Err(err) - Parse error
    pub fn next<'b>(&'b mut self) -> Result<Option<RtpExtensionElement<'b>>, Error> {
        // Skip padding bytes
        self.reader.skip_zeros();

        // If we've reached the end of the buffer, there's nothing more to do
        if self.reader.remaining() == 0 {
            return Ok(None);
        }

        // Parse an extension element
        Ok(Some(match self.header_size {
            ElementHeaderSize::OneByte => {
                let header = self.reader.unpack::<OneByteElementHeader>()?;
                let (data, range) = self.reader.read((header.length + 1) as usize)?;
                RtpExtensionElement {
                    id: header.id,
                    range: range,
                    data: data,
                }
            }
            ElementHeaderSize::TwoByte => {
                let header = self.reader.unpack::<TwoByteElementHeader>()?;
                let (data, range) = self.reader.read(header.length as usize)?;
                RtpExtensionElement {
                    id: header.id,
                    range: range,
                    data: data,
                }
            }
        }))
    }

    pub fn apply<F>(&mut self, mut f: F) -> Result<(), Error>
    where
        F: FnMut(RtpExtensionElement) -> Result<(), Error>,
    {
        loop {
            match self.next() {
                Ok(Some(elem)) => f(elem)?,
                Ok(None) => break,
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }
}

pub struct SrtpPacket<'a> {
    data: &'a mut [u8],

    // Unpacked, read-only headers
    pub header: RtpHeader,
    pub ext_header: Option<RtpExtensionHeader>,

    // Offsets
    ext_start: usize,
    payload_start: usize,
    payload_end: usize,
    packet_end: usize,
}

impl<'a> SrtpPacket<'a> {
    pub fn new(data: &'a mut [u8], pkt_len: usize) -> Result<Self, Error> {
        let mut r = OffsetReader::new(&mut data[..pkt_len]);

        // Parse the RTP header and CSRCs
        let header = r.unpack::<RtpHeader>()?;
        r.read(4 * (header.cc as usize))?;

        // Parse the extension header if present
        let ext_header = if header.x == 1 {
            Some(r.unpack::<RtpExtensionHeader>()?)
        } else {
            None
        };

        let ext_start = r.close();
        let ext_size = match ext_header.as_ref() {
            Some(hdr) => 4 * (hdr.length_u32 as usize),
            None => 0,
        };

        let payload_start = ext_start + ext_size;
        if payload_start > pkt_len {
            return Err(Error::ParseError);
        }

        Ok(SrtpPacket {
            data: data,

            header: header,
            ext_header: ext_header,

            ext_start: ext_start,
            payload_start: ext_start + ext_size,
            payload_end: pkt_len,
            packet_end: pkt_len,
        })
    }

    pub fn find_mki<'b>(
        &mut self,
        session_keys: &'b mut Vec<SessionKeys>,
    ) -> Option<&'b mut SessionKeys> {
        for sk in session_keys {
            let mki_size = sk.mki_id.len();
            let tag_size = match sk.rtp_auth.tag_size() {
                Ok(x) => x,
                Err(_) => return None,
            };

            if self.payload_size() < mki_size + tag_size {
                continue;
            }

            let mki_start = self.payload_end - (mki_size + tag_size);
            let mki_end = mki_start + mki_size;
            let possible_mki = &self.data[mki_start..mki_end];
            if possible_mki != &sk.mki_id {
                continue;
            }

            // This is our MKI.  Payload ends where MKI starts
            self.payload_end = mki_start;
            return Some(sk);
        }
        None
    }

    pub fn find_tag(&mut self, sk: &SessionKeys) -> Result<(), Error> {
        if self.payload_end != self.packet_end {
            // This method should only be called on a not-yet-fully-parsed packet
            return Err(Error::BadParam);
        }

        let tag_size = match sk.rtp_auth.tag_size() {
            Ok(x) => x,
            Err(_) => return Err(Error::BadParam),
        };

        let payload_size = self.payload_end - self.payload_start;
        if tag_size > payload_size {
            return Err(Error::BadParam);
        }

        self.payload_end -= tag_size;
        Ok(())
    }

    pub fn extensions<'b>(&'b mut self) -> Result<RtpExtensionReader<'b>, Error> {
        let ext_data = &mut self.data[self.ext_start..self.payload_start];
        RtpExtensionReader::new(self.ext_header.as_ref(), ext_data)
    }

    pub fn aad<'b>(&'b self) -> &'b [u8] {
        &self.data[..self.payload_start]
    }

    pub fn auth_data<'b>(&'b self) -> &'b [u8] {
        &self.data[..self.payload_end]
    }

    pub fn payload_for_encrypt<'b>(&'b mut self) -> &'b mut [u8] {
        &mut self.data[self.payload_start..]
    }

    pub fn payload_for_decrypt<'b>(&'b mut self) -> &'b mut [u8] {
        &mut self.data[self.payload_start..self.payload_end]
    }

    pub fn payload_size(&self) -> usize {
        self.payload_end - self.payload_start
    }

    pub fn set_payload_size(&mut self, size: usize) -> Result<(), Error> {
        // This method should only be called when the end of the payload is the end of the packet
        if self.payload_end != self.packet_end {
            return Err(Error::BadParam);
        }

        let new_payload_end = self.payload_start + size;
        if new_payload_end > self.data.len() {
            return Err(Error::BadParam);
        }

        self.payload_end = new_payload_end;
        self.packet_end = new_payload_end;
        Ok(())
    }

    pub fn append<'b>(&'b mut self, size: usize) -> Result<&'b mut [u8], Error> {
        let old_packet_end = self.packet_end;
        let new_packet_end = self.packet_end + size;
        if new_packet_end > self.data.len() {
            return Err(Error::BadParam);
        }

        self.packet_end = new_packet_end;
        Ok(&mut self.data[old_packet_end..new_packet_end])
    }

    pub fn last<'b>(&'b self, size: usize) -> Result<&'b [u8], Error> {
        if size > self.packet_end {
            return Err(Error::BadParam);
        }

        let start = self.packet_end - size;
        if start < self.payload_end {
            // Don't allow reading from within the payload
            return Err(Error::BadParam);
        }

        Ok(&self.data[start..self.packet_end])
    }

    pub fn strip(&mut self, size: usize) -> Result<(), Error> {
        // Only allow stripping of post-payload data
        if size > self.packet_end - self.payload_end {
            return Err(Error::BadParam);
        }

        self.packet_end -= size;
        Ok(())
    }

    pub fn size(&self) -> usize {
        self.packet_end
    }
}

// XXX(RLB) There's some duplicate logic here with SrtpPacket, e.g., around finding MKI/tag and
// appending/stripping.  It wasn't immediately clear to me how to improve this situation given that
// Rust lacks the sort of structure composition that C++ has.
#[derive(Debug)]
pub struct SrtcpPacket<'a> {
    pub data: &'a mut [u8],

    // Read-only state
    pub header: RtcpHeader,
    trailer: Option<SrtcpTrailer>,
    trailer_data: [u8; 4],

    // Offsets
    payload_start: usize,
    payload_end: usize,
    trailer_end: usize,
    packet_end: usize,
}

impl<'a> SrtcpPacket<'a> {
    pub fn new(data: &'a mut [u8], pkt_len: usize) -> Result<Self, Error> {
        let mut r = OffsetReader::new(&mut data[..pkt_len]);

        let header = r.unpack::<RtcpHeader>()?;
        let payload_start = r.close();

        Ok(SrtcpPacket {
            data: data,

            header: header,
            trailer: None,
            trailer_data: Default::default(),

            payload_start: payload_start,
            payload_end: pkt_len,
            trailer_end: pkt_len,
            packet_end: pkt_len,
        })
    }

    pub fn set_e_index(&mut self, services: SecurityServices, index: u32) -> Result<(), Error> {
        let trailer = SrtcpTrailer {
            e: services.confidentiality(),
            index: index,
        };
        let trailer_data = trailer.pack().map_err(|_| Error::Fail)?;

        self.trailer = Some(trailer);
        self.trailer_data = trailer_data;
        Ok(())
    }

    pub fn parse_trailer(&mut self) -> Result<SrtcpTrailer, Error> {
        if self.trailer_end < SrtcpTrailer::PACKED_SIZE {
            return Err(Error::BadParam);
        }

        let trailer_start = self.trailer_end - SrtcpTrailer::PACKED_SIZE;
        let trailer_data = &mut self.data[trailer_start..self.trailer_end];
        let trailer = OffsetReader::new(trailer_data).unpack::<SrtcpTrailer>()?;

        self.trailer = Some(trailer);
        self.trailer_data.copy_from_slice(trailer_data);
        Ok(trailer)
    }

    pub fn find_mki<'b>(
        &mut self,
        session_keys: &'b mut Vec<SessionKeys>,
    ) -> Option<&'b mut SessionKeys> {
        for sk in session_keys {
            let trailer_size = SrtcpTrailer::PACKED_SIZE;
            let mki_size = sk.mki_id.len();
            let tag_size = match sk.rtcp_auth.tag_size() {
                Ok(x) => x,
                Err(_) => return None,
            };

            if self.payload_size() < trailer_size + mki_size + tag_size {
                continue;
            }

            let mki_start = self.payload_end - (mki_size + tag_size);
            let mki_end = mki_start + mki_size;
            let possible_mki = &self.data[mki_start..mki_end];
            if possible_mki != &sk.mki_id {
                continue;
            }

            // This is our MKI.  End of the packet is trailer || mki || tag
            let trailer_start = mki_start - trailer_size;
            self.payload_end = trailer_start;
            self.trailer_end = mki_start;
            return Some(sk);
        }
        None
    }

    pub fn find_tag(&mut self, sk: &SessionKeys) -> Result<(), Error> {
        if self.payload_end != self.packet_end || self.trailer_end != self.packet_end {
            // This method should only be called on a not-yet-fully-parsed packet
            return Err(Error::BadParam);
        }

        let tag_size = match sk.rtcp_auth.tag_size() {
            Ok(x) => x,
            Err(_) => return Err(Error::BadParam),
        };

        let trailer_size = SrtcpTrailer::PACKED_SIZE;
        let payload_size = self.payload_end - self.payload_start;
        if tag_size + trailer_size > payload_size {
            return Err(Error::BadParam);
        }

        self.trailer_end = self.packet_end - tag_size;
        self.payload_end = self.packet_end - tag_size - trailer_size;
        Ok(())
    }

    pub fn aad<'b>(&'b mut self, overhead: usize) -> Result<(&'b [u8], &'b [u8]), Error> {
        let trailer = self.trailer.as_ref().ok_or(Error::BadParam)?;
        let base_aad_end = if trailer.e {
            RtcpHeader::PACKED_SIZE
        } else {
            if self.payload_end < overhead {
                return Err(Error::BadParam);
            }

            self.payload_end - overhead
        };

        Ok((&self.data[..base_aad_end], &self.trailer_data))
    }

    pub fn auth_data<'b>(&'b self) -> &'b [u8] {
        &self.data[..self.trailer_end]
    }

    pub fn payload_for_encrypt<'b>(&'b mut self, auth_only: bool) -> &'b mut [u8] {
        if auth_only {
            &mut self.data[self.payload_end..]
        } else {
            &mut self.data[self.payload_start..]
        }
    }

    pub fn payload_for_decrypt_tag_only<'b>(
        &'b mut self,
        overhead: usize,
    ) -> Result<&'b mut [u8], Error> {
        if overhead > self.payload_size() {
            return Err(Error::BadParam);
        }

        let tag_start = self.payload_end - overhead;
        Ok(&mut self.data[tag_start..self.payload_end])
    }

    pub fn payload_for_decrypt<'b>(&'b mut self) -> &'b mut [u8] {
        &mut self.data[self.payload_start..self.payload_end]
    }

    pub fn payload_size(&self) -> usize {
        self.payload_end - self.payload_start
    }

    pub fn set_payload_size(&mut self, size: usize) -> Result<(), Error> {
        // This method should only be called when the end of the payload is the end of the packet
        if self.payload_end != self.packet_end {
            return Err(Error::BadParam);
        }

        let new_payload_end = self.payload_start + size;
        if new_payload_end > self.data.len() {
            return Err(Error::BadParam);
        }

        self.payload_end = new_payload_end;
        self.trailer_end = new_payload_end;
        self.packet_end = new_payload_end;
        Ok(())
    }

    pub fn append<'b>(&'b mut self, size: usize) -> Result<&'b mut [u8], Error> {
        let old_packet_end = self.packet_end;
        let new_packet_end = self.packet_end + size;
        if new_packet_end > self.data.len() {
            return Err(Error::BadParam);
        }

        self.packet_end = new_packet_end;
        Ok(&mut self.data[old_packet_end..new_packet_end])
    }

    pub fn append_trailer(&mut self) -> Result<(), Error> {
        // This method should only be called when the end of the trailer is the end of the packet
        if self.trailer_end != self.packet_end {
            return Err(Error::BadParam);
        }

        let trailer = self.trailer_data;
        let trailer_size = SrtcpTrailer::PACKED_SIZE;
        self.append(trailer_size)?.copy_from_slice(&trailer);
        self.trailer_end = self.payload_end + trailer_size;
        Ok(())
    }

    pub fn last<'b>(&'b self, size: usize) -> Result<&'b [u8], Error> {
        if size > self.packet_end {
            return Err(Error::BadParam);
        }

        let start = self.packet_end - size;
        if start < self.payload_end {
            // Don't allow reading from within the payload
            return Err(Error::BadParam);
        }

        Ok(&self.data[start..self.packet_end])
    }

    pub fn strip(&mut self, size: usize) -> Result<(), Error> {
        // Only allow stripping of post-payload data
        if size > self.packet_end - self.payload_end {
            return Err(Error::BadParam);
        }

        self.packet_end -= size;
        Ok(())
    }

    pub fn strip_trailer(&mut self) -> Result<(), Error> {
        self.strip(SrtcpTrailer::PACKED_SIZE)?;
        self.trailer_end -= SrtcpTrailer::PACKED_SIZE;
        Ok(())
    }

    pub fn size(&self) -> usize {
        self.packet_end
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::{xor_eq, AuthTypeID, CipherTypeID, CryptoKernel, ExtensionCipherTypeID};
    use crate::key_limit::KeyLimitContext;
    use hex_literal::hex;

    // SRTP extension parsing

    //      0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |       0xBE    |    0xDE       |           length=3            |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |  ID   | L=0   |     data      |  ID   |  L=1  |   data...
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //       ...data   |    0 (pad)    |    0 (pad)    |  ID   | L=3   |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                          data                                 |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #[test]
    fn test_one_byte_extensions() -> Result<(), Error> {
        let ext_header = RtpExtensionHeader {
            defined_by_profile: 0xbede,
            length_u32: 3,
        };
        let mut ext_data = hex!("10aa21bbbb000033cccccccc");

        let expected_extensions = &[
            RtpExtensionElement {
                id: 1,
                range: 1..2,
                data: &mut hex!("aa"),
            },
            RtpExtensionElement {
                id: 2,
                range: 3..5,
                data: &mut hex!("bbbb"),
            },
            RtpExtensionElement {
                id: 3,
                range: 8..12,
                data: &mut hex!("cccccccc"),
            },
        ];

        let mut reader = RtpExtensionReader::new(Some(&ext_header), &mut ext_data)?;
        let mut i = 0usize;
        reader.apply(|ext| {
            assert_eq!(ext, expected_extensions[i]);
            i += 1;
            Ok(())
        })?;
        assert_eq!(i, expected_extensions.len());

        Ok(())
    }

    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |       0x10    |    0x00       |           length=3            |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |      ID       |     L=0       |     ID        |     L=1       |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |       data    |    0 (pad)    |       ID      |      L=4      |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                          data                                 |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #[test]
    fn test_two_byte_extensions() -> Result<(), Error> {
        let ext_header = RtpExtensionHeader {
            defined_by_profile: 0x1000,
            length_u32: 3,
        };
        let mut ext_data = hex!("01000201aa000304bbbbbbbb");

        let expected_extensions: &[RtpExtensionElement] = &[
            RtpExtensionElement {
                id: 1,
                range: 2..2,
                data: &mut [],
            },
            RtpExtensionElement {
                id: 2,
                range: 4..5,
                data: &mut hex!("aa"),
            },
            RtpExtensionElement {
                id: 3,
                range: 8..12,
                data: &mut hex!("bbbbbbbb"),
            },
        ];

        let mut reader = RtpExtensionReader::new(Some(&ext_header), &mut ext_data)?;
        let mut i = 0usize;
        loop {
            match reader.next() {
                Ok(Some(ext)) => {
                    assert_eq!(ext, expected_extensions[i]);
                    i += 1
                }
                Ok(None) => break,
                Err(err) => return Err(err),
            }
        }
        assert_eq!(i, expected_extensions.len());

        Ok(())
    }

    // SRTP Packet Parsing
    const PLAINTEXT_PACKET: &[u8] = &hex!(
        "
        // Header
        900f1234decafbadcafebabe
        // Extension
        bede000617414273a475262748220000c8308e4655996386b395fb00
        // Payload
        abababababababababababababababab"
    );

    const CIPHERTEXT_PACKET: &[u8] = &hex!(
        "
        // Header
        900f1234decafbadcafebabe
        // Extension
        bede00061712e0205bfa949b1c220000c830bb46732778d9929aab00
        // Payload
        0eca0cf95ee955b26cd3d288b49f6ca9f4b1b759719eb5bc113b9ff1d40cd25a
        // MKI = 'mki'
        6d6b69
        // Tag = 'tag'
        746167"
    );

    const EXTENSION_KEYSTREAM: &[u8] = &hex!("0053a253ff8fb2bc540000000000350026be1b5f210f5000");
    const PAYLOAD_KEYSTREAM: &[u8] = &hex!("a561a752f542fe19c77879231f34c702");
    const PAYLOAD_TAG: &[u8] = &hex!("f4b1b759719eb5bc113b9ff1d40cd25a");
    const AAD: &[u8] =
        &hex!("900f1234decafbadcafebabebede00061712e0205bfa949b1c220000c830bb46732778d9929aab00");
    const AUTH_DATA: &[u8] = &hex!(
        "900f1234decafbadcafebabebede00061712e0205bfa949b1c220000c830bb46
         732778d9929aab000eca0cf95ee955b26cd3d288b49f6ca9f4b1b759719eb5bc
         113b9ff1d40cd25a"
    );
    const MKI: &[u8] = &hex!("6d6b69");
    const TAG: &[u8] = &hex!("746167");

    #[test]
    fn test_header_parsing() -> Result<(), Error> {
        let pt_size = PLAINTEXT_PACKET.len();
        let mut pkt_data = [0u8; 100];
        pkt_data[..pt_size].copy_from_slice(PLAINTEXT_PACKET);
        let pkt = SrtpPacket::new(&mut pkt_data, pt_size)?;

        // Verify that header values are correct
        assert_eq!(pkt.header.v, 2);
        assert_eq!(pkt.header.p, 0);
        assert_eq!(pkt.header.x, 1);
        assert_eq!(pkt.header.cc, 0);
        assert_eq!(pkt.header.m, 0);
        assert_eq!(pkt.header.pt, 0x0f);
        assert_eq!(pkt.header.seq, 0x1234);
        assert_eq!(pkt.header.ts, 0xdecafbad);
        assert_eq!(pkt.header.ssrc, 0xcafebabe);

        // Verify that the extension parses properly
        assert!(pkt.ext_header.is_some());
        assert_eq!(pkt.ext_header.as_ref().unwrap().defined_by_profile, 0xbede);
        assert_eq!(pkt.ext_header.as_ref().unwrap().length_u32, 6);
        Ok(())
    }

    fn encrypt(buf: &mut [u8], keystream: &[u8], tag: &[u8], pt_size: usize) -> usize {
        xor_eq(&mut buf[..keystream.len()], keystream);

        let tag_end = pt_size + tag.len();
        buf[pt_size..tag_end].copy_from_slice(tag);
        tag_end
    }

    fn decrypt(
        buf: &mut [u8],
        keystream: &[u8],
        tag: &[u8],
        ct_size: usize,
    ) -> Result<usize, Error> {
        let pt_size = ct_size - tag.len();
        if &buf[pt_size..ct_size] != tag {
            return Err(Error::AuthFail);
        }

        xor_eq(&mut buf[..pt_size], keystream);
        Ok(pt_size)
    }

    #[test]
    fn test_srtp_protect_parsing() -> Result<(), Error> {
        let pkt_size = PLAINTEXT_PACKET.len();
        let mut pkt_data = [0u8; 100];
        pkt_data[..pkt_size].copy_from_slice(PLAINTEXT_PACKET);
        let mut pkt = SrtpPacket::new(&mut pkt_data, pkt_size)?;

        // Emulate encrypting header
        pkt.extensions()?.apply(|ext| {
            xor_eq(ext.data, &EXTENSION_KEYSTREAM[ext.range]);
            Ok(())
        })?;

        // Verify that AAD is as expected
        assert_eq!(pkt.aad(), AAD);

        // Emulate encrypting payload
        let pt_size = pkt.payload_size();
        let ct_size = encrypt(
            pkt.payload_for_encrypt(),
            PAYLOAD_KEYSTREAM,
            PAYLOAD_TAG,
            pt_size,
        );
        pkt.set_payload_size(ct_size)?;

        // Append MKI
        pkt.append(MKI.len())?.copy_from_slice(MKI);

        // Verify that auth input is as expected
        assert_eq!(pkt.auth_data(), AUTH_DATA);

        // Append tag
        pkt.append(TAG.len())?.copy_from_slice(TAG);

        // Verify that final packet content is correct
        let pkt_size = pkt.size();
        assert_eq!(&pkt_data[..pkt_size], CIPHERTEXT_PACKET);

        Ok(())
    }

    #[test]
    fn test_srtp_unprotect_parsing() -> Result<(), Error> {
        let kernel = CryptoKernel::default()?;
        let null_cipher = kernel.cipher(CipherTypeID::Null, &[], &[])?;
        let null_xtn_cipher = kernel.xtn_cipher(ExtensionCipherTypeID::Null, &[], &[])?;
        let hmac_auth = kernel.auth(AuthTypeID::HmacSha1, &[], TAG.len())?;

        let mut sks = vec![SessionKeys {
            rtp_cipher: null_cipher.clone(),
            rtp_xtn_hdr_cipher: null_xtn_cipher,
            rtp_auth: hmac_auth.clone(),
            rtcp_cipher: null_cipher.clone(),
            rtcp_auth: hmac_auth.clone(),

            mki_id: MKI.to_vec(),
            limit: KeyLimitContext::new(),
        }];

        let pkt_size = CIPHERTEXT_PACKET.len();
        let mut pkt_data = [0u8; 100];
        pkt_data[..pkt_size].copy_from_slice(CIPHERTEXT_PACKET);
        let mut pkt = SrtpPacket::new(&mut pkt_data, pkt_size)?;

        // Find MKI
        pkt.find_mki(&mut sks).ok_or(Error::Fail)?;

        // Verify that auth input is as expected
        assert_eq!(pkt.auth_data(), AUTH_DATA);

        // Verify and strip tag
        assert_eq!(pkt.last(TAG.len())?, TAG);
        pkt.strip(TAG.len())?;

        // Verify and strip MKI
        assert_eq!(pkt.last(MKI.len())?, MKI);
        pkt.strip(MKI.len())?;

        // Verify that AAD is as expected
        assert_eq!(pkt.aad(), AAD);

        // Emulate decrypting payload
        let ct_size = pkt.payload_size();
        let pt_size = decrypt(
            pkt.payload_for_decrypt(),
            PAYLOAD_KEYSTREAM,
            PAYLOAD_TAG,
            ct_size,
        )?;
        pkt.set_payload_size(pt_size)?;

        // Emulate decrypting extension
        pkt.extensions()?.apply(|ext| {
            xor_eq(ext.data, &EXTENSION_KEYSTREAM[ext.range]);
            Ok(())
        })?;

        // Verify that final packet content is correct
        let pkt_size = pkt.size();
        assert_eq!(&pkt_data[..pkt_size], PLAINTEXT_PACKET);

        Ok(())
    }

    // SRTCP Values (others borrowed from above)
    const PLAINTEXT_PACKET_RTCP: &[u8] = &hex!(
        "// Header
         800f1234decafbad
         // Payload
         decafbadabababababababababababababababababababababababababababab"
    );
    const CIPHERTEXT_PACKET_RTCP: &[u8] = &hex!(
        "// Header
         800f1234decafbad
         // Payload...
         ddad228413ad5d8f1d1bc7165bf52f86fd82ca685bd442cb1055472dd06641a1
         // Trailer
         80000001
         // MKI = 'mki'
         6d6b69
         // Tag = 'tag'
         746167"
    );
    const PAYLOAD_KEYSTREAM_RTCP: &[u8] =
        &hex!("0367d929b806f624b6b06cbdf05e842d562961c3f07fe960bbfeec867bcdea0a");
    const PAYLOAD_TAG_RTCP: &[u8] = &[];
    const AAD_RTCP_E: &[u8] = &hex!(
        "800f1234decafbad  // Header
         80000001          // Trailer"
    );
    const AAD_RTCP_NOT_E: &[u8] = &hex!(
        "// Header
         800f1234decafbad
         // Payload
         decafbadabababababababababababababababababababababababababababab
         // Trailer
         80000001"
    );
    const AUTH_DATA_RTCP: &[u8] = &hex!(
        "// Header
         800f1234decafbad
         // Payload...
         ddad228413ad5d8f1d1bc7165bf52f86fd82ca685bd442cb1055472dd06641a1
         // Trailer
         80000001"
    );

    #[test]
    fn test_srtcp_protect_parsing() -> Result<(), Error> {
        let pkt_size = PLAINTEXT_PACKET_RTCP.len();
        let mut pkt_data = [0u8; 100];
        pkt_data[..pkt_size].copy_from_slice(PLAINTEXT_PACKET_RTCP);
        let mut pkt = SrtcpPacket::new(&mut pkt_data, pkt_size)?;
        pkt.set_e_index(SecurityServices::ConfAndAuth, 1)?;

        // Verify that AAD is as expected (with and without encryption)
        let (base_aad, trailer_aad) = pkt.aad(0)?;
        assert_eq!([base_aad, trailer_aad].concat(), AAD_RTCP_E);

        pkt.trailer.as_mut().unwrap().e = false;
        let (base_aad, trailer_aad) = pkt.aad(0)?;
        assert_eq!([base_aad, trailer_aad].concat(), AAD_RTCP_NOT_E);
        pkt.trailer.as_mut().unwrap().e = true;

        // Emulate encrypting payload
        let pt_size = pkt.payload_size();
        let ct_size = encrypt(
            pkt.payload_for_encrypt(false),
            PAYLOAD_KEYSTREAM_RTCP,
            PAYLOAD_TAG_RTCP,
            pt_size,
        );
        pkt.set_payload_size(ct_size)?;

        // Append trailer
        pkt.append_trailer()?;

        // Append MKI
        pkt.append(MKI.len())?.copy_from_slice(MKI);

        // Verify that auth input is as expected
        assert_eq!(pkt.auth_data(), AUTH_DATA_RTCP);

        // Append tag
        pkt.append(TAG.len())?.copy_from_slice(TAG);

        // Verify that final packet content is correct
        let pkt_size = pkt.size();
        assert_eq!(&pkt_data[..pkt_size], CIPHERTEXT_PACKET_RTCP);

        Ok(())
    }

    #[test]
    fn test_srtcp_unprotect_parsing() -> Result<(), Error> {
        let kernel = CryptoKernel::default()?;
        let null_cipher = kernel.cipher(CipherTypeID::Null, &[], &[])?;
        let null_xtn_cipher = kernel.xtn_cipher(ExtensionCipherTypeID::Null, &[], &[])?;
        let hmac_auth = kernel.auth(AuthTypeID::HmacSha1, &[], TAG.len())?;

        let mut sks = vec![SessionKeys {
            rtp_cipher: null_cipher.clone(),
            rtp_xtn_hdr_cipher: null_xtn_cipher,
            rtp_auth: hmac_auth.clone(),
            rtcp_cipher: null_cipher.clone(),
            rtcp_auth: hmac_auth.clone(),

            mki_id: MKI.to_vec(),
            limit: KeyLimitContext::new(),
        }];

        let pkt_size = CIPHERTEXT_PACKET_RTCP.len();
        let mut pkt_data = [0u8; 100];
        pkt_data[..pkt_size].copy_from_slice(CIPHERTEXT_PACKET_RTCP);
        let mut pkt = SrtcpPacket::new(&mut pkt_data, pkt_size)?;

        // Find MKI
        pkt.find_mki(&mut sks).ok_or(Error::Fail)?;
        pkt.parse_trailer()?;

        // Verify that auth input is as expected
        assert_eq!(pkt.auth_data(), AUTH_DATA_RTCP);

        // Verify and strip tag
        assert_eq!(pkt.last(TAG.len())?, TAG);
        pkt.strip(TAG.len())?;

        // Verify and strip MKI
        assert_eq!(pkt.last(MKI.len())?, MKI);
        pkt.strip(MKI.len())?;

        // Strip the trailer
        pkt.strip_trailer()?;

        // Verify that AAD is as expected
        let (base_aad, trailer_aad) = pkt.aad(0)?;
        assert_eq!([base_aad, trailer_aad].concat(), AAD_RTCP_E);

        // Emulate decrypting payload
        let ct_size = pkt.payload_size();
        let pt_size = decrypt(
            pkt.payload_for_decrypt(),
            PAYLOAD_KEYSTREAM_RTCP,
            PAYLOAD_TAG_RTCP,
            ct_size,
        )?;
        pkt.set_payload_size(pt_size)?;

        // Check that AAD without encryption is as expected
        pkt.trailer.as_mut().unwrap().e = false;
        let (base_aad, trailer_aad) = pkt.aad(0)?;
        assert_eq!([base_aad, trailer_aad].concat(), AAD_RTCP_NOT_E);
        pkt.trailer.as_mut().unwrap().e = true;

        // Verify that final packet content is correct
        let pkt_size = pkt.size();
        assert_eq!(&pkt_data[..pkt_size], PLAINTEXT_PACKET_RTCP);

        Ok(())
    }
}
