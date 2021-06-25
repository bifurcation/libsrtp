use crate::srtp::{Error, SessionKeys};
use packed_struct::prelude::*;
use std::ops::Range;

trait PackedSize {
    const SIZE: usize;
}

struct OffsetReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> OffsetReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data: data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn read(&mut self, size: usize) -> Result<Range<usize>, Error> {
        let start = self.pos;
        let end = self.pos + size;
        if end > self.data.len() {
            return Err(Error::BadParam);
        }

        self.pos += size;
        Ok(start..end)
    }

    fn unpack<T: PackedStruct + PackedSize>(&mut self) -> Result<T, Error> {
        let val_range = self.read(T::SIZE)?;
        let val_data = &self.data[val_range.clone()];
        let val = T::unpack_from_slice(val_data).or(Err(Error::BadParam))?;
        Ok(val)
    }

    fn rest(self) -> Range<usize> {
        self.pos..self.data.len()
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
    v: u8,

    #[packed_field(bits = "2")]
    p: u8,

    #[packed_field(bits = "3")]
    x: u8,

    #[packed_field(bits = "4..8")]
    cc: u8,

    #[packed_field(bits = "8")]
    m: u8,

    #[packed_field(bits = "9..16")]
    pt: u8,

    #[packed_field(endian = "msb")]
    seq: u16,

    #[packed_field(endian = "msb")]
    ts: u32,

    #[packed_field(endian = "msb")]
    ssrc: u32,
}

impl PackedSize for RtpHeader {
    const SIZE: usize = 12;
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
    const SIZE: usize = 4;
}

pub struct SrtpPacket<'a> {
    data: &'a mut [u8],
    header: RtpHeader,
    csrc: Range<usize>,
    ext_header: Option<RtpExtensionHeader>,
    extension: Range<usize>,
    payload: Range<usize>,
    mki: Range<usize>,
    tag: Range<usize>,
}

impl<'a> SrtpPacket<'a> {
    fn parse_base(data: &'a mut [u8]) -> Result<Self, Error> {
        let mut r = OffsetReader::new(data);

        // Parse the RTP header and CSRCs
        let header = r.unpack::<RtpHeader>()?;
        let csrc = r.read(4 * (header.cc as usize))?;

        // Parse the extension header if present
        let mut ext_header: Option<RtpExtensionHeader> = None;
        let mut ext = 0..0;
        if header.x == 1 {
            let hdr = r.unpack::<RtpExtensionHeader>()?;
            ext = r.read(4 * (hdr.length_u32 as usize))?;
            ext_header = Some(hdr);
        }

        // For now, we assume that the payload consumes the remainder
        let payload = r.rest();

        Ok(SrtpPacket {
            data: data,
            header: header,
            csrc: csrc,
            ext_header: ext_header,
            extension: ext,
            payload: payload,
            mki: 0..0,
            tag: 0..0,
        })
    }

    // TODO(RLB): Allocate space for cipher overhead?
    pub fn parse_for_encrypt(data: &'a mut [u8], sk: &SessionKeys) -> Result<Self, Error> {
        let mut pkt = Self::parse_base(data)?;

        let tag_size = sk.rtp_auth.tag_size();
        let mki_size = sk.mki_id.len();
        let (payload, mki, tag) = pkt.split_payload(mki_size, tag_size)?;

        pkt.payload = payload;
        pkt.mki = mki;
        pkt.tag = tag;
        Ok(pkt)
    }

    pub fn parse_for_decrypt<'sk>(
        data: &'a mut [u8],
        session_keys: &'sk Vec<SessionKeys>,
    ) -> Result<(Self, &'sk SessionKeys), Error> {
        let mut pkt = Self::parse_base(data)?;

        for sk in session_keys {
            let mki_size = sk.mki_id.len();
            let tag_size = sk.rtp_auth.tag_size();
            let (payload, mki, tag) = match pkt.split_payload(mki_size, tag_size) {
                Ok(x) => x,
                Err(err) => continue,
            };

            let possible_mki = &pkt.data[mki.clone()];
            if possible_mki != sk.mki_id.as_slice() {
                continue;
            }

            // This is our MKI!
            pkt.payload = payload;
            pkt.mki = mki;
            pkt.tag = tag;
            return Ok((pkt, sk));
        }
        Err(Error::BadParam)
    }

    fn split_payload(
        &self,
        mki_size: usize,
        tag_size: usize,
    ) -> Result<(Range<usize>, Range<usize>, Range<usize>), Error> {
        let mut r = OffsetReader::new(self.payload());
        if r.remaining() < mki_size + tag_size {
            return Err(Error::BadParam);
        }

        let payload_size = r.remaining() - (mki_size + tag_size);
        let payload = r.read(payload_size)?;
        let mki = r.read(mki_size)?;
        let tag = r.read(tag_size)?;
        Ok((payload, mki, tag))
    }

    pub fn payload<'b>(&'b self) -> &'b [u8] {
        &self.data[self.payload.clone()]
    }
}
