use crate::srtp::{Error, SessionKeys};
use core::iter::Iterator;
use packed_struct::prelude::*;
use std::ops::Range;

trait PackedSize {
    const PACKED_SIZE: usize;
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
        if self.pos >= self.data.len() {
            return 0;
        }

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
        let val_range = self.read(T::PACKED_SIZE)?;
        let val_data = &self.data[val_range.clone()];
        let val = T::unpack_from_slice(val_data).or(Err(Error::BadParam))?;
        Ok(val)
    }

    fn rest(self) -> Range<usize> {
        self.pos..self.data.len()
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

#[repr(usize)]
#[derive(Copy, Clone)]
pub enum ElementHeaderSize {
    OneByte = 1,
    TwoByte = 2,
}

pub struct RtpExtensionElement {
    pub id: u8,
    pub header_size: ElementHeaderSize,
    pub range: Range<usize>,
}

impl RtpExtensionElement {
    fn new(
        header_size: ElementHeaderSize,
        reader: &mut OffsetReader,
    ) -> Result<RtpExtensionElement, Error> {
        // Parse the header
        let (id, elem_size) = match header_size {
            ElementHeaderSize::OneByte => {
                let header = reader.unpack::<OneByteElementHeader>()?;
                (header.id, header.length as usize)
            }
            ElementHeaderSize::TwoByte => {
                let header = reader.unpack::<TwoByteElementHeader>()?;
                (header.id, header.length as usize)
            }
        };

        // Extract the data
        let elem_data = reader.read(elem_size)?;
        let elem = RtpExtensionElement {
            id: id,
            header_size: header_size,
            range: elem_data,
        };
        Ok(elem)
    }
}

pub struct RtpExtensionReader<'a> {
    reader: OffsetReader<'a>,
    header_size: ElementHeaderSize,
    pos: usize,
}

impl<'a> RtpExtensionReader<'a> {
    fn empty() -> Self {
        RtpExtensionReader {
            reader: OffsetReader::new(&mut []),
            header_size: ElementHeaderSize::OneByte,
            pos: 0,
        }
    }

    fn new(header: &RtpExtensionHeader, data: &'a mut [u8]) -> Result<Self, Error> {
        let elem_header_size = match header.defined_by_profile {
            ONE_BYTE_HEADER => ElementHeaderSize::OneByte,
            x if (x & TWO_BYTE_HEADER_MASK) == TWO_BYTE_HEADER => ElementHeaderSize::TwoByte,
            _ => return Err(Error::BadParam),
        };

        Ok(RtpExtensionReader {
            reader: OffsetReader::new(data),
            header_size: elem_header_size,
            pos: 0,
        })
    }
}

impl<'a> Iterator for RtpExtensionReader<'a> {
    type Item = RtpExtensionElement;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.remaining() == 0 {
            return None;
        }

        // XXX(RLB) This throws away error information, so a packet with malformed extensions will
        // not result in an error.  Instead, the extensions will be processed up to the point where
        // the error occurs.  To fix this, we should either return errors (and thus not satisfy
        // Iterator), or pre-validate that the extensions are correct in new().
        RtpExtensionElement::new(self.header_size, &mut self.reader).ok()
    }
}

pub struct SrtpPacket<'a> {
    data: &'a mut [u8],

    // Unpacked, read-only headers
    pub header: RtpHeader,
    ext_header: Option<RtpExtensionHeader>,

    // Offsets
    ext_start: usize,
    payload_start: usize,
    payload_end: usize,
    packet_end: usize,
}

impl<'a> SrtpPacket<'a> {
    pub fn new(data: &'a mut [u8], pkt_len: usize) -> Result<Self, Error> {
        let mut r = OffsetReader::new(&data[..pkt_len]);

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
            let tag_size = sk.rtp_auth.tag_size();

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

    pub fn extension(&mut self) -> Result<RtpExtensionReader, Error> {
        let ext_data = &mut self.data[self.ext_start..self.payload_start];
        match self.ext_header.as_ref() {
            Some(hdr) => RtpExtensionReader::new(hdr, ext_data),
            None => Ok(RtpExtensionReader::empty()),
        }
    }

    pub fn aad<'b>(&'b self) -> &'b [u8] {
        &self.data[..self.payload_start]
    }

    pub fn auth_data<'b>(&'b self) -> &'b [u8] {
        &self.data[..self.payload_end]
    }

    pub fn payload<'b>(&'b mut self) -> &'b mut [u8] {
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

        Ok(&self.data[start..])
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

#[cfg(test)]
mod test {
    use super::*;

    fn test_srtp_protect_parsing() {
        // TODO encrypt extension
        // TODO verify that AAD is as expected
        // TODO encrypt payload
        // TODO append MKI
        // TODO verify that auth input is as expected
        // TODO append tag
        // TODO verify that final packet content is correct
    }

    fn test_srtp_unprotect_parsing() {
        // TODO find MKI
        // TODO verify that auth input is as expected
        // TODO strip tag
        // TODO strip MKI
        // TODO verify that AAD is as expected
        // TODO decrypt payload
        // TODO decrypt extension
        // TODO verify that final packet content is correct
    }
}
