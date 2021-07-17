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

    fn read(&mut self, size: usize) -> Result<Range<usize>, Error> {
        let start = self.pos;
        let end = self.pos + size;
        if end > self.data.len() {
            return Err(Error::ParseError);
        }

        self.pos += size;
        Ok(start..end)
    }

    fn unpack<T: PackedStruct + PackedSize>(&mut self) -> Result<T, Error> {
        let val_range = self.read(T::PACKED_SIZE)?;
        let val_data = &self.data[val_range.clone()];
        let val = T::unpack_from_slice(val_data).or(Err(Error::ParseError))?;
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

#[derive(Debug, PartialEq, Eq)]
pub struct RtpExtensionElement {
    pub id: u8,
    pub skip: usize,
    pub range: Range<usize>,
}

impl RtpExtensionElement {
    fn new(
        header_size: ElementHeaderSize,
        reader: &mut OffsetReader,
    ) -> Result<RtpExtensionElement, Error> {
        match header_size {
            ElementHeaderSize::OneByte => {
                let header = reader.unpack::<OneByteElementHeader>()?;
                Ok(RtpExtensionElement {
                    id: header.id,
                    skip: OneByteElementHeader::PACKED_SIZE,
                    range: reader.read((header.length + 1) as usize)?,
                })
            }
            ElementHeaderSize::TwoByte => {
                let header = reader.unpack::<TwoByteElementHeader>()?;
                Ok(RtpExtensionElement {
                    id: header.id,
                    skip: TwoByteElementHeader::PACKED_SIZE,
                    range: reader.read(header.length as usize)?,
                })
            }
        }
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

        // TODO Pre-validate that the extensions parse correctly

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
        // Skip padding bytes
        let padding_size = self.reader.skip_zeros();

        // If we've reached the end of the buffer, there's nothing more to do
        if self.reader.remaining() == 0 {
            return None;
        }

        // Parse an extension element
        // XXX(RLB) This throws away error information, so a packet with malformed extensions will
        // not result in an error.  Instead, the extensions will be processed up to the point where
        // the error occurs.  To fix this, we should either return errors (and thus not satisfy
        // Iterator), or pre-validate that the extensions are correct in new().
        match RtpExtensionElement::new(self.header_size, &mut self.reader) {
            Ok(mut elem) => {
                elem.skip += padding_size;
                Some(elem)
            }
            Err(_) => None,
        }
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

    pub fn extension_data<'b>(&'b mut self) -> &'b mut [u8] {
        &mut self.data[self.ext_start..self.payload_start]
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto_kernel::{AuthType, CipherType, ExtensionCipherType};
    use crate::hmac::NativeHMAC;
    use crate::key_limit::KeyLimitContext;
    use crate::null_auth::NullAuth;
    use crate::null_cipher::NullCipher;
    use crate::util::xor_eq;

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
        let mut ext_data: [u8; 12] = [
            0x10, 0xaa, 0x21, 0xbb, 0xbb, 0x00, 0x00, 0x33, 0xcc, 0xcc, 0xcc, 0xcc,
        ];

        let expected_extensions: [RtpExtensionElement; 3] = [
            RtpExtensionElement {
                id: 1,
                skip: 1,
                range: 1..2,
            },
            RtpExtensionElement {
                id: 2,
                skip: 1,
                range: 3..5,
            },
            RtpExtensionElement {
                id: 3,
                skip: 3,
                range: 8..12,
            },
        ];

        let reader = RtpExtensionReader::new(&ext_header, &mut ext_data)?;
        for (actual, expected) in reader.zip(&expected_extensions) {
            assert_eq!(&actual, expected);
        }

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
        let mut ext_data: [u8; 12] = [
            0x01, 0x00, 0x02, 0x01, 0xaa, 0x00, 0x03, 0x04, 0xbb, 0xbb, 0xbb, 0xbb,
        ];

        let expected_extensions: [RtpExtensionElement; 3] = [
            RtpExtensionElement {
                id: 1,
                skip: 2,
                range: 2..2,
            },
            RtpExtensionElement {
                id: 2,
                skip: 2,
                range: 4..5,
            },
            RtpExtensionElement {
                id: 3,
                skip: 3,
                range: 8..12,
            },
        ];

        let reader = RtpExtensionReader::new(&ext_header, &mut ext_data)?;
        for (actual, expected) in reader.zip(&expected_extensions) {
            assert_eq!(&actual, expected);
        }

        Ok(())
    }

    // SRTP Packet Parsing
    const PLAINTEXT_PACKET: &'static [u8] = &[
        // Header
        0x90, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe,
        // Extension
        0xbe, 0xde, 0x00, 0x06, 0x17, 0x41, 0x42, 0x73, 0xa4, 0x75, 0x26, 0x27, 0x48, 0x22, 0x00,
        0x00, 0xc8, 0x30, 0x8e, 0x46, 0x55, 0x99, 0x63, 0x86, 0xb3, 0x95, 0xfb, 0x00,
        // Payload
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab,
    ];

    const CIPHERTEXT_PACKET: &'static [u8] = &[
        // Header
        0x90, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe,
        // Extension
        0xbe, 0xde, 0x00, 0x06, 0x17, 0x12, 0xe0, 0x20, 0x5b, 0xfa, 0x94, 0x9b, 0x1c, 0x22, 0x00,
        0x00, 0xc8, 0x30, 0xbb, 0x46, 0x73, 0x27, 0x78, 0xd9, 0x92, 0x9a, 0xab, 0x00,
        // Payload
        0x0e, 0xca, 0x0c, 0xf9, 0x5e, 0xe9, 0x55, 0xb2, 0x6c, 0xd3, 0xd2, 0x88, 0xb4, 0x9f, 0x6c,
        0xa9, 0xf4, 0xb1, 0xb7, 0x59, 0x71, 0x9e, 0xb5, 0xbc, 0x11, 0x3b, 0x9f, 0xf1, 0xd4, 0x0c,
        0xd2, 0x5a, // end of payload
        0x6d, 0x6b, 0x69, // MKI = "mki"
        0x74, 0x61, 0x67, // Tag = "tag"
    ];

    const EXTENSION_KEYSTREAM: &'static [u8] = &[
        0x00, 0x53, 0xa2, 0x53, 0xff, 0x8f, 0xb2, 0xbc, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x35,
        0x00, 0x26, 0xbe, 0x1b, 0x5f, 0x21, 0x0f, 0x50, 0x00,
    ];
    const PAYLOAD_KEYSTREAM: &'static [u8] = &[
        0xa5, 0x61, 0xa7, 0x52, 0xf5, 0x42, 0xfe, 0x19, 0xc7, 0x78, 0x79, 0x23, 0x1f, 0x34, 0xc7,
        0x02,
    ];
    const PAYLOAD_TAG: &'static [u8] = &[
        0xf4, 0xb1, 0xb7, 0x59, 0x71, 0x9e, 0xb5, 0xbc, 0x11, 0x3b, 0x9f, 0xf1, 0xd4, 0x0c, 0xd2,
        0x5a,
    ];
    const PT_EXTENSION_DATA: &'static [u8] = &[
        0x17, 0x41, 0x42, 0x73, 0xa4, 0x75, 0x26, 0x27, 0x48, 0x22, 0x00, 0x00, 0xc8, 0x30, 0x8e,
        0x46, 0x55, 0x99, 0x63, 0x86, 0xb3, 0x95, 0xfb, 0x00,
    ];
    const CT_EXTENSION_DATA: &'static [u8] = &[
        0x17, 0x12, 0xe0, 0x20, 0x5b, 0xfa, 0x94, 0x9b, 0x1c, 0x22, 0x00, 0x00, 0xc8, 0x30, 0xbb,
        0x46, 0x73, 0x27, 0x78, 0xd9, 0x92, 0x9a, 0xab, 0x00,
    ];
    const AAD: &'static [u8] = &[
        0x90, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0xbe, 0xde, 0x00,
        0x06, 0x17, 0x12, 0xe0, 0x20, 0x5b, 0xfa, 0x94, 0x9b, 0x1c, 0x22, 0x00, 0x00, 0xc8, 0x30,
        0xbb, 0x46, 0x73, 0x27, 0x78, 0xd9, 0x92, 0x9a, 0xab, 0x00,
    ];
    const AUTH_DATA: &'static [u8] = &[
        0x90, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0xbe, 0xde, 0x00,
        0x06, 0x17, 0x12, 0xe0, 0x20, 0x5b, 0xfa, 0x94, 0x9b, 0x1c, 0x22, 0x00, 0x00, 0xc8, 0x30,
        0xbb, 0x46, 0x73, 0x27, 0x78, 0xd9, 0x92, 0x9a, 0xab, 0x00, 0x0e, 0xca, 0x0c, 0xf9, 0x5e,
        0xe9, 0x55, 0xb2, 0x6c, 0xd3, 0xd2, 0x88, 0xb4, 0x9f, 0x6c, 0xa9, 0xf4, 0xb1, 0xb7, 0x59,
        0x71, 0x9e, 0xb5, 0xbc, 0x11, 0x3b, 0x9f, 0xf1, 0xd4, 0x0c, 0xd2, 0x5a,
    ];
    const MKI: &'static [u8] = &[0x6d, 0x6b, 0x69];
    const TAG: &'static [u8] = &[0x74, 0x61, 0x67];

    #[test]
    fn test_header_parsing() -> Result<(), Error> {
        let pt_size = PLAINTEXT_PACKET.len();
        let mut pkt_data = [0u8; 100];
        pkt_data[..pt_size].copy_from_slice(PLAINTEXT_PACKET);
        let mut pkt = SrtpPacket::new(&mut pkt_data, pt_size)?;

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
        assert_eq!(pkt.extension_data(), PT_EXTENSION_DATA);
        Ok(())
    }

    fn encrypt(buf: &mut [u8], pt_size: usize) -> usize {
        xor_eq(&mut buf[..PAYLOAD_KEYSTREAM.len()], PAYLOAD_KEYSTREAM);

        let tag_end = pt_size + PAYLOAD_TAG.len();
        buf[pt_size..tag_end].copy_from_slice(PAYLOAD_TAG);
        tag_end
    }

    fn decrypt(buf: &mut [u8], ct_size: usize) -> Result<usize, Error> {
        let pt_size = ct_size - PAYLOAD_TAG.len();
        if &buf[pt_size..ct_size] != PAYLOAD_TAG {
            return Err(Error::AuthFail);
        }

        xor_eq(&mut buf[..pt_size], PAYLOAD_KEYSTREAM);
        Ok(pt_size)
    }

    #[test]
    fn test_srtp_protect_parsing() -> Result<(), Error> {
        let pkt_size = PLAINTEXT_PACKET.len();
        let mut pkt_data = [0u8; 100];
        pkt_data[..pkt_size].copy_from_slice(PLAINTEXT_PACKET);
        let mut pkt = SrtpPacket::new(&mut pkt_data, pkt_size)?;

        // Emulate encrypting header
        xor_eq(pkt.extension_data(), EXTENSION_KEYSTREAM);

        // Verify that AAD is as expected
        assert_eq!(pkt.aad(), AAD);

        // Emulate encrypting payload
        let pt_size = pkt.payload_size();
        let ct_size = encrypt(pkt.payload_for_encrypt(), pt_size);
        pkt.set_payload_size(ct_size);

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
        let null_cipher = NullCipher;
        let hmac_sha1 = NativeHMAC;
        let mut sks = vec![SessionKeys {
            rtp_cipher: NullCipher {}.create(&[], &[])?,
            rtp_xtn_hdr_cipher: NullCipher {}.xtn_create(&[], &[])?,
            rtp_auth: NativeHMAC {}.create(&[], TAG.len())?,
            rtcp_cipher: NullCipher {}.create(&[], &[])?,
            rtcp_auth: NullAuth {}.create(&[], 0)?,

            mki_id: MKI.to_vec(),
            limit: KeyLimitContext::new(),
        }];

        let pkt_size = CIPHERTEXT_PACKET.len();
        let mut pkt_data = [0u8; 100];
        pkt_data[..pkt_size].copy_from_slice(CIPHERTEXT_PACKET);
        let mut pkt = SrtpPacket::new(&mut pkt_data, pkt_size)?;

        // Find MKI
        let sk = pkt.find_mki(&mut sks).ok_or(Error::Fail)?;

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
        let pt_size = decrypt(pkt.payload_for_decrypt(), ct_size)?;
        pkt.set_payload_size(pt_size)?;

        // Emulate decrypting extension
        xor_eq(pkt.extension_data(), EXTENSION_KEYSTREAM);

        // Verify that final packet content is correct
        let pkt_size = pkt.size();
        assert_eq!(&pkt_data[..pkt_size], PLAINTEXT_PACKET);

        Ok(())
    }
}
