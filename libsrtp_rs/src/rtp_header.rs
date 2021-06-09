use crate::srtp::{Error, SessionKeys};
use packed_struct::prelude::*;

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

impl RtpHeader {
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

impl RtpExtensionHeader {
    const SIZE: usize = 12;
}

/*
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
pub struct OneByteExtensionHeader {
    #[packed_field(size_bits = 4)]
    id: u8,

    #[packed_field(size_bits = 4)]
    length: usize,
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
pub struct TwoByteExtensionHeader {
    #[packed_field(size_bits = 8)]
    id: u8,

    #[packed_field(size_bits = 8)]
    length: usize,
}
*/

pub struct SrtpPacket<'a> {
    header: RtpHeader,
    csrcs: &'a [u8],
    extension: &'a [u8],
    payload: &'a mut [u8],
    mki: Option<&'a mut [u8]>,
    tag: Option<&'a mut [u8]>,
}

impl<'a> SrtpPacket<'a> {
    fn new(data: &'a mut [u8]) -> Result<Self, Error> {
        if data.len() < RtpHeader::SIZE {
            return Err(Error::BadParam);
        }

        // Parse header
        let (header_data, data) = data.split_at_mut(RtpHeader::SIZE);
        let header = RtpHeader::unpack_from_slice(header_data).expect("unpack error");

        // Find the end of the CSRCs
        let csrc_size = 4 * (header.cc as usize);
        if data.len() < csrc_size {
            return Err(Error::BadParam);
        }
        let (csrc_data, data) = data.split_at_mut(csrc_size);

        // Find the end of the extension
        if data.len() < RtpExtensionHeader::SIZE {
            return Err(Error::BadParam);
        }
        let ext_header_data = &data[..RtpExtensionHeader::SIZE];
        let ext_header =
            RtpExtensionHeader::unpack_from_slice(ext_header_data).expect("unpack error");
        let ext_size = RtpExtensionHeader::SIZE + 4 * (ext_header.length_u32 as usize);

        if data.len() < ext_size {
            return Err(Error::BadParam);
        }
        let (ext_data, data) = data.split_at_mut(ext_size);

        Ok(SrtpPacket {
            header: header,
            csrcs: csrc_data,
            extension: ext_data,
            payload: data,
            mki: None,
            tag: None,
        })
    }

    fn configure_mki_tag(&'a mut self, sk: &SessionKeys) -> Result<(), Error> {
        let tag_size = sk.rtp_auth.tag_size();
        let mki_size = sk.mki_id.len();
        if self.payload.len() < mki_size + tag_size {
            return Err(Error::BadParam);
        }

        let mki_start = self.payload.len() - tag_size - mki_size;
        let (payload, mki_tag) = self.payload.split_at_mut(mki_start);
        let (mki, tag) = mki_tag.split_at_mut(mki_size);
        mki.copy_from_slice(sk.mki_id.as_slice());

        self.payload = payload;
        self.mki = Some(mki);
        self.tag = Some(tag);
        Ok(())
    }

    fn find_master_key<'sk>(
        &'a mut self,
        session_keys: &'sk Vec<SessionKeys>,
    ) -> Option<&'sk SessionKeys> {
        for sk in session_keys {
            let tag_size = sk.rtp_auth.tag_size();
            if self.payload.len() - tag_size < sk.mki_id.len() {
                continue;
            }

            let mki_size = sk.mki_id.len();
            let mki_end = self.payload.len() - tag_size;
            let mki_start = mki_end - sk.mki_id.len();
            let possible_mki = &mut self.payload[mki_start..mki_end];
            if possible_mki == sk.mki_id.as_slice() {
                let (payload, mki_tag) = self.payload.split_at_mut(mki_start);
                let (mki, tag) = mki_tag.split_at_mut(mki_size);

                self.payload = payload;
                self.mki = Some(mki);
                self.tag = Some(tag);
                return Some(sk);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtp_header() {
        let packed = hex::decode("8c0f1234decafbadcafebabe").expect("hex decode");
        let header = RtpHeader::unpack_from_slice(&packed).expect("unpack error");
        assert_eq!(header.v, 2);
        assert_eq!(header.p, 0);
        assert_eq!(header.x, 0);
        assert_eq!(header.cc, 0x0c);
        assert_eq!(header.m, 0);
        assert_eq!(header.pt, 0x0f);
        assert_eq!(header.seq, 0x1234);
        assert_eq!(header.ts, 0xdecafbad);
        assert_eq!(header.ssrc, 0xcafebabe);
    }
}
