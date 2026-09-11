//! The AWDL **data** header — how a payload is carried, as opposed to how peers find
//! each other.
//!
//! Everything else in this crate parses action frames: discovery, election, timing. This
//! is the other half. A payload frame is an ordinary 802.11 **QoS Data** frame whose
//! LLC/SNAP payload is not IP directly but this header, and then IP:
//!
//! ```text
//!   802.11 QoS Data  ->  LLC/SNAP  ->  AWDL data header  ->  IPv6  ->  UDP / ICMPv6
//! ```
//!
//! ## Why this could be decoded without capturing a file
//!
//! The unicast payload of a real AirDrop transfer is sent at high VHT rates and our
//! monitor adapter cannot demodulate it — 35,895 Block Acks were captured for data that
//! never appeared. But **multicast** frames cannot be rate-adapted, because there is no
//! ACK to adapt against, so they go out at the lowest basic rate and decode perfectly.
//!
//! AWDL carries its mDNS as IPv6 multicast to `ff02::fb` in exactly this encapsulation.
//! The header below therefore comes from frames we could read, and is the same header a
//! file transfer uses. The rate differs; the framing does not.
//!
//! ## Two formats
//!
//! The header is short or long depending on its third byte, and the long form embeds TLVs
//! using the **2-byte short tag header** (one length byte), not the 3-byte form that
//! action frames use. Reading it with the wrong tag width walks straight off the end.

use crate::le;

/// Ethertype for IPv6, which is what every AWDL data frame observed so far carries.
pub const ETHERTYPE_IPV6: u16 = 0x86dd;
pub const ETHERTYPE_IPV4: u16 = 0x0800;

/// Marks the long header form, and also terminates its TLV region.
const LONG_FORM: u8 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataHeader<'a> {
    /// Sequence number. Per-peer and monotonic, so a receiver can order and detect loss
    /// without involving IP.
    pub sequence: u16,
    /// Whether the long form was used.
    pub long_form: bool,
    /// The TLV region of the long form, unparsed. Short tag headers — see module note.
    pub tagged: &'a [u8],
    /// The protocol that follows. Big-endian, as ethertypes always are.
    pub ethertype: u16,
    /// Offset of the encapsulated packet from the start of this header.
    pub payload_offset: usize,
}

impl<'a> DataHeader<'a> {
    pub fn parse(b: &'a [u8]) -> Option<DataHeader<'a>> {
        // Two unnamed bytes, then the sequence.
        let sequence = le::u16(b, 2)?;
        let mut off = 4;

        let long_form = le::u8(b, off)? == LONG_FORM;
        let tagged: &[u8];

        if long_form {
            // 0x03 <len> <len bytes>, then TLVs, then another 0x03 <len> block closing
            // the region.
            let slen = le::u8(b, off + 1)? as usize;
            off += 2 + slen;
            let start = off;

            // Walk short-form tags until the closing 0x03 marker. Bounded on the buffer
            // as well as on the marker: a truncated frame otherwise spins or reads past
            // the end.
            while le::u8(b, off)? != LONG_FORM {
                let len = le::u8(b, off + 1)? as usize;
                off += 2 + len;
                if off >= b.len() {
                    return None;
                }
            }
            tagged = b.get(start..off)?;

            let slen = le::u8(b, off + 1)? as usize;
            off += 2 + slen;
        } else {
            tagged = &[];
            off += 2;
        }

        let ethertype = u16::from_be_bytes([le::u8(b, off)?, le::u8(b, off + 1)?]);
        off += 2;

        Some(DataHeader { sequence, long_form, tagged, ethertype, payload_offset: off })
    }

    /// The encapsulated packet — IPv6 in everything seen so far.
    pub fn payload(&self, b: &'a [u8]) -> Option<&'a [u8]> {
        b.get(self.payload_offset..)
    }

    pub fn ethertype_name(&self) -> &'static str {
        match self.ethertype {
            ETHERTYPE_IPV6 => "IPv6",
            ETHERTYPE_IPV4 => "IPv4",
            _ => "?",
        }
    }
}

/// Does this 802.11 destination address mean IPv6 multicast?
///
/// `33:33:xx:xx:xx:xx` is the standard IPv6 multicast mapping, and it is how AWDL's mDNS
/// travels: `33:33:00:00:00:fb` is `ff02::fb`. **These are the frames a monitor can
/// actually read**, because multicast is never rate-adapted — so they are where the data
/// plane becomes observable at all.
pub fn is_ipv6_multicast(dst: [u8; 6]) -> bool {
    dst[0] == 0x33 && dst[1] == 0x33
}
