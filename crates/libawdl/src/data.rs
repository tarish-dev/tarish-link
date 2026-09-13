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

// ---------------------------------------------------------------------------------------
// Building frames, not just reading them.
//
// Every constant below is measured across the 428 AWDL data frames in `captures/`, and
// each was invariant in all of them. That is a much narrower claim than it sounds: 428
// frames from a handful of Apple devices and one Pixel is not the protocol, and finding 47
// applies here as everywhere -- constant across this corpus is not constant across AWDL.
// They are recorded as measured facts, with their sample size, so a future capture that
// disagrees is a finding rather than a mystery.
// ---------------------------------------------------------------------------------------

/// The BSSID every AWDL data frame carries. Invariant across all 428 measured.
///
/// It is not a real BSS -- nothing associates to it and no access point answers for it.
/// It is a well-known constant that marks the frame as AWDL's, and the same value appears
/// in the action frames.
pub const AWDL_BSSID: [u8; 6] = [0x00, 0x25, 0x00, 0xff, 0x94, 0x73];

/// LLC/SNAP, and **not the standard one**.
///
/// A normal SNAP header carries OUI `00:00:00` and then an ethertype. AWDL carries
/// **Apple's OUI** `00:17:f2` and protocol ID `0x0800` — so the two bytes that look like
/// they should be the ethertype are not, and the real ethertype is four bytes further on,
/// inside the AWDL data header. Treating this as a normal SNAP reads `0x0800` and
/// concludes IPv4, which is wrong in every frame measured.
pub const SNAP_AWDL: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x17, 0xf2, 0x08, 0x00];

/// The two bytes the parser calls unnamed. `03 04` in all 428 frames measured.
pub const DATA_HEADER_PREFIX: [u8; 2] = [0x03, 0x04];

/// Traffic identifier in the QoS control field. Apple uses 6 and 0; 226 and 149 of 428.
pub const DEFAULT_TID: u8 = 6;

/// 802.11 QoS Data, with neither ToDS nor FromDS set — so `addr1` is the destination,
/// `addr2` the source and `addr3` the BSSID, which is the arrangement AWDL uses.
const FC_QOS_DATA: [u8; 2] = [0x88, 0x00];

/// Length of the 802.11 header AWDL data frames use: 24 plus the QoS control field.
pub const QOS_HEADER_LEN: usize = 26;

/// The short-form AWDL data header, which is the only form ever observed — 0 of 428
/// frames used the long form, despite the parser supporting it.
pub fn short_header(sequence: u16, ethertype: u16) -> [u8; 8] {
    let mut h = [0u8; 8];
    h[0..2].copy_from_slice(&DATA_HEADER_PREFIX);
    h[2..4].copy_from_slice(&sequence.to_le_bytes());
    // Bytes 4 and 5 are the form marker and are `00 00` in the short form. Anything other
    // than 3 at byte 4 is short; zero is what Apple sends.
    h[6..8].copy_from_slice(&ethertype.to_be_bytes());
    h
}

/// Wrap an IP packet as an AWDL data frame, ready for injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Encap {
    pub src: [u8; 6],
    pub dst: [u8; 6],
    pub tid: u8,
}

impl Encap {
    /// A frame to the IPv6 all-nodes-style multicast address AWDL uses for mDNS.
    pub fn multicast(src: [u8; 6]) -> Encap {
        // 33:33:00:00:00:fb is the standard IPv6 multicast mapping of ff02::fb.
        Encap { src, dst: [0x33, 0x33, 0x00, 0x00, 0x00, 0xfb], tid: DEFAULT_TID }
    }

    pub fn unicast(src: [u8; 6], dst: [u8; 6]) -> Encap {
        Encap { src, dst, tid: DEFAULT_TID }
    }

    /// `dot11_sequence` is the 802.11 sequence number, which is a different counter from
    /// the AWDL one: the first is per-transmitter and the second per-peer. Conflating them
    /// works until a retransmission, and then does not.
    pub fn frame(
        &self,
        dot11_sequence: u16,
        awdl_sequence: u16,
        ethertype: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut o = Vec::with_capacity(QOS_HEADER_LEN + 8 + 8 + payload.len());
        o.extend_from_slice(&FC_QOS_DATA);
        o.extend_from_slice(&[0, 0]); // duration, set by the radio
        o.extend_from_slice(&self.dst);
        o.extend_from_slice(&self.src);
        o.extend_from_slice(&AWDL_BSSID);
        // Sequence control: 4 bits of fragment number then 12 of sequence. No
        // fragmentation here, so the fragment nibble is zero.
        o.extend_from_slice(&((dot11_sequence & 0x0fff) << 4).to_le_bytes());
        o.extend_from_slice(&[self.tid & 0x0f, 0]);
        debug_assert_eq!(o.len(), QOS_HEADER_LEN);
        o.extend_from_slice(&SNAP_AWDL);
        o.extend_from_slice(&short_header(awdl_sequence, ethertype));
        o.extend_from_slice(payload);
        o
    }
}

/// An AWDL data frame taken apart: addresses, header, and the IP packet inside.
#[derive(Debug, Clone)]
pub struct Decap<'a> {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub header: DataHeader<'a>,
    pub payload: &'a [u8],
}

/// Recognise and unwrap an AWDL data frame, starting at the 802.11 header.
///
/// Returns `None` for anything that is not one — including other vendors' QoS Data, which
/// is why the SNAP is *checked* rather than skipped as a fixed eight bytes. Of the data
/// frames in `captures/`, most are not AWDL's, and skipping blind lands the ethertype on
/// another protocol's payload.
pub fn decapsulate(frame80211: &[u8]) -> Option<Decap<'_>> {
    use crate::dot11::{FrameControl, TYPE_DATA};

    let fc = FrameControl::parse(frame80211)?;
    if fc.frame_type != TYPE_DATA {
        return None;
    }
    // Bit 3 of the subtype is the QoS flag; without the QoS control field the header is
    // 24 bytes and everything after shifts by two.
    let hdr = if fc.subtype & 0x08 != 0 { QOS_HEADER_LEN } else { QOS_HEADER_LEN - 2 };
    let dst: [u8; 6] = frame80211.get(4..10)?.try_into().ok()?;
    let src: [u8; 6] = frame80211.get(10..16)?.try_into().ok()?;

    let rest = frame80211.get(hdr..)?;
    if rest.get(..8)? != SNAP_AWDL {
        return None;
    }
    let body = rest.get(8..)?;
    let header = DataHeader::parse(body)?;
    let payload = header.payload(body)?;
    Some(Decap { dst, src, header, payload })
}

/// The IPv6 link-local address a peer will have, derived from its AWDL MAC.
///
/// AWDL does not advertise IP addresses: a peer's address is **computed** from its
/// hardware address by the modified EUI-64 rule, and this is how a sender knows where to
/// send without any address resolution. Verified against a captured frame whose source MAC
/// was `8a:c3:f7:4b:ce:de` and whose IPv6 source was `fe80::88c3:f7ff:fe4b:cede`.
///
/// The two transformations are easy to get half-right: `ff:fe` is inserted in the middle,
/// **and** bit 1 of the first octet is flipped (`0x8a` becomes `0x88`). Omitting the flip
/// produces an address that looks plausible, belongs to nobody, and fails silently.
pub fn link_local_from_mac(mac: [u8; 6]) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0] = 0xfe;
    a[1] = 0x80;
    a[8] = mac[0] ^ 0x02;
    a[9] = mac[1];
    a[10] = mac[2];
    a[11] = 0xff;
    a[12] = 0xfe;
    a[13] = mac[3];
    a[14] = mac[4];
    a[15] = mac[5];
    a
}
