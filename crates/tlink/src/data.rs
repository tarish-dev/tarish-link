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
    decapsulate_all(frame80211).into_iter().next()
}

/// Bit 7 of the first QoS Control octet: the frame carries an **aggregate**, not one MSDU.
const QOS_AMSDU_PRESENT: u8 = 0x80;

/// Every AWDL packet in one 802.11 frame, which is not always one.
///
/// **A-MSDU aggregation is why a transfer between two of our own devices crawled at 0.8 KB/s.**
/// Under bulk load the radio packs several MSDUs into a single frame and sets bit 7 of the QoS
/// Control field. What follows the 802.11 header is then not the AWDL SNAP but a chain of
/// subframes, each `DA(6) SA(6) Length(2)` then its own LLC/SNAP, padded to a 4-byte boundary.
/// Reading one SNAP at a fixed offset finds the repeated destination address instead, the check
/// fails, and the WHOLE aggregate — every packet in it — is dropped.
///
/// It stayed hidden because it only bites when the peer's receiver is also ours. Apple and
/// Google de-aggregate in their own stacks, so sending to an iPhone or a stock Pixel was always
/// fast; and small control frames are never aggregated, so discovery, `/Discover` and `/Ask`
/// worked perfectly while every byte of payload was thrown away. Measured 2026-09-26: of 1081
/// data frames, 502 discarded; one of them 2990 bytes with QoS Control `86 00` and a first
/// subframe length of 1466.
///
/// Returns each packet in order. A frame with no aggregate yields at most one, so the common
/// path is unchanged.
pub fn decapsulate_all(frame80211: &[u8]) -> Vec<Decap<'_>> {
    use crate::dot11::{FrameControl, TYPE_DATA};

    let Some(fc) = FrameControl::parse(frame80211) else { return Vec::new() };
    if fc.frame_type != TYPE_DATA {
        return Vec::new();
    }
    let qos = fc.subtype & 0x08 != 0;
    // Bit 3 of the subtype is the QoS flag; without the QoS control field the header is
    // 24 bytes and everything after shifts by two.
    let hdr = if qos { QOS_HEADER_LEN } else { QOS_HEADER_LEN - 2 };
    let (Some(dst), Some(src)) = (
        frame80211.get(4..10).and_then(|b| <[u8; 6]>::try_from(b).ok()),
        frame80211.get(10..16).and_then(|b| <[u8; 6]>::try_from(b).ok()),
    ) else {
        return Vec::new();
    };

    // DETECT THE AGGREGATE BY SHAPE, NOT ONLY BY THE BIT.
    //
    // The A-MSDU Present bit is the documented signal and this radio does not always set it.
    // Measured 2026-09-26, three frames from our own peer, all carrying a subframe chain:
    //
    //     QoS `86 00`  bit set      2990 bytes
    //     QoS `01 b8`  bit CLEAR     470 bytes, subframe len 0x0066
    //     QoS `00 e0`  bit CLEAR     254 bytes, subframe len 0x0062
    //
    // Trusting the bit alone discarded the last two. The shape is unmistakable and cheap to
    // check: an A-MSDU subframe header repeats the frame's own destination and source before
    // its length, so twelve bytes that equal addr1 then addr2 mean an aggregate whatever the
    // bit says. A normal AWDL payload begins `aa aa 03` and can never look like this.
    let Some(rest) = frame80211.get(hdr..) else { return Vec::new() };
    let bit_set = qos
        && frame80211.get(QOS_HEADER_LEN - 2).map(|b| b & QOS_AMSDU_PRESENT != 0).unwrap_or(false);
    let looks_aggregated = rest.get(..6) == Some(&dst[..]) && rest.get(6..12) == Some(&src[..]);

    if !(bit_set || looks_aggregated) {
        // SNAP AT THE HEADER, OR TWO BYTES LATER.
        //
        // A driver may pad between the 802.11 header and the payload so the payload starts on
        // a 4-byte boundary, and a QoS header is 26 bytes, which is not one. Measured on
        // 120-byte multicast frames from our own peer: `06 00` sits where the SNAP should be
        // and the real `aa aa 03 00 17 f2 08 00` follows it. Trying the aligned offset costs
        // one comparison and cannot match by accident — eight fixed bytes is a strong
        // signature — so it is safer than modelling every driver's padding flag.
        return match one(dst, src, rest).or_else(|| rest.get(2..).and_then(|r| one(dst, src, r))) {
            Some(d) => vec![d],
            None => Vec::new(),
        };
    }

    // Walk the subframe chain. A malformed length must end the walk rather than loop or
    // index wildly, so every step is bounds-checked and the cursor only ever moves forward.
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + 14 <= rest.len() {
        let (Some(sda), Some(ssa)) = (
            rest.get(at..at + 6).and_then(|b| <[u8; 6]>::try_from(b).ok()),
            rest.get(at + 6..at + 12).and_then(|b| <[u8; 6]>::try_from(b).ok()),
        ) else {
            break;
        };
        let len = match rest.get(at + 12..at + 14) {
            Some(b) => u16::from_be_bytes([b[0], b[1]]) as usize,
            None => break,
        };
        if len == 0 || at + 14 + len > rest.len() {
            break;
        }
        if let Some(d) = rest.get(at + 14..at + 14 + len).and_then(|b| one(sda, ssa, b)) {
            out.push(d);
        }
        // Subframes are padded so the next one starts on a 4-byte boundary. The last one
        // carries no padding, which is why this is computed rather than always added.
        at += 14 + len;
        at += (4 - (at % 4)) % 4;
    }
    out
}

/// One AWDL packet: check the SNAP, then the AWDL data header.
fn one<'a>(dst: [u8; 6], src: [u8; 6], body: &'a [u8]) -> Option<Decap<'a>> {
    if body.get(..8)? != SNAP_AWDL {
        return None;
    }
    let inner = body.get(8..)?;
    let header = DataHeader::parse(inner)?;
    let payload = header.payload(inner)?;
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

/// Recover a peer's AWDL MAC from its link-local address — the inverse of
/// [`link_local_from_mac`].
///
/// This is what makes sending possible at all. A packet arrives from the kernel addressed
/// to `fe80::…`, and there is nothing to ask: AWDL has no ARP, no neighbour discovery that
/// would help, and no address advertisement anywhere in the protocol. The destination MAC
/// has to be *computed back* out of the address.
///
/// Returns `None` for anything that is not a modified-EUI-64 link-local, rather than
/// guessing: an address from SLAAC privacy extensions or set by hand carries no MAC, and a
/// frame sent to a MAC invented from one goes to nobody.
pub fn mac_from_link_local(addr: [u8; 16]) -> Option<[u8; 6]> {
    if addr[0] != 0xfe || addr[1] != 0x80 {
        return None;
    }
    // Bytes 2..8 must be zero for a plain link-local, and 11..13 must be the inserted
    // ff:fe that marks the address as EUI-64-derived. A stable-privacy address passes the
    // fe80 test and fails this one, which is the whole point of checking.
    if addr[2..8] != [0; 6] || addr[11] != 0xff || addr[12] != 0xfe {
        return None;
    }
    Some([addr[8] ^ 0x02, addr[9], addr[10], addr[13], addr[14], addr[15]])
}

/// The Ethernet multicast mapping of an IPv6 multicast address: `33:33` then its last four
/// bytes. RFC 2464 §7.
pub fn multicast_mac(addr: [u8; 16]) -> Option<[u8; 6]> {
    if addr[0] != 0xff {
        return None;
    }
    Some([0x33, 0x33, addr[12], addr[13], addr[14], addr[15]])
}

/// Where to send an IPv6 packet the kernel handed us, decided from the packet alone.
///
/// Multicast maps by RFC 2464; unicast is reversed out of the address by
/// [`mac_from_link_local`]. Anything else returns `None` and the caller should drop the
/// packet — which is the honest outcome, because AWDL offers no way to resolve an address
/// it was never told about.
pub fn dst_mac_for_ipv6(pkt: &[u8]) -> Option<[u8; 6]> {
    if pkt.len() < 40 || pkt[0] >> 4 != 6 {
        return None;
    }
    let dst: [u8; 16] = pkt.get(24..40)?.try_into().ok()?;
    multicast_mac(dst).or_else(|| mac_from_link_local(dst))
}

#[cfg(test)]
mod amsdu_tests {
    use super::*;

    /// Build one A-MSDU subframe: DA, SA, length, then an AWDL packet, 4-byte padded.
    fn subframe(dst: [u8; 6], src: [u8; 6], payload: &[u8], pad: bool) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&SNAP_AWDL);
        body.extend_from_slice(&short_header(1, ETHERTYPE_IPV6));
        body.extend_from_slice(payload);
        let mut o = Vec::new();
        o.extend_from_slice(&dst);
        o.extend_from_slice(&src);
        o.extend_from_slice(&(body.len() as u16).to_be_bytes());
        o.extend_from_slice(&body);
        if pad {
            while o.len() % 4 != 0 {
                o.push(0);
            }
        }
        o
    }

    /// An aggregate must yield EVERY packet, not the first.
    ///
    /// This is the regression guard for the 0.8 KB/s stall: the radio aggregates under bulk
    /// load, and reading one SNAP at a fixed offset found the repeated destination address,
    /// failed the check and discarded the whole frame — every packet in it.
    #[test]
    fn amsdu_yields_every_subframe() {
        let dst = [0xde, 0xcc, 0x36, 0xaf, 0xde, 0xc6];
        let src = [0xee, 0xc2, 0x95, 0x67, 0x02, 0xe6];

        let mut f = Vec::new();
        f.extend_from_slice(&[0x88, 0x00]); // QoS data
        f.extend_from_slice(&[0x2c, 0x00]); // duration
        f.extend_from_slice(&dst);
        f.extend_from_slice(&src);
        f.extend_from_slice(&[0x00, 0x25, 0x00, 0xff, 0x94, 0x73]); // BSSID
        f.extend_from_slice(&[0xf0, 0x08]); // sequence control
        f.extend_from_slice(&[0x86, 0x00]); // QoS control, A-MSDU present (bit 7)
        f.extend_from_slice(&subframe(dst, src, &[0x11; 64], true));
        f.extend_from_slice(&subframe(dst, src, &[0x22; 100], false));

        let got = decapsulate_all(&f);
        assert_eq!(got.len(), 2, "both subframes must come back");
        assert_eq!(got[0].payload, &[0x11u8; 64][..]);
        assert_eq!(got[1].payload, &[0x22u8; 100][..]);
        assert_eq!(got[0].dst, dst);
        assert_eq!(got[1].src, src);
    }

    /// A frame WITHOUT the aggregate bit must behave exactly as before: one packet.
    #[test]
    fn plain_qos_data_is_unchanged() {
        let dst = [1, 2, 3, 4, 5, 6];
        let src = [7, 8, 9, 10, 11, 12];
        let built = Encap { dst, src, tid: DEFAULT_TID }.frame(1, 1, ETHERTYPE_IPV6, &[0xab; 40]);
        let got = decapsulate_all(&built);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].payload, &[0xabu8; 40][..]);
        assert!(decapsulate(&built).is_some(), "the single-packet helper still works");
    }

    /// A truncated or lying length must stop the walk, never loop or panic.
    #[test]
    fn malformed_aggregate_stops_cleanly() {
        let dst = [1u8; 6];
        let src = [2u8; 6];
        let mut f = Vec::new();
        f.extend_from_slice(&[0x88, 0x00, 0x00, 0x00]);
        f.extend_from_slice(&dst);
        f.extend_from_slice(&src);
        f.extend_from_slice(&[0; 6]);
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&[0x80, 0x00]); // A-MSDU present
        f.extend_from_slice(&dst);
        f.extend_from_slice(&src);
        f.extend_from_slice(&0xffffu16.to_be_bytes()); // length far past the end
        f.extend_from_slice(&[0u8; 8]);
        assert!(decapsulate_all(&f).is_empty());
    }
}

#[cfg(test)]
mod variant_tests {
    use super::*;

    /// The aggregate bit is not always set, and the shape must be trusted over it.
    ///
    /// Measured 2026-09-26: frames with QoS `01 b8` and `00 e0` — bit 7 of the first octet
    /// clear — carried a full subframe chain. Reading them as a single packet found the
    /// repeated destination address where the SNAP belongs and dropped everything.
    #[test]
    fn aggregate_without_the_bit_is_still_an_aggregate() {
        let dst = [0x6a, 0xde, 0x7d, 0x59, 0xd8, 0xd6];
        let src = [0xb6, 0xda, 0x7c, 0x68, 0x5e, 0x38];

        let mut body = Vec::new();
        body.extend_from_slice(&SNAP_AWDL);
        body.extend_from_slice(&short_header(7, ETHERTYPE_IPV6));
        body.extend_from_slice(&[0x5c; 80]);

        let mut f = Vec::new();
        f.extend_from_slice(&[0x88, 0x00, 0x2c, 0x00]);
        f.extend_from_slice(&dst);
        f.extend_from_slice(&src);
        f.extend_from_slice(&AWDL_BSSID);
        f.extend_from_slice(&[0x20, 0x41]);
        f.extend_from_slice(&[0x01, 0xb8]); // QoS control, A-MSDU bit CLEAR
        f.extend_from_slice(&dst);
        f.extend_from_slice(&src);
        f.extend_from_slice(&(body.len() as u16).to_be_bytes());
        f.extend_from_slice(&body);

        let got = decapsulate_all(&f);
        assert_eq!(got.len(), 1, "the chain must be walked despite the clear bit");
        assert_eq!(got[0].payload, &[0x5cu8; 80][..]);
    }

    /// Two bytes of driver padding between the 802.11 header and the payload.
    ///
    /// Measured on 120-byte multicast frames: `06 00` where the SNAP should be, and the real
    /// SNAP two bytes further on. A QoS header is 26 bytes, so a driver aligning the payload
    /// to 4 bytes inserts exactly this.
    #[test]
    fn padded_payload_is_found_two_bytes_on() {
        let dst = [0x33, 0x33, 0xff, 0x18, 0xbe, 0x73];
        let src = [0x5e, 0x32, 0xbc, 0x75, 0xda, 0x5b];

        let mut f = Vec::new();
        f.extend_from_slice(&[0x88, 0x00, 0x00, 0x00]);
        f.extend_from_slice(&dst);
        f.extend_from_slice(&src);
        f.extend_from_slice(&AWDL_BSSID);
        f.extend_from_slice(&[0xd0, 0x15]);
        f.extend_from_slice(&[0x00, 0x5a]); // QoS control
        f.extend_from_slice(&[0x06, 0x00]); // the padding seen on air
        f.extend_from_slice(&SNAP_AWDL);
        f.extend_from_slice(&short_header(3, ETHERTYPE_IPV6));
        f.extend_from_slice(&[0x77; 64]);

        let got = decapsulate_all(&f);
        assert_eq!(got.len(), 1, "padding must not hide the payload");
        assert_eq!(got[0].payload, &[0x77u8; 64][..]);
        assert_eq!(got[0].dst, dst);
    }

    /// Padding must not make us accept rubbish: eight fixed SNAP bytes still have to match.
    #[test]
    fn padding_retry_does_not_accept_a_non_awdl_frame() {
        let dst = [1u8; 6];
        let src = [2u8; 6];
        let mut f = Vec::new();
        f.extend_from_slice(&[0x88, 0x00, 0x00, 0x00]);
        f.extend_from_slice(&dst);
        f.extend_from_slice(&src);
        f.extend_from_slice(&AWDL_BSSID);
        f.extend_from_slice(&[0, 0, 0, 0]);
        f.extend_from_slice(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00]); // ordinary SNAP
        f.extend_from_slice(&[0u8; 40]);
        assert!(decapsulate_all(&f).is_empty(), "another vendor's SNAP is not ours");
    }
}
