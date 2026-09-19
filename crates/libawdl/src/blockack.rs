//! 802.11 Block Ack, originator side — real link-layer ARQ for our outbound data.
//!
//! # Why this exists
//!
//! Our data path injects QoS Data frames on a monitor interface (`libawdl_hal::rawsock`),
//! which has no hardware ARQ: a frame that misses the peer's window is simply gone, and on a
//! bulk transfer the ~10% air loss stalls TCP (finding 105). Google's `libmosey` injects the
//! same way and has the same ceiling — it never sets up a Block Ack session for its *outbound*
//! data, so it too is best-effort. This module goes past that: as the data **originator** we
//! establish a Block Ack agreement with the peer, send our QoS Data under it, read the peer's
//! BlockAck bitmaps (we already receive them), and retransmit the frames the bitmap says were
//! lost. That is the ARQ the injection path lacks, done in software.
//!
//! # What is here
//!
//! Only the wire format and the frame recognisers — the builders for the two frames we send
//! (ADDBA Request, BlockAckReq) and the parsers for the two we receive (ADDBA Response,
//! BlockAck). The retransmit window and its state machine live in the session, which owns the
//! outbound queue and the radio; this module is pure, no I/O, and unit-testable on the host.
//!
//! # References
//!
//! IEEE 802.11-2020 §9.3.1.8 (BlockAckReq), §9.3.1.9 (BlockAck), §9.6.3 (ADDBA Request/
//! Response, DELBA). Addresses and BSSID follow AWDL: `addr3`/BSSID is the AWDL BSSID, no
//! ToDS/FromDS, `addr1` the peer, `addr2` us.

use crate::data::AWDL_BSSID;
use crate::dot11::MGMT_HEADER_LEN;

/// 802.11 action category for Block Ack.
pub const CATEGORY_BLOCK_ACK: u8 = 3;

/// Block Ack actions within category 3.
pub const ACTION_ADDBA_REQUEST: u8 = 0;
pub const ACTION_ADDBA_RESPONSE: u8 = 1;
pub const ACTION_DELBA: u8 = 2;

/// Frame Control for a management **Action** frame (type 0, subtype 13): `0xD0 0x00`.
const FC_ACTION: [u8; 2] = [0xD0, 0x00];
/// Frame Control for a **BlockAckReq** control frame (type 1, subtype 8): `0x84 0x00`.
const FC_BAR: [u8; 2] = [0x84, 0x00];
/// Frame Control for a **BlockAck** control frame (type 1, subtype 9): `0x94 0x00`.
const FC_BA: [u8; 2] = [0x94, 0x00];

/// A compressed BlockAck bitmap is 8 octets — one bit per sequence number, 64 in flight.
pub const BA_BITMAP_LEN: usize = 8;
/// The Block Ack window: at most this many unacknowledged MSDUs outstanding, matching the
/// 64-bit compressed bitmap. The buffer size we advertise in ADDBA.
pub const BA_WINDOW: u16 = 64;

/// Build the 24-byte 802.11 management header used by ADDBA (no ToDS/FromDS; AWDL BSSID).
fn mgmt_header(peer: [u8; 6], us: [u8; 6], seq: u16) -> [u8; MGMT_HEADER_LEN] {
    let mut h = [0u8; MGMT_HEADER_LEN];
    h[0..2].copy_from_slice(&FC_ACTION);
    // h[2..4] duration — left 0, set by the radio.
    h[4..10].copy_from_slice(&peer); // addr1 = RA = peer
    h[10..16].copy_from_slice(&us); // addr2 = TA = us
    h[16..22].copy_from_slice(&AWDL_BSSID); // addr3 = BSSID
    h[22..24].copy_from_slice(&((seq & 0x0fff) << 4).to_le_bytes());
    h
}

/// Build an **ADDBA Request** to open a Block Ack agreement with `peer` for `tid`.
///
/// `dialog_token` must be non-zero and is echoed in the response so we can match it. `ssn` is
/// the starting sequence number — the 802.11 sequence of the first data frame we will send
/// under the agreement. Immediate Block Ack policy, no A-MSDU, no timeout.
pub fn addba_request(
    peer: [u8; 6],
    us: [u8; 6],
    dot11_seq: u16,
    dialog_token: u8,
    tid: u8,
    ssn: u16,
    buffer_size: u16,
) -> Vec<u8> {
    let mut o = Vec::with_capacity(MGMT_HEADER_LEN + 9);
    o.extend_from_slice(&mgmt_header(peer, us, dot11_seq));
    o.push(CATEGORY_BLOCK_ACK);
    o.push(ACTION_ADDBA_REQUEST);
    o.push(dialog_token);
    // Block Ack Parameter Set (16 bits, little-endian):
    //   bit 0     A-MSDU supported            (0)
    //   bit 1     Block Ack Policy: 1=immediate
    //   bits 2-5  TID
    //   bits 6-15 Buffer Size (MSDUs)
    let params: u16 = (1 << 1)
        | ((u16::from(tid) & 0x0f) << 2)
        | ((buffer_size & 0x03ff) << 6);
    o.extend_from_slice(&params.to_le_bytes());
    // Block Ack Timeout (TUs) — 0 = no timeout.
    o.extend_from_slice(&0u16.to_le_bytes());
    // Block Ack Starting Sequence Control: bits 0-3 fragment (0), bits 4-15 SSN.
    o.extend_from_slice(&((ssn & 0x0fff) << 4).to_le_bytes());
    o
}

/// The useful contents of an **ADDBA Response**.
#[derive(Debug, Clone, Copy)]
pub struct AddbaResponse {
    pub dialog_token: u8,
    pub status: u16,
    pub tid: u8,
    pub buffer_size: u16,
    pub immediate: bool,
}

impl AddbaResponse {
    pub fn accepted(&self) -> bool {
        self.status == 0
    }
}

/// Parse an ADDBA Response addressed to `us`. Returns `None` for anything that is not one.
///
/// `b` starts at the 802.11 header. We check it is a category-3 action of type ADDBA Response
/// and that `addr1` is us, so a response to another peer on the same air is ignored.
pub fn parse_addba_response(b: &[u8], us: [u8; 6]) -> Option<AddbaResponse> {
    if b.len() < MGMT_HEADER_LEN + 9 {
        return None;
    }
    if b[0..2] != FC_ACTION {
        return None;
    }
    if b.get(4..10)? != us {
        return None;
    }
    let body = &b[MGMT_HEADER_LEN..];
    if body[0] != CATEGORY_BLOCK_ACK || body[1] != ACTION_ADDBA_RESPONSE {
        return None;
    }
    let dialog_token = body[2];
    let status = u16::from_le_bytes([body[3], body[4]]);
    let params = u16::from_le_bytes([body[5], body[6]]);
    let immediate = (params >> 1) & 1 == 1;
    let tid = ((params >> 2) & 0x0f) as u8;
    let buffer_size = (params >> 6) & 0x03ff;
    Some(AddbaResponse { dialog_token, status, tid, buffer_size, immediate })
}

/// Build a **compressed BlockAckReq** soliciting a BlockAck for `tid` starting at `ssn`.
///
/// Sent after a burst so the peer reports, via its BlockAck bitmap, which of our frames it has.
pub fn block_ack_req(peer: [u8; 6], us: [u8; 6], tid: u8, ssn: u16) -> Vec<u8> {
    let mut o = Vec::with_capacity(20);
    o.extend_from_slice(&FC_BAR);
    o.extend_from_slice(&[0, 0]); // duration
    o.extend_from_slice(&peer); // RA = peer
    o.extend_from_slice(&us); // TA = us
    // BAR Control: bit0 BAR Ack Policy (0=normal), bit1 Multi-TID (0), bit2 Compressed (1),
    // bits 12-15 TID.
    let control: u16 = (1 << 2) | ((u16::from(tid) & 0x0f) << 12);
    o.extend_from_slice(&control.to_le_bytes());
    // BAR Information: bits 0-3 fragment (0), bits 4-15 SSN.
    o.extend_from_slice(&((ssn & 0x0fff) << 4).to_le_bytes());
    o
}

/// The useful contents of a received **BlockAck**: the starting sequence and the 64-bit bitmap.
#[derive(Debug, Clone, Copy)]
pub struct BlockAck {
    pub tid: u8,
    pub ssn: u16,
    pub bitmap: u64,
    pub compressed: bool,
}

impl BlockAck {
    /// Is the frame with 802.11 sequence `seq` acknowledged by this BlockAck?
    ///
    /// A compressed BlockAck acknowledges `ssn + i` for each set bit `i` of the bitmap. A
    /// sequence outside the 64-frame window is reported as not acknowledged, which is the safe
    /// answer — the originator keeps it outstanding and a later BlockAck covers it.
    pub fn acks(&self, seq: u16) -> bool {
        let delta = seq.wrapping_sub(self.ssn) & 0x0fff;
        if delta >= 64 {
            return false;
        }
        (self.bitmap >> delta) & 1 == 1
    }
}

/// Parse a BlockAck addressed to `us`. Returns `None` for anything that is not one.
pub fn parse_block_ack(b: &[u8], us: [u8; 6]) -> Option<BlockAck> {
    // FC(2) dur(2) RA(6) TA(6) BA-Control(2) BA-SSC(2) bitmap(>=8 for compressed).
    if b.len() < 16 + 4 {
        return None;
    }
    if b[0..2] != FC_BA {
        return None;
    }
    if b.get(4..10)? != us {
        return None;
    }
    let control = u16::from_le_bytes([b[16], b[17]]);
    let compressed = (control >> 2) & 1 == 1;
    let tid = ((control >> 12) & 0x0f) as u8;
    let ssc = u16::from_le_bytes([b[18], b[19]]);
    let ssn = (ssc >> 4) & 0x0fff;
    let bitmap = if compressed {
        let bm = b.get(20..20 + BA_BITMAP_LEN)?;
        u64::from_le_bytes(bm.try_into().ok()?)
    } else {
        // Non-compressed BlockAck carries a 128-octet bitmap (4 bits per sequence). We never
        // request one, but fold it to the same "was this seq seen at all" question so a peer
        // that answers non-compressed is still usable: bit set if any of the seq's 4 bits are.
        let bm = b.get(20..20 + 128)?;
        let mut folded = 0u64;
        for i in 0..64 {
            let byte = bm[i / 2];
            let nibble = if i % 2 == 0 { byte & 0x0f } else { byte >> 4 };
            if nibble != 0 {
                folded |= 1 << i;
            }
        }
        folded
    };
    Some(BlockAck { tid, ssn, bitmap, compressed })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addba_request_roundtrips_shape() {
        let f = addba_request([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12], 0x123, 0x42, 6, 0x100, BA_WINDOW);
        assert_eq!(f.len(), MGMT_HEADER_LEN + 9);
        assert_eq!(f[0..2], FC_ACTION);
        assert_eq!(&f[4..10], &[1, 2, 3, 4, 5, 6]); // addr1 = peer
        assert_eq!(&f[10..16], &[7, 8, 9, 10, 11, 12]); // addr2 = us
        assert_eq!(f[MGMT_HEADER_LEN], CATEGORY_BLOCK_ACK);
        assert_eq!(f[MGMT_HEADER_LEN + 1], ACTION_ADDBA_REQUEST);
        assert_eq!(f[MGMT_HEADER_LEN + 2], 0x42); // dialog token
        // Params: immediate policy, tid 6, buffer 64.
        let params = u16::from_le_bytes([f[MGMT_HEADER_LEN + 3], f[MGMT_HEADER_LEN + 4]]);
        assert_eq!((params >> 1) & 1, 1);
        assert_eq!((params >> 2) & 0x0f, 6);
        assert_eq!((params >> 6) & 0x03ff, 64);
    }

    #[test]
    fn parse_addba_response_matches_us_only() {
        let us = [7, 8, 9, 10, 11, 12];
        // Build a response by hand: header addr1=us, category 3, action 1, token, status 0.
        let mut b = vec![0u8; MGMT_HEADER_LEN + 9];
        b[0..2].copy_from_slice(&FC_ACTION);
        b[4..10].copy_from_slice(&us);
        b[MGMT_HEADER_LEN] = CATEGORY_BLOCK_ACK;
        b[MGMT_HEADER_LEN + 1] = ACTION_ADDBA_RESPONSE;
        b[MGMT_HEADER_LEN + 2] = 0x42;
        // status 0 at +3..+5, params tid 6 buffer 64 at +5..+7
        let params: u16 = (1 << 1) | (6 << 2) | (64 << 6);
        b[MGMT_HEADER_LEN + 5..MGMT_HEADER_LEN + 7].copy_from_slice(&params.to_le_bytes());
        let r = parse_addba_response(&b, us).expect("parses");
        assert!(r.accepted());
        assert_eq!(r.dialog_token, 0x42);
        assert_eq!(r.tid, 6);
        assert_eq!(r.buffer_size, 64);
        // A different addr1 is not ours.
        assert!(parse_addba_response(&b, [9, 9, 9, 9, 9, 9]).is_none());
    }

    #[test]
    fn block_ack_bitmap_acks_the_right_sequences() {
        let us = [7, 8, 9, 10, 11, 12];
        let mut b = vec![0u8; 20 + BA_BITMAP_LEN];
        b[0..2].copy_from_slice(&FC_BA);
        b[4..10].copy_from_slice(&us);
        let control: u16 = (1 << 2) | (6 << 12); // compressed, tid 6
        b[16..18].copy_from_slice(&control.to_le_bytes());
        let ssn = 0x100u16;
        b[18..20].copy_from_slice(&((ssn & 0x0fff) << 4).to_le_bytes());
        // Ack ssn (bit0) and ssn+3 (bit3), leave ssn+1, ssn+2 as gaps.
        let bitmap: u64 = 0b1001;
        b[20..28].copy_from_slice(&bitmap.to_le_bytes());
        let ba = parse_block_ack(&b, us).expect("parses");
        assert_eq!(ba.ssn, 0x100);
        assert!(ba.acks(0x100));
        assert!(!ba.acks(0x101));
        assert!(!ba.acks(0x102));
        assert!(ba.acks(0x103));
        assert!(!ba.acks(0x140)); // outside the 64 window
    }
}
