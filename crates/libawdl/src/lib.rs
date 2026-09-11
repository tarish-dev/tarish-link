//! AWDL frame parsing.
//!
//! **This crate does no I/O and knows nothing about capture.** It takes a slice of
//! bytes and returns structures, which is what makes it testable on any machine from a
//! recorded capture, and what lets it be reused later as the parsing half of an actual
//! AWDL implementation. The same split earned its keep in `libtarish_protocol`.
//!
//! Nothing here panics on malformed input. Every parser takes a slice, validates its
//! own lengths, and returns `Option`/`Result` — because the input is, by definition,
//! whatever a stranger put in the air.
//!
//! ## Where the frame format came from
//!
//! Wireshark has dissected AWDL since 3.0, and `epan/dissectors/packet-awdl.c` is the
//! most precise written description of the format that exists. It was read as a
//! *specification* — field order, widths, endianness, tag numbers — and the code here
//! was written from that understanding rather than derived from it. Wireshark is
//! GPL-2.0 and this crate is not, so the distinction matters: protocol facts are not
//! copyrightable, an implementation is.
//!
//! The protocol semantics come from Stute et al., *One Billion Apples' Secret Sauce*
//! (MobiCom 2018), arXiv:1808.03156.
//!
//! ## What is deliberately NOT here yet
//!
//! Per-TLV field decoding beyond the framing. Reading a channel sequence or an election
//! parameter set correctly matters more than reading it quickly, and each one is worth a
//! capture to confirm against. The TLV layer gives you type, length and bytes; the typed
//! decoders land one at a time, each with a fixture.

pub mod action;
pub mod data;
pub mod dot11;
pub mod election;
pub mod radiotap;
pub mod service;
pub mod sync;
pub mod tlv;

/// Little-endian readers that return None rather than panicking at the end of a slice.
///
/// Every length in these frames comes from the air, so "read past the end" is an
/// expected input, not a bug to assert against.
pub(crate) mod le {
    pub fn u8(b: &[u8], off: usize) -> Option<u8> {
        b.get(off).copied()
    }
    pub fn u16(b: &[u8], off: usize) -> Option<u16> {
        Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?))
    }
    pub fn u32(b: &[u8], off: usize) -> Option<u32> {
        Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
    }
}
