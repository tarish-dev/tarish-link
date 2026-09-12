//! Just enough radiotap to get past it, plus the three fields that matter for AWDL.
//!
//! Radiotap is a variable-length header the driver prepends to every monitor-mode
//! frame. Its only load-bearing field for us is `len` — get that wrong and every
//! 802.11 parse downstream is garbage in a way that looks like a protocol problem.
//!
//! The optional fields are read positionally from a presence bitmap, and **each field
//! is aligned to its own natural boundary**. Skipping the alignment is the classic way
//! to read radiotap that works on one driver and silently misreads on the next.

use crate::le;

/// Bit positions in the `it_present` bitmap, in the order fields appear.
const TSFT: u32 = 0;
const FLAGS: u32 = 1;
const RATE: u32 = 2;
const CHANNEL: u32 = 3;
const FHSS: u32 = 4;
const ANTENNA_SIGNAL: u32 = 5;

/// The presence bit meaning "another 32-bit present word follows this one".
const EXT: u32 = 31;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Radiotap {
    /// Total header length; the 802.11 frame starts here.
    pub len: usize,
    /// MAC timestamp, microseconds. The anchor for any timing work, so its absence
    /// is worth knowing about rather than defaulting to zero.
    pub tsft: Option<u64>,
    /// Channel centre frequency in MHz.
    pub freq: Option<u16>,
    /// Antenna signal, dBm.
    pub signal_dbm: Option<i8>,
    /// The FLAGS byte, raw.
    ///
    /// **This was skipped for the first weeks of this project, and that was a mistake.**
    /// It carries `BADFCS`, so without it every capture-derived claim silently included
    /// frames the radio itself knew were corrupt — and a corrupt frame does not announce
    /// itself: TLV lengths are explicit, so a frame with flipped bits parses cleanly and
    /// contributes a plausible wrong value. It is kept raw because `DATAPAD` and `FCS`
    /// change how the payload should be measured, and only one of those is decoded here.
    pub flags: Option<u8>,
}

/// `BADFCS` — the radio checked the frame and it failed. Do not trust its contents.
pub const F_BADFCS: u8 = 0x40;
/// `FCS` — the 802.11 frame carries its 4-byte checksum, so it is included in the payload.
pub const F_FCS: u8 = 0x10;

impl Radiotap {
    pub fn parse(b: &[u8]) -> Option<Radiotap> {
        // it_version(1) it_pad(1) it_len(2) it_present(4)
        if le::u8(b, 0)? != 0 {
            return None; // only version 0 has ever existed
        }
        let len = le::u16(b, 2)? as usize;
        if len < 8 || len > b.len() {
            return None;
        }

        // Walk the chain of present words first: the field data begins after ALL of
        // them, not after the first.
        let mut present_words = Vec::new();
        let mut off = 4;
        loop {
            let w = le::u32(b, off)?;
            present_words.push(w);
            off += 4;
            if w & (1 << EXT) == 0 {
                break;
            }
            if off >= len {
                return None;
            }
        }

        let mut rt = Radiotap { len, tsft: None, freq: None, signal_dbm: None, flags: None };

        // Only the first present word carries the fields we read; a second word means
        // vendor namespaces, which we skip rather than guess at.
        let present = present_words[0];
        let mut cur = off;

        // align() is not optional. Each radiotap field starts on a multiple of its own
        // size, with padding inserted before it as needed.
        let align = |cur: &mut usize, to: usize| {
            let rem = (*cur - 0) % to;
            if rem != 0 {
                *cur += to - rem;
            }
        };

        if present & (1 << TSFT) != 0 {
            align(&mut cur, 8);
            let lo = le::u32(b, cur)? as u64;
            let hi = le::u32(b, cur + 4)? as u64;
            rt.tsft = Some((hi << 32) | lo);
            cur += 8;
        }
        if present & (1 << FLAGS) != 0 {
            rt.flags = le::u8(b, cur);
            cur += 1;
        }
        if present & (1 << RATE) != 0 {
            cur += 1;
        }
        if present & (1 << CHANNEL) != 0 {
            align(&mut cur, 2);
            rt.freq = le::u16(b, cur);
            cur += 4; // frequency(2) + channel flags(2)
        }
        if present & (1 << FHSS) != 0 {
            cur += 2;
        }
        if present & (1 << ANTENNA_SIGNAL) != 0 {
            rt.signal_dbm = le::u8(b, cur).map(|v| v as i8);
        }

        Some(rt)
    }

    /// The radio checked this frame's FCS and it failed.
    ///
    /// `false` when the driver reported no flags at all, which is not the same as "the
    /// frame is good" — it means the question was not answered. Callers that care about
    /// integrity should treat a missing FLAGS field as a gap in the instrument rather
    /// than as a pass, which is what [`fcs_known_good`] is for.
    pub fn bad_fcs(&self) -> bool {
        self.flags.is_some_and(|f| f & F_BADFCS != 0)
    }

    /// The radio checked the FCS and it passed: flags present, `BADFCS` clear.
    pub fn fcs_known_good(&self) -> bool {
        self.flags.is_some_and(|f| f & F_BADFCS == 0)
    }

    /// Whether the 4-byte FCS is included at the end of the 802.11 frame.
    ///
    /// It matters for byte accounting: with this set the last four bytes of
    /// [`payload`](Self::payload) are a checksum, not protocol.
    pub fn includes_fcs(&self) -> bool {
        self.flags.is_some_and(|f| f & F_FCS != 0)
    }

    /// The 802.11 frame that follows this header.
    pub fn payload<'a>(&self, b: &'a [u8]) -> Option<&'a [u8]> {
        b.get(self.len..)
    }
}
