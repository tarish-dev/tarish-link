//! Synchronization Parameters (tag 4) and Channel Sequence (tag 18).
//!
//! These two carry the answer to the question that decides whether an AWDL
//! implementation can run on hardware other than Apple's and Google's: **how tight does
//! the timing have to be, and what is the radio expected to do about it.**
//!
//! Everything here is decoded from the wire. Where a field's meaning is inferred rather
//! than measured, it says so.

use crate::le;

/// One Availability Window, in microseconds.
///
/// AWDL counts in Time Units: 1 TU = 1024 µs. The 2018 paper states an AW of 16 TU,
/// which is 16384 µs. **Do not hardcode that** — `aw_period` is on the wire precisely
/// because it is a parameter, and confirming it against real devices is the point.
pub const TU_US: u32 = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncParams {
    /// Channel this frame went out on.
    pub tx_channel: u8,
    pub tx_counter: u16,
    /// Channel the current master is on.
    pub master_channel: u8,
    pub guard_time: u8,
    /// Availability Window period, in TU. The paper says 16.
    pub aw_period: u16,
    /// How often action frames are sent, in TU.
    pub action_frame_period: u16,
    pub flags: u16,
    pub aw_ext_length: u16,
    pub aw_common_length: u16,
    /// TU left in the current window — the field a joining node uses to work out where
    /// in the schedule it has arrived.
    pub aw_remaining: u16,
    pub ext_min: u8,
    pub ext_max_multicast: u8,
    pub ext_max_unicast: u8,
    pub ext_max_af: u8,
    /// The master this node is synchronised to. All-zero when it believes it is master.
    pub master: [u8; 6],
    pub presence_mode: u8,
    /// Monotonic AW counter. The clock the whole cluster agrees on.
    pub aw_counter: u16,
    /// Offset between this node's schedule and an access point's beacon.
    ///
    /// **This field is the clearest evidence that AWDL is designed to coexist with an
    /// infrastructure association rather than merely tolerate one** — there is no
    /// reason to carry an AP's beacon offset unless you intend to line up with it. It
    /// was 0 in all 278 frames of the first capture, which is consistent with those
    /// devices not currently time-sharing with an AP, and is a measurement to repeat
    /// against a device that definitely is.
    pub ap_beacon_alignment_delta: u16,
    /// Byte 28, which has no published name and is non-zero on real devices.
    ///
    /// Kept rather than dropped because a builder must put it back: a field whose
    /// meaning is unknown is still a field, and writing zero where a device wrote
    /// something is a change to the frame, not a simplification of it.
    pub reserved_28: u8,
    /// A second channel sequence, carried INSIDE this tag.
    ///
    /// A frame therefore describes its schedule twice, in two different encodings: the
    /// one here has been observed as `Legacy`, while tag 18 carries `OpClass` for the
    /// same frame. They are not redundant — the Legacy list reports 151 where the
    /// OpClass list reports 149 or 153, which is the 40 MHz centre against the 20 MHz
    /// control channel. An implementation that reads only one of them gets a
    /// self-consistent and incomplete picture of where the peer actually listens.
    pub channel_sequence: Option<ChannelSequence>,
    /// The two bytes after the channel sequence. **Not padding, despite the name it
    /// carries everywhere else.**
    ///
    /// OWL's `frame.h` comments them `/* uint8_t pad[2]; */` and Wireshark shows them the
    /// same way. Across every capture in `captures/` that is wrong: of 7054
    /// Synchronization Parameters TLVs, **2018 have a non-zero value here** — Apple
    /// devices and `libmosey` both write them, and only OWL leaves them zero.
    ///
    /// What decides the answer is the low bits of [`flags`](Self::flags), not the frame:
    /// a sender advertising `0x1800` writes zero and puts its association channel in slot
    /// 0, while a sender advertising `0x1000` writes a value here and leaves slot 0 empty.
    /// One device was observed switching from `00 4c` to `20 64` mid-capture.
    ///
    /// The contrast that rules out uninitialised memory is tag 18: it has three
    /// equivalent trailing bytes, written by the same devices in the same frames, and
    /// across those same 7054 samples **not one** was non-zero. Stale stack would show up
    /// in both.
    ///
    /// So it is a real field and we cannot yet name it. It is carried raw so a parsed
    /// frame re-encodes to the bytes it arrived as; [`SyncParams::for_schedule`] writes
    /// zero, which is what OWL does and what every associated Apple device does.
    pub trailing: [u8; 2],
}

impl SyncParams {
    /// Smallest length that can hold every fixed field above. The embedded channel
    /// sequence follows and makes real tags considerably longer — 73 bytes observed.
    pub const MIN_LEN: usize = 33;

    pub fn parse(v: &[u8]) -> Option<SyncParams> {
        if v.len() < Self::MIN_LEN {
            return None;
        }
        Some(SyncParams {
            tx_channel: le::u8(v, 0)?,
            tx_counter: le::u16(v, 1)?,
            master_channel: le::u8(v, 3)?,
            guard_time: le::u8(v, 4)?,
            aw_period: le::u16(v, 5)?,
            action_frame_period: le::u16(v, 7)?,
            flags: le::u16(v, 9)?,
            aw_ext_length: le::u16(v, 11)?,
            aw_common_length: le::u16(v, 13)?,
            aw_remaining: le::u16(v, 15)?,
            ext_min: le::u8(v, 17)?,
            ext_max_multicast: le::u8(v, 18)?,
            ext_max_unicast: le::u8(v, 19)?,
            ext_max_af: le::u8(v, 20)?,
            master: v.get(21..27)?.try_into().ok()?,
            presence_mode: le::u8(v, 27)?,
            reserved_28: le::u8(v, 28)?,
            aw_counter: le::u16(v, 29)?,
            ap_beacon_alignment_delta: le::u16(v, 31)?,
            channel_sequence: v.get(33..).and_then(ChannelSequence::parse),
            // The last two bytes, wherever the tag happens to end. Taken from the end
            // rather than computed from the sequence length so a sender with an
            // unexpected sequence shape still round-trips.
            trailing: v
                .get(v.len().saturating_sub(2)..)
                .and_then(|t| t.try_into().ok())
                .unwrap_or([0, 0]),
        })
    }

    /// Availability Window length in microseconds, from the wire rather than the paper.
    pub fn aw_period_us(&self) -> u32 {
        u32::from(self.aw_period) * TU_US
    }

    /// Serialise back to the wire: 33 fixed bytes, the channel sequence, the two
    /// trailing bytes.
    ///
    /// Returns `None` if there is no channel sequence or it cannot be encoded. Every real
    /// frame carries one, and a Synchronization Parameters tag without a schedule tells a
    /// peer nothing it can act on, so this is a genuine error rather than a short frame.
    pub fn encode(&self) -> Option<Vec<u8>> {
        let seq = self.channel_sequence.as_ref()?.encode()?;
        let mut out = Vec::with_capacity(Self::MIN_LEN + seq.len() + 2);
        out.push(self.tx_channel);
        out.extend_from_slice(&self.tx_counter.to_le_bytes());
        out.push(self.master_channel);
        out.push(self.guard_time);
        out.extend_from_slice(&self.aw_period.to_le_bytes());
        out.extend_from_slice(&self.action_frame_period.to_le_bytes());
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&self.aw_ext_length.to_le_bytes());
        out.extend_from_slice(&self.aw_common_length.to_le_bytes());
        out.extend_from_slice(&self.aw_remaining.to_le_bytes());
        out.push(self.ext_min);
        out.push(self.ext_max_multicast);
        out.push(self.ext_max_unicast);
        out.push(self.ext_max_af);
        out.extend_from_slice(&self.master);
        out.push(self.presence_mode);
        out.push(self.reserved_28);
        out.extend_from_slice(&self.aw_counter.to_le_bytes());
        out.extend_from_slice(&self.ap_beacon_alignment_delta.to_le_bytes());
        debug_assert_eq!(out.len(), Self::MIN_LEN, "the fixed part is 33 bytes");
        out.extend_from_slice(&seq);
        out.extend_from_slice(&self.trailing);
        Some(out)
    }

    /// Whether this node claims to be the master of its own cluster.
    pub fn is_self_master(&self) -> bool {
        self.master == [0u8; 6]
    }
}

/// The operating class a channel belongs to, as Apple writes it in tag 18.
///
/// Only the values actually observed: 81 for 2.4 GHz and 128 for the 80 MHz 5 GHz
/// classes. An absent slot carries 0, matching the captures — the qualifier is not
/// meaningful when the node is not there.
pub fn opclass_for(channel: u8) -> u8 {
    match channel {
        0 => 0,
        1..=14 => 81,
        _ => 128,
    }
}

/// How the channel list is encoded. The list length depends on this, so guessing it
/// misreads every channel rather than failing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChanEncoding {
    /// One byte per slot: the channel number.
    ChannelNumber,
    /// Two bytes per slot: flags then channel number.
    Legacy,
    /// Two bytes per slot: channel number then operating class.
    OpClass,
    Unknown(u8),
}

impl ChanEncoding {
    fn from(v: u8) -> ChanEncoding {
        match v {
            0 => ChanEncoding::ChannelNumber,
            1 => ChanEncoding::Legacy,
            3 => ChanEncoding::OpClass,
            other => ChanEncoding::Unknown(other),
        }
    }

    /// The wire value. Round-trips `Unknown` so a sequence we cannot interpret still
    /// re-encodes as the sender wrote it.
    pub fn to_u8(self) -> u8 {
        match self {
            ChanEncoding::ChannelNumber => 0,
            ChanEncoding::Legacy => 1,
            ChanEncoding::OpClass => 3,
            ChanEncoding::Unknown(v) => v,
        }
    }

    fn stride(self) -> Option<usize> {
        match self {
            ChanEncoding::ChannelNumber => Some(1),
            ChanEncoding::Legacy | ChanEncoding::OpClass => Some(2),
            ChanEncoding::Unknown(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelSequence {
    pub encoding: ChanEncoding,
    pub duplicate: u8,
    pub step_count: u8,
    /// 0xffff means "repeat current".
    pub fill_channel: u16,
    /// The slots, in order. This is the schedule: which channel the node is listening
    /// on during each Availability Window of the cycle.
    ///
    /// A slot of 0 means the node is not present at all during that window. In the
    /// first capture most slots were 0 — one device was on-channel for only 5 of its
    /// 16 windows — so "how many slots does it occupy" is a first-class question and
    /// not an edge case.
    pub channels: Vec<u8>,
    /// The second byte of each slot, kept raw.
    ///
    /// Its meaning depends on [`ChanEncoding`]: an operating class under `OpClass`, a
    /// flags byte carrying band/bandwidth/control-channel position under `Legacy`.
    /// Kept undecoded because the two need separate confirmation against captures, and
    /// a shared accessor would invite reading one as the other.
    pub qualifiers: Vec<u8>,
}

impl ChannelSequence {
    pub fn parse(v: &[u8]) -> Option<ChannelSequence> {
        // THE COUNT IS STORED MINUS ONE. A 16-slot sequence is written as 15, and
        // reading it literally silently drops the last slot -- which shows up as a
        // sequence that almost matches a peer's.
        let count = usize::from(le::u8(v, 0)?) + 1;
        let encoding = ChanEncoding::from(le::u8(v, 1)?);
        let duplicate = le::u8(v, 2)?;
        let step_count = le::u8(v, 3)?;
        let fill_channel = le::u16(v, 4)?;

        let stride = encoding.stride()?;
        let list = v.get(6..6 + count * stride)?;
        // Legacy puts flags first and the channel second; OpClass is the other way
        // round. Getting this backwards yields plausible-looking garbage rather than
        // an error, which is the worst kind of wrong.
        let (chan_idx, qual_idx) = match encoding {
            ChanEncoding::Legacy => (1, 0),
            _ => (0, 1),
        };
        let channels = list.chunks_exact(stride).map(|c| c[chan_idx]).collect();
        let qualifiers = list
            .chunks_exact(stride)
            .map(|c| if stride > 1 { c[qual_idx] } else { 0 })
            .collect();

        Some(ChannelSequence {
            encoding,
            duplicate,
            step_count,
            fill_channel,
            channels,
            qualifiers,
        })
    }

    /// Serialise back to the wire, WITHOUT the trailing bytes of the containing tag.
    ///
    /// The trailing bytes are deliberately not written here because they are not the
    /// same in both places this structure appears: Synchronization Parameters carries two
    /// after it and the Channel Sequence tag carries three. Emitting them from here would
    /// make one of the two callers wrong, and by an amount too small to notice.
    ///
    /// Returns `None` for a sequence that cannot be represented: an empty one (the count
    /// is stored minus one, so zero slots has no encoding), one longer than 256 slots, or
    /// one whose encoding has no known stride.
    pub fn encode(&self) -> Option<Vec<u8>> {
        let stride = self.encoding.stride()?;
        if self.channels.is_empty() || self.channels.len() > 256 {
            return None;
        }
        let mut out = Vec::with_capacity(6 + self.channels.len() * stride);
        // Minus one, matching the parser. Writing the true count produces a sequence
        // with one extra slot that still parses, which is the failure this pairing exists
        // to prevent.
        out.push((self.channels.len() - 1) as u8);
        out.push(self.encoding.to_u8());
        out.push(self.duplicate);
        out.push(self.step_count);
        out.extend_from_slice(&self.fill_channel.to_le_bytes());
        for (i, chan) in self.channels.iter().enumerate() {
            let qual = self.qualifiers.get(i).copied().unwrap_or(0);
            match (stride, self.encoding) {
                (1, _) => out.push(*chan),
                (_, ChanEncoding::Legacy) => {
                    // Legacy puts the qualifier first. The parser knows this; so must we,
                    // or a round-trip swaps every slot's two bytes and still parses.
                    out.push(qual);
                    out.push(*chan);
                }
                _ => {
                    out.push(*chan);
                    out.push(qual);
                }
            }
        }
        Some(out)
    }

    /// The value of a Channel Sequence tag (18): the sequence, then its three zero bytes.
    ///
    /// Those three are zero in all 7054 samples in `captures/`, from Apple, `libmosey`
    /// and OWL alike — unlike the two in Synchronization Parameters. See
    /// [`SyncParams::trailing`].
    pub fn encode_tag18(&self) -> Option<Vec<u8>> {
        let mut out = self.encode()?;
        out.extend_from_slice(&[0, 0, 0]);
        Some(out)
    }

    /// The schedule this project exists to be able to build.
    ///
    /// Apple's own devices, measured in `captures/assoc-connected.pcap`, occupy **4 of 16
    /// slots** and are absent for the other 12:
    ///
    /// - **slot 0** — the channel of the infrastructure association, so the radio is
    ///   already where the AP expects it when the AP expects it. This is the slot that
    ///   makes AWDL and Wi-Fi coexist rather than fight, and it is empty on a device with
    ///   no association.
    /// - **slot 8** — channel 6, always, whatever band the rest of the schedule uses. Two
    ///   devices that share no 5 GHz channel still meet here, which is what makes
    ///   cross-band discovery work at all.
    /// - **slots 2 and 10** — the regional social channel (149 in the captures).
    /// - everything else — absent. Not "listening elsewhere": off.
    ///
    /// The last point is the one worth stating plainly, because the obvious implementation
    /// is to fill every unused slot with the social channel and be reachable more of the
    /// time. Apple does not, and a node that does is on the air twelve slots longer per
    /// cycle than its peers expect while gaining nothing they will use.
    ///
    /// `assoc` is the association's channel, or `None` when there is no association.
    pub fn apple_shaped(social: u8, assoc: Option<u8>) -> ChannelSequence {
        let mut channels = vec![0u8; 16];
        channels[0] = assoc.unwrap_or(0);
        channels[2] = social;
        channels[8] = 6;
        channels[10] = social;
        ChannelSequence {
            // Operating class, as tag 18 uses: it names the control channel, where the
            // Legacy encoding names a 40 MHz centre that is not a channel anyone tunes to.
            encoding: ChanEncoding::OpClass,
            duplicate: 0,
            step_count: 3,
            fill_channel: 0xffff,
            qualifiers: channels.iter().map(|c| opclass_for(*c)).collect(),
            channels,
        }
    }

    /// Slots where the node is present at all. Channel 0 means absent.
    pub fn occupied_slots(&self) -> usize {
        self.channels.iter().filter(|c| **c != 0).count()
    }

    /// The distinct channels this node actually visits, excluding "absent".
    pub fn distinct(&self) -> Vec<u8> {
        let mut v: Vec<u8> = self.channels.iter().copied().filter(|c| *c != 0).collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// How many slots sit on `channel`, out of the whole sequence.
    ///
    /// This is the overlap calculation: two nodes can only talk during windows where
    /// they are both on the same channel, so a node at 16/16 on 149 and a peer at 4/16
    /// on 149 have an upper bound of 4/16 = 25% of windows in common.
    pub fn slots_on(&self, channel: u8) -> usize {
        self.channels.iter().filter(|c| **c == channel).count()
    }
}
