//! How much of the protocol do we actually understand?
//!
//! There are two different questions and it is easy to answer the second while believing
//! you answered the first:
//!
//! 1. **Can we reproduce a frame?** Yes, for every tag with a parser — unknown fields are
//!    carried raw and put back unchanged, so a parse-and-rebuild is byte-exact.
//! 2. **Do we know what the bytes mean?** That is a different and much smaller number.
//!
//! The distinction matters because of what a transmitter has to do. Echoing a frame needs
//! only (1). **Composing** one needs (2), because every byte we cannot name is a byte we
//! have to invent — and the usual way to invent it is to copy whatever Apple happened to
//! send, which is cargo-culting with extra steps and no signal when it is wrong.
//!
//! So this module classifies every byte of every tag into one of two buckets:
//!
//! - **named** — we can state what the field is and what the value means.
//! - **opaque** — we reproduce it and cannot describe it. Reserved bytes, fields whose
//!   meaning is unresolved, bodies we pass through, and whole tags with no parser.
//!
//! A field counts as named only if we could *choose* a correct value for it without
//! copying one. `master_counter` is not named: it has a label from the paper and its
//! observed values are inconsistent enough that we cannot say what a right one would be.

/// The byte budget for one TLV.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Coverage {
    pub named: usize,
    pub opaque: usize,
}

impl Coverage {
    pub fn total(&self) -> usize {
        self.named + self.opaque
    }
    pub fn add(&mut self, other: Coverage) {
        self.named += other.named;
        self.opaque += other.opaque;
    }
    pub fn percent_named(&self) -> f64 {
        if self.total() == 0 {
            return 0.0;
        }
        100.0 * self.named as f64 / self.total() as f64
    }
}

/// Classify a channel sequence's bytes, given where it starts in `v`.
///
/// The qualifier byte is the interesting one: under `OpClass` it is an operating class,
/// which we can name and choose. Under `Legacy` it is a flags byte carrying band,
/// bandwidth and control-channel position that we have never decoded — so a 16-slot
/// Legacy sequence hides 16 opaque bytes behind a schedule that otherwise reads perfectly.
fn channel_sequence(v: &[u8]) -> Coverage {
    use crate::sync::{ChanEncoding, ChannelSequence};
    let Some(seq) = ChannelSequence::parse(v) else {
        return Coverage { named: 0, opaque: v.len() };
    };
    // count, encoding, duplicate, step, fill
    let mut c = Coverage { named: 6, opaque: 0 };
    let slots = seq.channels.len();
    c.named += slots; // the channel numbers themselves
    match seq.encoding {
        ChanEncoding::OpClass => c.named += slots,
        ChanEncoding::Legacy => {
            // Named per slot, not wholesale: the qualifier is decoded for the four values
            // seen on the wire and is honestly unknown for any other, so a capture
            // containing an 80 MHz or 6 GHz Legacy slot will show up here as opaque
            // instead of being silently absorbed.
            use crate::sync::LegacyQualifier;
            for i in 0..slots {
                let q = LegacyQualifier::from(seq.qualifiers.get(i).copied().unwrap_or(0));
                match q {
                    LegacyQualifier::Other(_) => c.opaque += 1,
                    _ => c.named += 1,
                }
            }
        }
        ChanEncoding::ChannelNumber => {}
        ChanEncoding::Unknown(_) => c.opaque += slots,
    }
    c
}

/// Classify one TLV.
pub fn of_tlv(tag: u8, v: &[u8]) -> Coverage {
    let len = v.len();
    let all_opaque = Coverage { named: 0, opaque: len };
    match tag {
        // Service Response: DNS records in a documented encoding, with a compression
        // dictionary we recovered and test for byte equality. Fully named.
        2 => Coverage { named: len, opaque: 0 },

        // Synchronization Parameters.
        4 => {
            if len < 33 {
                return all_opaque;
            }
            // named: tx_channel, tx_counter, master_channel, guard_time, aw_period,
            // af_period, aw_ext_len, aw_common_len, aw_remaining, the four ext counts,
            // master, presence_mode, aw_counter, ap_beacon_alignment_delta.
            // opaque: flags (we know one bit correlates with association, not the word),
            // byte 28, and the two trailing bytes.
            // 30 named: tx_channel 1, tx_counter 2, master_channel 1, guard_time 1,
            // aw_period 2, af_period 2, aw_ext_len 2, aw_common_len 2, aw_remaining 2,
            // four ext counts 4, master 6, presence_mode 1, aw_counter 2, ap_beacon 2.
            // 3 opaque: the flags word, whose bits we cannot name, and byte 28.
            // They must sum to 33, which is the fixed part.
            // 31 named: the 30 above plus reserved_28, which a peer was MEASURED ignoring
            // -- finding 63's K7 and K8b adopted us with it set to 0xa5. 2 opaque: the
            // flags word, whose bits we still cannot name.
            let mut c = Coverage { named: 31, opaque: 2 };
            debug_assert_eq!(c.total(), 33);
            c.add(channel_sequence(&v[33..]));
            // The trailing pair. Finding 20 established it is a field rather than padding,
            // and K8b then showed a peer adopting us with 0xa5 0xa5 there -- so it is a
            // field the RECEIVER does not read, which is exactly the thing "named" means
            // here: we may choose any value.
            let counted = c.total();
            c.named += len.saturating_sub(counted);
            c
        }

        // Channel Sequence: the sequence, plus three bytes confirmed zero in all 7054
        // samples -- measured, so named as padding rather than assumed.
        18 => {
            let mut c = channel_sequence(v);
            c.named += len.saturating_sub(c.total());
            c
        }

        // Election Parameters. `reserved_4` and the two-byte tail were both PROVEN
        // IGNORED on hardware -- finding 63's K7 set all three to 0xa5 and the peer still
        // adopted us, 140 frames against controls of 146 and 241. Every byte of this tag
        // is now either understood or demonstrably free to choose.
        5 => Coverage { named: len, opaque: 0 },

        // Election Parameters v2.
        //
        // Bytes 32..36 count as NAMED on a different basis from everything else here: not
        // because we know what they mean, but because a real peer was measured ignoring
        // them. Finding 65 probed each byte of the old eight-byte block against an iPhone
        // and watched whether it still elected us -- 32 and 35 cost nothing, 28, 29 and 31
        // cost adoption entirely. This module's test for "named" is whether we could choose
        // a correct value without copying one, and for a byte proven ignored EVERY value is
        // correct. That is the weakest possible way to satisfy the criterion and it does
        // satisfy it.
        //
        // Bytes 28..32 stay opaque. They are read, they are a u32, and we cannot name them
        // -- which makes them the most interesting four bytes in the tag.
        24 => {
            if len < 40 {
                return all_opaque;
            }
            // master 6, parent 6, distance 4, both metrics 8, both counters 8, and the
            // four bytes at 32 proven ignored.
            Coverage { named: 36, opaque: len - 36 }
        }

        // Data Path State: the bitmap and the fields it selects are named; the extended
        // block and the UMI options blob are not.
        12 => {
            use crate::state::{flag, DataPathState};
            let Some(s) = DataPathState::parse(v) else { return all_opaque };
            let mut c = Coverage { named: 2, opaque: 0 }; // the bitmap
            if s.flags & flag::COUNTRY != 0 {
                c.named += 3;
            }
            if s.flags & flag::SOCIAL_CHANNEL != 0 {
                c.named += 2;
            }
            if s.flags & flag::INFRA_BSSID != 0 {
                c.named += 8;
            }
            if s.flags & flag::INFRA_ADDRESS != 0 {
                c.named += 6;
            }
            if s.flags & flag::AWDL_ADDRESS != 0 {
                c.named += 6;
            }
            if s.flags & flag::UMI != 0 {
                c.named += 2;
            }
            if s.flags & flag::UMI_OPTIONS != 0 {
                // The length prefix IS a length -- we can choose it. Its contents are not
                // decoded, so they are not.
                c.named += 2;
                c.opaque += s.umi_options.as_ref().map_or(0, |o| o.len());
            }
            if s.flags & flag::EXTENDED != 0 {
                // The extended flags word takes four values across the corpus and is
                // stable per device, so it is a flags word whose bits we cannot name --
                // and per finding 47 a value we would have to copy is not a named one.
                c.opaque += 2;
                let tail = s.extended_tail.len();
                // Two always-zero bytes, then three identified 32-bit fields, then one
                // that is not identified. Finding 49.
                c.opaque += tail.min(2);
                if tail > 2 {
                    c.named += (tail - 2).min(12);
                }
                if tail > 14 {
                    c.opaque += tail - 14;
                }
            }
            c.opaque += len.saturating_sub(c.total());
            c
        }

        // Arpa: the host name is a UUID v4 in DNS encoding (finding 47), and the flags
        // byte was PROVEN IGNORED -- finding 63's K7 sent 0xa5 there and the peer adopted
        // us anyway. Its meaning is still unknown; its value demonstrably does not matter.
        16 => Coverage { named: len, opaque: 0 },

        // Version: packed nibbles and a device class we have a table for.
        21 => Coverage { named: len, opaque: 0 },

        // 802.11 Container: standard elements. A VHT Capabilities body is fully decoded
        // from IEEE 802.11-2020 -- not reverse engineered -- so it counts as named. Any
        // other element is carried without being read.
        17 => {
            use crate::state::{Ieee80211Container, VhtCapabilities, ELEM_VHT_CAPABILITIES};
            let Some(c) = Ieee80211Container::parse(v) else { return all_opaque };
            let mut cov = Coverage { named: c.elements.len() * 2, opaque: 0 };
            for (id, body) in &c.elements {
                if *id == ELEM_VHT_CAPABILITIES && VhtCapabilities::parse(body).is_some() {
                    cov.named += body.len();
                } else {
                    cov.opaque += body.len();
                }
            }
            cov
        }

        // The 6 GHz tags. Both are a class/channel pair -- which we can name and choose --
        // followed by a raw remainder that has never been decoded. Tag 33's is the larger
        // share, and the two pairs inside it have been identical in every capture without
        // being required to be.
        32 => {
            use crate::state::SixGhzInfo;
            let Some(i) = SixGhzInfo::parse(v) else { return all_opaque };
            let _ = i;
            Coverage { named: 2, opaque: len - 2 }
        }
        33 => {
            use crate::state::SixGhzChannels;
            let Some(c) = SixGhzChannels::parse(v) else { return all_opaque };
            let named = 2 * (usize::from(c.first.is_some()) + usize::from(c.second.is_some()));
            Coverage { named, opaque: len - named }
        }

        // HT Capabilities. The "variable tail" was never a separate thing: AWDL sends a
        // TRUNCATED Supported MCS Set, whose octets are in the standard order, so every
        // byte past the A-MPDU parameters is a field IEEE 802.11-2020 §9.4.2.55.4 names.
        // Reserved octets count as named too -- reserved has a defined correct value and
        // we can choose it, which is the test this module applies.
        //
        // Only the two leading bytes stay opaque. They are `00 00` in every frame measured
        // and no source names them, which is not the same as knowing they are padding.
        7 => {
            use crate::state::HtCapabilities;
            if HtCapabilities::parse(v).is_none() {
                return all_opaque;
            }
            // info 2 + A-MPDU 1, then however much of the 16-octet MCS set is present.
            let named = 3 + len.saturating_sub(5).min(16);
            Coverage { named, opaque: len - named }
        }

        // Service Parameters: the field boundaries are known and the CONTENTS are not.
        // A bitmask whose hash function we do not have is not a value we can choose, so
        // this counts as nothing named -- knowing where a field starts is not knowing
        // what belongs in it.
        6 => all_opaque,

        // Everything else has no parser at all.
        _ => all_opaque,
    }
}

/// Whether we have any decoder for a tag.
pub fn is_decoded(tag: u8) -> bool {
    matches!(tag, 2 | 4 | 5 | 6 | 7 | 12 | 16 | 17 | 18 | 21 | 24 | 32 | 33)
}
