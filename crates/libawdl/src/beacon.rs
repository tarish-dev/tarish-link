//! Building the frames we put on the air.
//!
//! Everything else in this crate reads AWDL. This writes it, and it is the first thing
//! here that can be *wrong in public* — a malformed frame is not a failed parse, it is
//! noise on a shared channel that other people's devices have to process.
//!
//! # What this deliberately does not do
//!
//! **It does not synchronise to anyone else.** A node that *follows* a master must align
//! its Availability Windows to that master's TSF, and this crate has no TSF read on the
//! hardware it runs on.
//!
//! **A master does not have that problem**, which is the thing worth noticing: the master
//! *is* the reference, so it needs timing that is **self-consistent**, not timing that
//! agrees with somebody else's. A monotonic clock can supply that. So the role that looks
//! harder is the one that is actually available to a radio without TSF support — and the
//! first transmit run bore that out, with two iPhones and a MacBook electing us.
//!
//! What is still missing is precision, not coherence: a host clock has scheduler jitter a
//! MAC timer does not, so our windows will wander by more than Apple's. That is a quality
//! problem to measure, not a correctness one.
//!
//! # PSF and MIF differ by identity, not by size
//!
//! An earlier version of this module guessed that a PSF was a stripped-down timing frame
//! carrying sync and election only. **Measured across 18378 captured frames, that is
//! wrong:**
//!
//! | | mean | tags |
//! |---|---|---|
//! | PSF | 329 B | `4, 5, 18, 6, 24, 12, 7, 17, 21` |
//! | MIF | 626 B | the same, plus `16` and **several** `2` |
//!
//! A PSF carries the whole state set and omits only *who we are* — Arpa — and *what we
//! offer* — Service Response. So the distinction is identity, not weight.
//!
//! Tag order is **not** rigid, which also corrects an earlier claim here. Tag 4 is first
//! in every captured frame; after that the order varies between frames from the same
//! device (`4,5,18,…` and `4,18,32,5,…` both occur). We emit a fixed order because there
//! is no reason not to, not because a peer requires one.
//!
//! We fill ten of the thirteen tags Apple sends. The three missing are 6 — a service hash
//! whose function we cannot compute, and which `libmosey` sends empty while AirDrop works
//! — and 32/33, conditional on a 6 GHz association we do not have. See `docs/GAPS.md`.

use crate::{
    action::{self, Fixed, SUBTYPE_MIF, SUBTYPE_PSF},
    dot11::{management_header, Mac, BROADCAST},
    election::{ElectionParams, ElectionParamsV2, AW_PER_COUNTER_TICK},
    service::{self, Record},
    state::{Arpa, DataPathState, HtCapabilities, Ieee80211Container, Version, ELEM_VHT_CAPABILITIES},
    sync::{ChannelSequence, SyncParams, TU_US},
};

/// One Availability Window in microseconds: 16 TU.
///
/// From the wire, not the paper — `aw_period` reads 16 in all 18157 captured frames.
pub const AW_US: u32 = 16 * TU_US;

/// One channel-sequence SLOT in microseconds: `presence_mode` availability windows.
///
/// **A slot is not an availability window**, and this crate transmitted as though it were
/// until OWL's `schedule.c` was read. Settled from the frames: `(aw_counter /
/// presence_mode) % 16` puts every captured Apple device inside its own advertised slots,
/// 100% against a 25% chance level; `aw_counter % 16` scores 34-43%. See
/// `libawdl::follow::DEFAULT_PRESENCE_MODE`.
///
/// The consequence for a transmitter is not subtle: stepping a slot per availability
/// window walks the cycle **four times too fast**, so "transmit in slots 2, 8 and 10"
/// lands somewhere different every cycle.
pub const SLOT_US: u32 = 4 * AW_US;

/// A full sixteen-slot cycle: 1024 TU, about 1.05 seconds.
pub const CYCLE_US: u32 = 16 * SLOT_US;

/// How often a master intends to send a Periodic Synchronization Frame, in TU.
///
/// 110 in every captured Apple frame, and `PSF_INTERVAL_MASTER_TU` in OWL — which both
/// advertises it as `af_period` and paces by it. It is an advertisement, so a transmitter
/// that emits it and sends at some other rate is misdescribing itself.
pub const PSF_INTERVAL_TU: u16 = 110;

/// A metric that loses to any real Apple device: 65, which is what `libmosey` advertises.
///
/// "I am here and I do not want the job." The right default until the schedule we advertise
/// is one we actually keep.
pub const METRIC_DECLINE: u32 = 65;

/// A metric observed to beat real Apple devices, which sat at 510-530.
///
/// **Apple's metrics are not fixed, so this constant goes stale.** In one room on one
/// evening, devices advertised 510, 515, 530, 537 and 539 — and an iPhone at 539 outranked
/// this value the same day it was chosen. Treat it as a starting point and override it when
/// the peers in the room say otherwise; the CLI takes `--metric N` for exactly that.
///
/// **Only correct on a radio that can anchor transmissions to a TSF.** See
/// [`Beacon::metric`] for what happened the first time this was the default.
pub const METRIC_COMPETE: u32 = 530;

/// Which measured-constant byte groups to fill with non-zero values.
///
/// **The experiment this exists for.** Around 450,000 bytes of the control plane are
/// classified opaque for one reason only: they have been zero in all 37,829 frames measured
/// and no specification names them. Finding 47 is blunt that constant is *not* the same as
/// understood — a byte could be zero across this corpus because it is reserved, or because
/// every device in it happens to share a value.
///
/// No amount of reading settles that. Transmitting does: put something else in those bytes
/// and see whether real Apple peers still synchronise to us and still adopt us. If they do,
/// the bytes are **proven ignored**, and choosing zero for them becomes knowledge rather
/// than imitation.
///
/// The measurement needs a condition where the unperturbed case reliably succeeds, or a
/// refusal means nothing. Finding 59 is that control: two iPhones adopting us in 1,223
/// frames, on demand.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Garbage {
    /// Tag 4: `reserved_28` and the two trailing bytes. Note the trailing pair is **not**
    /// padding — finding 20 — so this group is the least likely of the four to be ignored.
    pub t4: bool,
    /// Tag 5: `reserved_4` and the two-byte tail. Zero in all 37,829 frames.
    pub t5: bool,
    /// Tag 16: the Arpa flags byte, `0x03` in all 13,447 frames.
    pub t16: bool,
    /// Tag 24: the eight-byte `unknown_28` block. The largest single group, 302,632 opaque
    /// bytes, and the cleanest — eight contiguous bytes, zero in every frame measured.
    ///
    /// **Apple reads these** — finding 63. Kept as a control rather than as a candidate.
    pub t24: bool,
    /// Disturb a single byte of tag 24's block instead of all eight. Overrides `t24`.
    pub t24_probe: Option<T24Probe>,
    /// Tag 7: the two leading bytes, `00 00` in every frame measured.
    ///
    /// The only part of HT Capabilities that IEEE 802.11-2020 does not account for --
    /// finding 48 decoded everything from byte 2 onward as a truncated Supported MCS Set
    /// and left these two unexplained. 74,478 opaque bytes.
    pub t7: bool,
}

/// The default fill value. Recognisable on purpose: a capture has to confirm our own frames
/// really carried it, because an encoder that quietly drops the change would make the
/// experiment look like a success.
pub const GARBAGE_BYTE: u8 = 0xa5;

/// Which bytes of tag 24's eight-byte block to disturb, and with what.
///
/// **Why this granularity exists.** Finding 63 established that filling all eight bytes with
/// `0xa5` makes an Apple peer refuse to adopt us — 0 against controls of 146 and 241. One
/// value at one width cannot distinguish two very different explanations:
///
/// - a **strict zero check**: any non-zero byte anywhere in 28..36 invalidates the frame
/// - a **field we have mislabelled**: `0xa5a5…` happens to mean something, and other values
///   would pass
///
/// The first says "send zeros and move on". The second says there is a real field there
/// worth identifying. Setting **one byte** to **0x01** separates them: if a single bit still
/// kills adoption it is a strict check, and if adoption survives then `0xa5` was hitting
/// something specific and the block can be bisected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct T24Probe {
    /// Offset within `unknown_28`, 0..8.
    pub offset: usize,
    /// The value to write there. Everything else in the block stays zero.
    pub value: u8,
}

impl Garbage {
    /// `"t24"`, `"t4,t24"`, `"all"`. Returns `None` for an unrecognised group rather than
    /// silently running a weaker experiment than the one asked for.
    pub fn parse(spec: &str) -> Option<Garbage> {
        let mut g = Garbage::default();
        for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            if let Some(p) = Garbage::parse_probe(part) {
                g.t24_probe = p.t24_probe;
                continue;
            }
            match part {
                "all" => {
                    g = Garbage { t4: true, t5: true, t16: true, t24: true, t7: true, t24_probe: None }
                }
                "t4" => g.t4 = true,
                "t5" => g.t5 = true,
                "t16" => g.t16 = true,
                "t24" => g.t24 = true,
                "t7" => g.t7 = true,
                _ => return None,
            }
        }
        Some(g)
    }

    pub fn any(&self) -> bool {
        self.t4 || self.t5 || self.t16 || self.t24 || self.t7 || self.t24_probe.is_some()
    }

    /// `"t24@3=01"` — one byte of tag 24's block, at that offset, set to that value.
    pub fn parse_probe(spec: &str) -> Option<Garbage> {
        let rest = spec.strip_prefix("t24@")?;
        let (off, val) = rest.split_once('=')?;
        let offset: usize = off.parse().ok()?;
        if offset >= 8 {
            return None;
        }
        let value = u8::from_str_radix(val.trim_start_matches("0x"), 16).ok()?;
        Some(Garbage { t24_probe: Some(T24Probe { offset, value }), ..Garbage::default() })
    }

    /// Which groups, and how many bytes per frame each one perturbs.
    pub fn describe(&self) -> String {
        let mut v: Vec<&str> = Vec::new();
        if self.t4 {
            v.push("t4 reserved_28 + trailing pair (3B)");
        }
        if self.t5 {
            v.push("t5 reserved_4 + tail (3B)");
        }
        if self.t16 {
            v.push("t16 flags byte (1B)");
        }
        if self.t7 {
            v.push("t7 leading pair (2B)");
        }
        if let Some(p) = self.t24_probe {
            return format!("t24 unknown_28[{}] = 0x{:02x} (1 byte, rest zero)", p.offset, p.value);
        }
        if self.t24 {
            v.push("t24 unknown_28 (8B)");
        }
        if v.is_empty() {
            "none".to_string()
        } else {
            v.join(", ")
        }
    }
}

/// Everything needed to emit a frame, and the counters that move between frames.
#[derive(Debug, Clone)]
pub struct Beacon {
    /// Our AWDL address. Expected to be locally administered and to rotate; every sender
    /// in `captures/` randomises it, and nothing may treat it as an identity.
    pub addr: [u8; 6],
    /// The host name published in Arpa, without the `.local`.
    pub host: String,
    /// The regional social channel — 6, 44 or 149. See `libawdl_hal::SOCIAL_CHANNELS`.
    pub social_channel: u8,
    /// Our infrastructure association's channel, if we have one. It goes in slot 0 of the
    /// schedule and in Data Path State, and those two must agree.
    pub assoc_channel: Option<u8>,
    /// ISO country code for Data Path State.
    pub country: String,
    /// Our election metric — **how badly we want to be master of the cluster.**
    ///
    /// The default is [`METRIC_DECLINE`], and that is a safety decision rather than a
    /// timidity one. On the first transmit run this defaulted to 530 and **won**: two
    /// iPhones and a MacBook elected our node master, one of them two hops out through the
    /// other. That proved the frames are right and it also anchored three Apple devices'
    /// synchronisation to a node that **does not keep the schedule it advertises**, because
    /// this crate has no TSF to transmit against yet.
    ///
    /// Winning an election you cannot serve is worse than losing it: the cluster follows a
    /// clock that is not a clock. Raise it deliberately, on a radio that can hold time.
    pub metric: u32,
    /// The mDNS instance name we advertise AirDrop under, e.g. `0011223344556677`.
    pub instance: String,
    /// Frames sent, which feeds `tx_counter`.
    pub sent: u16,
    /// Where our tenure counter stood when we took the job. See
    /// [`ElectionParamsV2::self_counter`].
    pub tenure_base: u32,
    /// VHT capability bits. **These describe the radio and must come from it.** The
    /// default is a plausible two-stream 80 MHz claim, which is a placeholder, and
    /// announcing capabilities the hardware lacks invites a peer to use them.
    pub vht: [u8; 12],
    /// HT capability bits, same caveat as [`vht`](Self::vht): they describe the radio, so
    /// the radio is the only correct source. The default mirrors a captured Apple value —
    /// LDPC, 40 MHz, short GI at both widths, two spatial streams.
    pub ht: HtCapabilities,
    /// Fill measured-constant bytes with [`GARBAGE_BYTE`] instead of zero. See [`Garbage`].
    pub garbage: Garbage,
    /// Occupy this many windows of sixteen instead of Apple's four.
    ///
    /// **An experimental control for finding 38.** Trial E took mastership from a settled
    /// Apple cluster while occupying six windows; trials F and G, at three windows and up
    /// to the same frame rate, did not. But E's six were an accident — half its frames
    /// landed in windows it did not advertise — so "breadth wins" is a hypothesis from one
    /// success, and testing it needs breadth that is *deliberate* and *honestly advertised*.
    ///
    /// The schedule this produces still puts channel 6 in slot 8 and the association in
    /// slot 0; the extra windows carry the social channel. What we announce is what we
    /// transmit in, which is the whole difference from the bug that prompted it.
    ///
    /// `None` is Apple's measured shape and the right default.
    pub windows: Option<usize>,
    /// **Reproduce the timing defect of the first transmit run, on purpose.**
    ///
    /// `aw_remaining` becomes 0 in every frame and `aw_counter` follows the frame count
    /// rather than the clock, which is what the beacon did before finding 35. It exists
    /// only as an experimental control: the question of whether that defect is what made
    /// Apple devices follow us cannot be answered by comparing two runs with different
    /// peers present, and answering it needs the broken condition reproducible on demand.
    ///
    /// **Never set this for anything but an experiment.** It puts a field on the air that
    /// tells every peer our availability window is ending, continuously.
    pub legacy_timing: bool,
}

impl Beacon {
    /// A beacon for a node that is master of a cluster of one.
    pub fn new(addr: [u8; 6], social_channel: u8, country: &str) -> Beacon {
        Beacon {
            garbage: Garbage::default(),
            addr,
            host: "tarish".to_string(),
            social_channel,
            assoc_channel: None,
            country: country.to_string(),
            metric: METRIC_DECLINE,
            instance: addr.iter().map(|b| format!("{b:02x}")).collect(),
            sent: 0,
            tenure_base: 0,
            vht: [0x32, 0x00, 0x80, 0x03, 0xfa, 0xff, 0, 0, 0xfa, 0xff, 0, 0],
            ht: HtCapabilities {
                unknown_0: [0, 0],
                info: 0x006f,
                ampdu_params: 0x17,
                rx_mcs_bitmap: 0xffff,
                trailing: vec![0, 0],
            },
            windows: None,
            legacy_timing: false,
        }
    }

    /// The schedule we advertise: Apple's measured shape, four slots of sixteen — or a
    /// deliberately wider one when [`windows`](Self::windows) asks for it.
    pub fn schedule(&self) -> ChannelSequence {
        let base = ChannelSequence::apple_shaped(self.social_channel, self.assoc_channel);
        let Some(n) = self.windows else { return base };
        let n = n.clamp(1, 16);

        let mut channels = vec![0u8; 16];
        // Spread n windows as evenly as the cycle allows, so breadth is what varies and
        // not clustering.
        for i in 0..n {
            channels[i * 16 / n] = self.social_channel;
        }
        // The two slots that carry meaning keep it: slot 8 is channel 6 whatever the rest
        // of the schedule does, and slot 0 is the association when there is one.
        channels[8] = 6;
        if let Some(a) = self.assoc_channel {
            channels[0] = a;
        }
        ChannelSequence {
            encoding: crate::sync::ChanEncoding::OpClass,
            duplicate: 0,
            step_count: 3,
            fill_channel: 0xffff,
            qualifiers: channels.iter().map(|c| crate::sync::opclass_for(*c)).collect(),
            channels,
        }
    }

    /// Availability Windows elapsed at `now_us`, counted from our own epoch.
    ///
    /// Still counted in AWs, not slots: `aw_counter` is an availability-window counter and
    /// a peer divides it by `presence_mode` to get the slot. Emitting a slot index here
    /// would put us in slot `n/4` of our own schedule as far as every receiver is
    /// concerned.
    pub fn aws_at(now_us: u64) -> u32 {
        (now_us / u64::from(AW_US)) as u32
    }

    /// How often we have told peers we will send a PSF, in microseconds.
    pub fn psf_interval_us(&self) -> u64 {
        u64::from(PSF_INTERVAL_TU) * u64::from(TU_US)
    }

    /// Which channel-sequence slot `now_us` falls in, on our own cycle.
    pub fn slot_at(now_us: u64) -> usize {
        ((now_us % u64::from(CYCLE_US)) / u64::from(SLOT_US)) as usize
    }

    /// Microseconds left in the current Availability Window at `now_us`.
    pub fn aw_remaining_us(now_us: u64) -> u32 {
        AW_US - (now_us % u64::from(AW_US)) as u32
    }

    fn sync(&self, now_us: u64) -> SyncParams {
        SyncParams {
            tx_channel: self.social_channel,
            tx_counter: self.sent,
            master_channel: self.social_channel,
            guard_time: 0,
            // 16 TU, which is what the paper says and what all 18157 captured frames say.
            aw_period: 16,
            // THE PSF INTERVAL, in TU, and a promise we should keep. OWL sets this field
            // from its own `psf_interval` (`PSF_INTERVAL_MASTER_TU 110`) and paces PSFs by
            // it; every Apple frame carries 110 too. This crate emitted the number and
            // paced by an unrelated rule, so the frame told every receiver how often we
            // intended to send and we did not honour it. `psf_interval_us` is the value to
            // pace by.
            action_frame_period: PSF_INTERVAL_TU,
            // Bit 11 set: the trailing field is absent, which is what every associated
            // Apple device says. See `FLAG_NO_TRAILING`.
            flags: 0x1800,
            aw_ext_length: 16,
            aw_common_length: 16,
            // TU left in this window, from our own clock. **Zero here is a lie**, and it
            // was what this sent on the first transmit run: a joining node reads this to
            // work out where in the schedule it has arrived, and "my window ends now",
            // every frame, forever, is not something it can align to.
            aw_remaining: if self.legacy_timing {
                0
            } else {
                (Self::aw_remaining_us(now_us) / TU_US) as u16
            },
            ext_min: 3,
            ext_max_multicast: 3,
            ext_max_unicast: 3,
            ext_max_af: 3,
            master: self.addr,
            presence_mode: 4,
            reserved_28: if self.garbage.t4 { GARBAGE_BYTE } else { 0 },
            // Derived from the clock rather than from the frame count. Those only agree
            // if every frame goes out exactly one window apart, which no scheduler
            // guarantees -- and a counter that drifts from its own clock is a counter a
            // follower cannot use.
            aw_counter: if self.legacy_timing {
                // 16 windows per frame, assumed rather than measured -- the original bug.
                self.sent.wrapping_mul(16)
            } else {
                (Self::aws_at(now_us) & 0xffff) as u16
            },
            ap_beacon_alignment_delta: 0,
            channel_sequence: Some(self.schedule()),
            // Finding 20: these two are a FIELD, not padding, and OWL is the only
            // implementation that zeroes them. Of every group --garbage can perturb this
            // is the one most likely to be read, which is exactly why it must actually be
            // perturbed -- it was not, for a whole hardware trial.
            trailing: if self.garbage.t4 { [GARBAGE_BYTE; 2] } else { [0, 0] },
        }
    }

    fn tenure(&self, now_us: u64) -> u32 {
        ElectionParamsV2::counter_after(self.tenure_base, Self::aws_at(now_us))
    }

    /// The state every frame carries, PSF and MIF alike.
    ///
    /// This is the measured PSF set minus tag 6, which we cannot fill. A MIF is this plus
    /// identity and services.
    fn state_tlvs(&self, now_us: u64) -> Vec<(u8, Vec<u8>)> {
        let seq = self.schedule();
        let mut tlvs: Vec<(u8, Vec<u8>)> = Vec::new();
        if let Some(v) = self.sync(now_us).encode() {
            tlvs.push((4, v));
        }
        tlvs.push((5, {
            let mut e = ElectionParams::claiming(self.addr, self.metric);
            if self.garbage.t5 {
                e.reserved_4 = GARBAGE_BYTE;
                e.tail = vec![GARBAGE_BYTE; 2];
            }
            e.encode()
        }));
        if let Some(v) = seq.encode_tag18() {
            tlvs.push((18, v));
        }
        tlvs.push((24, {
            let mut e = ElectionParamsV2::claiming(self.addr, self.metric, self.tenure(now_us));
            // A single-byte probe takes precedence: it is the finer instrument and running
            // both at once would measure neither.
            if let Some(p) = self.garbage.t24_probe {
                if p.offset < 8 {
                    // The probe addresses the old eight-byte block by offset, which now
                    // straddles two fields: 0..4 is the u32 the peer reads, 4..8 the
                    // padding it ignores. Kept as one address space so the probe results
                    // in finding 65 stay directly comparable.
                    if p.offset < 4 {
                        let mut b = e.unknown_28.to_le_bytes();
                        b[p.offset] = p.value;
                        e.unknown_28 = u32::from_le_bytes(b);
                    } else {
                        e.ignored_32[p.offset - 4] = p.value;
                    }
                }
            } else if self.garbage.t24 {
                e.unknown_28 = u32::from_le_bytes([GARBAGE_BYTE; 4]);
                e.ignored_32 = [GARBAGE_BYTE; 4];
            }
            e.encode()
        }));
        tlvs.push((
            12,
            DataPathState::describing(
                self.addr,
                &self.country,
                self.social_channel,
                // A BSSID we do not know is not a BSSID we should invent. Apple zeroes
                // this field even when associated, so zero is what a real device sends.
                self.assoc_channel.map(|c| ([0u8; 6], u16::from(c))),
            )
            .encode(),
        ));
        tlvs.push((7, {
            let mut h = self.ht.clone();
            if self.garbage.t7 {
                h.unknown_0 = [GARBAGE_BYTE; 2];
            }
            h.encode()
        }));
        tlvs.push((
            17,
            Ieee80211Container { elements: vec![(ELEM_VHT_CAPABILITIES, self.vht.to_vec())] }
                .encode(),
        ));
        // v3.4, which is what libmosey and OWL announce. Raising it to Apple's 10.0 is a
        // capability claim and a separate decision -- see docs/GAPS.md section 1, where it
        // is also recorded as no longer being the decisive experiment it was thought to be.
        tlvs.push((21, Version { major: 3, minor: 4, device_class: 2 }.encode().to_vec()));
        tlvs
    }

    /// A Periodic Synchronization Frame: state without identity.
    ///
    /// Apple sends these roughly twice as often as MIFs and at about half the size. The
    /// mistake to avoid is sending MIFs at PSF rate — legal, and it wastes a shared
    /// channel.
    pub fn psf_tlvs(&self, now_us: u64) -> Vec<(u8, Vec<u8>)> {
        self.state_tlvs(now_us)
    }

    /// A Master Indication Frame: the state set, plus who we are and what we offer.
    pub fn mif_tlvs(&self, now_us: u64) -> Vec<(u8, Vec<u8>)> {
        let mut tlvs = self.state_tlvs(now_us);
        tlvs.push((
            16,
            Arpa {
                flags: if self.garbage.t16 { GARBAGE_BYTE } else { 3 },
                name: format!("{}.local", self.host),
            }
            .encode(),
        ));
        tlvs.push((
            2,
            service::encode_records(&[Record::Ptr {
                name: "_airdrop._tcp.local".into(),
                target: format!("{}._airdrop._tcp.local", self.instance),
            }]),
        ));
        tlvs
    }

    /// A complete 802.11 frame, ready for injection.
    ///
    /// `target_tx_time` should come from the radio's TSF. Passing anything else makes the
    /// header's own jitter figure a fiction — see `Fixed::for_tx`.
    pub fn frame(&self, subtype: u8, now_us: u64) -> Vec<u8> {
        let tlvs =
            if subtype == SUBTYPE_MIF { self.mif_tlvs(now_us) } else { self.psf_tlvs(now_us) };
        let mut f = management_header(BROADCAST, Mac(self.addr), self.sent).to_vec();
        // target_tx_time is the same clock, truncated. On a radio that reports TSF this
        // should be the TSF -- see `Fixed::for_tx`.
        f.extend_from_slice(&action::encode_body(
            &Fixed::for_tx(subtype, now_us as u32),
            &tlvs,
        ));
        f
    }

    pub fn mif(&self, now_us: u64) -> Vec<u8> {
        self.frame(SUBTYPE_MIF, now_us)
    }
    pub fn psf(&self, now_us: u64) -> Vec<u8> {
        self.frame(SUBTYPE_PSF, now_us)
    }

    /// The slots we advertise as occupied, in order.
    pub fn advertised_slots(&self) -> Vec<usize> {
        self.schedule()
            .channels
            .iter()
            .enumerate()
            .filter(|(_, c)| **c != 0)
            .map(|(i, _)| i)
            .collect()
    }

    /// Microseconds from `now_us` until the start of the next window we advertise.
    ///
    /// **This is what makes the schedule we announce and the schedule we keep the same
    /// thing.** Before this existed the beacon transmitted every sixteen windows — exactly
    /// one cycle — which meant it sat on one arbitrary phase for a whole run, decided by
    /// when the process happened to start, while announcing slots 0, 2, 8 and 10. Measured
    /// on the air it occupied 3 of 16 slots, none of them the advertised ones.
    ///
    /// Needs no TSF and no peer: a master is its own reference, and this aligns us to our
    /// own cycle rather than to anybody else's.
    ///
    /// Returns 0 if we are already inside an advertised window, so a caller loops rather
    /// than sleeping through the window it was waiting for.
    pub fn us_until_next_advertised_window(&self, now_us: u64) -> u64 {
        let slots = self.advertised_slots();
        if slots.is_empty() {
            return u64::from(SLOT_US);
        }
        // A SLOT, not an availability window. See SLOT_US.
        let slot = u64::from(SLOT_US);
        let cycle = u64::from(CYCLE_US);
        let pos = now_us % cycle;
        let here = (pos / slot) as usize;
        if slots.contains(&here) {
            return 0;
        }
        let next = slots.iter().copied().find(|s| *s > here).unwrap_or(slots[0] + 16);
        (next as u64) * slot - pos
    }

    /// Count one frame out. Timing no longer lives here — it comes from the clock.
    pub fn advance(&mut self) {
        self.sent = self.sent.wrapping_add(1);
    }

    /// Availability windows per tenure tick, re-exported so a caller pacing this does not
    /// have to reach into `election`.
    pub const AWS_PER_TENURE_TICK: u32 = AW_PER_COUNTER_TICK;
}
