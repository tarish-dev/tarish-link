//! The beacon, checked against the same real frame the parser was built on.

mod fixture_frame;

use libawdl::{
    action::{ActionFrame, SUBTYPE_MIF, SUBTYPE_PSF},
    beacon::{Beacon, AW_US, CYCLE_US, SLOT_US},
    dot11::{Dot11, Mac, BROADCAST},
    radiotap::Radiotap,
    sync::SyncParams,
};

const ADDR: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

#[test]
fn a_beacon_frame_parses_as_awdl_through_our_own_reader() {
    let b = Beacon::new(ADDR, 149, "QA");
    let f = b.mif(0x1234_5678);

    let d = Dot11::parse(&f).expect("802.11 header");
    assert!(d.is_action());
    assert_eq!(d.dst, BROADCAST);
    assert_eq!(d.src, Mac(ADDR));
    assert_eq!(d.bssid, Mac(libawdl::action::BSSID));

    let af = ActionFrame::parse(&f[24..]).expect("recognised as AWDL");
    assert_eq!(af.fixed.subtype, SUBTYPE_MIF);
    assert_eq!(af.fixed.target_tx_time, 0x1234_5678);
    let tags: Vec<u8> = af.tlvs().map(|t| t.tag).collect();
    assert_eq!(tags, vec![4, 5, 18, 24, 12, 7, 17, 21, 16, 2]);
}

/// Our frame carries every tag an Apple device sends except the four we know about.
#[test]
fn the_beacon_omits_only_the_tags_we_cannot_fill() {
    use std::collections::BTreeSet;
    let rt = Radiotap::parse(fixture_frame::FRAME).unwrap();
    let real = rt.payload(fixture_frame::FRAME).unwrap();
    let theirs: BTreeSet<u8> = ActionFrame::parse(&real[24..]).unwrap().tlvs().map(|t| t.tag).collect();

    let f = Beacon::new(ADDR, 149, "QA").mif(0);
    let ours: BTreeSet<u8> = ActionFrame::parse(&f[24..]).unwrap().tlvs().map(|t| t.tag).collect();

    let missing: Vec<u8> = theirs.difference(&ours).copied().collect();
    assert_eq!(missing, vec![6, 32, 33], "tag 7 is filled now; 6 and the 6 GHz pair are not");
}

/// PSF and MIF differ by identity, not by weight — which is what the captures show, and
/// not what an earlier version of the beacon assumed.
///
/// Apple's mean PSF is 329 bytes against a 626-byte MIF, and the tags it drops are exactly
/// Arpa and Service Response. A PSF that carried only sync and election would be half the
/// size of a real one and would be announcing far less state than a peer expects.
#[test]
fn a_psf_carries_the_state_set_without_the_identity() {
    let b = Beacon::new(ADDR, 149, "QA");
    let (psf_bytes, mif_bytes) = (b.psf(0), b.mif(0));
    let psf = ActionFrame::parse(&psf_bytes[24..]).unwrap();
    let mif = ActionFrame::parse(&mif_bytes[24..]).unwrap();
    assert_eq!(psf.fixed.subtype, SUBTYPE_PSF);

    let ptags: Vec<u8> = psf.tlvs().map(|t| t.tag).collect();
    let mtags: Vec<u8> = mif.tlvs().map(|t| t.tag).collect();
    assert_eq!(ptags, vec![4, 5, 18, 24, 12, 7, 17, 21], "the measured PSF set, less tag 6");
    assert_eq!(mtags, vec![4, 5, 18, 24, 12, 7, 17, 21, 16, 2], "plus Arpa and services");

    // Smaller, but nothing like half: the state set dominates both.
    assert!(psf_bytes.len() < mif_bytes.len());
    assert!(psf_bytes.len() * 2 > mif_bytes.len(), "a PSF is most of a MIF, not a fraction");
}

/// The association is stated in two places and they must agree, because a peer that finds
/// them disagreeing has no way to tell which is right.
#[test]
fn the_association_channel_agrees_between_the_schedule_and_data_path_state() {
    use libawdl::state::DataPathState;
    let mut b = Beacon::new(ADDR, 149, "QA");
    b.assoc_channel = Some(104);
    let f = b.mif(0);
    let af = ActionFrame::parse(&f[24..]).unwrap();

    let sync = af.tlvs().find(|t| t.tag == 4).and_then(|t| SyncParams::parse(t.value)).unwrap();
    let slot0 = sync.channel_sequence.unwrap().control_channels()[0];
    let dps = af.tlvs().find(|t| t.tag == 12).and_then(|t| DataPathState::parse(t.value)).unwrap();

    assert_eq!(slot0, Some(104), "slot 0 is the association");
    assert_eq!(dps.infra_channel, Some(104), "and so is Data Path State");
    assert!(dps.is_associated());

    // With no association, slot 0 is empty and Data Path State says so too.
    let alone = Beacon::new(ADDR, 149, "QA").mif(0);
    let af2 = ActionFrame::parse(&alone[24..]).unwrap();
    let s2 = af2.tlvs().find(|t| t.tag == 4).and_then(|t| SyncParams::parse(t.value)).unwrap();
    assert_eq!(s2.channel_sequence.unwrap().control_channels()[0], None);
    let d2 = af2.tlvs().find(|t| t.tag == 12).and_then(|t| DataPathState::parse(t.value)).unwrap();
    assert!(!d2.is_associated());
}

/// The counters move, and the tenure ticks on the 192-window boundary rather than smoothly.
#[test]
fn the_counters_advance_the_way_apple_devices_do() {
    use libawdl::election::ElectionParamsV2;
    let mut b = Beacon::new(ADDR, 149, "QA");

    let tenure_at = |b: &Beacon, now: u64| {
        let f = b.mif(now);
        let af = ActionFrame::parse(&f[24..]).unwrap();
        ElectionParamsV2::parse(af.tlvs().find(|t| t.tag == 24).unwrap().value).unwrap().self_counter
    };

    assert_eq!(tenure_at(&b, 0), 0);
    // Tenure now follows the clock, not the frame count: 191 windows is not a tick and
    // 192 is, whatever number of frames went out in between.
    assert_eq!(tenure_at(&b, 191 * u64::from(AW_US)), 0, "the step is on the boundary");
    assert_eq!(tenure_at(&b, 192 * u64::from(AW_US)), 1, "192 windows is one tick");
    b.advance();
    b.advance();
    assert_eq!(b.sent, 2, "and the frame counter is its own thing");

    // tx_counter reaches the frame as written.
    let f = b.mif(0);
    let af = ActionFrame::parse(&f[24..]).unwrap();
    let sync = SyncParams::parse(af.tlvs().find(|t| t.tag == 4).unwrap().value).unwrap();
    assert_eq!(sync.tx_counter, 2);
}

/// We default to losing the election, on purpose.
///
/// The first transmit run defaulted to 530 and won: two iPhones and a MacBook elected our
/// node master, one of them two hops out. The frames were right; the timing was not, and
/// three Apple devices ended up synchronised to a wall-clock timer. Until this crate can
/// anchor to a TSF, the correct claim is that we do not want the job.
#[test]
fn the_default_metric_loses_to_a_real_apple_device() {
    use libawdl::beacon::{METRIC_COMPETE, METRIC_DECLINE};
    use libawdl::election::ElectionParamsV2;

    let b = Beacon::new(ADDR, 149, "QA");
    assert_eq!(b.metric, METRIC_DECLINE);
    assert!(METRIC_DECLINE < 510, "Apple devices were observed at 510-530");

    let apple = [0xea, 0x8e, 0x0d, 0xcc, 0x09, 0x73];
    let ours = ElectionParamsV2::claiming(ADDR, b.metric, 0);
    let theirs = ElectionParamsV2::claiming(apple, 515, 0);
    assert!(theirs.beats(&ours, apple, ADDR), "a real device must win against the default");
    assert!(!ours.beats(&theirs, ADDR, apple));

    // And competing is available, deliberately, for a radio that can hold time.
    let strong = ElectionParamsV2::claiming(ADDR, METRIC_COMPETE, 0);
    assert!(strong.beats(&theirs, ADDR, apple), "530 beat 515 on hardware");
}

/// The timing fields must describe the same instant and count down within a window.
///
/// This is the fix for what the first transmit run actually did wrong. It sent
/// `aw_remaining = 0` in every frame — "my window ends right now", forever — while a
/// joining node reads exactly that field to work out where in the schedule it has arrived.
/// A master does not have to agree with anyone else's clock, but it does have to agree
/// with its own.
#[test]
fn the_window_fields_are_self_consistent() {
    use libawdl::sync::TU_US;
    let b = Beacon::new(ADDR, 149, "QA");

    let remaining_at = |us: u64| -> u16 {
        let f = b.mif(us);
        let af = ActionFrame::parse(&f[24..]).unwrap();
        SyncParams::parse(af.tlvs().find(|t| t.tag == 4).unwrap().value).unwrap().aw_remaining
    };
    let counter_at = |us: u64| -> u16 {
        let f = b.mif(us);
        let af = ActionFrame::parse(&f[24..]).unwrap();
        SyncParams::parse(af.tlvs().find(|t| t.tag == 4).unwrap().value).unwrap().aw_counter
    };

    // At the start of a window the whole window is left; a quarter in, three quarters.
    assert_eq!(remaining_at(0), 16, "a full 16 TU window");
    assert_eq!(remaining_at(u64::from(AW_US) / 4), 12);
    assert_eq!(remaining_at(u64::from(AW_US) / 2), 8);
    // It must MOVE, which is the point: the bug was one value forever. Zero is legal at
    // the very end of a window and real Apple devices emit it too -- a captured MacBook
    // spanned 0..16 -- so the assertion is on the spread, not on avoiding zero.
    let mut seen = std::collections::BTreeSet::new();
    for i in 0..256u64 {
        let us = i * u64::from(TU_US) / 4;
        let r = remaining_at(us);
        assert!(r <= 16, "aw_remaining is a TU count within a 16 TU window, got {r}");
        seen.insert(r);
    }
    assert!(seen.len() >= 16, "it must sweep the window, not sit still: saw {seen:?}");

    // The counter advances exactly one per window, and agrees with the remaining field.
    assert_eq!(counter_at(0), 0);
    assert_eq!(counter_at(u64::from(AW_US) - 1), 0, "still in window 0");
    assert_eq!(counter_at(u64::from(AW_US)), 1, "and over the boundary");
    assert_eq!(counter_at(10 * u64::from(AW_US)), 10);

    // aws_at and aw_remaining_us describe one clock, not two.
    let t = 3 * u64::from(AW_US) + 5000;
    assert_eq!(Beacon::aws_at(t), 3);
    assert_eq!(Beacon::aw_remaining_us(t), AW_US - 5000);
}

/// The experimental control reproduces the original defect exactly.
///
/// It exists so the question "was the broken timing what made Apple devices follow us"
/// can be answered by running both conditions against the SAME peers, rather than by
/// comparing two runs that differed in who was in the room.
#[test]
fn legacy_timing_reproduces_the_original_defect() {
    let mut b = Beacon::new(ADDR, 149, "QA");
    b.legacy_timing = true;

    let remaining_at = |b: &Beacon, us: u64| -> u16 {
        let f = b.mif(us);
        let af = ActionFrame::parse(&f[24..]).unwrap();
        SyncParams::parse(af.tlvs().find(|t| t.tag == 4).unwrap().value).unwrap().aw_remaining
    };

    // The defect: one value, forever, whatever the clock says.
    for i in 0..32u64 {
        assert_eq!(remaining_at(&b, i * 997), 0, "legacy mode pins aw_remaining to 0");
    }
    // And the corrected path still sweeps, so the flag is the only difference.
    let good = Beacon::new(ADDR, 149, "QA");
    let mut seen = std::collections::BTreeSet::new();
    for i in 0..64u64 {
        seen.insert(remaining_at(&good, i * u64::from(AW_US) / 16));
    }
    assert!(seen.len() > 8, "the default must still move: {seen:?}");
    assert!(!good.legacy_timing, "and must never default to the defect");
}

/// We must transmit in the windows we advertise, not on an arbitrary phase.
///
/// Measured on the air, the old beacon occupied 3 of 16 slots and none of them were the
/// slots it announced — it transmitted every sixteen windows, which is exactly one cycle,
/// so the phase was whatever the start time happened to be.
#[test]
fn the_beacon_can_align_to_the_windows_it_advertises() {
    let b = Beacon::new(ADDR, 149, "QA");
    assert_eq!(b.advertised_slots(), vec![2, 8, 10], "no association, so slot 0 is empty");

    // A SLOT, not an availability window: a slot is four of them. Getting this wrong walks
    // the cycle four times too fast, which is what the beacon did before OWL was read.
    let aw = u64::from(SLOT_US);
    assert_eq!(SLOT_US, 4 * AW_US);
    assert_eq!(CYCLE_US, 16 * SLOT_US);
    // Inside an advertised window: transmit now.
    assert_eq!(b.us_until_next_advertised_window(2 * aw), 0);
    assert_eq!(b.us_until_next_advertised_window(2 * aw + 500), 0);
    assert_eq!(b.us_until_next_advertised_window(8 * aw + aw / 2), 0);
    // Outside one: wait for the next.
    assert_eq!(b.us_until_next_advertised_window(0), 2 * aw, "slot 0 empty, next is 2");
    assert_eq!(b.us_until_next_advertised_window(3 * aw), 5 * aw, "3 -> 8");
    assert_eq!(b.us_until_next_advertised_window(9 * aw), aw, "9 -> 10");
    // Past the last one, wrap into the next cycle.
    assert_eq!(b.us_until_next_advertised_window(11 * aw), 7 * aw, "11 -> 18 == 2 of next");
    assert_eq!(b.us_until_next_advertised_window(15 * aw), 3 * aw);

    // With an association, slot 0 is occupied and becomes a transmit window too.
    let mut assoc = Beacon::new(ADDR, 149, "QA");
    assoc.assoc_channel = Some(104);
    assert_eq!(assoc.advertised_slots(), vec![0, 2, 8, 10]);
    assert_eq!(assoc.us_until_next_advertised_window(0), 0, "slot 0 is ours now");
    assert_eq!(assoc.us_until_next_advertised_window(15 * aw), aw, "15 -> 0 of next");

    // Every wait lands us inside an advertised window, from anywhere in the cycle.
    for i in 0..16u64 {
        let now = i * aw + 77;
        let wait = b.us_until_next_advertised_window(now);
        let landed = ((now + wait) % (16 * aw) / aw) as usize;
        assert!(b.advertised_slots().contains(&landed), "from slot {i} we land in {landed}");
    }
}

/// The breadth control advertises exactly what it transmits in.
///
/// That is the difference from trial E, which won an election by accident: it fired in the
/// window after each advertised one, so half its frames were somewhere it never claimed to
/// be. Testing whether breadth is what matters requires breadth that is honest.
#[test]
fn the_breadth_control_is_honest_about_where_it_transmits() {
    for n in [3usize, 6, 9, 12] {
        let mut b = Beacon::new(ADDR, 149, "QA");
        b.windows = Some(n);
        let slots = b.advertised_slots();
        assert!(slots.len() >= n.min(16) - 1, "asked for {n}, advertised {slots:?}");
        assert!(slots.contains(&8), "slot 8 stays channel 6 at every breadth");

        // Every wait lands inside a window we advertise -- transmit set == advertised set.
        for i in 0..16u64 {
            let now = i * u64::from(SLOT_US) + 123;
            let wait = b.us_until_next_advertised_window(now);
            let landed = ((now + wait) % u64::from(CYCLE_US) / u64::from(SLOT_US)) as usize;
            assert!(slots.contains(&landed), "n={n}: from {i} we land in {landed}, not in {slots:?}");
        }

        // And the frame really carries the wider schedule, not just the transmit loop.
        let f = b.mif(0);
        let af = ActionFrame::parse(&f[24..]).unwrap();
        let seq = SyncParams::parse(af.tlvs().find(|t| t.tag == 4).unwrap().value)
            .unwrap().channel_sequence.unwrap();
        assert_eq!(seq.occupied_slots(), slots.len(), "n={n}: announced breadth must match");
        assert_eq!(seq.channels[8], 6);
    }

    // Default is unchanged: Apple's shape.
    assert_eq!(Beacon::new(ADDR, 149, "QA").advertised_slots(), vec![2, 8, 10]);
}

/// We must pace PSFs by the interval we advertise.
///
/// `action_frame_period` is the PSF interval: OWL sets the field from its own
/// `psf_interval` and paces by it, and every Apple frame carries 110 TU. Emitting the
/// number while sending at some other rate misdescribes us to every receiver.
#[test]
fn the_advertised_psf_interval_is_the_one_we_would_pace_by() {
    use libawdl::beacon::PSF_INTERVAL_TU;
    let b = Beacon::new(ADDR, 149, "QA");
    let f = b.mif(0);
    let af = ActionFrame::parse(&f[24..]).unwrap();
    let sync = SyncParams::parse(af.tlvs().find(|t| t.tag == 4).unwrap().value).unwrap();

    assert_eq!(sync.action_frame_period, PSF_INTERVAL_TU, "we advertise 110 TU");
    assert_eq!(b.psf_interval_us(), u64::from(PSF_INTERVAL_TU) * 1024);
    // Sanity: the interval is shorter than a slot, so a PSF is not a per-slot event.
    assert!(b.psf_interval_us() > u64::from(AW_US), "longer than one availability window");
    assert!(b.psf_interval_us() < u64::from(CYCLE_US), "and shorter than a full cycle");
}

/// Cycle prevention, which OWL has and this crate did not.
#[test]
fn adopting_a_peer_that_already_follows_us_would_cycle() {
    use libawdl::election::ElectionParamsV2;
    let me = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    let them = [0xaa; 6];
    assert!(ElectionParamsV2::would_cycle(me, me), "a peer whose parent is us");
    assert!(!ElectionParamsV2::would_cycle(them, me));
    assert_eq!(ElectionParamsV2::MAX_TREE_HEIGHT, 10);
}

/// The counter and the metric can be made to disagree, which is the whole point.
///
/// OWL orders the election counter-first; this crate orders it metric-first; and no capture
/// held distinguishes them, because they all begin with the devices already synchronised.
/// A probe that advertises the highest metric with the lowest counter makes the two rules
/// predict opposite outcomes, so a peer joining from cold answers by which way it goes.
#[test]
fn a_probe_can_make_counter_and_metric_disagree() {
    use libawdl::beacon::{METRIC_COMPETE, METRIC_DECLINE};
    use libawdl::election::ElectionParamsV2;

    let mut high_metric_low_counter = Beacon::new(ADDR, 149, "QA");
    high_metric_low_counter.metric = 600;
    high_metric_low_counter.tenure_base = 0;

    let mut low_metric_high_counter = Beacon::new(ADDR, 149, "QA");
    low_metric_high_counter.metric = 50;
    low_metric_high_counter.tenure_base = 99_999;

    let read = |b: &Beacon| -> (u32, u32) {
        let f = b.mif(0);
        let af = ActionFrame::parse(&f[24..]).unwrap();
        let e = ElectionParamsV2::parse(af.tlvs().find(|t| t.tag == 24).unwrap().value).unwrap();
        (e.self_metric, e.self_counter)
    };

    let (m_a, c_a) = read(&high_metric_low_counter);
    let (m_b, c_b) = read(&low_metric_high_counter);
    assert!(m_a > m_b && c_a < c_b, "the two probes must rank oppositely on the two fields");
    assert!(m_a > 539, "probe A must out-metric the highest Apple value observed");
    assert!(m_b < METRIC_DECLINE, "probe B must lose on metric to everything");
    assert!(c_b > 68_364, "probe B must out-count the highest Apple value observed");
    assert_eq!(METRIC_COMPETE, 530);
}

/// The garbage really reaches the wire — finding 60's precondition.
///
/// An encoder that quietly dropped the change would make the experiment look like a
/// success: the peers would adopt us because we sent them exactly what we always send.
/// So this asserts on the ENCODED TLV bytes, at the offsets the perturbed fields occupy,
/// not on the struct fields that were set.
#[test]
fn garbage_reaches_the_encoded_tlvs() {
    use libawdl::beacon::{Garbage, GARBAGE_BYTE};

    let addr = [0x00, 0xc0, 0xca, 0xb0, 0x60, 0x4c];
    let find = |tlvs: &[(u8, Vec<u8>)], tag: u8| -> Vec<u8> {
        tlvs.iter().find(|(t, _)| *t == tag).expect("tag present").1.clone()
    };

    let mut clean = Beacon::new(addr, 149, "QA");
    clean.metric = 600;
    let c = clean.mif_tlvs(0);

    let mut dirty = Beacon::new(addr, 149, "QA");
    dirty.metric = 600;
    dirty.garbage = Garbage::parse("all").expect("all parses");
    let d = dirty.mif_tlvs(0);

    // Tag 24: unknown_28 occupies bytes 28..36, and self_counter 36..40 must be untouched.
    let (c24, d24) = (find(&c, 24), find(&d, 24));
    assert_eq!(&c24[28..36], &[0u8; 8], "the control really is zeros there");
    assert_eq!(&d24[28..36], &[GARBAGE_BYTE; 8], "and the treatment really is not");
    assert_eq!(c24[..28], d24[..28], "nothing before it moved");
    assert_eq!(c24[36..], d24[36..], "and self_counter is intact");

    // Tag 5: reserved_4 is byte 4, the tail is 19..21.
    let (c5, d5) = (find(&c, 5), find(&d, 5));
    assert_eq!(c5[4], 0);
    assert_eq!(d5[4], GARBAGE_BYTE);
    assert_eq!(&d5[19..21], &[GARBAGE_BYTE; 2]);
    assert_eq!(c5[5..19], d5[5..19], "master, metrics untouched");

    // Tag 16: the flags byte, and the host name must survive it.
    let (c16, d16) = (find(&c, 16), find(&d, 16));
    assert_eq!(c16[0], 3);
    assert_eq!(d16[0], GARBAGE_BYTE);
    assert_eq!(c16[1..], d16[1..], "the DNS-encoded name is unchanged");

    // Tag 4: reserved_28 is byte 28. The named fields around it must not shift.
    let (c4, d4) = (find(&c, 4), find(&d, 4));
    assert_eq!(c4[28], 0);
    assert_eq!(d4[28], GARBAGE_BYTE);
    assert_eq!(c4.len(), d4.len(), "the TLV must not change length");
    assert_eq!(c4[..28], d4[..28]);
    assert_eq!(c4[29..33], d4[29..33], "aw_counter and ap_beacon_delta intact");
    // THE TRAILING PAIR. Asserting only on byte 28 let a half-working --garbage t4 ship:
    // describe() promised "reserved_28 + trailing pair (3B)" and only one byte was ever
    // perturbed, which a whole hardware trial then failed to test. A test that checks the
    // fields it happens to remember is a test that certifies whatever was implemented.
    assert_eq!(&c4[c4.len() - 2..], &[0, 0], "the control really ends in zeros");
    assert_eq!(&d4[d4.len() - 2..], &[GARBAGE_BYTE; 2], "and the treatment really does not");

    // Tag 7: the two leading bytes, and the 802.11 fields after them must not move.
    let (c7, d7) = (find(&c, 7), find(&d, 7));
    assert_eq!(&c7[..2], &[0, 0], "the control really is 00 00 there");
    assert_eq!(&d7[..2], &[GARBAGE_BYTE; 2]);
    assert_eq!(c7[2..], d7[2..], "info, A-MPDU and the MCS set are untouched");

    // And selecting one group must not perturb the others.
    let mut only24 = Beacon::new(addr, 149, "QA");
    only24.metric = 600;
    only24.garbage = Garbage::parse("t24").unwrap();
    let o = only24.mif_tlvs(0);
    assert_eq!(&find(&o, 24)[28..36], &[GARBAGE_BYTE; 8]);
    assert_eq!(find(&o, 5), find(&c, 5), "tag 5 untouched by --garbage t24");
    assert_eq!(find(&o, 16), find(&c, 16), "tag 16 untouched");
    assert_eq!(find(&o, 4), find(&c, 4), "tag 4 untouched");
    assert_eq!(find(&o, 7), find(&c, 7), "tag 7 untouched");
}

#[test]
fn an_unknown_garbage_group_is_refused() {
    use libawdl::beacon::Garbage;
    assert!(Garbage::parse("t24").is_some());
    assert!(Garbage::parse("t4,t24").is_some());
    assert_eq!(
        Garbage::parse("all"),
        Some(Garbage {
            t4: true, t5: true, t16: true, t24: true, t7: true,
            no_t24: false, t24_probe: None
        })
    );
    assert!(Garbage::parse("t99").is_none(), "a typo must not run a weaker experiment");
    assert!(Garbage::parse("t24,nonsense").is_none());
    assert!(!Garbage::parse("").unwrap().any());
}

/// The single-byte probe: one byte of tag 24's block, everything else left zero.
///
/// Finding 63 showed all eight bytes as 0xa5 kills adoption. This exists to tell a strict
/// zero check from a field we have mislabelled, and it is only meaningful if exactly one
/// byte moves — so that is what is asserted, byte by byte, on the encoded TLV.
#[test]
fn the_t24_probe_disturbs_exactly_one_byte() {
    use libawdl::beacon::Garbage;

    let addr = [0x00, 0xc0, 0xca, 0xb0, 0x60, 0x4c];
    let find = |tlvs: &[(u8, Vec<u8>)], tag: u8| -> Vec<u8> {
        tlvs.iter().find(|(t, _)| *t == tag).expect("tag present").1.clone()
    };

    let mut clean = Beacon::new(addr, 149, "QA");
    clean.metric = 600;
    let c = find(&clean.mif_tlvs(0), 24);
    assert_eq!(&c[28..36], &[0u8; 8]);

    for off in 0..8usize {
        let mut b = Beacon::new(addr, 149, "QA");
        b.metric = 600;
        b.garbage = Garbage::parse(&format!("t24@{off}=01")).expect("probe parses");
        let d = find(&b.mif_tlvs(0), 24);

        assert_eq!(d.len(), c.len(), "length must not change");
        assert_eq!(c[..28], d[..28], "nothing before the block moved");
        assert_eq!(c[36..], d[36..], "self_counter intact");
        for i in 0..8 {
            let want = if i == off { 0x01 } else { 0x00 };
            assert_eq!(d[28 + i], want, "block byte {i} with probe at {off}");
        }
    }
}

#[test]
fn a_malformed_probe_is_refused() {
    use libawdl::beacon::Garbage;
    assert!(Garbage::parse("t24@0=01").is_some());
    assert!(Garbage::parse("t24@7=ff").is_some());
    assert!(Garbage::parse("t24@8=01").is_none(), "offset past the eight-byte block");
    assert!(Garbage::parse("t24@x=01").is_none());
    assert!(Garbage::parse("t24@0").is_none());
    // The probe must win over the whole-block flag, or a run would measure neither.
    let g = Garbage::parse("t24,t24@2=01").expect("parses");
    assert!(g.t24_probe.is_some());
}


/// Omitting tag 24 must remove it and change nothing else — finding 67.
///
/// The run this supports asks whether a MALFORMED tag 24 is worse than an ABSENT one. That
/// is only a fair question if absence is all that differs, so the other tags are asserted
/// byte-identical rather than merely present.
#[test]
fn no_t24_omits_exactly_that_tag() {
    use libawdl::beacon::Garbage;

    let addr = [0x00, 0xc0, 0xca, 0xb0, 0x60, 0x4c];
    let mut clean = Beacon::new(addr, 149, "QA");
    clean.metric = 600;
    let c = clean.mif_tlvs(0);

    let mut without = Beacon::new(addr, 149, "QA");
    without.metric = 600;
    without.garbage = Garbage::parse("no-t24").expect("parses");
    let w = without.mif_tlvs(0);

    assert!(c.iter().any(|(t, _)| *t == 24), "the control carries tag 24");
    assert!(!w.iter().any(|(t, _)| *t == 24), "and the treatment does not");
    assert_eq!(c.len(), w.len() + 1, "exactly one TLV fewer");

    // Tag 5 still claims the same metric -- the whole point is that v1 is still there.
    let t5 = |v: &[(u8, Vec<u8>)]| v.iter().find(|(t, _)| *t == 5).unwrap().1.clone();
    assert_eq!(t5(&c), t5(&w), "Election Parameters v1 is untouched");

    for tag in [4u8, 5, 7, 12, 16, 17, 18, 21, 2] {
        let a = c.iter().find(|(t, _)| *t == tag).map(|(_, v)| v.clone());
        let b = w.iter().find(|(t, _)| *t == tag).map(|(_, v)| v.clone());
        assert_eq!(a, b, "tag {tag} must be byte-identical");
    }
}
