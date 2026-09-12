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
