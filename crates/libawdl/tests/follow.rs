//! Recovering a cluster's clock from what its frames say about themselves.

use libawdl::follow::{Cluster, ClusterClock, Sighting, AW_US, CYCLE_US};

/// One frame is enough to place a window boundary, which is the whole idea.
#[test]
fn a_single_frame_places_the_window_boundary() {
    // "6 TU left in window 4" arriving at t=1_000_000.
    let s = Sighting { arrived_us: 1_000_000, counter: 4, remaining_tu: 6 };
    assert_eq!(s.slot(), 4);
    assert_eq!(s.window_end_us(), 1_000_000 + 6 * 1024);
    // Slot 4 ends there, so the cycle began five windows earlier.
    assert_eq!(s.cycle_origin_us(), 1_000_000 + 6 * 1024 - 5 * AW_US);
}

/// Consistent sightings converge, and the estimate knows it is tight.
#[test]
fn consistent_sightings_converge_to_one_phase() {
    let mut c = ClusterClock::new();
    let phase = 7_000u64;
    // Ten frames from different slots of different cycles, all consistent with `phase`.
    for k in 0..10u64 {
        let slot = k % 16;
        let cycle = k / 16;
        let window_end = phase + cycle * CYCLE_US + (slot + 1) * AW_US;
        let remaining_tu = 3 + (k % 5);
        c.observe(Sighting {
            arrived_us: window_end - remaining_tu * 1024,
            counter: (cycle * 16 + slot) as u16,
            remaining_tu: remaining_tu as u16,
        });
    }
    assert_eq!(c.observations(), 10);
    assert_eq!(c.phase_us(), Some(phase));
    assert_eq!(c.spread_us(), Some(0));
    assert!(c.is_usable());
}

/// **The wrap-around case, where an arithmetic mean is maximally wrong.**
///
/// A cluster whose phase sits near zero produces observations at both ends of the ring —
/// a few microseconds, and a few microseconds short of a whole cycle. Averaging those
/// lands half a cycle away: the most wrong answer available, and a plausible-looking one.
#[test]
fn a_phase_near_zero_does_not_average_to_the_far_side() {
    let mut c = ClusterClock::new();
    // Observations scattered by +-2000us around a true phase of 0.
    for (i, off) in [0u64, 1500, CYCLE_US - 1200, 800, CYCLE_US - 400].iter().enumerate() {
        // Construct a sighting whose cycle_origin lands on `off`.
        let slot = 0usize;
        let window_end = off + (slot as u64 + 1) * AW_US;
        c.observe(Sighting {
            arrived_us: window_end - 4 * 1024,
            counter: (i as u16) * 16,
            remaining_tu: 4,
        });
    }
    let phase = c.phase_us().expect("a phase");
    // Must be near zero, i.e. within a few ms of either end of the ring.
    let dist_to_zero = phase.min(CYCLE_US - phase);
    assert!(dist_to_zero < 5_000, "phase {phase} is not near zero — the ring was averaged");
    // A naive arithmetic mean would have produced roughly half a cycle.
    assert!(dist_to_zero < CYCLE_US / 4);
}

/// A noisy estimate must refuse to be acted on rather than quietly mislead.
#[test]
fn a_smeared_estimate_reports_itself_unusable() {
    let mut c = ClusterClock::new();
    // Sightings scattered across most of the cycle: no real phase at all.
    for k in 0..8u64 {
        c.observe(Sighting { arrived_us: k * 31_000, counter: 0, remaining_tu: 4 });
    }
    assert!(!c.is_usable(), "a spread near a whole cycle is not a phase");
    assert!(c.spread_us().unwrap() > AW_US / 4);

    // And too few observations is also unusable, however tight.
    let mut thin = ClusterClock::new();
    thin.observe(Sighting { arrived_us: 1000, counter: 0, remaining_tu: 4 });
    assert!(!thin.is_usable());
}

/// Aiming at a slot lands in that slot.
#[test]
fn waiting_for_a_slot_lands_in_it() {
    let mut c = ClusterClock::new();
    let phase = 12_345u64;
    for k in 0..8u64 {
        let window_end = phase + k * CYCLE_US + AW_US;
        c.observe(Sighting {
            arrived_us: window_end - 5 * 1024,
            counter: (k * 16) as u16,
            remaining_tu: 5,
        });
    }
    assert!(c.is_usable());
    for slot in [0usize, 3, 8, 15] {
        for probe in [0u64, 50_000, 131_000, 260_000] {
            let now = phase + probe;
            let wait = c.us_until_slot(now, slot).unwrap();
            assert_eq!(c.slot_at(now + wait), Some(slot), "slot {slot} from probe {probe}");
            // The centre is in the same slot, and is half a window further in.
            let mid = c.us_until_slot_centre(now, slot).unwrap();
            assert_eq!(c.slot_at(now + mid), Some(slot), "centre of {slot} from {probe}");
        }
    }

    // Aiming at the centre survives an error that would break aiming at the boundary.
    let slop = AW_US / 3;
    let now = phase;
    let mid = c.us_until_slot_centre(now, 8).unwrap();
    assert_eq!(c.slot_at(now + mid + slop), Some(8), "a third-window late still lands in 8");
    assert_eq!(c.slot_at(now + mid - slop), Some(8), "and a third early");
}

/// The cluster follows the network's own opinion of who is master, and anchors only on
/// that node's frames.
#[test]
fn only_the_master_anchors_the_clock() {
    use libawdl::election::ElectionParamsV2;
    use libawdl::sync::{ChannelSequence, SyncParams};

    let master = [0xaa; 6];
    let follower = [0xbb; 6];
    let mut cl = Cluster::new();

    let sync_of = |counter: u16, remaining: u16| SyncParams {
        tx_channel: 149, tx_counter: 0, master_channel: 149, guard_time: 0,
        aw_period: 16, action_frame_period: 110, flags: 0x1800,
        aw_ext_length: 16, aw_common_length: 16, aw_remaining: remaining,
        ext_min: 3, ext_max_multicast: 3, ext_max_unicast: 3, ext_max_af: 3,
        master, presence_mode: 4, reserved_28: 0, aw_counter: counter,
        ap_beacon_alignment_delta: 0,
        channel_sequence: Some(ChannelSequence::apple_shaped(149, None)),
        trailing: [0, 0],
    };

    // A follower's frame names the master but must not anchor the clock.
    let e_follower = ElectionParamsV2 { distance: 1, ..ElectionParamsV2::claiming(master, 530, 3) };
    cl.observe(1_000_000, follower, &sync_of(9, 4), Some(&e_follower));
    assert_eq!(cl.master, Some(master));
    assert_eq!(cl.clock.observations(), 0, "a follower must not anchor the clock");

    // The master's own frames do.
    let e_master = ElectionParamsV2::claiming(master, 530, 3);
    for k in 0..6u64 {
        cl.observe(2_000_000 + k * CYCLE_US, master, &sync_of((k * 16) as u16, 5), Some(&e_master));
    }
    assert_eq!(cl.clock.observations(), 6);
    assert_eq!(cl.master_metric, Some(530), "what we would have to beat");
    assert_eq!(cl.master_slots, vec![2, 8, 10]);
    assert!(cl.clock.is_usable());

    // And we can aim at a window the master is demonstrably awake in.
    let wait = cl.us_until_master_window(3_000_000).expect("a target");
    assert!(cl.master_slots.contains(&cl.clock.slot_at(3_000_000 + wait).unwrap()));
}

/// With no usable clock there is no target — it refuses rather than guessing.
#[test]
fn no_clock_means_no_target() {
    let cl = Cluster::new();
    assert_eq!(cl.us_until_master_window(1_000), None);
}
