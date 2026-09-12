//! Recovering a cluster's clock from what its frames say about themselves.

use libawdl::follow::{cycle_us, eaw_us, Cluster, ClusterClock, Sighting, DEFAULT_PRESENCE_MODE};

const PM: u8 = DEFAULT_PRESENCE_MODE;
/// One channel-sequence slot: four availability windows, 64 TU.
const SLOT_US: u64 = 4 * 16 * 1024;
const CYCLE: u64 = 16 * SLOT_US;

/// One frame is enough to place a window boundary, which is the whole idea.
#[test]
fn a_single_frame_places_the_window_boundary() {
    // "6 TU left in window 4" arriving at t=1_000_000.
    // aw_counter 4 is the first window of slot 1, with 6 TU left in that window.
    let s = Sighting { arrived_us: 1_000_000, counter: 4, remaining_tu: 6, presence_mode: PM };
    assert_eq!(s.slot(), 1);
    assert_eq!(s.window_end_us(), 1_000_000 + 6 * 1024);
    // We are (16 - 6) TU into the slot's first window, and the slot is slot 1.
    assert_eq!(s.into_slot_us(), 10 * 1024);
    assert_eq!(s.cycle_origin_us(), 1_000_000 - 10 * 1024 - SLOT_US);
}

/// Consistent sightings converge, and the estimate knows it is tight.
#[test]
fn consistent_sightings_converge_to_one_phase() {
    let mut c = ClusterClock::new();
    let phase = 7_000u64;
    // Ten frames from different slots, all consistent with `phase`. Counter k*4 is the
    // first window of slot k, and we place each frame at the very start of its slot.
    for k in 0..10u64 {
        c.observe(Sighting {
            arrived_us: phase + k * SLOT_US,
            counter: (k * 4) as u16,
            remaining_tu: 16,
            presence_mode: PM,
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
    for off in [0u64, 1500, CYCLE - 1200, 800, CYCLE - 400] {
        // A frame at the very start of slot 0 of a cycle beginning at `off`.
        c.observe(Sighting { arrived_us: off, counter: 0, remaining_tu: 16, presence_mode: PM });
    }
    let phase = c.phase_us().expect("a phase");
    // Must be near zero, i.e. within a few ms of either end of the ring.
    let dist_to_zero = phase.min(CYCLE - phase);
    assert!(dist_to_zero < 5_000, "phase {phase} is not near zero — the ring was averaged");
    // A naive arithmetic mean would have produced roughly half a cycle.
    assert!(dist_to_zero < CYCLE / 4);
}

/// A noisy estimate must refuse to be acted on rather than quietly mislead.
#[test]
fn a_smeared_estimate_reports_itself_unusable() {
    let mut c = ClusterClock::new();
    // Sightings scattered across most of the cycle: no real phase at all.
    for k in 0..8u64 {
        c.observe(Sighting { arrived_us: k * 124_000, counter: 0, remaining_tu: 4, presence_mode: PM });
    }
    assert!(!c.is_usable(), "a spread near a whole cycle is not a phase");
    assert!(c.spread_us().unwrap() > SLOT_US / 2);

    // And too few observations is also unusable, however tight.
    let mut thin = ClusterClock::new();
    thin.observe(Sighting { arrived_us: 1000, counter: 0, remaining_tu: 4, presence_mode: PM });
    assert!(!thin.is_usable());
}

/// Aiming at a slot lands in that slot.
#[test]
fn waiting_for_a_slot_lands_in_it() {
    let mut c = ClusterClock::new();
    let phase = 12_345u64;
    for k in 0..8u64 {
        c.observe(Sighting {
            arrived_us: phase + k * CYCLE,
            counter: 0,
            remaining_tu: 16,
            presence_mode: PM,
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
    let slop = SLOT_US / 3;
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
        cl.observe(2_000_000 + k * CYCLE, master, &sync_of(0, 16), Some(&e_master));
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

/// A slot is an EXTENDED availability window, and the frame says which one.
///
/// Settled from field values, not timing: `(aw_counter / presence_mode) % 16` puts every
/// captured Apple device's frames inside its own advertised slots, 100% against a 25%
/// chance level over 1397 frames. `aw_counter % 16` scores 34-43%.
#[test]
fn a_slot_is_four_availability_windows() {
    assert_eq!(eaw_us(PM), SLOT_US);
    assert_eq!(cycle_us(PM), CYCLE);
    assert_eq!(cycle_us(PM), 1024 * 1024, "1024 TU, about 1.05 seconds");

    // aw_counter 0..3 are all slot 0; 4..7 are slot 1.
    for c in 0..4u16 {
        assert_eq!(Sighting { arrived_us: 0, counter: c, remaining_tu: 16, presence_mode: PM }.slot(), 0);
    }
    for c in 4..8u16 {
        assert_eq!(Sighting { arrived_us: 0, counter: c, remaining_tu: 16, presence_mode: PM }.slot(), 1);
    }
    // And slot 8 -- channel 6 in Apple's schedule -- is counters 32..35.
    assert_eq!(Sighting { arrived_us: 0, counter: 32, remaining_tu: 16, presence_mode: PM }.slot(), 8);
    assert_eq!(Sighting { arrived_us: 0, counter: 35, remaining_tu: 16, presence_mode: PM }.slot(), 8);
    assert_eq!(Sighting { arrived_us: 0, counter: 36, remaining_tu: 16, presence_mode: PM }.slot(), 9);
}

/// Position within a slot needs the window index as well as aw_remaining.
#[test]
fn position_in_a_slot_spans_all_four_windows() {
    let aw = 16 * 1024u64;
    // Start of the slot's first window: a full 16 TU remaining, zero windows in.
    let a = Sighting { arrived_us: 0, counter: 8, remaining_tu: 16, presence_mode: PM };
    assert_eq!(a.slot(), 2);
    assert_eq!(a.into_slot_us(), 0);
    // Third window of the same slot, half way through it.
    let b = Sighting { arrived_us: 0, counter: 10, remaining_tu: 8, presence_mode: PM };
    assert_eq!(b.slot(), 2, "still slot 2");
    assert_eq!(b.into_slot_us(), 2 * aw + aw / 2);
    // Last window, nearly over: close to a full slot in.
    let c = Sighting { arrived_us: 0, counter: 11, remaining_tu: 1, presence_mode: PM };
    assert_eq!(c.into_slot_us(), 3 * aw + aw - 1024);
}

/// Drift must not accumulate into the phase.
///
/// A median over a long history is robust to jitter and blind to drift. On hardware that
/// showed up as an estimate starting at 0 µs of spread and degrading to 156 ms over
/// seventy seconds — wider than a whole 65 ms slot, and confidently wrong. OWL re-anchors
/// on every frame from the master and averages nothing; so do we.
#[test]
fn the_phase_follows_a_drifting_cluster() {
    let mut c = ClusterClock::new();
    // A cluster whose phase creeps by 2 ms per observation: two clocks running apart.
    let drift = 2_000u64;
    for k in 0..40u64 {
        c.observe(Sighting {
            arrived_us: k * CYCLE + k * drift,
            counter: 0,
            remaining_tu: 16,
            presence_mode: PM,
        });
    }
    let phase = c.phase_us().expect("a phase");
    let latest = (39 * drift) % CYCLE;
    assert_eq!(phase, latest, "the newest anchor decides, not the history");

    // The median of the whole run lags far behind, which is exactly the failure.
    let median = c.median_phase_us().unwrap();
    assert!(median < latest, "a median over a drifting series trails it");
    assert!(latest - median > 10 * drift, "and by a lot: {median} vs {latest}");

    // Health is judged on RECENT anchors, so steady drift stays usable rather than
    // reporting the whole run's divergence as noise.
    assert!(c.spread_us().unwrap() < SLOT_US, "recent anchors are close together");
    assert!(c.is_usable(), "a tracked drift is still a usable estimate");
}

/// A genuinely erratic cluster is still refused.
#[test]
fn jitter_wider_than_a_slot_is_still_rejected() {
    let mut c = ClusterClock::new();
    for k in 0..12u64 {
        // Alternating far apart: not drift, noise.
        let jump = if k % 2 == 0 { 0 } else { SLOT_US * 3 };
        c.observe(Sighting { arrived_us: jump, counter: 0, remaining_tu: 16, presence_mode: PM });
    }
    assert!(!c.is_usable(), "spread {:?} should be rejected", c.spread_us());
}
