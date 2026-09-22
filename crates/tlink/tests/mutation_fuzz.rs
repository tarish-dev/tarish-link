//! Mutation fuzzing for every parser that sees bytes from the air.
//!
//! Stable-toolchain, no dependencies: seeds come from `captures/*.pcap`, each input is
//! mutated (bit flips, byte overwrites, length-field inflation, truncation, splicing)
//! and pushed through the same path a received frame takes, then through every typed
//! TLV decoder and into the cluster clock. Any panic is a remote crash of whatever
//! process hosts tlink -- in production, tarishd.
//!
//! Run:   FUZZ_ITERS=2000000 cargo test -p tlink --test mutation_fuzz -- --nocapture
//! Debug builds (the default for `cargo test`) keep overflow checks on, so arithmetic
//! overflow on attacker-controlled values shows up as a panic too.

use std::collections::BTreeMap;
use std::panic;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
static REACHED_ACTION: AtomicUsize = AtomicUsize::new(0);
static REACHED_SYNC: AtomicUsize = AtomicUsize::new(0);
static REACHED_ELECT: AtomicUsize = AtomicUsize::new(0);

use tlink::action::ActionFrame;
use tlink::dot11::{Dot11, FrameControl};
use tlink::election::{ElectionParams, ElectionParamsV2};
use tlink::follow::Cluster;
use tlink::radiotap::Radiotap;
use tlink::state::{Arpa, DataPathState, ServiceParams, Version};
use tlink::sync::{ChannelSequence, SyncParams};

fn read_pcap(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if bytes.len() < 24 {
        return out;
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let le = match magic {
        0xa1b2c3d4 | 0xa1b23c4d => true,
        0xd4c3b2a1 | 0x4d3cb2a1 => false,
        _ => return out,
    };
    let rd = |b: &[u8]| {
        let a: [u8; 4] = b.try_into().unwrap();
        if le { u32::from_le_bytes(a) } else { u32::from_be_bytes(a) }
    };
    let linktype = rd(&bytes[20..24]);
    if linktype != 127 {
        return out; // radiotap only
    }
    let mut off = 24;
    while off + 16 <= bytes.len() {
        let incl = rd(&bytes[off + 8..off + 12]) as usize;
        off += 16;
        if off + incl > bytes.len() {
            break;
        }
        out.push(bytes[off..off + incl].to_vec());
        off += incl;
    }
    out
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }
}

const INTERESTING: [u8; 8] = [0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff, 0x10, 0x04];

fn mutate(rng: &mut Rng, seed: &[u8], other: &[u8]) -> Vec<u8> {
    let mut v = seed.to_vec();
    let rounds = 1 + rng.below(6);
    for _ in 0..rounds {
        if v.is_empty() {
            v.push(rng.next() as u8);
            continue;
        }
        match rng.below(8) {
            0 => {
                let i = rng.below(v.len());
                v[i] ^= 1 << rng.below(8);
            }
            1 => {
                let i = rng.below(v.len());
                v[i] = INTERESTING[rng.below(INTERESTING.len())];
            }
            2 => {
                // inflate/deflate a little-endian u16 -- TLV and radiotap lengths
                if v.len() >= 2 {
                    let i = rng.below(v.len() - 1);
                    let val: u16 = match rng.below(4) {
                        0 => 0,
                        1 => 0xffff,
                        2 => u16::from_le_bytes([v[i], v[i + 1]]).wrapping_add(1 + rng.below(64) as u16),
                        _ => u16::from_le_bytes([v[i], v[i + 1]]).wrapping_sub(1 + rng.below(64) as u16),
                    };
                    v[i..i + 2].copy_from_slice(&val.to_le_bytes());
                }
            }
            3 => v.truncate(rng.below(v.len() + 1)),
            4 => {
                let i = rng.below(v.len() + 1);
                let n = 1 + rng.below(16);
                for _ in 0..n {
                    v.insert(i.min(v.len()), rng.next() as u8);
                }
            }
            5 => {
                if !other.is_empty() {
                    let cut = rng.below(v.len() + 1);
                    let from = rng.below(other.len());
                    v.truncate(cut);
                    v.extend_from_slice(&other[from..]);
                }
            }
            6 => {
                let a = rng.below(v.len());
                let b = a + rng.below(v.len() - a);
                v.drain(a..b);
            }
            _ => {
                let i = rng.below(v.len());
                v[i] = rng.next() as u8;
            }
        }
    }
    v
}

/// The receive path, as far as it can be driven without a radio.
fn exercise(pkt: &[u8], cluster: &mut Cluster, t: u64) {
    let _ = tlink::data::decapsulate(pkt);
    let Some(rt) = Radiotap::parse(pkt) else {
        // Also try the bytes as a bare 802.11 frame and as a bare action body.
        drive_80211(pkt, cluster, t);
        drive_body(pkt, cluster, t, [0; 6]);
        return;
    };
    let _ = (rt.bad_fcs(), rt.fcs_known_good(), rt.includes_fcs());
    if let Some(f) = rt.payload(pkt) {
        drive_80211(f, cluster, t);
    }
}

fn drive_80211(f: &[u8], cluster: &mut Cluster, t: u64) {
    let _ = FrameControl::parse(f).map(|fc| (fc.is_action(), fc.type_name()));
    let _ = tlink::data::decapsulate(f);
    let _ = tlink::data::DataHeader::parse(f);
    let _ = tlink::blockack::parse_addba_response(f, [2, 0, 0, 0, 0, 1]);
    let _ = tlink::blockack::parse_block_ack(f, [2, 0, 0, 0, 0, 1]);
    if let Some(d) = Dot11::parse(f) {
        if let Some(body) = d.body(f) {
            drive_body(body, cluster, t, d.src.0);
        }
    }
}

fn drive_body(body: &[u8], cluster: &mut Cluster, t: u64, src: [u8; 6]) {
    let Some(af) = ActionFrame::parse(body) else { return };
    REACHED_ACTION.fetch_add(1, Relaxed);
    let mut sync = None;
    let mut elect = None;
    let mut it = af.tlvs();
    for tlv in it.by_ref() {
        let v = tlv.value;
        let _ = tlink::coverage::of_tlv(tlv.tag, v);
        match tlv.tag {
            2 => {
                let _ = tlink::service::records(v);
                let _ = tlink::service::decode_name(v, v.len());
            }
            4 => sync = SyncParams::parse(v),
            5 => {
                let _ = ElectionParams::parse(v);
            }
            6 => {
                let _ = ServiceParams::parse(v);
            }
            12 => {
                let _ = DataPathState::parse(v);
            }
            16 => {
                let _ = Arpa::parse(v);
            }
            18 => {
                let _ = ChannelSequence::parse(v);
            }
            21 => {
                let _ = Version::parse(v);
            }
            24 => elect = ElectionParamsV2::parse(v),
            _ => {}
        }
    }
    let _ = it.stop();
    if elect.is_some() { REACHED_ELECT.fetch_add(1, Relaxed); }
    if let Some(s) = sync {
        REACHED_SYNC.fetch_add(1, Relaxed);
        let _ = s.aw_period_us();
        let _ = s.is_self_master();
        cluster.observe_at(t, src, &s, elect.as_ref(), af.fixed.phy_tx_time);
        let _ = cluster.us_until_master_window(t);
        let _ = cluster.next_master_window(t);
        let _ = cluster.clock.phase_us();
        let _ = cluster.clock.slot_at(t);
        let _ = cluster.clock.us_until_slot_centre(t, 3);
    }
}

#[test]
fn awdl_parsers_survive_mutated_real_frames() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../captures");
    let mut seeds = Vec::new();
    for e in std::fs::read_dir(dir).expect("captures/") {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "pcap") {
            seeds.extend(read_pcap(&std::fs::read(&p).unwrap()));
        }
    }
    assert!(!seeds.is_empty(), "no radiotap seeds found");
    seeds.sort();
    seeds.dedup();

    let iters: usize = std::env::var("FUZZ_ITERS").ok().and_then(|s| s.parse().ok()).unwrap_or(300_000);
    let mut rng = Rng(std::env::var("FUZZ_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(0x9e37_79b9_7f4a_7c15));

    // Quiet the default hook; record location + message instead.
    let hits: std::sync::Arc<std::sync::Mutex<BTreeMap<String, usize>>> = Default::default();
    let h2 = hits.clone();
    panic::set_hook(Box::new(move |info| {
        let loc = info.location().map(|l| format!("{}:{}", l.file(), l.line())).unwrap_or_default();
        let msg = info.payload().downcast_ref::<String>().cloned()
            .or_else(|| info.payload().downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default();
        *h2.lock().unwrap().entry(format!("{loc}  {msg}")).or_default() += 1;
    }));

    let mut crashers: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut cluster = Cluster::for_us([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
    for i in 0..iters {
        let a = &seeds[rng.below(seeds.len())];
        let b = &seeds[rng.below(seeds.len())];
        let input = mutate(&mut rng, a, b);
        let t = (i as u64).wrapping_mul(1_000) ^ (rng.next() & 0xffff_ffff_ffff);
        let before = hits.lock().unwrap().len();
        let r = panic::catch_unwind(panic::AssertUnwindSafe(|| exercise(&input, &mut cluster, t)));
        if r.is_err() {
            cluster = Cluster::for_us([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
            let map = hits.lock().unwrap();
            if map.len() > before {
                let key = map.keys().last().cloned().unwrap_or_default();
                crashers.entry(key).or_insert(input);
            }
        }
    }
    let _ = panic::take_hook();

    let map = hits.lock().unwrap();
    println!("seeds: {}  iterations: {iters}  distinct panics: {}", seeds.len(), map.len());
    println!("adopters tracked after run: {}", cluster.adopters.len());
    println!("reached: action={} sync+cluster={} electionV2={}", REACHED_ACTION.load(Relaxed), REACHED_SYNC.load(Relaxed), REACHED_ELECT.load(Relaxed));
    for (k, n) in map.iter() {
        println!("  {n:>7}x  {k}");
    }
    if !crashers.is_empty() {
        let out = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/fuzz-crashers");
        std::fs::create_dir_all(out).ok();
        for (i, (k, v)) in crashers.iter().enumerate() {
            std::fs::write(format!("{out}/crash-{i}.bin"), v).ok();
            println!("  crash-{i}.bin ({} bytes) -> {k}", v.len());
        }
    }
    assert!(map.is_empty(), "{} distinct panic site(s) reachable from the air", map.len());
}
