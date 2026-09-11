//! awdl — watch the air, keep only AWDL.
//!
//! Three subcommands, all reading the same parser:
//!
//! ```text
//!   awdl live <iface> [--chan N]   capture from a monitor interface
//!   awdl read <file.pcap>          the same, from a recorded capture
//!   awdl stats <file.pcap>         how much of a capture is AWDL, and which tags
//! ```
//!
//! `read` exists so every finding is reproducible without the radio. A capture is
//! evidence; a live run is an anecdote.

use std::collections::BTreeMap;

use libawdl::{
    action::ActionFrame,
    data::{is_ipv6_multicast, DataHeader},
    dot11::{Dot11, FrameControl},
    radiotap::Radiotap,
    election::{ElectionParams, ElectionParamsV2},
    service,
    sync::{ChannelSequence, SyncParams},
    tlv::Stop,
};

/// What one captured frame turned out to be.
enum Seen<'a> {
    /// No radiotap, or not 802.11 at all. Should be rare; if it is not, something
    /// upstream is wrong and the number is worth seeing.
    NotTrusted,
    /// 802.11, but not AWDL. Counted BY TYPE rather than lumped together, because
    /// "half the capture is unparseable" and "half the capture is ACKs" look identical
    /// otherwise, and only one of them is a bug.
    OtherWifi(FrameControl),
    /// An AWDL **data** frame: the payload path rather than the control plane.
    AwdlData { seq: u16, ethertype: &'static str, multicast: bool, bytes: usize },
    Awdl { rt: Radiotap, dot11: Dot11, af: ActionFrame<'a> },
}

fn classify(pkt: &[u8]) -> Seen<'_> {
    let Some(rt) = Radiotap::parse(pkt) else { return Seen::NotTrusted };
    let Some(body80211) = rt.payload(pkt) else { return Seen::NotTrusted };
    let Some(fc) = FrameControl::parse(body80211) else { return Seen::NotTrusted };
    if fc.frame_type == libawdl::dot11::TYPE_DATA {
        // QoS Data carries a 26-byte header (24 + 2 for the QoS control field), then
        // LLC/SNAP (8), then the AWDL data header. Getting the QoS field wrong shifts
        // everything by two bytes and the ethertype lands on garbage.
        let qos = if fc.subtype & 0x08 != 0 { 2 } else { 0 };
        let dst: [u8; 6] = match body80211.get(4..10).and_then(|b| b.try_into().ok()) {
            Some(d) => d,
            None => return Seen::OtherWifi(fc),
        };
        if let Some(h) = body80211.get(24 + qos + 8..).and_then(DataHeader::parse) {
            return Seen::AwdlData {
                seq: h.sequence,
                ethertype: h.ethertype_name(),
                multicast: is_ipv6_multicast(dst),
                bytes: pkt_len_of(body80211, &h),
            };
        }
        return Seen::OtherWifi(fc);
    }
    if !fc.is_action() {
        return Seen::OtherWifi(fc);
    }
    // Only now is the full 24-byte management header worth demanding.
    let Some(dot11) = Dot11::parse(body80211) else { return Seen::OtherWifi(fc) };
    let Some(body) = dot11.body(body80211) else { return Seen::OtherWifi(fc) };
    match ActionFrame::parse(body) {
        Some(af) => Seen::Awdl { rt, dot11, af },
        None => Seen::OtherWifi(fc),
    }
}

/// Size of the encapsulated packet, for reporting only.
fn pkt_len_of(body: &[u8], h: &DataHeader) -> usize {
    body.len().saturating_sub(h.payload_offset)
}

fn print_frame(n: u64, rt: &Radiotap, d: &Dot11, af: &ActionFrame) {
    let freq = rt.freq.map(|f| format!("{f} MHz")).unwrap_or_else(|| "?".into());
    let sig = rt.signal_dbm.map(|s| format!("{s} dBm")).unwrap_or_else(|| "?".into());
    println!(
        "#{n}  {}  {}  v{}.{}  {} -> {}  {}  {}  tx_delay={}",
        libawdl::action::subtype_name(af.fixed.subtype),
        freq,
        af.fixed.version_major,
        af.fixed.version_minor,
        d.src,
        d.dst,
        sig,
        rt.tsft.map(|t| format!("tsft={t}")).unwrap_or_else(|| "tsft=-".into()),
        af.fixed.tx_delay(),
    );
    let mut tlvs = af.tlvs();
    for t in tlvs.by_ref() {
        println!("      [{:>2}] {:<28} {:>4} bytes", t.tag, t.name(), t.value.len());
        // The two tags that carry the timing answer get decoded inline rather than
        // just counted -- everything else is bytes until it has a capture behind it.
        match t.tag {
            4 => {
                if let Some(s) = SyncParams::parse(t.value) {
                    println!(
                        "           AW {} TU ({} us)  remaining {}  counter {}  master {}  tx_ch {}",
                        s.aw_period,
                        s.aw_period_us(),
                        s.aw_remaining,
                        s.aw_counter,
                        if s.is_self_master() {
                            "self".to_string()
                        } else {
                            libawdl::dot11::Mac(s.master).to_string()
                        },
                        s.tx_channel,
                    );
                }
            }
            2 => {
                for r in service::records(t.value) {
                    match r {
                        service::Record::Ptr { name, target } => {
                            println!("           PTR  {name} -> {target}")
                        }
                        service::Record::Srv { name, port, target, .. } => {
                            println!("           SRV  {name} -> {target}:{port}")
                        }
                        service::Record::Txt { name, strings } => {
                            println!("           TXT  {name}  {}", strings.join(" "))
                        }
                        service::Record::Other { name, rtype, data } => println!(
                            "           {:<4} {name}  {} bytes",
                            service::type_name(rtype),
                            data.len()
                        ),
                    }
                }
            }
            5 => {
                if let Some(e) = ElectionParams::parse(t.value) {
                    println!(
                        "           distance {}  self_metric {}  master_metric {}  master {}",
                        e.distance,
                        e.self_metric,
                        e.master_metric,
                        libawdl::dot11::Mac(e.master),
                    );
                }
            }
            24 => {
                if let Some(e) = ElectionParamsV2::parse(t.value) {
                    println!(
                        "           v2 distance {}  self {}#{}  master {}#{}",
                        e.distance,
                        e.self_metric,
                        e.self_counter,
                        e.master_metric,
                        e.master_counter,
                    );
                }
            }
            18 => {
                if let Some(c) = ChannelSequence::parse(t.value) {
                    println!(
                        "           {:?}  {} slots  distinct {:?}  step {}",
                        c.encoding,
                        c.channels.len(),
                        c.distinct(),
                        c.step_count,
                    );
                }
            }
            _ => {}
        }
    }
    // A truncated or malformed TLV region is a finding, not noise -- say so.
    match tlvs.stop() {
        Some(Stop::Clean) | None => {}
        Some(Stop::Trailing(n)) => println!("      !! {n} trailing byte(s) after the last tag"),
        Some(Stop::Overrun { tag, claimed, available }) => println!(
            "      !! tag {tag} claims {claimed} bytes, {available} remain — truncated capture or malformed frame"
        ),
    }
}

/// Election state over time, one row per sender.
///
/// THIS EXISTS BECAUSE A TALLY LIED. Summed over a capture, our node looked like it was
/// flapping between claiming and yielding mastership -- 498 frames one way, 292 the
/// other. Plotted against time it had changed its mind exactly once, six seconds after
/// every peer went silent, which is correct behaviour rather than a defect. A per-sender
/// total cannot tell those apart and the difference is everything, so any claim about
/// election behaviour gets made from this view or not at all.
///
/// `M` = claiming mastership (distance 0), `f` = following someone, `.` = silent.
fn timeline<T: pcap::Activated + ?Sized>(mut cap: pcap::Capture<T>, bucket_s: i64) {
    let mut first_ts: Option<i64> = None;
    // sender -> bucket -> (claims, follows)
    let mut rows: BTreeMap<String, BTreeMap<i64, (u32, u32)>> = BTreeMap::new();
    let mut last_bucket = 0i64;

    while let Ok(pkt) = cap.next_packet() {
        let ts = pkt.header.ts.tv_sec;
        let base = *first_ts.get_or_insert(ts);
        let bucket = (ts - base) / bucket_s;
        last_bucket = last_bucket.max(bucket);

        if let Seen::Awdl { dot11, af, .. } = classify(pkt.data) {
            for t in af.tlvs() {
                if t.tag != 24 {
                    continue;
                }
                if let Some(e) = ElectionParamsV2::parse(t.value) {
                    let row = rows.entry(dot11.src.to_string()).or_default();
                    let cell = row.entry(bucket).or_insert((0, 0));
                    if e.claims_mastership() {
                        cell.0 += 1;
                    } else {
                        cell.1 += 1;
                    }
                }
            }
        }
    }

    println!("election over time — one column per {bucket_s}s.  M = claims master, f = follows, . = silent\n");
    for (who, row) in &rows {
        print!("{who}  ");
        for b in 0..=last_bucket {
            print!("{}", match row.get(&b) {
                None => '.',
                // A bucket containing both is a real transition, not noise -- shown as
                // its own symbol so it cannot be mistaken for either state.
                Some((m, f)) if *m > 0 && *f > 0 => '*',
                Some((m, _)) if *m > 0 => 'M',
                _ => 'f',
            });
        }
        println!();
    }
    println!("\n* = both states within one bucket (a transition)");
}

fn run<T: pcap::Activated + ?Sized>(mut cap: pcap::Capture<T>, stats_only: bool) {
    let mut total: u64 = 0;
    let mut awdl_n: u64 = 0;
    let mut other: u64 = 0;
    let mut not_trusted: u64 = 0;
    let mut data_n: u64 = 0;
    let mut data_mcast: u64 = 0;
    let mut data_bytes: u64 = 0;
    let mut data_seq_max: u16 = 0;
    let mut data_proto: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut by_kind: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut by_subtype: BTreeMap<u8, u64> = BTreeMap::new();
    let mut by_tag: BTreeMap<u8, u64> = BTreeMap::new();
    let mut peers: BTreeMap<String, u64> = BTreeMap::new();
    // Timing facts, aggregated across the capture rather than eyeballed per frame.
    let mut aw_periods: BTreeMap<u16, u64> = BTreeMap::new();
    let mut seq_shapes: BTreeMap<String, u64> = BTreeMap::new();
    let mut masters: BTreeMap<String, u64> = BTreeMap::new();
    let mut ap_align: BTreeMap<u16, u64> = BTreeMap::new();
    // Election state per sender: the strongest claim each node made, and how often it
    // said it was following someone else.
    let mut claims: BTreeMap<String, (u32, u32, u64, u64)> = BTreeMap::new();
    // Who names whom. An election claim is only meaningful as a relationship, so this
    // records the edge rather than two separate tallies that have to be guessed at.
    let mut follows: BTreeMap<(String, String), u64> = BTreeMap::new();
    let mut services: BTreeMap<String, u64> = BTreeMap::new();
    let mut instances: BTreeMap<String, u64> = BTreeMap::new();

    while let Ok(pkt) = cap.next_packet() {
        total += 1;
        match classify(pkt.data) {
            Seen::AwdlData { seq, ethertype, multicast, bytes } => {
                data_n += 1;
                if multicast {
                    data_mcast += 1;
                }
                *data_proto.entry(ethertype).or_default() += 1;
                data_bytes += bytes as u64;
                data_seq_max = data_seq_max.max(seq);
            }
            Seen::NotTrusted => not_trusted += 1,
            Seen::OtherWifi(fc) => {
                other += 1;
                *by_kind.entry(fc.type_name()).or_default() += 1;
            }
            Seen::Awdl { rt, dot11, af } => {
                awdl_n += 1;
                *by_subtype.entry(af.fixed.subtype).or_default() += 1;
                *peers.entry(dot11.src.to_string()).or_default() += 1;
                for t in af.tlvs() {
                    *by_tag.entry(t.tag).or_default() += 1;
                    if t.tag == 4 {
                        if let Some(sp) = SyncParams::parse(t.value) {
                            *aw_periods.entry(sp.aw_period).or_default() += 1;
                            *ap_align.entry(sp.ap_beacon_alignment_delta).or_default() += 1;
                            // The sequence carried INSIDE tag 4, in its own encoding.
                            if let Some(cs) = &sp.channel_sequence {
                                let shape = format!(
                                    "tag4  {:?} {}/{} slots -> {:?}",
                                    cs.encoding,
                                    cs.occupied_slots(),
                                    cs.channels.len(),
                                    cs.distinct()
                                );
                                *seq_shapes.entry(shape).or_default() += 1;
                            }
                            let m = if sp.is_self_master() {
                                "(self)".to_string()
                            } else {
                                libawdl::dot11::Mac(sp.master).to_string()
                            };
                            *masters.entry(m).or_default() += 1;
                        }
                    }
                    if t.tag == 2 {
                        for r in service::records(t.value) {
                            match &r {
                                service::Record::Ptr { name, target } => {
                                    *services.entry(name.clone()).or_default() += 1;
                                    *instances.entry(target.clone()).or_default() += 1;
                                }
                                service::Record::Srv { target, port, .. } => {
                                    *instances
                                        .entry(format!("{target}:{port}"))
                                        .or_default() += 1;
                                }
                                _ => {}
                            }
                        }
                    }
                    if t.tag == 24 {
                        if let Some(e) = ElectionParamsV2::parse(t.value) {
                            let k = dot11.src.to_string();
                            let slot = claims.entry(k).or_insert((0, 0, 0, 0));
                            slot.0 = slot.0.max(e.self_metric);
                            slot.1 = slot.1.max(e.self_counter);
                            if e.claims_mastership() {
                                slot.2 += 1;
                            } else {
                                slot.3 += 1;
                            }
                            let m = if e.claims_mastership() {
                                "(itself)".to_string()
                            } else {
                                libawdl::dot11::Mac(e.master).to_string()
                            };
                            *follows.entry((dot11.src.to_string(), m)).or_default() += 1;
                        }
                    }
                    if t.tag == 18 {
                        if let Some(cs) = ChannelSequence::parse(t.value) {
                            let shape = format!(
                                "tag18 {:?} {}/{} slots -> {:?}",
                                cs.encoding,
                                cs.occupied_slots(),
                                cs.channels.len(),
                                cs.distinct()
                            );
                            *seq_shapes.entry(shape).or_default() += 1;
                        }
                    }
                }
                if !stats_only {
                    print_frame(awdl_n, &rt, &dot11, &af);
                }
            }
        }
    }

    eprintln!("\n--- {total} frames: {awdl_n} AWDL action, {data_n} AWDL data, {other} other 802.11, {not_trusted} not 802.11");
    if data_n > 0 {
        eprintln!(
            "AWDL data plane: {data_n} frames ({data_mcast} multicast), {data_bytes} payload bytes, highest seq {data_seq_max}"
        );
        for (p, n) in &data_proto {
            eprintln!("  carries {p:<6} {n}");
        }
    }
    for (k, n) in &by_kind {
        eprintln!("  other {k:<12} {n}");
    }
    if awdl_n == 0 {
        return;
    }
    eprintln!("subtypes:");
    for (s, n) in &by_subtype {
        eprintln!("  {:<6} {n}", libawdl::action::subtype_name(*s));
    }
    eprintln!("senders:");
    for (m, n) in &peers {
        eprintln!("  {m}  {n}");
    }
    if !aw_periods.is_empty() {
        eprintln!("availability window (from the wire, not the paper):");
        for (tu, n) in &aw_periods {
            eprintln!("  {tu} TU = {} us   in {n} frames", u32::from(*tu) * libawdl::sync::TU_US);
        }
    }
    if !seq_shapes.is_empty() {
        eprintln!("channel sequences:");
        for (s, n) in &seq_shapes {
            eprintln!("  {s}   {n}");
        }
    }
    if !ap_align.is_empty() {
        eprintln!("AP beacon alignment delta:");
        for (d, n) in &ap_align {
            eprintln!("  {d}   in {n} frames");
        }
    }
    if !claims.is_empty() {
        eprintln!("election (per sender: best metric, best counter, frames claiming master / following):");
        for (who, (metric, counter, master_n, follow_n)) in &claims {
            eprintln!("  {who}  metric {metric:<12} counter {counter:<8} master {master_n:<5} following {follow_n}");
        }
    }
    if !services.is_empty() {
        eprintln!("services advertised:");
        for (k, n) in &services {
            eprintln!("  {k:<40} {n}");
        }
    }
    if !instances.is_empty() {
        eprintln!("instances / targets seen:");
        for (k, n) in instances.iter().take(12) {
            eprintln!("  {k:<48} {n}");
        }
    }
    if !follows.is_empty() {
        eprintln!("who names whom as master:");
        for ((src, m), n) in &follows {
            eprintln!("  {src}  ->  {m:<20} {n}");
        }
    }
    if !masters.is_empty() {
        eprintln!("synchronised to:");
        for (m, n) in &masters {
            eprintln!("  {m}  {n}");
        }
    }
    eprintln!("tags seen:");
    for (t, n) in &by_tag {
        eprintln!("  [{:>2}] {:<28} {n}", t, libawdl::tlv::tag_name(*t));
    }
}

fn usage() -> ! {
    eprintln!("awdl — pull AWDL out of the air\n");
    eprintln!("  awdl live  <iface>       capture from a monitor interface (needs root)");
    eprintln!("  awdl read  <file.pcap>   dissect a recorded capture");
    eprintln!("  awdl stats <file.pcap>   counts only, no per-frame output");
    eprintln!("  awdl timeline <file.pcap> [bucket_s]   election state over time");
    std::process::exit(2)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        usage();
    }
    match args[1].as_str() {
        "live" => {
            // Radiotap is not optional: without it there is no frequency, no signal and
            // no TSFT, and TSFT is the anchor for every timing question worth asking.
            let cap = pcap::Capture::from_device(args[2].as_str())
                .expect("open device")
                .rfmon(true)
                .immediate_mode(true)
                .snaplen(65535)
                .open()
                .expect("activate capture — is the interface in monitor mode, and are you root?");
            run(cap, false);
        }
        "read" | "stats" => {
            let cap = pcap::Capture::from_file(&args[2]).expect("open capture file");
            run(cap, args[1] == "stats");
        }
        "timeline" => {
            let cap = pcap::Capture::from_file(&args[2]).expect("open capture file");
            let bucket = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(5);
            timeline(cap, bucket);
        }
        _ => usage(),
    }
}
