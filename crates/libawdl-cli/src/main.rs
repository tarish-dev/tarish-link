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
    state::{Arpa, DataPathState, SixGhzChannels, SixGhzInfo, Version},
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
    let mut assoc: BTreeMap<String, u64> = BTreeMap::new();
    let mut hostnames: BTreeMap<String, u64> = BTreeMap::new();
    let mut versions: BTreeMap<String, u64> = BTreeMap::new();
    let mut sixghz: BTreeMap<String, u64> = BTreeMap::new();
    let mut instances: BTreeMap<String, u64> = BTreeMap::new();
    // Capture integrity. A frame the radio knew was corrupt still parses cleanly here --
    // TLV lengths are explicit, so flipped bits become a plausible wrong value rather than
    // an error -- so the count of them is the error bar on everything else printed below.
    let mut bad_fcs: u64 = 0;
    let mut no_flags: u64 = 0;

    while let Ok(pkt) = cap.next_packet() {
        total += 1;
        if let Some(rt) = libawdl::radiotap::Radiotap::parse(pkt.data) {
            if rt.flags.is_none() {
                no_flags += 1;
            } else if rt.bad_fcs() {
                bad_fcs += 1;
            }
        }
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
                    // Tag 12 names the access point directly -- an independent source
                    // for the association that slot 0 of the channel sequence implies.
                    if t.tag == 12 {
                        if let Some(d) = DataPathState::parse(t.value) {
                            let k = match (d.infra_bssid, d.infra_channel) {
                                (Some(b), Some(ch)) => format!(
                                    "associated to {} on channel {ch}",
                                    libawdl::dot11::Mac(b)
                                ),
                                _ => "not associated".to_string(),
                            };
                            *assoc.entry(k).or_default() += 1;
                        }
                    }
                    if t.tag == 16 {
                        if let Some(a) = Arpa::parse(t.value) {
                            *hostnames.entry(a.name).or_default() += 1;
                        }
                    }
                    if t.tag == 21 {
                        if let Some(v) = Version::parse(t.value) {
                            *versions
                                .entry(format!("v{}.{} {}", v.major, v.minor, v.class_name()))
                                .or_default() += 1;
                        }
                    }
                    if t.tag == 32 {
                        if let Some(i) = SixGhzInfo::parse(t.value) {
                            *sixghz
                                .entry(format!(
                                    "tag32 channel {} class {} ({})",
                                    i.channel.channel,
                                    i.channel.opclass,
                                    i.channel.band()
                                ))
                                .or_default() += 1;
                        }
                    }
                    if t.tag == 33 {
                        if let Some(c) = SixGhzChannels::parse(t.value) {
                            let d = |p: Option<libawdl::state::ClassChannel>| match p {
                                Some(c) => format!("{} ({})", c.channel, c.band()),
                                None => "-".into(),
                            };
                            *sixghz
                                .entry(format!("tag33 {} / {}", d(c.first), d(c.second)))
                                .or_default() += 1;
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
    if !assoc.is_empty() {
        eprintln!("infrastructure association (from Data Path State, tag 12):");
        for (k, n) in &assoc {
            eprintln!("  {k:<46} {n}");
        }
    }
    if !hostnames.is_empty() {
        eprintln!("host names (Arpa, tag 16):");
        for (k, n) in &hostnames {
            eprintln!("  {k:<30} {n}");
        }
    }
    if !sixghz.is_empty() {
        eprintln!("6 GHz advertisement (tags 32/33 — undocumented, decoded from captures):");
        for (k, n) in &sixghz {
            eprintln!("  {k:<44} {n}");
        }
    }
    if !versions.is_empty() {
        eprintln!("peer versions (tag 21):");
        for (k, n) in &versions {
            eprintln!("  {k:<24} {n}");
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
    // Printed unconditionally, including the zero: "no corrupt frames" is a result, and
    // one that silently disappears when it is good is not one anybody can rely on.
    eprintln!("capture integrity: {bad_fcs} frame(s) failed FCS");
    if no_flags > 0 {
        eprintln!(
            "  {no_flags} frame(s) carried no radiotap FLAGS field, so their integrity is \
             unknown rather than good — locally injected frames look like this"
        );
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
    eprintln!("  awdl tlv   <file.pcap> <tag> [mac]     dump raw TLV values as a Rust fixture");
    eprintln!("  awdl coverage <file.pcap>...           how much of the air do we understand");
    eprintln!("  awdl phase <file.pcap>                 WHEN in the AWDL cycle each node transmits");
    eprintln!("  awdl beacon <managed> <mon> [chan] [secs] [psf-per-mif] [--compete] [--legacy-timing] [--metric N] [--per-window N] [--windows N]");
    eprintln!("                                         TRANSMIT. needs root. see the fn comment");
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
        "profile" => {
            let cap = pcap::Capture::from_file(&args[2]).expect("open capture file");
            profile(cap);
        }
        "timeline" => {
            let cap = pcap::Capture::from_file(&args[2]).expect("open capture file");
            let bucket = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(5);
            timeline(cap, bucket);
        }
        "beacon" => {
            if args.len() < 4 {
                usage();
            }
            beacon(
                &args[2],
                &args[3],
                args.get(4).and_then(|s| s.parse().ok()).unwrap_or(149),
                args.get(5).and_then(|s| s.parse().ok()).unwrap_or(30),
                args.get(6).and_then(|s| s.parse().ok()).unwrap_or(2),
                args.iter().any(|a| a == "--compete"),
                args.iter().any(|a| a == "--legacy-timing"),
                args.iter().position(|a| a == "--metric")
                    .and_then(|i| args.get(i + 1))
                    .and_then(|v| v.parse().ok()),
                args.iter().position(|a| a == "--per-window")
                    .and_then(|i| args.get(i + 1))
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(1),
                args.iter().position(|a| a == "--windows")
                    .and_then(|i| args.get(i + 1))
                    .and_then(|v| v.parse().ok()),
            );
        }
        "phase" => {
            let cap = pcap::Capture::from_file(&args[2]).expect("open capture file");
            phase(cap);
        }
        "coverage" => {
            coverage(&args[2..]);
        }
        "tlv" => {
            let cap = pcap::Capture::from_file(&args[2]).expect("open capture file");
            let Some(tag) = args.get(3).and_then(|s| s.parse::<u8>().ok()) else { usage() };
            dump_tlv(cap, tag, args.get(4).map(|s| s.as_str()));
        }
        _ => usage(),
    }
}

/// Per-sender profile: what one implementation actually puts on the air.
///
/// **This exists to make the gap table reproducible.** We are building a replacement for
/// `libmosey`, and the specification for it is the difference between what Apple sends,
/// what `libmosey` sends, and what OWL sends. A table typed out by hand goes stale the
/// moment another capture is taken; this regenerates it.
///
/// Run it over captures from each implementation and compare the output.
fn profile<T: pcap::Activated + ?Sized>(mut cap: pcap::Capture<T>) {
    use std::collections::BTreeSet;

    struct Prof {
        frames: u64,
        psf: u64,
        mif: u64,
        tags: BTreeMap<u8, u64>,
        seq_shapes: BTreeSet<String>,
        aw_periods: BTreeSet<u16>,
        metrics: BTreeSet<u32>,
        counters: BTreeSet<u32>,
        versions: BTreeSet<String>,
        assoc_channels: BTreeSet<u16>,
        six_ghz: BTreeSet<u8>,
        services: BTreeSet<String>,
        host_names: BTreeSet<String>,
    }
    impl Default for Prof {
        fn default() -> Self {
            Prof {
                frames: 0, psf: 0, mif: 0,
                tags: BTreeMap::new(),
                seq_shapes: BTreeSet::new(), aw_periods: BTreeSet::new(),
                metrics: BTreeSet::new(), counters: BTreeSet::new(),
                versions: BTreeSet::new(), assoc_channels: BTreeSet::new(),
                six_ghz: BTreeSet::new(), services: BTreeSet::new(),
                host_names: BTreeSet::new(),
            }
        }
    }

    let mut by_sender: BTreeMap<String, Prof> = BTreeMap::new();

    while let Ok(pkt) = cap.next_packet() {
        let Seen::Awdl { dot11, af, .. } = classify(pkt.data) else { continue };
        let p = by_sender.entry(dot11.src.to_string()).or_default();
        p.frames += 1;
        match af.fixed.subtype {
            libawdl::action::SUBTYPE_PSF => p.psf += 1,
            libawdl::action::SUBTYPE_MIF => p.mif += 1,
            _ => {}
        }
        for t in af.tlvs() {
            *p.tags.entry(t.tag).or_default() += 1;
            match t.tag {
                2 => {
                    for r in service::records(t.value) {
                        if let service::Record::Ptr { name, .. } = &r {
                            p.services.insert(name.clone());
                        }
                    }
                }
                4 => {
                    if let Some(sp) = SyncParams::parse(t.value) {
                        p.aw_periods.insert(sp.aw_period);
                    }
                }
                12 => {
                    if let Some(d) = DataPathState::parse(t.value) {
                        if let Some(ch) = d.infra_channel {
                            p.assoc_channels.insert(ch);
                        }
                    }
                }
                16 => {
                    if let Some(a) = Arpa::parse(t.value) {
                        p.host_names.insert(a.name);
                    }
                }
                18 => {
                    if let Some(cs) = ChannelSequence::parse(t.value) {
                        p.seq_shapes.insert(format!(
                            "{:?} {}/{} -> {:?}",
                            cs.encoding, cs.occupied_slots(), cs.channels.len(), cs.distinct()
                        ));
                    }
                }
                21 => {
                    if let Some(v) = Version::parse(t.value) {
                        p.versions.insert(format!("v{}.{} {}", v.major, v.minor, v.class_name()));
                    }
                }
                24 => {
                    if let Some(e) = ElectionParamsV2::parse(t.value) {
                        p.metrics.insert(e.self_metric);
                        p.counters.insert(e.self_counter);
                    }
                }
                32 => {
                    if let Some(i) = SixGhzInfo::parse(t.value) {
                        p.six_ghz.insert(i.channel.channel);
                    }
                }
                _ => {}
            }
        }
    }

    for (who, p) in &by_sender {
        println!("\n=== {who}   {} frames  ({} PSF, {} MIF)", p.frames, p.psf, p.mif);
        let tags: Vec<String> = p.tags.keys().map(|t| t.to_string()).collect();
        println!("  tags emitted       {}", tags.join(" "));
        println!("  availability window{:?} TU", p.aw_periods);
        for s in &p.seq_shapes {
            println!("  channel sequence   {s}");
        }
        println!("  self metric        {:?}", p.metrics);
        println!("  self counter       {:?}", p.counters);
        if !p.versions.is_empty() {
            println!("  version            {:?}", p.versions);
        }
        if !p.assoc_channels.is_empty() {
            println!("  assoc channel      {:?}", p.assoc_channels);
        }
        if !p.six_ghz.is_empty() {
            println!("  6 GHz channel      {:?}", p.six_ghz);
        }
        if !p.services.is_empty() {
            println!("  services           {:?}", p.services);
        }
        if !p.host_names.is_empty() {
            println!("  host name          {:?}", p.host_names);
        }
    }
}

/// Dump every DISTINCT raw value of one tag, as a Rust byte array ready to paste.
///
/// This exists because of the discipline in `tests/build.rs`: a serialiser that only
/// round-trips through its own parser proves nothing, so every builder is tested for byte
/// equality against something a real device actually sent. That needs fixtures, and
/// hand-transcribing them from a hex dump is how a fixture ends up subtly wrong — at which
/// point the test is worse than no test, because it certifies the wrong bytes.
///
/// Distinct values, not every frame: a capture holds thousands of near-identical
/// Synchronization Parameters and the interesting thing is how many *shapes* there are.
/// The count is printed so a one-off can be told from the steady state, and the first
/// sighting is what gets dumped — a value seen once in 3000 frames is more likely a
/// transient than a specimen worth building against.
fn dump_tlv<T: pcap::Activated + ?Sized>(mut cap: pcap::Capture<T>, tag: u8, from: Option<&str>) {
    use std::collections::BTreeMap;

    // Keyed on the bytes so identical values collapse; the value keeps enough to judge
    // whether a shape is representative.
    struct Sighting {
        count: u64,
        first_frame: u64,
        senders: std::collections::BTreeSet<String>,
    }
    let mut seen: BTreeMap<Vec<u8>, Sighting> = BTreeMap::new();
    let mut frame = 0u64;
    let want = from.map(|m| m.to_ascii_lowercase());

    while let Ok(pkt) = cap.next_packet() {
        frame += 1;
        let Seen::Awdl { dot11, af, .. } = classify(pkt.data) else { continue };
        let src = dot11.src.to_string().to_ascii_lowercase();
        if let Some(w) = &want {
            if &src != w {
                continue;
            }
        }
        for t in af.tlvs() {
            if t.tag != tag {
                continue;
            }
            let e = seen.entry(t.value.to_vec()).or_insert_with(|| Sighting {
                count: 0,
                first_frame: frame,
                senders: Default::default(),
            });
            e.count += 1;
            e.senders.insert(src.clone());
        }
    }

    if seen.is_empty() {
        eprintln!("no tag {tag} ({}) in this capture{}", libawdl::tlv::tag_name(tag),
            from.map(|m| format!(" from {m}")).unwrap_or_default());
        std::process::exit(1);
    }

    eprintln!("tag {tag} ({}): {} distinct value(s)", libawdl::tlv::tag_name(tag), seen.len());
    // Most-seen first: the steady state is what a builder should reproduce.
    let mut order: Vec<_> = seen.iter().collect();
    order.sort_by(|a, b| b.1.count.cmp(&a.1.count));

    // A tag carrying a counter is distinct in EVERY frame -- Synchronization Parameters
    // yields 331 "shapes" from one device in one capture, all differing only in
    // tx_counter and aw_remaining. So a high distinct count is not a finding, and
    // dumping all of them is not useful. Three is enough to see which fields move.
    const LIMIT: usize = 3;
    if order.len() > LIMIT {
        eprintln!(
            "  showing {LIMIT}; {} more suppressed. Many distinct values usually means \
             the tag carries a counter, not that the sender is inconsistent.",
            order.len() - LIMIT
        );
        order.truncate(LIMIT);
    }

    for (i, (value, s)) in order.iter().enumerate() {
        let senders: Vec<&str> = s.senders.iter().map(|x| x.as_str()).collect();
        println!("// tag {tag} ({}) -- {} bytes, seen {}x, first at frame {}",
            libawdl::tlv::tag_name(tag), value.len(), s.count, s.first_frame);
        println!("// from {}", senders.join(", "));
        println!("pub const TLV_{i}: &[u8] = &[");
        for row in value.chunks(16) {
            let cells: Vec<String> = row.iter().map(|b| format!("0x{b:02x}")).collect();
            println!("    {},", cells.join(", "));
        }
        println!("];");
    }
}

/// How much of what is actually on the air can we NAME, as opposed to merely reproduce.
///
/// The two are different and the difference is the whole point. Every tag with a parser
/// round-trips byte for byte, because unknown fields are carried raw — so "we can rebuild
/// any frame" is true and says nothing about understanding. What a transmitter needs is
/// the other number: a byte we cannot name is a byte we have to invent, and inventing it
/// usually means copying whatever Apple sent, which is cargo-culting with no signal when
/// it is wrong.
///
/// Weighted by frames, not by tags. A tag in every frame matters more than one seen twice.
fn coverage(files: &[String]) {
    use libawdl::coverage::{is_decoded, of_tlv, Coverage};
    use std::collections::BTreeMap;

    let mut per_tag: BTreeMap<u8, (Coverage, u64)> = BTreeMap::new();
    // "Are you sure of them in every frame?" is a second question, and shape variance is
    // how to answer it: a tag that is 9 bytes from one device and 20 from another is not
    // a fixed struct, whatever a table says its fields are.
    let mut lengths: BTreeMap<u8, BTreeMap<usize, u64>> = BTreeMap::new();
    let mut frames: u64 = 0;

    for f in files {
        let Ok(mut cap) = pcap::Capture::from_file(f) else {
            eprintln!("skipping {f}: not a capture");
            continue;
        };
        while let Ok(pkt) = cap.next_packet() {
            let Seen::Awdl { af, .. } = classify(pkt.data) else { continue };
            frames += 1;
            for t in af.tlvs() {
                let e = per_tag.entry(t.tag).or_insert((Coverage::default(), 0));
                e.0.add(of_tlv(t.tag, t.value));
                e.1 += 1;
                *lengths.entry(t.tag).or_default().entry(t.value.len()).or_insert(0) += 1;
            }
        }
    }

    if frames == 0 {
        eprintln!("no AWDL frames");
        return;
    }

    let mut total = Coverage::default();
    let mut control = Coverage::default();
    println!("{frames} AWDL action frames\n");
    println!(
        "{:<4} {:<28} {:>7} {:>9} {:>9} {:>6}  {}",
        "tag", "name", "TLVs", "named", "opaque", "%", "lengths seen"
    );
    for (tag, (c, n)) in &per_tag {
        total.add(*c);
        // Service Response is DNS -- a documented encoding we happen to carry. Counting it
        // with the rest flatters the number, because the tags a transmitter has to compose
        // from nothing are the other ones.
        if *tag != 2 {
            control.add(*c);
        }
        let shapes = lengths.get(tag).map(|m| {
            let mut v: Vec<String> = m.iter().map(|(l, n)| format!("{l}x{n}")).collect();
            if v.len() > 4 {
                let extra = v.len() - 4;
                v.truncate(4);
                v.push(format!("+{extra} more"));
            }
            v.join(" ")
        }).unwrap_or_default();
        let pct = if c.total() == 0 { "  n/a".to_string() } else { format!("{:>5.1}", c.percent_named()) };
        println!(
            "{:<4} {:<28} {:>7} {:>9} {:>9} {}  {}{}",
            tag,
            libawdl::tlv::tag_name(*tag),
            n,
            c.named,
            c.opaque,
            pct,
            shapes,
            if is_decoded(*tag) { "" } else { "   NO PARSER" }
        );
    }
    println!();
    println!(
        "all TLVs:        {:>9} bytes   named {:>9} ({:.1}%)   opaque {:>9}",
        total.total(), total.named, total.percent_named(), total.opaque
    );
    println!(
        "without tag 2:   {:>9} bytes   named {:>9} ({:.1}%)   opaque {:>9}",
        control.total(), control.named, control.percent_named(), control.opaque
    );
    println!();
    println!("Every one of those bytes round-trips exactly. That is a separate claim from");
    println!("understanding them, and it is the weaker one. A zero-length tag (0, SSTH");
    println!("Request) is a presence flag and has no bytes to understand.");
}

/// Put frames on the air.
///
/// ```text
///   awdl beacon <managed> <monitor> [channel] [seconds] [psf-per-mif]
///   awdl beacon wlan1 mon0 149 30 2
/// ```
///
/// **This transmits on a shared channel and needs root.** Everything else in this binary
/// only listens; this is the one subcommand that other people's devices have to deal with.
/// It is deliberately time-bounded rather than a daemon.
///
/// # What it is honest about
///
/// The frames are correct as far as we can make them — ten of the thirteen tags Apple
/// sends, each pinned by byte equality against a captured device. **The timing is not.** A
/// real node transmits inside its own Availability Windows anchored to the cluster's TSF;
/// this emits on a wall-clock timer, because the HAL has no TSF read on this hardware. So
/// we advertise a schedule we do not keep, which is also what OWL does, and the whole point
/// of running it is to find out how much that costs.
///
/// # How to tell whether it worked
///
/// Not by whether it "sent" — `send()` succeeding means the driver accepted the bytes. The
/// test is whether a real peer *acts* on them, and the cheapest evidence is the election:
/// advertise a metric and an Apple device must either follow us or beat us, and either way
/// **its own frames change**. Capture alongside and look at who it names as master.
fn beacon(managed: &str, monitor: &str, channel: u8, secs: u64, psf_per_mif: u32, compete: bool, legacy: bool, metric: Option<u32>, per_window: u32, windows: Option<usize>) {
    use libawdl::beacon::Beacon;
    use libawdl_hal::{nl80211::Nl80211, Radio, TxParams};

    let mut radio = match Nl80211::new(managed, monitor) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cannot reach the radio: {e:?}");
            std::process::exit(1);
        }
    };
    // Down first, monitor vif second, channel third. Getting this wrong fails as EAGAIN on
    // every send with nothing in dmesg -- see rawsock's module note.
    if let Err(e) = radio.bring_up(channel) {
        eprintln!("bring_up failed: {e:?}");
        std::process::exit(1);
    }
    let addr = match radio.mac_address() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("no MAC for {monitor}: {e:?}");
            std::process::exit(1);
        }
    };

    let mut b = Beacon::new(addr, channel, "QA");
    if compete {
        b.metric = libawdl::beacon::METRIC_COMPETE;
    }
    // --metric N overrides both. Apple's metrics are NOT fixed: devices have been observed
    // at 510, 515, 530, 537 and 539 in one room, so a constant compiled in here goes stale
    // the moment a newer phone walks in. METRIC_COMPETE was calibrated at 510-530 and was
    // already being outranked by an iPhone at 539 the same evening.
    if let Some(m) = metric {
        b.metric = m;
    }
    if let Some(w) = windows {
        // An experimental control. See Beacon::windows.
        b.windows = Some(w);
    }
    if legacy {
        // An experimental control. See Beacon::legacy_timing.
        b.legacy_timing = true;
    }
    // Our epoch. Every timing field in the frame is derived from this one monotonic
    // reading, which is what makes them agree with each other -- a master's timing has to
    // be self-consistent, and does not have to agree with anybody else's.
    let epoch = std::time::Instant::now();
    eprintln!("beaconing as {} on channel {channel} for {secs}s", libawdl::dot11::Mac(addr));
    eprintln!(
        "  metric {} — {}",
        b.metric,
        if b.metric >= libawdl::beacon::METRIC_COMPETE {
            "competing: above the values Apple devices were seen advertising"
        } else {
            "declining the election"
        }
    );
    eprintln!("  MIF {} bytes, PSF {} bytes, 1 MIF per {psf_per_mif} PSF", b.mif(0).len(), b.psf(0).len());
    if legacy {
        eprintln!("  --legacy-timing: aw_remaining pinned to 0. EXPERIMENTAL CONTROL ONLY.");
    }
    eprintln!("  not synchronised to any peer's TSF; self-consistent from a monotonic clock");

    // Transmit inside the windows we ADVERTISE, rather than on a fixed period.
    //
    // The old loop slept exactly one cycle between frames, which pinned us to whatever
    // phase the process started on -- measured on the air as 3 of 16 slots, none of them
    // the ones we announce. `awdl phase` is the check.
    eprintln!("  transmitting in advertised slots {:?} of 16, {per_window} frame(s) per window",
        b.advertised_slots());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    let (mut sent_mif, mut sent_psf, mut failed) = (0u64, 0u64, 0u64);
    let mut n = 0u32;
    let mut first_error: Option<String> = None;

    while std::time::Instant::now() < deadline {
        // Only transmit INSIDE a window we advertise.
        //
        // The first version of this loop sent unconditionally at the top and then waited,
        // which fired in slot 2, slept one window, and fired again in slot 3 -- a slot we
        // do not advertise. Half of every run's frames were in the wrong windows, visible
        // in `awdl phase` as adjacent pairs, and the frame rate was double what it should
        // have been. Waiting FIRST is the whole fix.
        let now_us = epoch.elapsed().as_micros() as u64;
        let wait = b.us_until_next_advertised_window(now_us);
        if wait > 0 {
            std::thread::sleep(std::time::Duration::from_micros(wait));
            continue;
        }
        let now_us = epoch.elapsed().as_micros() as u64;
        let is_mif = psf_per_mif == 0 || n % (psf_per_mif + 1) == 0;
        let frame = if is_mif { b.mif(now_us) } else { b.psf(now_us) };
        match radio.tx(&frame, TxParams::default()) {
            Ok(()) => {
                if is_mif { sent_mif += 1 } else { sent_psf += 1 }
            }
            Err(e) => {
                failed += 1;
                if first_error.is_none() {
                    first_error = Some(format!("{e:?}"));
                }
            }
        }
        b.advance();
        n += 1;
        // Pace within the window. `per_window` frames fit in one 16 TU window; the next
        // iteration's wait carries us to the following advertised one.
        //
        // This knob exists as an EXPERIMENTAL CONTROL, not a tuning parameter. Trial E
        // won an election at 22.5 frames/s while trial F lost one at 11.2 with the same
        // alignment and metric, so rate and window-count were confounded. Holding the
        // windows correct and raising only the rate is what separates them.
        std::thread::sleep(std::time::Duration::from_micros(
            u64::from(libawdl::beacon::AW_US) / u64::from(per_window.max(1)),
        ));
    }

    eprintln!("\nsent {sent_mif} MIF, {sent_psf} PSF, {failed} failed");
    if let Some(e) = first_error {
        eprintln!("first error: {e}");
        eprintln!("EAGAIN here means another vif on the same phy is up, not a full buffer.");
    }
    let end_us = epoch.elapsed().as_micros() as u64;
    eprintln!(
        "tx_counter {}, aw_counter {}, tenure {}",
        b.sent,
        Beacon::aws_at(end_us) & 0xffff,
        libawdl::election::ElectionParamsV2::counter_after(b.tenure_base, Beacon::aws_at(end_us))
    );
}

/// Where in the AWDL cycle does each node actually transmit?
///
/// A cycle is sixteen Availability Windows of 16 TU, 262144 us in total. A node is present
/// in only a few of those windows -- Apple occupies four of sixteen -- so **two nodes can
/// only hear each other in a window they both attend.** Advertising a schedule is not the
/// same as keeping one, and this is the measurement that tells them apart.
///
/// Each frame's radiotap TSFT is folded onto the cycle and bucketed into sixteen slots.
/// The absolute phase is the capturing radio's, not the cluster's, so **slot numbers here
/// are not the slot numbers in a channel sequence** -- what is comparable is the SHAPE:
/// which senders concentrate, which spread, and whether two senders concentrate in the
/// same place.
///
/// The specific thing this was built to check: our beacon transmits every sixteen windows,
/// which is exactly one cycle, so it should land on a single phase for a whole run -- and
/// whether that phase coincides with a peer's is then a matter of when the process
/// happened to start.
fn phase<T: pcap::Activated + ?Sized>(mut cap: pcap::Capture<T>) {
    use std::collections::BTreeMap;

    const SLOTS: u64 = 16;
    const TU: u64 = 1024;
    const AW_US: u64 = 16 * TU;
    const CYCLE_US: u64 = SLOTS * AW_US;

    let mut hist: BTreeMap<String, [u64; 16]> = BTreeMap::new();
    let mut no_tsf: u64 = 0;
    let mut total: u64 = 0;

    while let Ok(pkt) = cap.next_packet() {
        let Seen::Awdl { rt, dot11, .. } = classify(pkt.data) else { continue };
        total += 1;
        // TSFT is the right clock and this radio does not report it -- 0 of 801 frames in
        // every capture we hold. Falling back to the host's capture timestamp, which is a
        // USB adapter's idea of when the frame reached the kernel, not when it was on the
        // air. THAT MAY BE FAR TOO COARSE, which is why the Apple senders act as the
        // control: they are known to occupy four windows of sixteen, so if their
        // distribution comes out flat the instrument cannot see windows at all and nothing
        // below means anything.
        let t = match rt.tsft {
            Some(t) => t,
            None => {
                no_tsf += 1;
                (pkt.header.ts.tv_sec as u64).wrapping_mul(1_000_000)
                    + pkt.header.ts.tv_usec as u64
            }
        };
        let slot = ((t % CYCLE_US) / AW_US) as usize;
        hist.entry(dot11.src.to_string()).or_insert([0; 16])[slot.min(15)] += 1;
    }

    if total == 0 {
        eprintln!("no AWDL frames");
        return;
    }
    if no_tsf > 0 {
        println!("{total} AWDL frames; {no_tsf} had NO TSFT — host capture timestamps used instead");
        println!("READ THE APPLE SENDERS FIRST: they occupy four windows of sixteen. If they");
        println!("look flat here, the timestamps cannot resolve windows and nothing below counts.");
    } else {
        println!("{total} AWDL frames, all with TSFT");
    }
    println!("(slot numbers are the capturing radio's phase, not the cluster's — compare shapes, not indices)\n");

    for (src, h) in &hist {
        let n: u64 = h.iter().sum();
        if n == 0 {
            continue;
        }
        let occupied = h.iter().filter(|c| **c > 0).count();
        let bars: String = h
            .iter()
            .map(|c| {
                let frac = *c as f64 / n as f64;
                match (frac * 16.0) as u32 {
                    0 if *c == 0 => '.',
                    0 => '\u{2581}',
                    1 => '\u{2582}',
                    2 => '\u{2583}',
                    3..=4 => '\u{2584}',
                    5..=7 => '\u{2585}',
                    8..=11 => '\u{2586}',
                    _ => '\u{2588}',
                }
            })
            .collect();
        println!("  {src}  [{bars}]  {n:>5} frames in {occupied}/16 slots");
    }

    // The comparison that matters: does any pair of senders share their busiest slots?
    println!();
    let keys: Vec<&String> = hist.keys().collect();
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            let (a, b) = (&hist[keys[i]], &hist[keys[j]]);
            let (na, nb): (u64, u64) = (a.iter().sum(), b.iter().sum());
            if na == 0 || nb == 0 {
                continue;
            }
            // Overlap: the probability mass they share, slot by slot. 1.0 means identical
            // distributions, 0.0 means they are never on the air at the same time.
            let overlap: f64 = (0..16)
                .map(|k| (a[k] as f64 / na as f64).min(b[k] as f64 / nb as f64))
                .sum();
            println!("  {} vs {}  shared airtime {:.0}%", keys[i], keys[j], overlap * 100.0);
        }
    }
}
