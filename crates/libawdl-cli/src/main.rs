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
    eprintln!("  awdl coverage <file.pcap>... [--baseline F] [--update-baseline F]");
    eprintln!("                                         how much of the air do we understand");
    eprintln!("  awdl bytemap <file.pcap>... [tag]      which bytes of a tag ever VARY");
    eprintln!("  awdl correlate <file.pcap>...          match unknown bytes against KNOWN fields");
    eprintln!("  awdl tun <name> [secs] [mac]           open the awdl0 netdev. needs root, Linux");
    eprintln!("  awdl datapath <mon> <our-mac> [name] [secs] [--verbose]");
    eprintln!("                                         RUN THE PIPE: tun <-> radio. root, Linux");
    eprintln!("  awdl phase <file.pcap>                 WHEN in the AWDL cycle each node transmits");
    eprintln!("  awdl follow <file.pcap>                recover the cluster's clock from its own frames");
    eprintln!("  awdl beacon <managed> <mon> [chan] [secs] [psf-per-mif] [--compete] [--legacy-timing] [--metric N] [--per-window N] [--windows N] [--follow] [--tenure N] [--datapath NAME]");
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
                args.iter().any(|a| a == "--follow"),
                args.iter().position(|a| a == "--tenure")
                    .and_then(|i| args.get(i + 1))
                    .and_then(|v| v.parse().ok()),
                args.iter().position(|a| a == "--datapath")
                    .and_then(|i| args.get(i + 1))
                    .map(|s| s.as_str()),
            );
        }
        "follow" => {
            let cap = pcap::Capture::from_file(&args[2]).expect("open capture file");
            follow(cap);
        }
        "phase" => {
            let cap = pcap::Capture::from_file(&args[2]).expect("open capture file");
            phase(cap);
        }
        "coverage" => {
            coverage(&args[2..]);
        }
        "bytemap" => {
            bytemap(&args[2..]);
        }
        "correlate" => {
            correlate(&args[2..]);
        }
        "tun" => {
            tun(&args[2..]);
        }
        "datapath" => {
            datapath(&args[2..]);
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
/// The worst-classified TLV of a tag, kept as an exact fraction.
///
/// THE HEADLINE PERCENTAGE IS NOT A RATCHETABLE NUMBER. It is a byte-weighted average over
/// whatever captures happen to be in the corpus, so adding a 6 GHz-heavy capture drops it
/// with no code change at all, and a ratchet built on it would cry wolf every time the
/// corpus grew. This is the number that does not move: for one TLV, `of_tlv` is a pure
/// function of its bytes, so the worst case across a tag can only fall if the PARSER got
/// worse or if a capture arrived carrying a shape we cannot classify.
///
/// Both of those deserve to fail. The second is not a false positive -- a new capture
/// containing something we do not understand is exactly the thing this repository exists
/// to notice, and absorbing it silently into an average is how 78% becomes a number
/// nobody checks.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Floor {
    named: usize,
    total: usize,
}

impl Floor {
    /// `self < other`, by cross-multiplication rather than float division: the fractions
    /// are small integers and an == comparison on f64 here would be a coin toss.
    fn worse_than(&self, other: &Floor) -> bool {
        self.named * other.total < other.named * self.total
    }
}

fn coverage(args: &[String]) {
    use libawdl::coverage::{is_decoded, of_tlv, Coverage};
    use std::collections::BTreeMap;

    let mut files: Vec<String> = Vec::new();
    let mut baseline: Option<String> = None;
    let mut update: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--baseline" => {
                baseline = args.get(i + 1).cloned();
                i += 2;
            }
            "--update-baseline" => {
                update = args.get(i + 1).cloned();
                i += 2;
            }
            f => {
                files.push(f.to_string());
                i += 1;
            }
        }
    }
    let files = &files[..];

    let mut per_tag: BTreeMap<u8, (Coverage, u64)> = BTreeMap::new();
    let mut floors: BTreeMap<u8, Floor> = BTreeMap::new();
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
                let c = of_tlv(t.tag, t.value);
                let e = per_tag.entry(t.tag).or_insert((Coverage::default(), 0));
                e.0.add(c);
                e.1 += 1;
                // A zero-length tag is a presence flag: there is nothing to classify and
                // 0/0 is not a fraction. Excluded rather than counted as 0%.
                if c.total() > 0 {
                    let f = Floor { named: c.named, total: c.total() };
                    let slot = floors.entry(t.tag).or_insert(f);
                    if f.worse_than(slot) {
                        *slot = f;
                    }
                }
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
        "{:<4} {:<28} {:>7} {:>9} {:>9} {:>6} {:>9}  {}",
        "tag", "name", "TLVs", "named", "opaque", "%", "floor", "lengths seen"
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
        let floor = floors
            .get(tag)
            .map(|f| format!("{}/{}", f.named, f.total))
            .unwrap_or_else(|| "-".to_string());
        println!(
            "{:<4} {:<28} {:>7} {:>9} {:>9} {} {:>9}  {}{}",
            tag,
            libawdl::tlv::tag_name(*tag),
            n,
            c.named,
            c.opaque,
            pct,
            floor,
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

    if let Some(path) = update {
        write_baseline(&path, &floors, &per_tag);
        println!("\nbaseline written to {path}");
        return;
    }
    if let Some(path) = baseline {
        std::process::exit(check_baseline(&path, &floors));
    }
}

/// The committed floor, one line per tag, as `tag named/total`.
///
/// Text rather than JSON so a diff says what moved. Regenerating it is a deliberate act:
/// a floor that drops is either a parser regression or a capture we do not understand,
/// and both want a human deciding which.
fn write_baseline(
    path: &str,
    floors: &std::collections::BTreeMap<u8, Floor>,
    per_tag: &std::collections::BTreeMap<u8, (libawdl::coverage::Coverage, u64)>,
) {
    let mut out = String::new();
    out.push_str("# libawdl coverage floor -- the WORST-classified TLV of each tag.\n");
    out.push_str("#\n");
    out.push_str("# Regenerate with:  awdl coverage captures/*.pcap --update-baseline docs/coverage-floor.txt\n");
    out.push_str("# Check with:       awdl coverage captures/*.pcap --baseline docs/coverage-floor.txt\n");
    out.push_str("#\n");
    out.push_str("# NOT the headline percentage: that is byte-weighted over the corpus and moves\n");
    out.push_str("# whenever a capture is added. This is a pure function of the parser, so a drop\n");
    out.push_str("# means the parser got worse OR a capture arrived carrying a shape we cannot\n");
    out.push_str("# classify. Both should fail; neither should be averaged away.\n");
    out.push_str("#\n");
    out.push_str("# tag  floor       corpus%   name\n");
    for (tag, f) in floors {
        let pct = per_tag
            .get(tag)
            .map(|(c, _)| c.percent_named())
            .unwrap_or(0.0);
        out.push_str(&format!(
            "{:<5} {:<11} {:>7.1}   {}\n",
            tag,
            format!("{}/{}", f.named, f.total),
            pct,
            libawdl::tlv::tag_name(*tag)
        ));
    }
    std::fs::write(path, out).expect("write baseline");
}

/// Returns a process exit code: 0 clean, 3 on drift, 2 if the baseline is unreadable.
///
/// Exit 3 for drift matches the convention the integration scripts already use, where 3
/// means "something changed and you must decide", as distinct from 1 meaning "broken".
fn check_baseline(path: &str, floors: &std::collections::BTreeMap<u8, Floor>) -> i32 {
    let Ok(text) = std::fs::read_to_string(path) else {
        eprintln!("\ncannot read baseline {path}");
        return 2;
    };
    let mut want: std::collections::BTreeMap<u8, Floor> = std::collections::BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.split_whitespace();
        let (Some(tag), Some(frac)) = (it.next(), it.next()) else { continue };
        let Ok(tag) = tag.parse::<u8>() else { continue };
        let Some((n, t)) = frac.split_once('/') else { continue };
        let (Ok(named), Ok(total)) = (n.parse::<usize>(), t.parse::<usize>()) else { continue };
        want.insert(tag, Floor { named, total });
    }

    let mut regressed = Vec::new();
    let mut improved = Vec::new();
    let mut fresh = Vec::new();
    for (tag, now) in floors {
        match want.get(tag) {
            Some(base) if now.worse_than(base) => regressed.push((*tag, *base, *now)),
            Some(base) if base.worse_than(now) => improved.push((*tag, *base, *now)),
            Some(_) => {}
            None => fresh.push((*tag, *now)),
        }
    }

    println!();
    for (tag, base, now) in &improved {
        println!(
            "IMPROVED  tag {tag:<3} {}  {}/{} -> {}/{}",
            libawdl::tlv::tag_name(*tag), base.named, base.total, now.named, now.total
        );
    }
    for (tag, now) in &fresh {
        println!(
            "NEW TAG   tag {tag:<3} {}  {}/{} -- not in the baseline",
            libawdl::tlv::tag_name(*tag), now.named, now.total
        );
    }
    for (tag, base, now) in &regressed {
        println!(
            "REGRESSED tag {tag:<3} {}  {}/{} -> {}/{}",
            libawdl::tlv::tag_name(*tag), base.named, base.total, now.named, now.total
        );
    }

    if !regressed.is_empty() {
        println!();
        println!("A floor fell. Either the parser classifies less than it did, or a capture in");
        println!("the corpus carries a shape it cannot classify. Find out which before running");
        println!("--update-baseline: regenerating is how a real gap becomes the new normal.");
        return 3;
    }
    if improved.is_empty() && fresh.is_empty() {
        println!("coverage floor held on {} tags", floors.len());
    } else {
        println!();
        println!("No regressions. Record the improvements with --update-baseline.");
    }
    0
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
#[allow(clippy::too_many_arguments)]
fn beacon(managed: &str, monitor: &str, channel: u8, secs: u64, psf_per_mif: u32, compete: bool, legacy: bool, metric: Option<u32>, per_window: u32, windows: Option<usize>, follow: bool, tenure: Option<u32>, datapath: Option<&str>) {
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
    // Listening as well as transmitting. Everything before this aimed at OUR cycle, whose
    // phase is decided by when the process started; a cluster already on the air has its
    // own, and it tells us what it is in every frame. See libawdl::follow.
    let mut cluster = libawdl::follow::Cluster::new();
    let mut adopted = false;

    // The data plane shares this loop and this radio. It is not a second process, because
    // two processes cannot both inject on one phy -- the mt76 answers the second with
    // EAGAIN and says nothing in dmesg.
    //
    // OUTBOUND PACKETS ARE QUEUED, NOT SENT ON ARRIVAL, and that is the whole reason this
    // had to merge with the beacon rather than run beside it. An AWDL peer listens only
    // during its availability windows; a data frame sent the moment the kernel hands it
    // over goes out while the peer is deaf, and the sender sees a successful transmit and
    // no reply. So the queue drains in the same windows the beacons go out in.
    let tundev = match datapath {
        #[cfg(target_os = "linux")]
        Some(name) => match libawdl_hal::tun::Tun::open(name) {
            Ok(t) => {
                // Configured here, not printed for the operator to paste. The order
                // matters and one of the three steps fails silently when done late --
                // see Tun::configure.
                match t.configure(addr) {
                    Ok(a) => eprintln!("  --datapath {name}: up on {a}, IPv6 queued and drained in-window"),
                    Err(e) => {
                        eprintln!("  --datapath {name}: opened but NOT configured: {e:?}");
                        eprintln!("  the interface exists and carries no address, so nothing will flow.");
                        std::process::exit(1);
                    }
                }
                Some(t)
            }
            Err(e) => {
                eprintln!("{e:?}");
                std::process::exit(1);
            }
        },
        #[cfg(not(target_os = "linux"))]
        Some(_) => {
            eprintln!("--datapath is Linux only: it needs /dev/net/tun.");
            std::process::exit(1);
        }
        None => None,
    };
    // Bounded deliberately. An unbounded queue turns a burst the radio cannot keep up with
    // into unbounded memory and ever-staler packets; dropping the OLDEST is right for a
    // link where a late packet is worth less than a fresh one.
    const OUTBOUND_MAX: usize = 64;
    /// How many queued packets to drain per window visit. One beacon plus a few data
    /// frames fits an extended availability window; emptying a full queue into one window
    /// would overrun it and transmit into the next slot, which is the thing this project
    /// spent three build cycles learning not to do.
    const DRAIN_PER_WINDOW: usize = 4;
    let mut outbound: std::collections::VecDeque<Vec<u8>> = std::collections::VecDeque::new();
    let mut tbuf = vec![0u8; 4096];
    let (mut dp_sent, mut dp_recvd, mut dp_noroute, mut dp_dropped) = (0u64, 0u64, 0u64, 0u64);
    let mut awdl_data_seq: u16 = 0;
    let mut d11_data_seq: u16 = 0;
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
    if let Some(t) = tenure {
        // Sets where our election COUNTER starts. It exists to make the counter and the
        // metric disagree on purpose: OWL orders the election counter-first and this crate
        // orders it metric-first, and no capture held tests the difference because every
        // one begins with the devices already synchronised. Advertising a high metric with
        // a low counter (or the reverse) makes the two rules predict opposite outcomes,
        // so a peer joining from cold answers the question by which way it goes.
        // See FINDINGS 42.
        b.tenure_base = t;
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
    eprintln!("  election counter starts at {}", b.tenure_base);
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
    if follow {
        eprintln!("  --follow: listening for a cluster and adopting its window phase");
    } else {
        eprintln!("  not synchronised to any peer; self-consistent from a monotonic clock");
    }

    // Transmit inside the windows we ADVERTISE, rather than on a fixed period.
    //
    // The old loop slept exactly one cycle between frames, which pinned us to whatever
    // phase the process started on -- measured on the air as 3 of 16 slots, none of them
    // the ones we announce. `awdl phase` is the check.
    eprintln!("  transmitting in advertised slots {:?} of 16, {per_window} frame(s) per window",
        b.advertised_slots());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    let (mut sent_mif, mut sent_psf, mut failed) = (0u64, 0u64, 0u64);
    let mut last_tx_us = 0u64;
    let mut n = 0u32;
    let mut first_error: Option<String> = None;

    while std::time::Instant::now() < deadline {
        // LISTEN FIRST. A frame from the cluster carries aw_counter and aw_remaining, which
        // place a slot boundary on our own clock -- so a short receive before each decision
        // is what turns "our phase" into "theirs". The timeout is deliberately small: this
        // is a poll between transmissions, not a receive loop.
        if follow {
            // A SHORT poll, and the reason is arithmetic. We stamp a frame when `rx`
            // returns, not when it reached the antenna, so the poll interval is injected
            // straight into every anchor as quantisation. At 20 ms against a 65 ms slot
            // that was most of a slot of self-inflicted jitter, and the measured spread
            // went from 3.8-12.4 ms offline to 65 ms live.
            //
            // The real fix is SO_TIMESTAMP -- ask the kernel when the frame arrived rather
            // than asking the clock when we noticed. This is the cheap approximation.
            if let Ok(Some(rx)) = radio.rx(2) {
                let now_us = epoch.elapsed().as_micros() as u64;
                // A data frame is not an action frame, so it never reaches parse_awdl and
                // would otherwise be silently discarded by a loop that only looks for
                // election state.
                if tundev.is_some() {
                    deliver_data_frame(&rx.bytes, addr, tundev.as_ref(), &mut dp_recvd);
                }
                if let Some((src, sync, elect)) = parse_awdl(&rx.bytes) {
                    // Never synchronise to ourselves. Monitor mode hands our own
                    // transmissions straight back, and adopting them would lock the
                    // estimate to the phase we are trying to replace.
                    if src != addr {
                        cluster.observe(now_us, src, &sync, elect.as_ref());
                    }
                }
            }
            // Re-evaluated every pass, not latched. An earlier version set this once and
            // kept aiming with an estimate that had since degraded from 0 to 156 ms of
            // spread -- worse than not following at all, because it was confident.
            let usable = cluster.clock.is_usable();
            if usable != adopted {
                adopted = usable;
                eprintln!(
                    "  {} cluster clock: master {:?}, slots {:?}, spread {:?} us",
                    if usable { "ADOPTED" } else { "DROPPED (estimate degraded)" },
                    cluster.master.map(libawdl::dot11::Mac),
                    cluster.master_slots,
                    cluster.clock.spread_us()
                );
            }
        }

        // Only transmit INSIDE a window we advertise.
        //
        // The first version of this loop sent unconditionally at the top and then waited,
        // which fired in slot 2, slept one window, and fired again in slot 3 -- a slot we
        // do not advertise. Half of every run's frames were in the wrong windows, visible
        // in `awdl phase` as adjacent pairs, and the frame rate was double what it should
        // have been. Waiting FIRST is the whole fix.
        let now_us = epoch.elapsed().as_micros() as u64;
        // Aim at a window the CLUSTER attends when we know where those are; fall back to
        // our own advertised schedule when we do not. `us_until_master_window` already
        // targets slot centres, which is the only sane place to aim.
        let wait = match cluster.us_until_master_window(now_us) {
            Some(w) if follow && adopted => w,
            _ => b.us_until_next_advertised_window(now_us),
        };
        if wait > 0 {
            // Sleep in short hops so reception continues while we wait, rather than going
            // deaf for most of a cycle.
            // Hop in short steps for the same reason: a long sleep is a long deaf spell,
            // and the next frame's timestamp is only as good as how promptly we read it.
            //
            // The gap between windows is also when the kernel's packets are collected. The
            // tun is read here and the frames are BUILT here, but not sent -- see the queue
            // note above.
            if let Some(t) = tundev.as_ref() {
                enqueue_from_tun(
                    t, addr, &mut tbuf, &mut outbound, OUTBOUND_MAX,
                    &mut d11_data_seq, &mut awdl_data_seq, &mut dp_noroute, &mut dp_dropped,
                );
            }
            let hop = wait.min(3_000);
            std::thread::sleep(std::time::Duration::from_micros(hop));
            continue;
        }
        let now_us = epoch.elapsed().as_micros() as u64;
        // One frame per visit to a window. Without this the centre-aimed target stays
        // satisfied for the whole window and the loop spins inside it.
        if follow && last_tx_us > 0 && now_us.saturating_sub(last_tx_us) < u64::from(libawdl::beacon::SLOT_US) / 2 {
            std::thread::sleep(std::time::Duration::from_micros(3_000));
            continue;
        }
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
        // IN-WINDOW DRAIN. The beacon has just gone out, so we are inside a slot the
        // cluster attends and the peer is listening. This is the only moment a data frame
        // is worth sending.
        for _ in 0..DRAIN_PER_WINDOW {
            let Some(f) = outbound.pop_front() else { break };
            match radio.tx(&f, TxParams::default()) {
                Ok(()) => dp_sent += 1,
                Err(e) => {
                    failed += 1;
                    if first_error.is_none() {
                        first_error = Some(format!("{e:?}"));
                    }
                }
            }
        }

        b.advance();
        n += 1;
        last_tx_us = epoch.elapsed().as_micros() as u64;
        // Pace by the interval we ADVERTISE. `action_frame_period` is the PSF interval --
        // OWL sets the field from its own psf_interval and paces by it, and every Apple
        // frame carries 110 TU. Emitting the number and sending at some other rate
        // misdescribes us to every receiver, which this loop did until FINDINGS 42.
        //
        // `per_window` still divides it, as an experimental control only.
        //
        // This knob exists as an EXPERIMENTAL CONTROL, not a tuning parameter. Trial E
        // won an election at 22.5 frames/s while trial F lost one at 11.2 with the same
        // alignment and metric, so rate and window-count were confounded. Holding the
        // windows correct and raising only the rate is what separates them.
        std::thread::sleep(std::time::Duration::from_micros(
            b.psf_interval_us() / u64::from(per_window.max(1)),
        ));
    }

    eprintln!("\nsent {sent_mif} MIF, {sent_psf} PSF, {failed} failed");
    if tundev.is_some() {
        eprintln!(
            "datapath: {dp_sent} sent in-window, {dp_recvd} delivered, {dp_noroute} unroutable, \
             {dp_dropped} dropped (queue full), {} still queued",
            outbound.len()
        );
    }
    if follow {
        eprintln!(
            "cluster: {} anchors, master {:?}, phase {:?}, spread {:?} us, adopted={adopted}",
            cluster.clock.observations(),
            cluster.master.map(libawdl::dot11::Mac),
            cluster.clock.phase_us(),
            cluster.clock.spread_us()
        );
    }
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
    // A channel-sequence slot is presence_mode (4) availability windows, so the cycle is
    // 1024 TU and not 256. Folding onto a quarter of the real period aliases four
    // different slots together, which is what this tool did before OWL was read properly.
    const SLOT_US: u64 = 4 * AW_US;
    const CYCLE_US: u64 = SLOTS * SLOT_US;

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
        let slot = ((t % CYCLE_US) / SLOT_US) as usize;
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

/// Recover a cluster's cycle phase from the frames it sends, without a TSF.
///
/// The adapter reports no TSFT, so the obvious route to synchronisation is closed. It does
/// not matter: `aw_remaining` says how far into its window the sender was, and `aw_counter`
/// says which window — so each frame places a window boundary on OUR clock and identifies
/// it. See `libawdl::follow`.
///
/// Run against a capture to check the estimate converges before trusting it live. The
/// number that decides whether it is usable is the SPREAD, not the phase.
fn follow<T: pcap::Activated + ?Sized>(mut cap: pcap::Capture<T>) {
    use libawdl::election::ElectionParamsV2;
    use libawdl::follow::Cluster;
    use libawdl::sync::SyncParams;

    let mut cl = Cluster::new();
    let mut t0 = 0u64;
    let mut frames = 0u64;

    while let Ok(pkt) = cap.next_packet() {
        let t = (pkt.header.ts.tv_sec as u64).wrapping_mul(1_000_000)
            + pkt.header.ts.tv_usec as u64;
        if t0 == 0 {
            t0 = t;
        }
        let Seen::Awdl { dot11, af, .. } = classify(pkt.data) else { continue };
        frames += 1;
        let (mut sync, mut elect) = (None, None);
        for tlv in af.tlvs() {
            match tlv.tag {
                4 => sync = SyncParams::parse(tlv.value),
                24 => elect = ElectionParamsV2::parse(tlv.value),
                _ => {}
            }
        }
        let Some(sync) = sync else { continue };
        cl.observe(t - t0, dot11.src.0, &sync, elect.as_ref());
    }

    println!("{frames} AWDL frames");
    match cl.master {
        Some(m) => println!("master:  {} (metric {:?})", libawdl::dot11::Mac(m), cl.master_metric),
        None => {
            println!("no master identified");
            return;
        }
    }
    println!("slots:   {:?} of 16", cl.master_slots);
    println!("anchors: {} frames from the master", cl.clock.observations());
    let slot_us = cl.clock.slot_us();
    match (cl.clock.phase_us(), cl.clock.spread_us()) {
        (Some(p), Some(spread)) => {
            println!("phase:   {p} us into a {} us cycle", cl.clock.cycle());
            // Against the SLOT, which is presence_mode availability windows. Quoting it
            // against a single window overstates the error fourfold.
            println!(
                "spread:  {spread} us  ({:.1}% of a {slot_us} us slot)",
                100.0 * spread as f64 / slot_us as f64
            );
            // Aim at the window's CENTRE and the margin is half a window either side, so
            // what has to fit is half the spread. Say the arithmetic rather than a verdict.
            let half = spread / 2;
            let margin = slot_us / 2;
            if cl.clock.is_usable() {
                println!(
                    "VERDICT: usable — half the spread is {half} us against {margin} us of margin"
                );
                println!("         (aim at the window's centre; the boundary is the worst target)");
            } else {
                println!(
                    "VERDICT: NOT usable — half the spread is {half} us, over {margin} us of margin,"
                );
                println!("         so a transmission aimed at a window can land outside it.");
                println!("         Host timestamps on a USB adapter are the likely limit.");
            }
        }
        _ => println!("not enough anchors for a phase"),
    }
}

/// Pull the two TLVs the clock needs out of a received frame.
///
/// Returns the sender as well, because a sighting is only meaningful attributed — and
/// because our own frames come straight back on a monitor interface and must be dropped.
fn parse_awdl(
    bytes: &[u8],
) -> Option<([u8; 6], libawdl::sync::SyncParams, Option<libawdl::election::ElectionParamsV2>)> {
    use libawdl::{action::ActionFrame, dot11::Dot11, election::ElectionParamsV2, radiotap::Radiotap,
                  sync::SyncParams, tlv};
    let rt = Radiotap::parse(bytes)?;
    let body = rt.payload(bytes)?;
    let d = Dot11::parse(body)?;
    if !d.is_action() {
        return None;
    }
    let af = ActionFrame::parse(body.get(d.body_offset..)?)?;
    let (mut sync, mut elect) = (None, None);
    for t in tlv::Tlvs::new(af.tagged) {
        match t.tag {
            4 => sync = SyncParams::parse(t.value),
            24 => elect = ElectionParamsV2::parse(t.value),
            _ => {}
        }
    }
    Some((d.src.0, sync?, elect))
}

/// Which bytes of a tag ever change, measured over the whole corpus.
///
/// WHY THIS IS NOT THE SAME QUESTION AS COVERAGE. `coverage` splits bytes into named and
/// opaque, where opaque means "we cannot say what it is". That conflates two very
/// different situations:
///
///   - a byte that takes 44 different values across the corpus is carrying information
///     we do not understand. It is a real gap, and copying Apple's value is a guess.
///   - a byte that has been 0x00 in all 37,829 frames is not obviously carrying anything.
///     Reproducing it correctly requires no understanding at all.
///
/// Both count as opaque today, which makes the opaque total a worse work queue than it
/// looks: some of it is genuinely unknown and some of it is very probably padding.
///
/// The repository already set the precedent for how to resolve that, on tag 18's three
/// trailing bytes -- "confirmed zero in all 7054 samples, measured, so named as padding
/// rather than assumed". This command produces that evidence for every tag at once.
///
/// WHAT IT CANNOT TELL YOU. Constant across THIS corpus is not constant across the
/// protocol. Every capture here comes from a handful of Apple device models, one Pixel
/// and one Pi; a field that identifies something all of them share would look like
/// padding and is not. The sample size is a floor on confidence, not a proof, and a run
/// of `.` on a tag seen 66 times means very little next to one seen 37,829 times.
fn bytemap(args: &[String]) {
    use std::collections::BTreeMap;

    let mut files: Vec<&str> = Vec::new();
    let mut only: Option<u8> = None;
    for a in args {
        match a.parse::<u8>() {
            Ok(t) => only = Some(t),
            Err(_) => files.push(a),
        }
    }

    // (tag, len) -> per-offset set of values seen. A 256-bit set per offset: the tags are
    // short and this stays trivially small next to the captures themselves.
    let mut seen: BTreeMap<(u8, usize), (Vec<[u64; 4]>, u64)> = BTreeMap::new();

    for f in &files {
        let Ok(mut cap) = pcap::Capture::from_file(f) else {
            eprintln!("skipping {f}: not a capture");
            continue;
        };
        while let Ok(pkt) = cap.next_packet() {
            let Seen::Awdl { af, .. } = classify(pkt.data) else { continue };
            for t in af.tlvs() {
                if only.is_some_and(|o| o != t.tag) {
                    continue;
                }
                // Tag 2 is DNS: fully named, variable-length by nature, and a byte map of
                // it would be a map of whatever names happened to be on the air.
                if only.is_none() && t.tag == 2 {
                    continue;
                }
                let len = t.value.len();
                if len == 0 || len > 256 {
                    continue;
                }
                let e = seen.entry((t.tag, len)).or_insert_with(|| (vec![[0u64; 4]; len], 0));
                e.1 += 1;
                for (i, b) in t.value.iter().enumerate() {
                    e.0[i][usize::from(*b) / 64] |= 1u64 << (u32::from(*b) % 64);
                }
            }
        }
    }

    if seen.is_empty() {
        eprintln!("no AWDL frames");
        return;
    }

    println!("Which bytes ever vary, per tag and per TLV length.\n");
    println!("  .  one value in every sample -- never varied");
    println!("  2-9  that many distinct values      +  ten or more");
    println!();

    for ((tag, len), (offs, n)) in &seen {
        let name = libawdl::tlv::tag_name(*tag);
        println!("tag {tag:<3} len {len:<4} n={n:<7} {name}");

        let mut map = String::new();
        for o in offs {
            let d: u32 = o.iter().map(|w| w.count_ones()).sum();
            map.push(match d {
                0 | 1 => '.',
                2..=9 => char::from(b'0' + d as u8),
                _ => '+',
            });
        }
        // Wrapped at 64 with an offset ruler, so a run of dots can be read back to a
        // byte offset without counting on screen.
        for (row, chunk) in map.as_bytes().chunks(64).enumerate() {
            println!("  {:>4}  {}", row * 64, std::str::from_utf8(chunk).unwrap());
        }

        // The constant runs, with their values -- this is the part that can be acted on.
        let mut runs: Vec<(usize, usize)> = Vec::new();
        let mut start: Option<usize> = None;
        for (i, o) in offs.iter().enumerate() {
            let d: u32 = o.iter().map(|w| w.count_ones()).sum();
            match (d <= 1, start) {
                (true, None) => start = Some(i),
                (false, Some(s)) => {
                    runs.push((s, i));
                    start = None;
                }
                _ => {}
            }
        }
        if let Some(s) = start {
            runs.push((s, offs.len()));
        }
        for (a, b) in &runs {
            let vals: Vec<String> = (*a..*b)
                .map(|i| {
                    let set = &offs[i];
                    for v in 0..=255u32 {
                        if set[v as usize / 64] & (1u64 << (v % 64)) != 0 {
                            return format!("{v:02x}");
                        }
                    }
                    "--".to_string()
                })
                .collect();
            println!("        constant {a}..{} = {}", b - 1, vals.join(" "));
        }
        println!();
    }

    println!("Constant across THIS corpus is not constant across the protocol. These");
    println!("captures come from a few Apple models, one Pixel and one Pi -- a field every");
    println!("one of them happens to share reads as padding here and is not. Weigh a run of");
    println!("dots by its n: 37,829 samples is evidence, 66 is barely a hint.");
}

/// Match every undecoded byte window against every field we already understand, within
/// the SAME frame.
///
/// This is the method that identified tag 12's relayed master counter (finding 49), and
/// it beat staring at the bytes by a wide margin -- staring produced two exact-looking
/// relations from three samples of one device, and neither survived the corpus.
///
/// THE TRAP, and it is why the variation filter is not optional. Most unknown bytes are
/// zero and most known fields are zero most of the time, so a naive comparison reports
/// pairs of zeros as 100% matches. The first run of this printed four such pairings for
/// tag 33 and they were all a constant zero byte agreeing with a mostly-zero field.
/// Requiring both sides to take three distinct values is NOT enough on its own -- a field
/// taking 1293 values while sitting at zero in 96% of frames still matches any mostly-zero
/// byte. So the score is computed only over the frames where the known field is NOT at its
/// most common value. Two fields that are really the same agree there too; two fields that
/// merely share a popular value do not, and drop from 96% to nothing.
///
/// Comparing inside one frame is the other half. Two counters sampled from different
/// frames drift apart for reasons that have nothing to do with whether they are the same
/// counter, and a match found across frames would need a story about timing. A match
/// inside one frame does not.
fn correlate(files: &[String]) {
    use libawdl::election::ElectionParamsV2;
    use libawdl::state::DataPathState;
    use libawdl::sync::SyncParams;
    use std::collections::{BTreeMap, BTreeSet};

    // (tag, "off..off+n") -> known field -> (matches, total)
    let mut score: BTreeMap<(u8, String, &'static str), (u64, u64)> = BTreeMap::new();
    let mut spread: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();
    // Scored a second time over only the frames where the known field is off its modal
    // value. This is the number that decides; the raw rate is kept for contrast.
    let mut offmode: BTreeMap<(u8, String, &'static str), (u64, u64)> = BTreeMap::new();
    let mut mode_count: BTreeMap<&'static str, BTreeMap<u32, u64>> = BTreeMap::new();
    let mut frames: Vec<(Vec<(u8, Vec<u8>)>, Vec<(&'static str, u32)>)> = Vec::new();

    for f in files {
        let Ok(mut cap) = pcap::Capture::from_file(f) else {
            eprintln!("skipping {f}: not a capture");
            continue;
        };
        while let Ok(pkt) = cap.next_packet() {
            let Seen::Awdl { af, .. } = classify(pkt.data) else { continue };

            let mut known: Vec<(&'static str, u32)> = Vec::new();
            let mut tlvs: Vec<(u8, Vec<u8>)> = Vec::new();
            for t in af.tlvs() {
                tlvs.push((t.tag, t.value.to_vec()));
                match t.tag {
                    4 => {
                        if let Some(s) = SyncParams::parse(t.value) {
                            known.push(("sync.tx_counter", s.tx_counter.into()));
                            known.push(("sync.aw_counter", s.aw_counter.into()));
                            known.push(("sync.aw_remaining", s.aw_remaining.into()));
                            known.push(("sync.ap_beacon_delta", s.ap_beacon_alignment_delta.into()));
                        }
                    }
                    24 => {
                        if let Some(e) = ElectionParamsV2::parse(t.value) {
                            known.push(("ev2.master_counter", e.master_counter));
                            known.push(("ev2.self_counter", e.self_counter));
                            known.push(("ev2.self_metric", e.self_metric));
                            known.push(("ev2.master_metric", e.master_metric));
                            known.push(("ev2.distance", e.distance));
                        }
                    }
                    12 => {
                        if let Some(d) = DataPathState::parse(t.value) {
                            if let Some(c) = d.ext_clock_ms() { known.push(("dps.clock_ms", c)) }
                            if let Some(a) = d.ext_aw_counter() { known.push(("dps.aw_counter", a)) }
                        }
                    }
                    _ => {}
                }
            }
            if known.is_empty() { continue }
            for (kn, kv) in &known {
                spread.entry((*kn).to_string()).or_default().insert(*kv);
                *mode_count.entry(kn).or_default().entry(*kv).or_insert(0) += 1;
            }
            frames.push((tlvs.clone(), known.clone()));

            for (tag, v) in &tlvs {
                // Tag 2 is DNS and fully named; there is nothing here to look for.
                if *tag == 2 { continue }
                for off in 0..v.len() {
                    for width in [1usize, 2, 4] {
                        if off + width > v.len() { continue }
                        let mut buf = [0u8; 4];
                        buf[..width].copy_from_slice(&v[off..off + width]);
                        let cv = u32::from_le_bytes(buf);
                        let key = format!("t{tag}[{off}..{}]", off + width);
                        spread.entry(key.clone()).or_default().insert(cv);
                        for (kn, kv) in &known {
                            let e = score.entry((*tag, key.clone(), kn)).or_insert((0, 0));
                            e.1 += 1;
                            if cv == *kv { e.0 += 1 }
                        }
                    }
                }
            }
        }
    }

    // Second pass, now that the modal value of each known field is known.
    let modes: BTreeMap<&'static str, u32> = mode_count
        .iter()
        .filter_map(|(k, m)| m.iter().max_by_key(|(_, n)| **n).map(|(v, _)| (*k, *v)))
        .collect();
    for (tlvs, known) in &frames {
        for (tag, v) in tlvs {
            if *tag == 2 { continue }
            for off in 0..v.len() {
                for width in [1usize, 2, 4] {
                    if off + width > v.len() { continue }
                    let mut buf = [0u8; 4];
                    buf[..width].copy_from_slice(&v[off..off + width]);
                    let cv = u32::from_le_bytes(buf);
                    let key = format!("t{tag}[{off}..{}]", off + width);
                    for (kn, kv) in known {
                        if modes.get(kn) == Some(kv) { continue }
                        let e = offmode.entry((*tag, key.clone(), kn)).or_insert((0, 0));
                        e.1 += 1;
                        if cv == *kv { e.0 += 1 }
                    }
                }
            }
        }
    }

    println!("Undecoded byte windows matching a known field, in the same frame.\n");
    println!("Both sides must take 3+ distinct values: a constant zero byte agreeing with a");
    println!("mostly-zero field is two zeros, not a match, and that is most of what a naive");
    println!("run reports.\n");
    println!("{:<16} {:<22} {:>8} {:>9} {:>9}", "window", "known field", "off-mode", "raw", "frames");

    let mut shown = 0u32;
    let mut rows: Vec<(f64, String)> = Vec::new();
    for ((_t, cn, kn), (hit, tot)) in &score {
        if *tot == 0 { continue }
        let pct = 100.0 * *hit as f64 / *tot as f64;
        let cs = spread.get(cn).map_or(0, |s| s.len());
        let ks = spread.get(*kn).map_or(0, |s| s.len());
        let (ohit, otot) = offmode.get(&(*_t, cn.clone(), *kn)).copied().unwrap_or((0, 0));
        if otot < 50 { continue }
        let opct = 100.0 * ohit as f64 / otot as f64;
        if opct >= 50.0 && cs >= 3 && ks >= 3 {
            rows.push((opct, format!("{cn:<16} {kn:<22} {opct:>7.1}% {pct:>8.1}% {otot:>9}")));
        }
    }
    rows.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    for (_, r) in rows.iter().take(40) {
        println!("{r}");
        shown += 1;
    }
    if shown == 0 {
        println!("(nothing above 50% survives the filter)");
    }
}

/// Open the `awdl0` netdev and hold it, so the interface can be inspected from elsewhere.
///
/// A diagnostic, not the data plane. It proves three things that are easy to assume: the
/// tun module is loaded, we have CAP_NET_ADMIN, and the name is free. Those are the
/// failures that otherwise surface much later as "the peer sent us nothing".
///
/// It deliberately does NOT bring the interface up or assign an address. Both are the
/// caller's job and the commands are printed instead, because an address that does not
/// match the one peers compute from our MAC means they send to somebody else -- and that
/// failure looks exactly like nothing listening on the port.
#[cfg(target_os = "linux")]
fn tun(args: &[String]) {
    use libawdl_hal::tun::Tun;

    let name = args.first().map(|s| s.as_str()).unwrap_or("awdl0");
    let secs: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(10);

    let t = match Tun::open(name) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{e:?}");
            std::process::exit(1);
        }
    };
    println!("opened {} -- it exists only while this process holds it", t.name());

    if let Some(mac) = args.get(2).and_then(|s| parse_mac(s)) {
        let a = libawdl::data::link_local_from_mac(mac);
        // Canonical compressed form -- what `ip` prints back, so the output can be
        // compared against `ip -6 addr show` without squinting.
        let addr = std::net::Ipv6Addr::from(a);
        println!();
        println!("the address peers will compute for {}:", fmt_mac(mac));
        println!("  {addr}");
        println!();
        println!("so the interface needs exactly that, and a rule, or nothing is consulted:");
        // addr_gen_mode FIRST: it is only read when the interface comes up, and without it
        // the kernel adds a stable-privacy link-local beside ours and may use that as the
        // source address -- replies then come from an address no peer has heard of.
        println!("  sysctl -w net.ipv6.conf.{name}.addr_gen_mode=1   # BEFORE up, or the");
        println!("                                                  # kernel adds its own");
        println!("  ip link set {name} up");
        println!("  ip -6 addr add {addr}/64 dev {name} scope link");
        println!("  ip -6 route add fe80::/64 dev {name} table 200");
        println!("  ip -6 rule add iif {name} table 200");
    }

    println!();
    println!("holding for {secs}s -- check it with:  ip -6 addr show {name}");
    std::thread::sleep(std::time::Duration::from_secs(secs));
    println!("released");
}

#[cfg(not(target_os = "linux"))]
fn tun(_args: &[String]) {
    eprintln!("awdl tun is Linux only: it is /dev/net/tun and a TUNSETIFF ioctl.");
    std::process::exit(1);
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut m = [0u8; 6];
    for (d, p) in m.iter_mut().zip(parts) {
        *d = u8::from_str_radix(p, 16).ok()?;
    }
    Some(m)
}

fn fmt_mac(m: [u8; 6]) -> String {
    m.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

/// The data plane: carry IP between the kernel and the radio.
///
/// One loop over `poll`, not two threads. A blocking read on either descriptor starves the
/// other, and two threads would need a lock around a radio that can only send one frame at
/// a time anyway.
///
/// ## Three filters, and what each is actually worth
///
/// **Frames from our own MAC are dropped.** Whether a monitor interface hears its own
/// injections is adapter-dependent, and on the MT7612U used here it does **not**: a run
/// that transmitted six frames counted `own 0`. So this filter earned nothing on this
/// hardware and stays anyway, because if an adapter does loop back, every packet we send is
/// re-injected into the kernel, answered, and sent again — and a feedback loop is a much
/// worse failure than a redundant comparison. Measured, not assumed, and the counter is
/// printed so the next adapter can be checked rather than guessed at.
///
/// **Other peers' unicast is not ours to deliver.** In a cluster of three, a monitor sees
/// A talking to B. Handing that to our stack gives us traffic addressed to somebody else.
///
/// **A packet the kernel hands us may have nowhere to go.** AWDL has no address
/// resolution: a destination is either multicast, or a link-local whose MAC can be
/// reversed out of it, or undeliverable. Counted and dropped rather than guessed —
/// a frame sent to an invented MAC goes to nobody and looks like packet loss.
#[cfg(target_os = "linux")]
fn datapath(args: &[String]) {
    use libawdl::data::{decapsulate, dst_mac_for_ipv6, is_ipv6_multicast, Encap, ETHERTYPE_IPV6};
    use libawdl_hal::{poll::wait_readable, rawsock::RawSock, tun::Tun};
    use std::os::fd::AsRawFd;

    let verbose = args.iter().any(|a| a == "--verbose");
    let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();

    let Some(mon) = positional.first() else {
        eprintln!("awdl datapath <mon-iface> <our-mac> [tun-name] [secs] [--verbose]");
        std::process::exit(2);
    };
    let Some(our_mac) = positional.get(1).and_then(|s| parse_mac(s)) else {
        eprintln!("need our AWDL MAC as the second argument, e.g. 00:c0:ca:b0:60:4c");
        eprintln!("peers compute our IPv6 from it, so it must be the address we advertise.");
        std::process::exit(2);
    };
    let name = positional.get(2).map(|s| s.as_str()).unwrap_or("awdl0");
    let secs: u64 = positional.get(3).and_then(|s| s.parse().ok()).unwrap_or(30);

    let tun = match Tun::open(name) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{e:?}");
            std::process::exit(1);
        }
    };
    let sock = match RawSock::open(mon) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e:?}");
            std::process::exit(1);
        }
    };

    let addr = match tun.configure(our_mac) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e:?}");
            std::process::exit(1);
        }
    };
    println!("datapath: {name} <-> {mon}, as {} on {addr}", fmt_mac(our_mac));
    println!();

    let mut tbuf = vec![0u8; 4096];
    let mut rbuf = vec![0u8; 4096];
    let (mut sent, mut recvd, mut no_route, mut own, mut not_ours, mut not_awdl) =
        (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let mut d11_seq: u16 = 0;
    let mut awdl_seq: u16 = 0;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    while std::time::Instant::now() < deadline {
        let ready = match wait_readable(tun.as_raw_fd(), sock.as_raw_fd(), 250) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{e:?}");
                break;
            }
        };

        // Kernel -> radio.
        if ready.first {
            match tun.read(&mut tbuf) {
                Ok(n) => {
                    let pkt = &tbuf[..n];
                    match dst_mac_for_ipv6(pkt) {
                        Some(dst) => {
                            let f = Encap::unicast(our_mac, dst)
                                .frame(d11_seq, awdl_seq, ETHERTYPE_IPV6, pkt);
                            match sock.tx(&f) {
                                Ok(()) => {
                                    sent += 1;
                                    d11_seq = (d11_seq + 1) & 0x0fff;
                                    awdl_seq = awdl_seq.wrapping_add(1);
                                    if verbose {
                                        println!("tx {n:>4}B -> {}", fmt_mac(dst));
                                    }
                                }
                                Err(e) => eprintln!("tx: {e:?}"),
                            }
                        }
                        None => {
                            no_route += 1;
                            if verbose {
                                println!("drop {n}B: no AWDL route to that address");
                            }
                        }
                    }
                }
                Err(e) => eprintln!("tun read: {e:?}"),
            }
        }

        // Radio -> kernel.
        if ready.second {
            match sock.rx(&mut rbuf) {
                Ok(Some(n)) => {
                    let pkt = &rbuf[..n];
                    let parsed = Radiotap::parse(pkt)
                        .and_then(|rt| rt.payload(pkt))
                        .and_then(decapsulate);
                    match parsed {
                        Some(d) if d.src == our_mac => own += 1,
                        Some(d) if d.dst != our_mac && !is_ipv6_multicast(d.dst) => not_ours += 1,
                        Some(d) => match tun.write(d.payload) {
                            Ok(_) => {
                                recvd += 1;
                                if verbose {
                                    println!(
                                        "rx {:>4}B <- {}  seq {}",
                                        d.payload.len(),
                                        fmt_mac(d.src),
                                        d.header.sequence
                                    );
                                }
                            }
                            Err(e) => eprintln!("tun write: {e:?}"),
                        },
                        None => not_awdl += 1,
                    }
                }
                Ok(None) => {}
                Err(e) => eprintln!("rx: {e:?}"),
            }
        }
    }

    println!();
    println!("sent      {sent:>8}   kernel -> radio");
    println!("received  {recvd:>8}   radio -> kernel");
    println!("no route  {no_route:>8}   dropped: not multicast and no MAC in the address");
    println!("own       {own:>8}   our own frames, heard back on the monitor and ignored");
    println!("not ours  {not_ours:>8}   another peer's unicast");
    println!("not awdl  {not_awdl:>8}   everything else on the channel");
}

#[cfg(not(target_os = "linux"))]
fn datapath(_args: &[String]) {
    eprintln!("awdl datapath is Linux only: it needs /dev/net/tun and an AF_PACKET socket.");
    std::process::exit(1);
}

/// Collect whatever the kernel has for us and build frames, WITHOUT sending them.
///
/// Reading is non-blocking by construction: this is only called from the gap between
/// availability windows, and it takes at most a handful of packets per visit so that a
/// busy interface cannot hold the loop past the next window. Missing a window is worse
/// than a packet waiting one more cycle.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn enqueue_from_tun(
    tun: &libawdl_hal::tun::Tun,
    our_mac: [u8; 6],
    buf: &mut [u8],
    queue: &mut std::collections::VecDeque<Vec<u8>>,
    max: usize,
    d11_seq: &mut u16,
    awdl_seq: &mut u16,
    unroutable: &mut u64,
    dropped: &mut u64,
) {
    use libawdl::data::{dst_mac_for_ipv6, Encap, ETHERTYPE_IPV6};
    use libawdl_hal::poll::wait_readable;
    use std::os::fd::AsRawFd;

    for _ in 0..4 {
        // Polled with a zero timeout rather than read blindly: a TUN read with nothing
        // waiting blocks, and blocking here means going deaf and missing the window.
        match wait_readable(tun.as_raw_fd(), tun.as_raw_fd(), 0) {
            Ok(r) if r.first => {}
            _ => return,
        }
        let n = match tun.read(buf) {
            Ok(n) => n,
            Err(_) => return,
        };
        let pkt = &buf[..n];
        let Some(dst) = dst_mac_for_ipv6(pkt) else {
            *unroutable += 1;
            continue;
        };
        let frame =
            Encap::unicast(our_mac, dst).frame(*d11_seq, *awdl_seq, ETHERTYPE_IPV6, pkt);
        *d11_seq = (*d11_seq + 1) & 0x0fff;
        *awdl_seq = awdl_seq.wrapping_add(1);
        if queue.len() >= max {
            // Oldest first. On a link where a packet may wait a whole cycle, the stale end
            // of the queue is the part worth losing.
            queue.pop_front();
            *dropped += 1;
        }
        queue.push_back(frame);
    }
}

/// Hand a received AWDL data frame to the kernel, if it is one and if it is ours.
#[cfg(target_os = "linux")]
fn deliver_data_frame(
    bytes: &[u8],
    our_mac: [u8; 6],
    tun: Option<&libawdl_hal::tun::Tun>,
    delivered: &mut u64,
) {
    use libawdl::data::{decapsulate, is_ipv6_multicast};

    let Some(tun) = tun else { return };
    let Some(d) = Radiotap::parse(bytes).and_then(|rt| rt.payload(bytes)).and_then(decapsulate)
    else {
        return;
    };
    // Ours, or a group we are in. Our own frames are excluded for the reason in
    // `datapath`: whether a monitor hears its own injections is adapter-dependent, and a
    // feedback loop is much worse than a redundant comparison.
    if d.src == our_mac || (d.dst != our_mac && !is_ipv6_multicast(d.dst)) {
        return;
    }
    if tun.write(d.payload).is_ok() {
        *delivered += 1;
    }
}

// Stubs so the beacon loop compiles on a development machine, where there is no
// /dev/net/tun and --datapath exits before reaching either of these.
#[cfg(not(target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
fn enqueue_from_tun(
    _t: &(), _m: [u8; 6], _b: &mut [u8],
    _q: &mut std::collections::VecDeque<Vec<u8>>, _max: usize,
    _d: &mut u16, _a: &mut u16, _u: &mut u64, _dr: &mut u64,
) {
}

#[cfg(not(target_os = "linux"))]
fn deliver_data_frame(_bytes: &[u8], _our_mac: [u8; 6], _tun: Option<&()>, _delivered: &mut u64) {}

#[cfg(test)]
mod tests {
    use super::Floor;

    /// The floors that actually occur have unequal denominators, which is the whole reason
    /// this is a cross-multiplication and not `named as f64 / total as f64`. Tag 7's floor
    /// is 5/20 and tag 12's is 21/47; comparing those as floats is fine until two of them
    /// are equal-but-not-bitwise-equal and a ratchet starts flapping.
    #[test]
    fn floors_compare_as_fractions_not_floats() {
        let tag7 = Floor { named: 5, total: 20 }; // 25.0%
        let tag12 = Floor { named: 21, total: 47 }; // 44.7%
        assert!(tag7.worse_than(&tag12));
        assert!(!tag12.worse_than(&tag7));
    }

    /// Equal fractions written differently must not read as a regression. 1/3 and 2/6 are
    /// the same floor, and a tag whose TLV length doubles between captures produces exactly
    /// this shape.
    #[test]
    fn equal_fractions_with_different_denominators_are_not_a_regression() {
        let a = Floor { named: 1, total: 3 };
        let b = Floor { named: 2, total: 6 };
        assert!(!a.worse_than(&b));
        assert!(!b.worse_than(&a));
    }

    /// A tag that names nothing is the floor, and it is not worse than itself -- otherwise
    /// tag 6 (0/9, a hash we cannot compute) would fail the ratchet on every run.
    #[test]
    fn naming_nothing_is_stable_rather_than_perpetually_regressing() {
        let six = Floor { named: 0, total: 9 };
        assert!(!six.worse_than(&six));
        assert!(six.worse_than(&Floor { named: 1, total: 9 }));
    }

    /// The EUI-64 rule exists twice -- in `libawdl::data` with the tests, and in
    /// `libawdl_hal::tun` so the HAL need not depend on the protocol crate. A silent
    /// divergence would configure the interface with an address no peer computes, and the
    /// symptom would be a peer that discovers us and never gets a reply.
    #[test]
    #[cfg(target_os = "linux")]
    fn the_two_copies_of_the_eui64_rule_agree() {
        for mac in [
            [0x00, 0xc0, 0xca, 0xb0, 0x60, 0x4c],
            [0x8a, 0xc3, 0xf7, 0x4b, 0xce, 0xde],
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x00],
        ] {
            assert_eq!(
                libawdl::data::link_local_from_mac(mac),
                libawdl_hal::tun::link_local(mac),
                "the HAL and the protocol crate disagree for {mac:02x?}"
            );
        }
    }

    /// Fully named is the ceiling and never reads as worse, whatever it is compared against.
    #[test]
    fn a_fully_named_tag_is_never_worse() {
        let full = Floor { named: 41, total: 41 };
        assert!(!full.worse_than(&Floor { named: 68, total: 73 }));
        assert!(Floor { named: 68, total: 73 }.worse_than(&full));
    }
}
