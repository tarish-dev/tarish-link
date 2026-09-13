//! Who is on the air: class, services, host name, and how strong.
//!
//! Signal is the discriminator that matters for "is this in the building": AWDL carries
//! through walls, so a neighbour's phone is a real possibility and shows up quiet.
use libawdl::{action::ActionFrame, dot11::Dot11, radiotap::Radiotap, service, state::{Arpa, Version}, tlv};
use std::collections::{BTreeMap, BTreeSet};
fn main() {
    struct D { cls: BTreeSet<String>, svc: BTreeSet<String>, name: BTreeSet<String>, rssi: Vec<i8>, n: u64 }
    let mut per: BTreeMap<String, D> = BTreeMap::new();
    for f in std::env::args().skip(1) {
        let Ok(mut cap) = pcap::Capture::from_file(&f) else { continue };
        while let Ok(p) = cap.next_packet() {
            let Some(rt) = Radiotap::parse(p.data) else { continue };
            let Some(b) = rt.payload(p.data) else { continue };
            let Some(d) = Dot11::parse(b) else { continue };
            if !d.is_action() { continue }
            let Some(af) = ActionFrame::parse(&b[24..]) else { continue };
            let e = per.entry(d.src.to_string()).or_insert(D {
                cls: Default::default(), svc: Default::default(),
                name: Default::default(), rssi: vec![], n: 0 });
            e.n += 1;
            if let Some(s) = rt.signal_dbm { e.rssi.push(s) }
            for t in tlv::Tlvs::new(af.tagged) {
                match t.tag {
                    21 => { if let Some(v) = Version::parse(t.value) {
                        e.cls.insert(format!("{} v{}.{}", v.class_name(), v.major, v.minor)); } }
                    16 => { if let Some(a) = Arpa::parse(t.value) { e.name.insert(a.name); } }
                    2 => { for r in service::records(t.value) {
                        if let service::Record::Ptr { name, .. } = r {
                            e.svc.insert(name.replace("._tcp.local", "").replace("._udp.local", ""));
                        } } }
                    _ => {}
                }
            }
        }
    }
    for (src, d) in &per {
        let med = if d.rssi.is_empty() { None } else {
            let mut v = d.rssi.clone(); v.sort_unstable(); Some(v[v.len()/2]) };
        println!("{src}  {} frames  signal {:?} dBm", d.n, med);
        println!("     class:    {:?}", d.cls);
        if !d.name.is_empty() { println!("     name:     {:?}", d.name); }
        if !d.svc.is_empty()  { println!("     services: {:?}", d.svc); }
    }
}
