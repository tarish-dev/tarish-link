//! Are our data frames in the same availability windows as our beacons?
//!
//! The merged loop queues outbound packets and drains them immediately after a beacon, on
//! the claim that this puts them inside a window the cluster attends. That claim is only
//! worth anything if measured: for each data frame we sent, how long since our last
//! action frame?
use libawdl::{data::decapsulate, dot11::Dot11, radiotap::Radiotap, action::ActionFrame};

const US: f64 = 1_000_000.0;

fn main() {
    let path = std::env::args().nth(1).expect("usage: inwindow <pcap> <our-mac>");
    let mac: [u8; 6] = {
        let s = std::env::args().nth(2).expect("usage: inwindow <pcap> <our-mac>");
        let parts: Vec<&str> = s.split(':').collect();
        assert_eq!(parts.len(), 6, "a MAC has six octets");
        let mut m = [0u8; 6];
        for (d, p) in m.iter_mut().zip(parts) {
            *d = u8::from_str_radix(p, 16).expect("hex octet");
        }
        m
    };
    let mut cap = pcap::Capture::from_file(&path).expect("open");

    let mut last_action: Option<f64> = None;
    let mut deltas: Vec<f64> = Vec::new();
    let mut action_n = 0u64;

    while let Ok(p) = cap.next_packet() {
        let t = p.header.ts.tv_sec as f64 + p.header.ts.tv_usec as f64 / US;
        let Some(rt) = Radiotap::parse(p.data) else { continue };
        let Some(body) = rt.payload(p.data) else { continue };

        // Ours only. Another sender's frames say nothing about our own windowing.
        if let Some(d) = Dot11::parse(body) {
            if d.src == libawdl::dot11::Mac(mac) && d.is_action()
                && body.get(d.body_offset..).and_then(ActionFrame::parse).is_some()
            {
                last_action = Some(t);
                action_n += 1;
                continue;
            }
        }
        if let Some(d) = decapsulate(body) {
            if d.src != mac { continue }
            if let Some(la) = last_action {
                deltas.push((t - la) * 1000.0);
            } else {
                println!("data frame before any beacon of ours -- cannot place it");
            }
        }
    }

    println!("our action frames: {action_n}");
    println!("our data frames:   {}", deltas.len());
    if deltas.is_empty() {
        return;
    }
    deltas.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!("\nms since our previous beacon, per data frame:");
    for d in &deltas {
        println!("   {d:8.2} ms");
    }
    // An extended availability window is 4 x 16 TU = 65.536 ms. A data frame drained right
    // after a beacon should be a small fraction of that; anything past it went out while
    // the cluster was on another channel.
    let eaw = 65.536;
    let inside = deltas.iter().filter(|d| **d >= 0.0 && **d < eaw).count();
    println!("\nwithin one extended AW ({eaw} ms) of a beacon of ours: {inside}/{}", deltas.len());
    println!("median {:.2} ms", deltas[deltas.len() / 2]);
}
