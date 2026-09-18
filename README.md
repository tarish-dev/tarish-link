# tarish-libawdl

**An open AWDL implementation, built from captures — the replacement for
`libmosey_daemon_ffi.so`, the closed Google library our AirDrop stack sits on.**

Apple Wireless Direct Link is how AirDrop moves bytes. This is a clean-room implementation of
it, written from the frame format rather than around an existing library. It began as a parser
— Wireshark can already put AWDL on a screen, so the point was to *understand* the protocol
well enough to implement it — and it is now a transmitting implementation that, on a Pixel with
Google's `libmosey` daemon killed, brings the radio up, wins Apple's master election against
real iPhones, synchronises to an Apple device's schedule, and carries IP.

Part of **[Tarish](https://github.com/tarish-dev/tarish-app)** — file sharing for Android that
works with AirDrop and Quick Share, with no Google Play Services and no Google account.

---

## Status

Proven on a Pixel 10 Pro, against live Apple devices, with **no `libmosey` in the AWDL path**:

| capability | state |
|---|---|
| **Radio bring-up on `wonder.ko`** | ✅ our own netlink code — the vendor commands, the monitor, the transmit path — brings the RF up and airs AWDL frames |
| **Apple elects us master** | ✅ real iPhones adopt us; it tracks the metric we advertise (530 loses to a stronger peer, 600 wins) — their own election logic acting on our frames |
| **We synchronise to an Apple master** | ✅ track a real master's availability windows in software (~2–12 ms inside a 65 ms slot), the way `libmosey` does |
| **Data path** | ✅ `awdl0` netdev up with the correct derived address; we encapsulate and air IP, and decapsulate real Apple data frames (multicast mDNS) onto the interface |
| **Decode coverage** | agrees with Wireshark frame-for-frame; election, sync and channel-sequence tags at 100%; 6 GHz tags the main gap |

It runs on two backends behind one radio trait: **mainline `nl80211` + monitor mode** (an ALFA
adapter on `mt76`, no vendor code — the reference), and the **`wonder.ko`** backend (the Pixel).
The remaining work before Tarish's shipping daemon rides this instead of `libmosey` is a
routable `awdl0` for unicast and the `libmosey`-ABI shim — the daemon already owns mDNS, TLS
and the transfers. See [docs/FINDINGS.md](docs/FINDINGS.md) for the evidence behind every claim
above.

---

## Why it exists

Tarish's AirDrop works because it sits on two Google binaries that ship in the Pixel vendor
image. This project opens the load-bearing one:

| Layer | Today | This project |
|---|---|---|
| AirDrop protocol, mDNS, transfers | **ours** (`tarish-daemon`) | — |
| **AWDL protocol** — election, sync, peer tables, channel sequence | `libmosey_daemon_ffi.so` (closed blob) | **this — an open reimplementation** |
| MAC/radio shim — `wonder.ko` | Google, GPL, a *virtual* mac80211 wiphy | driven directly over netlink; the one layer that stays a vendor's |
| Chip driver — `bcmdhd` | Broadcom FullMAC | no |

**The layering is easy to get wrong:** `wonder.ko` is not the chip driver. It is a SoftMAC shim
that presents the Broadcom radio as a mac80211 wiphy. AWDL does not *require* `wonder.ko` — it
requires monitor mode, frame injection, channel control and timing. On commodity hardware (an
ALFA AWUS036ACM on `mt76`) those come from mainline mac80211, which is why the reference backend
needs no Google code at all.

## How it is built

```
crates/libawdl        the protocol engine. No I/O, no OS dependency — bytes in, structures out,
                      frames out. Election, sync, channel sequence, the data header.
crates/libawdl-hal    the radio seam: a Radio trait, a mainline nl80211/monitor backend, and
                      the wonder.ko backend (netlink vendor commands + AF_PACKET), plus the
                      awdl0 TUN.
crates/libawdl-cli    the CLI: capture and dissect a pcap, or run a live session (beacon,
                      follow, datapath).
crates/awdl-inject    a thin injector — the smallest thing that proves frames reach the air.
captures/             real captures kept as fixtures, so findings are reproducible.
docs/                 what each field turned out to mean, and how we know.
```

The engine is deliberately I/O-free so it is testable on a build host with no radio — the same
discipline `libtarish_protocol` follows. A parser that needs a radio to test is a parser nobody
tests.

## Use

```sh
cargo build --release

# read the air, or a recording — no radio needed for a pcap
awdl read  capture.pcap        # dissect a recording
awdl stats capture.pcap        # how much of a capture is AWDL, and which tags
sudo awdl live mon0            # capture from a monitor interface

# run a live session on a monitor interface (Pi/ALFA) or on wonder (Pixel)
sudo awdl beacon mon0 mon0 149 30 --compete                 # be a master, mainline backend
sudo awdl beacon wonder0 wonder0 6 30 --follow --wonder     # follow an Apple master on wonder
sudo awdl beacon wonder0 wonder0 6 30 --follow --wonder --datapath awdl0   # + bring up awdl0
```

On a mainline monitor there is one trap worth knowing: **the managed interface on the same phy
must be down**, or `mt76` refuses to transmit and to change channel while reporting success. The
`wonder` backend brings its own interface up over netlink; see [docs/HAL.md](docs/HAL.md).

## Telling AWDL from everything else

Four things have to line up; checking fewer lets other traffic through:

```
802.11 type/subtype   management / action   (0 / 13)
category              0x7f                  vendor specific
OUI                   00:17:f2              Apple
awdl type             0x08                  Apple's own sub-protocol tag
```

The OUI alone is not enough — Apple ships several protocols behind `00:17:f2`.

## Where to start reading

| | |
|---|---|
| **[docs/FINDINGS.md](docs/FINDINGS.md)** | the lab notebook, in discovery order, including the wrong turns and their corrections — bring-up, election, sync and the data path are findings 91–96 |
| **[docs/SPEC.md](docs/SPEC.md)** | the wire format, tag by tag. Read this to implement — every field is marked *named*, *carried* or *measured-constant* |
| [docs/GAPS.md](docs/GAPS.md) | Apple vs `libmosey` vs OWL, side by side, plus what fraction of the bytes we can name |
| [docs/HAL.md](docs/HAL.md) | the radio contract — what a chip has to do, written for the person who owns the driver |
| [docs/PHONE-PORT.md](docs/PHONE-PORT.md) | running this on a Pixel |

## What has been established

Every claim names the capture or run behind it — see [docs/FINDINGS.md](docs/FINDINGS.md).

- **The radio comes up from our own code.** DEL/NEW monitor, the four OUI-`0x001a11` vendor
  commands, and one rtnetlink interface-up over raw netlink — no `iw`, no `libmosey` — light the
  RF and transmit. The bring-up sequence was recovered byte-for-byte from `libmosey`'s own.
- **Real Apple devices elect us master**, and it is causal: the same peer adopts us at metric
  600 and not at 530, so Apple is running its election against *our* beacon, not a Google one.
- **We synchronise to a real Apple master** in software, tracking its availability-window
  schedule to a few milliseconds — the same approach `libmosey` uses, because the hardware TSF
  read is a stub.
- **The data plane works on hardware**: `awdl0` carries the derived link-local address, our IP
  is encapsulated and aired in the master's windows, and real Apple data frames decapsulate onto
  the interface.
- The parser agrees with Wireshark **frame for frame**. Availability Window is **16 TU** and
  sequences are **16 slots** — the 2018 paper holds on 2026 devices.
- **Every device keeps slot 8 on channel 6**, in all sequences observed — a fixed cross-band
  rendezvous, and where Apple concentrates discovery traffic.
- **Slot 0 is the association slot**: AWDL/Wi-Fi coexistence on one radio is one window in
  sixteen — not DBS, not a second radio, not firmware.
- The **data header** is `802.11 QoS Data → LLC/SNAP → AWDL data header → IPv6`; the
  **discovery layer** decodes to device names, `_airdrop._tcp.local` and port **8770**.
- Tags **32 and 33**, in no published table, **carry 6 GHz channels**.
- Elections order on **metric**, not on the counter.

## Provenance of the frame format

Wireshark has dissected AWDL since 3.0, and `epan/dissectors/packet-awdl.c` is the most precise
written description of the format in existence. It was read as a **specification** — field
order, widths, endianness, tag numbers — and this code was written from that understanding
rather than derived from it. Wireshark is GPL-2.0 and this is not, so the distinction matters:
protocol facts are not copyrightable, an implementation is.

Semantics come from Stute et al., *One Billion Apples' Secret Sauce: Recipe for the Apple
Wireless Direct Link Ad hoc Protocol* (MobiCom 2018),
[arXiv:1808.03156](https://arxiv.org/pdf/1808.03156), and from
[OWL](https://github.com/seemoo-lab/owl), the same group's implementation.

**The paper is from 2018 and must not be assumed to still describe what Apple ships.** Every
claim taken from it gets a capture behind it or a note saying it is unverified.

## Licence

Apache 2.0. See [LICENSE](LICENSE).

AirDrop is a trademark of Apple Inc., registered in the U.S. and other countries and regions.
Quick Share, Android and Pixel are trademarks of their respective owners. Tarish is an
independent project and is not affiliated with or endorsed by Apple, Google or Samsung.
