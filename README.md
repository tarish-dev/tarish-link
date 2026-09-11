# tarish-libawdl

**An AWDL implementation, built from captures.** Named for what it replaces:
`libmosey_daemon_ffi.so`, the closed Google library our AirDrop stack currently sits on.

Apple Wireless Direct Link is how AirDrop moves bytes. This is a parser for it, written
from the frame format rather than around an existing implementation, because the point
is to *understand* the protocol well enough to implement it — not to get packets on a
screen. Wireshark can already put AWDL packets on a screen.

## Why it exists

We have a working AirDrop implementation for Android with no Google account and no Play
Services. It works because it sits on two Google binaries that happen to ship in the
Pixel vendor image:

| Layer | Today | Replaceable? |
|---|---|---|
| AirDrop protocol, mDNS, transfers | **ours** | — |
| **AWDL protocol** — election, sync, peer tables, channel sequence | `libmosey_daemon_ffi.so` (closed blob) | **this is the target** |
| MAC/radio shim | `wonder.ko` (Google, GPL, a *virtual* mac80211 wiphy) | separate question |
| Chip driver | `bcmdhd` (Broadcom FullMAC) | no |

The middle row is what this leads to. `libmosey` is a closed blob whose ABI can move
under us with a vendor bump; understanding AWDL completely is what makes replacing it a
project rather than a hope.

**Note the layering, because it is easy to get wrong:** `wonder.ko` is not the chip
driver. It is a SoftMAC shim that takes `wondertap0` — a raw radiotap interface the
Broadcom driver exposes — and presents it as a mac80211 wiphy. AWDL therefore does not
*require* `wonder.ko`; it requires monitor mode, frame injection, channel control and
timing. On commodity hardware (an ALFA AWUS036ACM on `mt76`) those come from mainline
mac80211, which is why OWL runs on a Raspberry Pi with no Google code at all.

## What has been established so far

Every claim names the capture behind it — see [docs/FINDINGS.md](docs/FINDINGS.md).

- The parser agrees with Wireshark **frame for frame**: both pick the same 278 of 6584.
- Availability Window is **16 TU (16384 us)** and sequences are **16 slots** — the 2018
  paper holds on 2026 devices.
- **Every device keeps slot 8 on channel 6, in all 556 sequences observed.** A fixed
  cross-band rendezvous. This corrects a real limitation in our Android stack, which
  picks one band and stays there.
- A device is **absent for most of its own schedule** (3/16 to 9/16 slots occupied).
  Slot occupancy, not link rate, is what governs AWDL throughput.
- **Slot 0 appears to be an association slot** — a device advertises its access point's
  channel there, and that is not a social channel. If it holds, AWDL/Wi-Fi coexistence on
  one radio is one window in sixteen. The controlling experiment has **not** been run;
  finding 16 records a version of it that was written up before it happened.
- A frame carries its schedule **twice, in two different encodings**.
- The **discovery layer decodes**: device names, `_airdrop._tcp.local`, and port **8770**,
  under a fixed 15-entry label dictionary with no negotiation.
- A device announces it has stopped sharing by **dropping its BLE `0x05` beacon**, 1-5
  seconds before its AWDL frames stop. AWDL silence is not departure.
- Tags **32 and 33** are on the wire and in no published table.
- The election **works**, verified across four devices and two captures: highest metric
  holds mastership, and our node followed correctly for 1019 consecutive advertisements.
  Elections order on **metric**, not on the counter — a node carrying a counter a hundred
  times the winner's follows without contest. An earlier reading said otherwise and was
  wrong; finding 9 is kept as the correction.
- `AP Beacon alignment delta` exists — evidence AWDL is designed to time-share with an
  access point, not merely tolerate one.

## Layout

```
crates/awdl      the parser. No I/O, no OS dependency — bytes in, structures out.
crates/libawdl-cli    the CLI. Capture, filter, dissect.
captures/        real captures kept as fixtures, so findings are reproducible
docs/            what each field turned out to mean, and how we know
```

The split is deliberate and has earned its keep before: `libtarish_protocol` is
Android-free for the same reason, and carries 202 tests that run on a build host with no
phone attached. A parser that needs a radio to test is a parser nobody tests.

## Use

```sh
cargo build --release

sudo awdl live mon0        # capture from a monitor interface
awdl read  capture.pcap    # dissect a recording
awdl stats capture.pcap    # how much of this capture is AWDL, and which tags
```

Bringing up a monitor interface has one trap worth knowing: **the managed interface on
the same phy must be down.** Leave it up and `mt76` refuses to transmit and refuses to
change channel, while everything reports success — see `docs/` once that is written up.

## Telling AWDL from everything else

Four things have to line up, and checking fewer lets other traffic through:

```
802.11 type/subtype   management / action   (0 / 13)
category              0x7f                  vendor specific
OUI                   00:17:f2              Apple
awdl type             0x08                  Apple's own sub-protocol tag
```

The OUI alone is not enough — Apple ships several protocols behind `00:17:f2`.

## Provenance of the frame format

Wireshark has dissected AWDL since 3.0, and `epan/dissectors/packet-awdl.c` is the most
precise written description of the format in existence. It was read as a **specification**
— field order, widths, endianness, tag numbers — and this code was written from that
understanding rather than derived from it. Wireshark is GPL-2.0 and this is not, so the
distinction matters: protocol facts are not copyrightable, an implementation is.

Semantics come from Stute et al., *One Billion Apples' Secret Sauce: Recipe for the Apple
Wireless Direct Link Ad hoc Protocol* (MobiCom 2018), [arXiv:1808.03156](https://arxiv.org/pdf/1808.03156),
and from [OWL](https://github.com/seemoo-lab/owl), the same group's implementation.

**The paper is from 2018 and must not be assumed to still describe what Apple ships.**
Every claim taken from it gets a capture behind it or a note saying it is unverified.
