# AWDL on the wire

*A reference for the frame format, derived from captures. Generated against the parsers in
`crates/libawdl`, not from memory or from a paper.*

## How to read this, and what it is not

`FINDINGS.md` is the lab notebook — 2,700 lines in the order things were discovered,
including the wrong turns, which is where most of its value is. It is the wrong shape to
implement from. This file is the other shape: what the bytes are, tag by tag, with every
unknown marked as unknown.

**Every field here is marked with how well it is understood, and the mark is the important
part.** Three states, and they are not interchangeable:

| | meaning |
|---|---|
| **named** | we can state what it is *and choose a correct value without copying one* |
| **carried** | reproduced exactly, meaning unresolved. A value we would have to copy |
| **measured-constant** | never varied in the corpus. **Not the same as understood** — finding 47 |

The distinction between the first two is the whole difference between echoing a frame and
composing one. A field carried raw round-trips perfectly while telling you nothing, and the
tempting way to invent a value for it is to copy whatever Apple sent — which is
cargo-culting with no signal when it is wrong.

**`measured-constant` is a trap with a specific shape.** Tag 24 shows a ten-byte run of
zeros that reads exactly like a reserved block; two of those bytes are the high half of
`self_metric`, a fully named `u32` that never exceeds 65535. A protocol carrying small
numbers in 32-bit fields is mostly zeros, and zeros are what the measurement finds. Check
whether a constant run straddles a named field before concluding anything about it.

Regenerate the coverage figures with `awdl coverage captures/*.pcap`; check them against
the committed floor with `scripts/coverage-check.sh`.

---

## 1. Frame structure

AWDL rides in an 802.11 **vendor-specific action frame**.

```
802.11 MAC header (24 bytes)
  └── body
       0       category           0x7f   vendor specific
       1..4    OUI                00:17:f2   Apple
       4       type               0x08
       5       version            0x10, packed nibbles = 1.0, in every frame
       6       subtype            0 = PSF, 3 = MIF
       7       reserved           zero in every frame measured; carried
       8..12   phy_tx_time        u32, when the PHY actually started transmitting
       12..16  target_tx_time     u32, when the sender intended to
       16..    TLVs
```

`target_tx_time - phy_tx_time` is the sender telling you its own transmit jitter, and it is
what a receiver has to compensate for to stay in the cluster. It wraps, so subtract
wrapping.

**PSF** (Periodic Synchronization Frame, subtype 0) and **MIF** (Master Indication Frame,
subtype 3) differ in which TLVs they carry, not in structure. A master sends PSF every 110
TU. Apple sends roughly 0 PSF per MIF; OWL sends 524 per 900, which is one of the ways an
OWL node is identifiable on sight.

### TLVs

```
  0       tag       u8
  1..3    length    u16 little-endian
  3..     value
```

**The 2-byte length is the action-frame form.** Inside tag 12's UMI options and inside the
long form of the data-path header, TLVs use a **1-byte** length instead. Reading one with
the other's width walks straight off the end.

---

## 2. Time

Everything in AWDL is counted in **Availability Windows**.

```
1 TU                 1024 µs
1 AW                 16 TU      = 16,384 µs
1 extended AW        presence_mode × AW,  presence_mode = 4 on Apple  = 64 TU
1 channel cycle      16 extended AWs  = 1024 TU ≈ 1.049 s
1 counter tick       192 AWs    = 3,145,728 µs = 3.145728 s
```

**A channel-sequence slot is an extended AW, not an AW.** The slot index is

```
slot = (aw_counter / presence_mode) % 16
```

not `aw_counter % 16`. Getting this wrong makes every timing decision four times too fast,
and it scores 34–43% against the field values instead of 100%.

`aw_remaining` plus `aw_counter` let a receiver recover the cluster's clock **without a
TSF**, which matters because the MT7612U reports no TSFT in radiotap — 0 of 801 frames. OWL
does this in `rx.c`; it is not novel here.

---

## 3. The tags

Coverage as measured over 57 captures, 79,614 action frames, 29,615,190 TLV bytes.
**92.1% of control-plane bytes named** (excluding tag 2, which is DNS and was specified
elsewhere). Over the 19 captures containing no transmissions of our own — the honest
measure of how much of *Apple's* protocol is understood — it is **90.3%**; see
`docs/GAPS.md` for why the two differ and why the floors do not.

| tag | name | named | floor | opaque bytes |
|---|---|---|---|---|
| 0 | SSTH Request | — | — | 0 (zero-length) |
| 2 | Service Response | 100% | 24/24 | 0 |
| 4 | Synchronization Parameters | 97.3% | 71/73 | 159,228 |
| 5 | Election Parameters | **100%** | 21/21 | 0 |
| 6 | Service Parameters | 15.9% | 2/17 | 595,555 |
| 7 | HT Capabilities | 80.9% | 6/8 | 158,048 |
| 12 | Data Path State | 92.9% | 43/47 | 204,820 |
| 16 | Arpa | **100%** | 40/40 | 0 |
| 17 | IEEE 802.11 Container | 100% | 14/14 | 0 |
| 18 | Channel Sequence | 100% | 41/41 | 0 |
| 21 | Version | 100% | 2/2 | 0 |
| 24 | Election Parameters v2 | 90.0% | 36/40 | 313,660 |
| 32 | 6 GHz Info | 15.4% | 2/13 | 60,742 |
| 33 | 6 GHz Channels | 21.9% | 2/14 | 131,712 |
| 35 | *unrecognised* | **0%** | 0/2 | 132 |

A **floor** is the worst-classified single TLV of that tag. It is the number to watch, not
the percentage: the percentage is byte-weighted over the corpus and moves whenever a
capture is added, while the floor is a pure function of the parser. Tag 7 read 45% with a
floor of 5/20, and chasing the floor is what found the truncated MCS set.

### Tag 4 — Synchronization Parameters (73 bytes + sequence)

```
  0       tx_channel                   u8     named
  1..3    tx_counter                   u16    named
  3       master_channel               u8     named
  4       guard_time                   u8     named
  5..7    aw_period                    u16    named
  7..9    action_frame_period          u16    named
  9..11   flags                        u16    CARRIED -- see below
  11..13  aw_ext_length                u16    named
  13..15  aw_common_length             u16    named
  15..17  aw_remaining                 u16    named
  17      ext_min                      u8     named
  18      ext_max_multicast            u8     named
  19      ext_max_unicast              u8     named
  20      ext_max_af                   u8     named
  21..27  master                       6      named
  27      presence_mode                u8     named
  28      reserved_28                  u8     IGNORED by the receiver, free to choose
  29..31  aw_counter                   u16    named
  31..33  ap_beacon_alignment_delta    u16    named
  33..    channel sequence             see below
  tail    two bytes                    IGNORED by the receiver — a field, not padding (f20)
```

**`flags` takes exactly two values in the whole corpus: `0x1000` and `0x1800`.** Bit 12 is
always set. Bit 11 varies and tracks "sender is associated to an AP" only 19.2% of the
time, so it is not an association flag whatever it looks like. OWL sends `0x1800` always.

**The trailing two bytes are not padding.** OWL is the only implementation that zeroes them.

**`aw_remaining` must be computed, not sent as zero.** Sending zero in every frame is the
defect that made our transmitter look like it had decided not to compete.

### Channel sequence (inside tag 4, and all of tag 18)

```
  0       count - 1        u8     named  (so 0x0f means 16 slots)
  1       encoding         u8     named
  2       duplicate        u8     named
  3       step_count       u8     named
  4..6    fill_channel     u16    named
  6..     slots            count × stride
```

Three encodings, and the stride and byte order differ:

- **OpClass** — `channel, opclass` per slot. Fully named.
- **Legacy** — the qualifier comes **first**. Reading it as OpClass yields a plausible
  channel number and the wrong band.
- **ChannelNumber** — bare channel numbers.

**Legacy qualifiers encode 40 MHz CENTRE channels, not tunable ones.** `0x1d` = control
2 below, `0x1e` = control 2 above, `0x2b` = 20 MHz. A qualifier outside those four is
reported as opaque rather than absorbed silently, so a capture containing an 80 MHz or
6 GHz Legacy slot shows up as a gap instead of a wrong answer.

Apple occupies **3–6 of 16 slots**, measured as {0, 2, 8, 10}: slot 0 is the association
slot, slot 8 is channel 6 always, 2 and 10 are social. `libmosey` and OWL both fill 16/16
on one channel.

The three bytes after the slot list were zero in all 7,054 samples, so they are named as
padding **because measured**, not because assumed.

> **A note on the sample counts in the source.** Several doc comments in `crates/libawdl`
> cite 18,157 frames or 7,054 samples. Those were the corpus when each was written; it is
> now 37,829 frames. The conclusions still hold — `awdl bytemap` re-derives them across the
> whole corpus — but the numbers in those comments are stale, and a claim resting on a count
> should be re-run rather than quoted.

### Tag 5 — Election Parameters (19+ bytes)

```
  0       flags             u8     named
  1..3    id                u16    named
  3       distance          u8     named
  4       reserved_4        u8     IGNORED by the receiver, free to choose
  5..11   master            6      named
  11..15  master_metric     u32    named
  15..19  self_metric       u32    named
  19..21  tail              2      IGNORED by the receiver, free to choose
```

**This whole tag is vestigial for election purposes.** Peers still send it and still fill it
consistently, but a receiver's decision comes from tag 24: emit no tag 24 and you are not
elected, however correct your tag 5 is (finding 67). `reserved_4` and the trailing pair were
both sent as garbage with peers adopting anyway (finding 63), which is why this tag reads
100% — every byte in it is either named or proven not to matter.

### Tag 24 — Election Parameters v2 (40 bytes)

```
  0..6    master            6      named
  6..12   other             6      named -- the PARENT, next hop toward the master
  12..16  master_counter    u32    named -- the master's tenure, RELAYED not invented
  16..20  distance          u32    named
  20..24  master_metric     u32    named
  24..28  self_metric       u32    named
  28..32  unknown_28        u32    THE PEER READS THIS. Send zero — see below
  32..36  ignored           4      IGNORED by the receiver, free to choose
  36..40  self_counter      u32    named — own tenure, in units of 192 AWs
```

**Byte 28 is the one field in this protocol that a receiver was caught checking.** Every
Apple frame in the corpus carries zero across 28..36, so reading alone cannot tell the two
halves apart — they are identical on the air. A transmitter can: put `0xa5` at byte 28, 29
or 31 and an iPhone refuses to elect you, put it at byte 32 or 35 and it elects you anyway.
The adjacent reject/accept pair at 31/32 fixes the boundary, which is the `u32` shape every
other field in this tag has. Byte 30 was never probed and is assumed to belong to the field.

**The check is "must be exactly zero", not a range.** Setting the `u32` to **1** — the
smallest possible non-zero value — is refused as completely as `0xa5a5a5a5`. Measured as a
counterbalanced 2x2 against two iPhones entering the room: two controls adopted at 1,265 and
688 frames, two treatments at 0 and 0 (finding 73). In both treatment runs the peers arrived,
saw us advertising metric 600 against their own 510–541, and elected *each other* instead.

So: **send zero, and do not treat the surrounding zeros as licence to invent.** What the
field means is still unknown — we know one accepted value out of 2^32 and not the rule
behind it. This is the weakest entry in this document and the only one where being wrong
costs you the election. Findings 65, 67, 73.

**Tag 24 is mandatory.** A malformed one is treated exactly as an absent one: emitting no
tag 24 at all produces the same zero adoptions as emitting a corrupt one, which also makes
tag 5 vestigial for election purposes. Finding 67.

`other` is the parent pointer, proven 634/634. `master_counter` is somebody else's number:
a follower reproduces its master's values exactly, one frame behind each change, for as
long as it follows. A node that invents a value here is lying about its master.

`self_counter` advances by exactly one every 192 AWs and **only while the node claims
mastership**. An Apple device followed for 28 seconds without it moving, then began
incrementing the moment it took the job. The period is exact: AW counters read 15434,
15625, 15817, 16009 at successive increments — 191, 192, 192.

Apple's `self_metric` sits at **510–537**; `libmosey` sends **1**; OWL sends **60** and
never moves its counter, which is why an OWL node is structurally a permanent follower.

### Tag 7 — HT Capabilities (7–20 bytes)

```
  0..2    unknown           2      CARRIED, measured-constant 00 00
  2..4    HT Capability Information    u16    named -- 802.11-2020 §9.4.2.55.2
  4       A-MPDU Parameters            u8     named -- §9.4.2.55.3
  5..     Supported MCS Set, TRUNCATED        named -- §9.4.2.55.4
            octets 0-9    Rx MCS bitmask
            octets 10-11  Rx Highest Supported Data Rate, B0-B9, in Mb/s
            octet  12     Tx MCS parameters
            octets 13-15  reserved
```

**The three lengths are one structure stopping in three places**, not a fixed part with a
tail appended. Apple sends 4 MCS octets in the 9-byte form and 15 in the 20-byte one;
`libmosey` sends 4. This was recorded the other way round for a long time, with the varying
length taken as *evidence* for a separate field — it is evidence for a variable-length one.

### Tag 12 — Data Path State (13–47 bytes)

A flags word, then only the fields the flags select. **The order is not the bit order**:
country (`0x0100`) and social channel (`0x0200`) come before the infrastructure fields
(`0x0001`, `0x0002`), so iterating bits numerically reads every later field from the wrong
offset.

```
  0..2    flags             u16    named
  then, in this order, each only if its bit is set:
    0x0100  country              3      named -- 3 ASCII bytes
    0x0200  social_channel       2      named
    0x0001  infra_bssid + channel 8     named -- the AP this device is associated to
    0x0002  infra_address        6      named
    0x0004  awdl_address         6      named
    0x0010  umi                  2      named
    0x1000  umi_options          2 + n  length named, contents CARRIED
    0x8000  extended block       see below
```

`flags & 0x0001` being set is itself the signal that the device is associated.

The extended block:

```
  +0..2   extended_flags    u16    IGNORED by the receiver. Apple: 0x117d | (k << 10)
  +2..4   zero              2      IGNORED by the receiver, measured-constant
  +4..8   master_counter    u32    named — EQUAL to tag 24's in 100% of 24,915 frames
  +8..12  clock_ms          u32    named — 3145.766 ms per tick measured vs 3145.728
  +12..16 aw_counter        u32    named — exactly 192 per tick; NOT tag 4's aw_counter
  +16..20 unidentified      u32    IGNORED by the receiver — advances 1.0 to 3.2 per tick
```

**Everything in this block except the three counters is ignored by the receiver**, measured
by transmitting garbage in it and still being elected master: findings 69 (the trailing u32)
and 71 (`extended_flags` and the zero pair). *Ignored* is a stronger statement than *carried*
— it means we may choose the value rather than copy one.

**`extended_flags` is `0x0000` from every non-Apple sender** — OWL and `libmosey` both — and
one of the `0x_7d` family from Apple. The two-bit `k` is stable per device and never
correlates with association, so it looks like a device class rather than state. We send zero,
which is now a measured choice and not merely the polite one.

On a **6 GHz** association, `infra_channel` is reported as **0** — verified on a MacBook
that was associated and still published zero. Tags 32/33 are the only place a 6 GHz
association is visible.

### Tag 16 — Arpa (10–40 bytes)

```
  0       flags       u8     IGNORED by the receiver, free to choose (Apple sends 0x03)
  1..     DNS-encoded host name
```

**Apple's host name is a UUID v4.** The 40-byte form is fully accounted for: `0x24` = 36,
the length of a UUID string; dashes at the 8-4-4-4-12 positions; ASCII `'4'` at the version
nibble; exactly four values at the variant nibble; `c0 0c` is a DNS compression pointer to
offset 12. 1 + 1 + 36 + 2 = 40.

```
14ca8109-4388-4ebc-925f-27b8a1ea8c97
5aaca6e6-f79c-41bd-939f-4c8b28715f47
24b2a2df-68d6-4892-8d05-851dfa216349
```

It is therefore a rotating pseudonym and identifies a device no better than the MAC does.
`libmosey` omits this tag entirely; OWL sends `raspberrypi.local`.

### Tag 17 — IEEE 802.11 Container

Standard 802.11 elements, `id, length, body`. A VHT Capabilities body (id `0xbf`) is
decoded from 802.11-2020 and counts as named. Any other element is carried without being
read. OWL omits this tag.

### Tag 18 — Channel Sequence

The channel sequence structure above, on its own. 100% named.

### Tag 21 — Version (2 bytes)

```
  0       version        u8     named -- packed nibbles, major and minor
  1       device_class   u8     named
```

Apple sends **v10.0**; `libmosey` and OWL both send **v3.4**.

### Tag 6 — Service Parameters (9–17 bytes)

**0% named, and it will stay that way.** The field boundaries are known; the contents are a
bitmask whose hash function we do not have, so it is not a value that can be chosen.
Knowing where a field starts is not knowing what belongs in it. Bytes 0..3 are `00 00 00`
in all 30,210 TLVs.

Finding 25 established that **it does not matter** — discovery works without composing it
meaningfully.

### Tags 32 and 33 — 6 GHz

```
tag 32 (13 bytes)
  0..2    unknown           CARRIED, measured-constant 00 00
  2..4    operating class   named   -- 0x86 = 134
  4..6    channel           named   -- 0x35 = 53
  6..9    04 08 02          CARRIED, measured-constant in ALL 5,460 TLVs
  9..11   two bytes         CARRIED -- only 7 distinct pairs corpus-wide
  11..13  zero              CARRIED, measured-constant

tag 33 (14 bytes)
  0..4    01 00 00 00       CARRIED, measured-constant
  4..6    channel, class    named -- the device's own 6 GHz association, 00 00 if none
  6       01                CARRIED, measured-constant
  7..9    channel, class    named -- populated either way
  9       one byte          CARRIED -- three values: 0x00, 0x20, 0x27
  10..14  zero              CARRIED, measured-constant
```

**Tag 33 puts channel before class; tag 32 puts class before channel.** Proven against a
MacBook whose own OS reported "Channel: 53 (6GHz, 160MHz)" while its frames carried channel
53, operating class 134.

### Tag 35

Two bytes, no parser, seen 66 times. Byte 0 is `0x01`. Not in any published tag table.

---

## 4. What is left, and why reading cannot finish it

| | bytes | route |
|---|---|---|
| tag 6's hash | 595,555 | **none.** Finding 25 settled it, and it does not matter |
| tag 24's `unknown_28` | 313,660 | the transmitter — **it is READ**, and that is all we know |
| tags 32/33, the 6 GHz pair | 192,454 | the transmitter, once it can advertise 6 GHz honestly |
| tag 7's two leading bytes | 158,048 | the transmitter — one inconclusive pair so far |
| tag 4's flags word | 159,228 | the transmitter |

`awdl correlate` matches every undecoded byte window against every field already understood,
within the same frame. Across the whole corpus **every match above 50% is a known field at
its own offset** — it re-finds `master_counter`, `self_counter`, `distance` and `aw_counter`
where they live, and nothing else. Corpus-internal analysis is exhausted; finding 50 has
the detail.

**The transmitter is the only remaining instrument, and it has now been used.** The
experiment is direct: send frames with a field set to garbage and see whether Apple peers
still sync and adopt. If behaviour does not change the field is proven ignored, and choosing
zero becomes knowledge rather than imitation.

That pass is done for every constant-zero region a transmitter can reach — tag 4's
`reserved_28` and trailing pair, tag 5 entirely, tag 16's flags byte, tag 12's extended
block, tag 24's bytes 32..36. **Exactly one of them turned out to be read**: the `u32` at
tag 24 offset 28. Findings 63 through 71.

The outcome is worth stating plainly because it is not what a careful reader would predict.
These fields are indistinguishable in every capture ever taken — all zero, all constant,
all the same shape. A reasonable person would guess they are all padding, or that a strict
implementation checks all of them. Neither is true, and no amount of listening separates
them.

The ceiling this leaves is about **96.5%** — everything except tag 6, whose contents are a
hash and stay unreachable by any method.

---

## 5. Implementing a transmitter from this

Three things that are not in any byte layout and each cost real time:

**Every builder in `upgrade.rs` already returns a complete frame.** Wrapping one again
raises no error anywhere: the inner `version = 1` lands on `event_type` and the frame
silently becomes something else, which the peer then ignores.

**A settled cluster does not re-elect, whatever you advertise.** Eight runs, metrics from 50
to 600 against settled Apple peers, zero adoptions. Every adoption on record has the same
shape: a device *entering* a room adopts whoever is already claiming master. So to be
adopted, be transmitting before the peer arrives — losing an election you never get to
contest is not a defect in `beats()`.

**Two iPhones re-form a cluster in under ten seconds.** Any experiment that establishes a
condition *before* opening the capture has already missed it.

## 6. The data plane

Measured across the 428 AWDL data frames in `captures/`; every constant below was invariant
in all of them, and the long form the parser supports appeared **0 times**.

```
802.11 QoS Data, 26 bytes
  88 00              FC: QoS Data, neither ToDS nor FromDS
  00 00              duration, set by the radio
  <dst 6>            addr1
  <src 6>            addr2
  00 25 00 ff 94 73  addr3 -- the well-known AWDL BSSID, all 428 frames
  <seq ctrl 2>       4 bits fragment, 12 bits sequence
  06 00 | 00 00      QoS control. TID 6 in 226 frames, TID 0 in 149

LLC/SNAP, 8 bytes
  aa aa 03           LLC
  00 17 f2           Apple's OUI -- NOT the standard 00:00:00
  08 00              protocol ID

AWDL data header, short form, 8 bytes
  03 04              all 428 frames
  <sequence 2>       little-endian, per-peer
  00 00              form marker. 0x03 at the first byte would mark the long form
  86 dd              ethertype. IPv6 in all 428, never IPv4

then the IP packet.
```

**The SNAP is the trap.** A standard SNAP puts an ethertype at its last two bytes; here
those bytes are `08 00`, which reads as IPv4, and every frame is IPv6. The real ethertype
is four bytes further on. So **check** the SNAP rather than skipping eight bytes — most QoS
Data in these captures belongs to other vendors.

### Addresses are computed, not advertised

AWDL carries no IP address anywhere. A peer's address is the **modified EUI-64** of its AWDL
MAC, which is how a sender knows where to send with no resolution step:

```
8a:c3:f7:4b:ce:de   ->   fe80::88c3:f7ff:fe4b:cede
```

`ff:fe` inserted in the middle, **and** bit 1 of the first octet flipped. Doing only the
first gives a well-formed address belonging to nobody.

### The interface

`hal::tun` opens `/dev/net/tun` with `TUNSETIFF`, `IFF_TUN | IFF_NO_PI`. TUN rather than TAP
because the payload that goes inside the AWDL header is the IP packet; an Ethernet header
would be discarded immediately. `IFF_NO_PI` is not optional — without it every read carries
four bytes of prefix and the IPv6 version nibble lands in the wrong place.

`Tun::configure(mac)` does the bring-up, and it is one function because the **order** is the
content and one of the three steps fails silently when done late:

```
1.  addr_gen_mode = 1     BEFORE up. Read once, at that moment
2.  IFF_UP
3.  the derived address
```

Without step 1 — or with it done after step 2 — the kernel adds a **second** link-local of
its own, `scope link stable-privacy`, and may use it as the source address. Peers reach us at
the derived address and our replies come from one they have never heard of: discovery works
and every answer is dropped. `addr_gen_mode` reads back as `0` (EUI-64), which looks right; a
TUN has no hardware address (`link/none`), so EUI-64 has nothing to work from and the kernel
falls back to stable-privacy. Finding 51.

**No route or rule is needed on Linux.** The kernel installs `fe80::/64 proto kernel metric
256` itself when the address is added. The `ip rule` requirement is an *Android* fwmark
problem and does not apply here — an earlier version of these docs said it did.

The address is not a parameter: it is derived from the MAC we advertise, because any other
value is wrong by construction. The rule exists in `libawdl::data` and again in
`libawdl_hal::tun` so the HAL need not depend on the protocol crate, and a test holds the
two copies against each other — a silent divergence would put the interface on an address no
peer computes.

`awdl datapath <mon> <our-mac> [name] [secs]` runs the loop: one `poll` over the tun and the
raw socket, encapsulating one way and decapsulating the other. Verified on the Pi — a
`ping6 -I awdl0 ff02::1` left as well-formed AWDL data frames that our own parser read back
off the air.

Three filters, and the loop is wrong without the last two:

- frames from our own MAC. Adapter-dependent: the MT7612U does **not** hear its own
  injections (`own 0` measured), so this earns nothing there and stays because a feedback
  loop is worse than a redundant comparison
- another peer's unicast, which is not ours to deliver into our own stack
- packets with nowhere to go. AWDL has no address resolution, so a destination is multicast,
  or a link-local whose MAC reverses out of it, or undeliverable

### Both planes in one process

`awdl beacon --datapath awdl0` runs the control plane and the data plane in one loop, which
is not a convenience:

- **two processes cannot both inject on one phy.** The mt76 answers the second with `EAGAIN`
  and writes nothing to dmesg
- **a peer listens only during its availability windows.** A data frame sent when the kernel
  hands it over goes out while the peer is deaf, and the sender sees a successful transmit
  and no reply — indistinguishable from being ignored

So outbound packets are **queued and drained immediately after each beacon**, which puts
them inside a window the cluster attends. Measured: every data frame went out **0.03–0.08 ms**
after a beacon, 8 of 8 inside one 65.536 ms extended window. Finding 53.

The queue is bounded at 64 and drops the *oldest* — on a link where a packet may wait a
cycle, the stale end is the part worth losing — and drains at most 4 per window, because
emptying it into one window would overrun into the next slot.

**Still missing: anything received from a peer.** `0 delivered` so far, which is expected —
we declined the election, so no Apple device had reason to send us anything. That experiment
needs us inside a cluster (transmitting before the peer arrives, finding 46) and an mDNS
query on `ff02::fb` that a real device answers.
