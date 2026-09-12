# Findings

Each entry names the capture it came from. A claim with no capture behind it says so.

---

## 1. The parser agrees with Wireshark, frame for frame and tag for tag

`captures/awdl-149.pcap` — 45s, channel 149, Raspberry Pi 400 + ALFA AWUS036ACM (`mt76x2u`).

|  | ours | `tshark -Y awdl` |
|---|---|---|
| frames in capture | 6584 | 6584 |
| identified as AWDL | **278** | **278** |

The TLV histogram is identical too, tag for tag:

```
 154 [ 0] SSTH Request           278 [12] Data Path State
 576 [ 2] Service Response       192 [16] Arpa
 278 [ 4] Sync Parameters        278 [17] IEEE 802.11 Container
 278 [ 5] Election Parameters    278 [18] Channel Sequence
 278 [ 6] Service Parameters     278 [21] Version
 278 [ 7] HT Capabilities        278 [24] Election Parameters v2
                                 184 [32] undocumented
                                 184 [33] undocumented
```

This matters more than it looks. Independent agreement on **which 278 of 6584 frames are
AWDL** is what makes every later measurement worth reporting. Without it, a parser that
quietly drops a frame class produces clean, confident, wrong numbers.

## 2. Tags 32 and 33 are on the wire and in no published table

Wireshark's enum ends at 24 (`AWDL_ELECTION_PARAMETERS_V2_TLV`). Tags **32** and **33**
appear 184 times each in 45 seconds, in MIFs from current Apple devices. `tshark
-e awdl.tag.number` reports them too, so this is not our parser inventing them — it is
Wireshark having no name for them.

Contents undecoded. Two tags appearing at identical counts, in the same frames, is the
sort of pairing that usually means a capability/operation pair (as 7/8 are), but that is
a guess and is flagged as one.

The 2018 paper does not describe them. This is the first concrete instance of the drift
the research brief warned about: **do not assume the paper still describes what Apple
ships.**

## 3. AWDL is in the air with nobody touching anything

Nobody opened a share sheet during this capture. Three Apple devices were nonetheless
sending AWDL continuously:

```
06:37:6f:45:5c:68    94 frames
1a:90:37:31:e6:58   107 frames
ee:4b:4f:cc:5b:12    77 frames
```

269 MIF to 9 PSF. So Master Indication Frames are the steady state, not an artefact of an
active transfer, and a passive listener sees a device's full parameter set — channel
sequence, election state, services — without any interaction at all.

Useful consequence: **channel 149 is already the right place to listen in this region**,
and no Apple device needs to be doing anything for the experiment to run.

## 4. Every AWDL sender uses a randomised MAC

All three senders have the locally-administered bit set (`0x02` in the first octet):
`06:`, `1a:`, `ee:`. There is no hardware address to key on. Anything that identifies a
peer by MAC will work on a bench, where addresses happen to be stable for a while, and
fail in the field. Asserted in `crates/awdl/tests/real_capture.rs` so it cannot be
forgotten.

## 5. Half the air is ACKs, which is not the same as unparseable

The first version of `awdl stats` reported 3158 of 6584 frames "unparsed", which looked
alarming and was an artefact: it demanded a full 24-byte management header before it
would say what a frame was, and a control frame is ten bytes with no third address.

Corrected breakdown of the same capture:

```
6584 frames: 278 AWDL, 6306 other 802.11, 0 not 802.11
  other control      6287
  other management     19
```

Zero unaccounted for. The lesson is worth keeping: a classifier that cannot distinguish
"too short for the header I wanted" from "not 802.11" will make a healthy capture look
broken.

## 6. The paper's timing claims hold on 2026 devices — and there is more in the frame than it describes

`captures/awdl-149.pcap`, all 278 AWDL frames. Cross-checked against `tshark -V`.

| Claim (Stute et al., 2018) | Verdict | Evidence |
|---|---|---|
| Availability Window is 16 TU | **confirmed** | `aw_period = 16` in 278/278 frames; 16 x 1024 = 16384 us |
| Channel sequence has 16 slots | **confirmed** | count field is 15, and the count is stored **minus one** |
| Social channels 6 / 44 / 149 | **confirmed for this region** | only 6 and 149 in use; 44 never appears, consistent with Qatar mapping to 149 |

### A frame carries its schedule TWICE, in two different encodings

This is not in the paper and is the kind of thing that makes an implementation subtly
wrong rather than broken. **Synchronization Parameters (tag 4) embeds a complete channel
sequence of its own**, in addition to the standalone Channel Sequence (tag 18). In the
same frame:

```
tag 4  (Legacy encoding)    0, 0, 151, 0, 0, 151, 0, 0, 6, 0, 151, 0, 0, 151, 0, 0
tag 18 (OpClass encoding)   0, 0, 149, 0, 0, 149, 0, 0, 6, 0, 149, 0, 0, 149, 0, 0
```

Identical occupancy, different channel numbers: **151 is the 40 MHz centre, 149 and 153
are its 20 MHz halves.** The two encodings also order their bytes differently — Legacy is
`flags, channel`, OpClass is `channel, opclass` — so reading one as the other produces
plausible garbage rather than an error.

Occupancy matched slot-for-slot across the whole capture (3/16, 4/16, 5/16, 6/16 and 9/16,
with identical frame counts on both), which is what establishes they describe one schedule
rather than two.

### A device is absent for most of its own schedule

Occupancy ranged from **3 of 16 slots to 9 of 16**. Channel 0 means "not present", and
most slots are 0.

This is the number that governs throughput between two peers, and it is not the link rate.
Two nodes can only exchange anything during windows where **both** are present **and** on
the same channel. A peer at 3/16 imposes a hard ceiling of 18% of airtime on anyone
talking to it, however fast the modulation.

It also explains the earlier iPhone measurement from the Android work — 4 of 16 slots
split across 149 and 6, against our own devices at 16/16 on one channel, giving roughly
19% overlap and 2.6-4.7 MB/s. That figure was previously attributed to the radio. It is
the schedule.

### `AP Beacon alignment delta` exists

A named field in Synchronization Parameters, immediately after the AW sequence number.
**There is no reason to carry an access point's beacon offset unless you intend to line
up with it**, which is direct evidence that AWDL is designed to time-share with an
infrastructure association rather than merely tolerate one — the question the research
brief flags as highest value.

It was **0 in all 278 frames**, consistent with these particular devices not currently
time-sharing with an AP. That is a measurement to repeat against a device that
demonstrably is, and until then the field's existence is the finding, not its value.

**What this does NOT yet show.** Channel 153 appears in some sequences alongside 149, and
there is an AP on 153 nearby, so it is tempting to read that as the AP's channel appearing
in the slots. It is more likely the other half of the 149+153 bond centred on 151 — the
Legacy sequence reports 151 in exactly those slots. Not claimed either way.

## 7. Every device keeps slot 8 on channel 6, without exception — and this corrects what we do

Across all 278 frames and both channel sequences in each — **556 sequences** — channel 6
appears exactly once, and always at **slot index 8**, the midpoint of the 16-slot cycle:

```
$ tshark ... | awk '{for(i=1;i<=NF;i++) if($i==6) print i-1}' | sort -n | uniq -c
   556 8
```

Three different devices, every frame, no exceptions. The operating-class histogram agrees
independently: class `0x51` (2.4 GHz) appears exactly 278 times, once per frame.

**This is a cross-band rendezvous, and it is almost certainly deliberate.** A device whose
useful traffic is on 5 GHz still guarantees it is listening on the 2.4 GHz social channel
for one window in every sixteen. That is how a 5 GHz device meets a 2.4 GHz-only device,
and how devices in different regulatory domains — Europe on 44, Qatar on 149 — still find
each other. A fixed slot index means no negotiation is needed: everyone is there at the
same point in the cycle.

### What this corrects on our side

`tarishd`'s `channels_for()` picks **one band**:

```rust
0              => vec![CHANNELS_24, CHANNELS_5],   // 2.4 first when unknown
f if f >= 5000 => vec![CHANNELS_24, CHANNELS_5],   // Wi-Fi on 5 -> AWDL on 2.4
_              => vec![CHANNELS_5,  CHANNELS_24],  // Wi-Fi on 2.4 -> AWDL on 5
```

with `CHANNELS_24 = [6]` and `CHANNELS_5 = [149, 44]`. The list is a **preference order**
— the first set that starts is the one used — so a device ends up wholly on 2.4 **or**
wholly on 5 GHz. It never occupies both, and our own devices were previously measured at
16/16 slots on a single channel.

That is why a 4383 forced to 2.4 GHz and a 4390 on 149 cannot discover each other, which
was written up as an unavoidable trade-off for the operator to settle.

**It is not a trade-off. Apple solved it, and the solution is one slot.**

The concrete experiment, which needs no new code: pass a **combined** list such as
`[149, 6]` to `mosey_start_5` rather than one band's set, and capture the channel
sequence that results. If `libmosey` builds a mixed sequence, the cross-band cliff
disappears and the per-mode channel choice proposed in BUILD-NOTES 59 stops needing a
decision at all. If it does not, we have learned something specific about what `libmosey`
will and will not schedule — which is equally useful, and is exactly the kind of thing our
own implementation would then do differently.

### And it re-explains an old measurement

The iPhone figure from the Android work — 2.6-4.7 MB/s, 4 of 16 slots split across 149
and 6 — was attributed to the radio. It is the schedule. Our device at 16/16 on one
channel is already maximally available, so the ceiling is the peer's occupancy and not
anything we can tune. **Slot occupancy, not link rate, is what governs AWDL throughput**,
and any future capacity claim should be stated in slots.

## 8. libmosey will not build a cross-band sequence — the cheap fix does not exist

The experiment proposed in finding 7, run on hardware the same day.

`persist.tarish.channels=149,6` on a Pixel 10 Pro, forcing a **combined** two-band list
into `mosey_start_5` instead of one band's set. The daemon accepted it:

```
tarishd: using persist.tarish.channels override: [149, 6]
tarishd: AWDL session up, mode=Netlink, channel=149, country=QA
```

No rejection, no fallback, no complaint. So the question is not whether `libmosey` takes
the list — it is what it does with it. `captures/blazer-mix.pcap`, 40s, our device and a
real Apple device in the same capture on the same channel:

| sender | channel sequence |
|---|---|
| **ours** (`56:ba:4f:f6:3a:44`, 346 frames) | `OpClass 16/16 slots -> [149]` |
| **Apple** (`ce:6d:8b:0c:31:01`, 37 frames) | `OpClass 6/16 slots -> [6, 149]` |

Apple's list, verbatim, with channel 6 in slot 8 exactly as finding 7 predicts:

```
149, 149, 149, 0, 0, 0, 0, 0, 6, 149, 149, 0, 0, 0, 0, 0
```

Ours has **no slot on channel 6 at all**, despite 6 being in the list we handed it.

**`libmosey` takes the first channel and builds a single-channel 16/16 sequence.** The
second entry is used as a fallback for starting the radio, not as a member of the
schedule.

### What this settles

The cross-band cliff — a 2.4 GHz device and a 5 GHz device never discovering each other —
**cannot be fixed at the integration layer.** There is no channel list, no property, no
ordering that makes `libmosey` schedule two bands. It is not a configuration we have
failed to find; it is a capability the library does not have.

That moves the item out of "integration tuning" and into the case for `libawdl`:

- **It is a requirement, not a nice-to-have.** Building a schedule that reserves slot 8
  for channel 6 is something our own implementation must do, because nothing else can.
- **We now have the target shape, measured.** Not inferred from a paper: a real device's
  sequence, in a capture, next to ours for comparison.
- **It is testable the same way.** The same Pi, the same parser, the same one-command
  comparison — so the day `libawdl` builds a sequence, we can check it against Apple's
  side by side rather than hoping.

### A second divergence, noticed in passing

In tag 4, `libmosey` encodes its embedded sequence as **OpClass**; the Apple device uses
**Legacy**. Both are valid and peers evidently accept either. Worth knowing before
assuming a peer's encoding, and a reminder that "what Apple does" and "what libmosey
does" are two different reference points — we have been treating the second as though it
were the first.

## 9. The election works. My first reading of it did not.

**This entry replaces an earlier version that was wrong on its central claim.** It is kept
as a correction rather than deleted, because the way it was wrong is the useful part.

### What I claimed, on 40 seconds and two devices

That our node "oscillates" between claiming and yielding mastership — 514 advertisements
at distance 0 against 178 at distance 1 — and that this was a candidate mechanism for the
long-standing "sending does not find peers" bug.

### What a longer capture with four devices actually shows

`captures/run-d-iphone.pcap`, 90s, channel 149, one Pixel and three Apple devices
including an iPhone actively scanning.

```
who names whom as master
  6a:89:d8:a5:88:9b  ->  be:35:be:c9:05:1f    98     (100% consistent)
  aa:a8:1b:28:3a:10  ->  (itself)            175     (100% consistent)
  be:35:be:c9:05:1f  ->  (itself)            142     (100% consistent)
  f6:49:75:da:e8:d4  ->  (itself)            498     <- ours
  f6:49:75:da:e8:d4  ->  be:35:be:c9:05:1f   292     <- ours
```

Our node looks inconsistent in aggregate. Plotted against time it is not:

```
 0s-10s: 1111111111111111111111111111111111111111     following be:35
10s-20s: 1111111111111111111111111111111111111111
20s-30s: 1111111111111111111111111111111111111111
30s-40s: 1111111111111111111111111100000000000000     <- one transition, ~37s
40s-90s: 0000000000000000000000000000000000000000     claiming master
```

One clean transition, not flapping. And the reason is in the same capture:

```
6a:89:d8:a5:88:9b   last heard 25.6s
be:35:be:c9:05:1f   last heard 30.3s      <- the master it was following
aa:a8:1b:28:3a:10   last heard 31.4s
```

**Every Apple device stopped transmitting at around 30 seconds, and our node promoted
itself about six seconds later.** A node whose master disappears is supposed to take over
its own cluster. That is not a bug; it is the behaviour working.

### What the aggregate hid, and the lesson

Two contiguous phases summed into counts that looked like 63/37 flapping. **A per-sender
total cannot distinguish "changed its mind repeatedly" from "changed its mind once", and
the difference is everything.** Any future claim about election behaviour needs the time
series, not the tally.

### The ordering claim was also wrong

I wrote that the election orders on **(counter, metric, address)**, counter first, from
the paper's phrasing. The same capture refutes it:

| device | metric | counter | outcome |
|---|---|---|---|
| `6a:89` | 510 | **68364** | **followed** |
| `be:35` | 520 | 608 | **won** |

A counter more than a hundred times larger lost to a higher metric. **Metric decides**;
whatever the counter orders, it is not this. `ElectionParamsV2::beats` has been corrected.
Address as the tie-break is still inferred — no capture yet holds two nodes with equal
metrics.

The counters are also not a cluster-wide clock: 68364, 608, 155 and 0 in one capture. Two
Apple devices in an earlier capture sat within 2 of each other (68349, 68351), which is
what suggested a shared clock; four devices show that was a coincidence. **Meaning
unresolved, and deliberately not guessed at.**

### What does survive

Only this, and it is much weaker than what it replaced:

- Our node advertises **metric 1** where Apple devices advertise 510, 520 and 537.
- Our node advertises **self counter 0**, unchanged across every frame in every capture,
  where Apple's vary.

Both are still true and still look like fields nobody fills in. **Neither has been shown
to cause a problem.** Our node followed the strongest peer while that peer was present and
promoted itself correctly when it left — with a metric of 1 throughout. For a phone, never
wanting to be master is arguably the right posture anyway.

So this is a note for `libawdl` to decide deliberately rather than a defect to fix, and
the link to the sending bug is **withdrawn**. There was never evidence for it.

### The open question this leaves

Three Apple devices stopped transmitting within six seconds of each other, mid-capture.
That is either the share sheet closing, a cluster-wide idle timeout, or AWDL teardown —
and which it is matters, because it determines how long a peer stays reachable after a
user stops looking at their screen. Worth a capture designed around it.

## 10. Verified: our election is correct, and the behaviour I called a defect is Apple's too

`captures/run-e-long.pcap` — 120s, channel 149, one Pixel and three Apple devices, with an
iPhone's share sheet **held open for the whole capture** so a master is present throughout.
That was the control finding 9 lacked.

```
election over time, one column per 5s.  M = claims master, f = follows, * = transition

02:3b:e8:75:9c:03  fffffffffffffffffffffffff
86:85:97:ed:a7:2e  MMMMMMMMMMM*fffff*fffff*f
be:35:be:c9:05:1f  MMMMMMMMMMMMMMMMMMMMMMMMM
f6:49:75:da:e8:d4  fffffffffffffffffffffffff     <- ours
```

| device | metric | counter | claims | follows | names as master |
|---|---|---|---|---|---|
| `be:35` (Apple) | **527** | 659 | 821 | 0 | itself — **holds it for all 120s** |
| `86:85` (Apple) | 523 | 208 | 552 | 629 | **alternates** — itself, then `be:35`, repeatedly |
| `02:3b` (Apple) | 510 | 68368 | 0 | 216 | `be:35` |
| **ours** | **1** | 0 | **0** | **1019** | `be:35`, in every single frame |

### Our node is exonerated

**1019 advertisements, every one of them following, no claim at any point.** With a master
present for the full two minutes our node stayed a follower throughout — which is exactly
right for a node whose metric is 1. Taken with finding 9, where it promoted itself six
seconds after every peer went silent, the election logic is doing both halves correctly:
yield while a stronger node is present, take over when it leaves.

### The behaviour I called a defect is what Apple devices do

`86:85` — a genuine Apple device — **alternates repeatedly** between claiming mastership
and following `be:35`, with three transitions inside two minutes. That is the pattern I
flagged as suspicious in our stack.

Its metric is **523 against the master's 527.** A near-tie contends; a distant one does
not. Our node at metric 1, and `02:3b` at 510, both follow without ever wavering.

So oscillation is not a symptom of anything. It is what AWDL does when two candidates are
closely matched, and had I looked at an Apple device first rather than only at ours, I
would not have raised it.

### Metric ordering, confirmed on four devices

```
527  be:35   master
523  86:85   contends, mostly follows
510  02:3b   follows
  1  ours    follows
```

Highest metric holds mastership. The counter remains irrelevant to the outcome: `02:3b`
carries **68368**, a hundred times the winner's 659, and follows without contest.

### What this means for libawdl

- **The election is understood well enough to implement.** Advertise a metric, follow the
  highest, take over on silence. Confirmed against four devices in two captures.
- **Metric 1 is a deliberate posture, not a bug.** A node that never wants to be master
  is a legitimate configuration, and ours behaves correctly as one. Whether `libawdl`
  should ever claim mastership is now a design choice with evidence behind it rather than
  a defect to fix.
- **Counter still unexplained**, and now demonstrably not load-bearing for the election.
  `libawdl` can advertise something sane and revisit it if a peer ever appears to care.

### The method note

`awdl timeline` exists because of finding 9. A tally said our node flapped; the time
series said it changed its mind once, correctly. **Any claim about election behaviour is
made from the timeline or not at all** — and it was the operator insisting on more
verification, not the data, that caught the first version.

## 11. BLE gives ten seconds' earlier notice of a departure than AWDL silence does

Prompted by an operator observation: Apple devices notice when another device goes away,
and that the mechanism is probably BLE rather than AWDL.

`captures/dual-awdl.pcap` and the matching BLE capture — 150s, both radios recorded
simultaneously on the same Pi, `tcpdump` on `mon0` and `btmon` on `hci0`. An iPhone had
its AirDrop sheet open, and its screen was locked partway through.

| event | t |
|---|---|
| iPhone's AirDrop BLE beacon last seen | **35.8s** |
| AWDL master `be:35` last frame | **46.1s** (+10.3s) |
| another node promotes itself to master | **50.3s** (+14.5s) |

**BLE stopped first, by ten seconds.** Then AWDL took another four before any peer
reacted at all.

### Why this is what you would expect, structurally

The AirDrop BLE beacon is **only** emitted while a device is actively sharing. With no
sheet open anywhere, a scan of the air returns Apple types 9 (AirPlay) and 22 and no
type `0x05` at all. So its presence is a continuously refreshed binary: *this device is
AirDropping right now*.

AWDL cannot be that, and the reason is finding 6: **a device occupies only 3 to 9 of its
16 availability windows.** A peer is legitimately not transmitting most of the time, so
"silent" and "gone" are indistinguishable without waiting long enough to be sure — which
is exactly the ten seconds observed. Absence is normal in AWDL; absence is meaningful in
BLE.

Two beacons were distinguishable in the capture by payload, which is what made the
measurement possible at all:

```
0512409728940000000003ef8b5c621691d06a00   real contact hashes  -> the iPhone
0512000000000000000001000000000000000000   all-zero hashes      -> our own device
```

Ours continued throughout; the iPhone's stopped and never returned.

### What is NOT established

**That the BLE device and the AWDL device are the same physical unit.** BLE addresses and
AWDL addresses are independently randomised, so they cannot be linked from the capture.
The correlation is temporal and circumstantial: one device's AirDrop beacon ceased, and
about ten seconds later one device's AWDL presence ceased, in a window where exactly one
device was locked.

There is a competing explanation worth taking seriously: **AWDL clusters may idle
collectively.** In `run-d-iphone.pcap` three Apple devices went quiet within six seconds
of each other, and here `be:35` — which held mastership for a full 120s in an earlier
capture — went silent shortly after the iPhone's sheet closed. It is possible the open
sheet was keeping the whole cluster awake rather than that we watched one device leave.

The BLE scan also ran with duplicate filtering on, so "last seen" is approximate.

### What it means for us

If BLE cessation is the signal, then **peer expiry belongs in the app, not the daemon** —
BLE lives in the app, deliberately, because `libmosey` links no Bluetooth library at all
and Google draws the same line. A peer list that expires entries on AWDL silence will
either drop live peers that are simply between windows, or hold dead ones for ten seconds
longer than Apple does.

That is a concrete, testable difference in behaviour, and it would show up to a user
exactly as "devices linger in the list after they are gone".

## 12. Departure is per-device, not a cluster winding down

Finding 11 left two explanations open: either a device's own BLE beacon ceasing is the
departure signal, or an AWDL cluster idles collectively and the ten-second gap was a
wind-down. `captures/two-iphones-awdl.pcap` and `two-iphones-ble.pcap` separate them.

Setup: **both Pixels taken off the air entirely** (`mosey0` absent, `tarish.awdl.wanted=0`,
channel override cleared), two iPhones with AirDrop sheets open, 180s on channel 149 with
BLE and AWDL recorded at once. The operator locked one iPhone, then the other.

| device | locked? | AWDL last frame |
|---|---|---|
| `be:35:be:c9:05:1f` | yes | 100.1s |
| `8a:c3:f7:4b:ce:de` | yes | 101.7s |
| `02:3b:e8:75:9c:03` | **no** | **178.2s — transmitted throughout** |

**The third device is the control, and it settles it.** `02:3b` was never touched, kept
sending AWDL for the full capture, and took over as master when the other two stopped. A
cluster winding down collectively would have taken it with them. Departure is per-device.

The two that were locked stopped **1.6s apart**, which matches "one before the other".

### The ten-second gap reproduces

BLE AirDrop beacons last seen at 90.4s; the locked devices' AWDL frames ceased at 100.1s
and 101.7s. Same ordering and roughly the same interval as finding 11: **BLE first, AWDL
about ten seconds later.**

### Presence and sharing are separate signals

After the AirDrop beacons stopped, the air still carried Apple types **0x10 (Nearby),
0x12 (Find My), 0x09 (AirPlay)** from the same devices — 42 frames in the remaining
85 seconds. Only type **0x05** went away.

So the devices never left; they stopped *sharing*. A peer list wants exactly that
distinction, and BLE draws it with two different beacon types. AWDL cannot draw it at all.

### A measurement limitation, now fixed

The BLE side was captured through `bluetoothctl scan on`, which enables **duplicate
filtering**: the controller reports each unchanged advertisement roughly once per 16
seconds. Both iPhones' beacons therefore appear on the same 16s cadence and both fall in
one sampling window, so BLE could not resolve the 1.6s separation that AWDL showed
clearly.

`tools/dual-capture.sh` now uses `hcitool lescan --duplicates`, which reports every
advertisement. Good enough for presence, useless for timing a departure — worth knowing
before trusting a BLE timestamp.

### What this means for Tarish

Peer expiry should hang off **the AirDrop beacon specifically**, not AWDL silence and not
BLE presence in general:

- **AWDL silence is not departure.** A device attends 3-9 of its 16 windows, so silence is
  its normal state, and it stopped transmitting ten seconds after it had already stopped
  sharing.
- **BLE presence is not sharing.** Nearby and Find My continue from a device that has
  closed its share sheet.
- **The `0x05` beacon is the signal**, and it lives in the app, where Bluetooth already
  belongs — `libmosey` links no Bluetooth library and Google draws the same line.

## 13. Two locks, 35s apart: each device's BLE beacon stops before its own AWDL — and the gap is 1-5s, not 10

The definitive version of findings 11 and 12, and it **corrects the interval I reported in
both**.

`captures/two-locks-awdl.pcap` and `two-locks-ble.pcap`. Two iPhones with AirDrop sheets
open, both Pixels off the air, 180s on channel 149 with BLE and AWDL recorded together.
One iPhone locked, then the other about 35 seconds later — a deliberate gap, so the two
departures could not blur into one event.

| device | AirDrop beacon last seen | its AWDL last frame | gap |
|---|---|---|---|
| iPhone B -> `8a:c3:f7:4b:ce:de` | **48.1s** | **53.3s** | **+5.2s** |
| iPhone A -> `be:35:be:c9:05:1f` | **83.4s** | **84.7s** | **+1.3s** |
| third device `02:3b` (never locked) | — | 128.8s | — |

```
AirDrop beacons     40826f6a  first  0.0  last 48.1   139 beacons
                    40401947  first  0.5  last 83.4   287 beacons
```

**35.3s apart on BLE, 31.4s apart on AWDL.** The two departures are cleanly separated and
each BLE device pairs with exactly one AWDL device by timing — which is what finding 12
explicitly could not do, because the address spaces are independently randomised and
nothing links them but coincidence in time.

### BLE goes first, per device, every time

Not as an aggregate and not as a cluster effect. Each phone's own beacon ceased at its own
lock, and its own AWDL frames followed 1.3 to 5.2 seconds later.

### The "ten seconds" in findings 11 and 12 was my measurement, not the protocol

Both earlier numbers came from a BLE capture running through `bluetoothctl scan on`, which
enables duplicate filtering: each unchanged advertisement is reported roughly once per 16
seconds. The last beacon I could see was therefore up to 16s **before** the true
cessation, which inflated every gap.

With `hcitool lescan --duplicates` the same two phones produced 139 and 287 beacons instead
of 6 each, and the real interval is **1-5 seconds**.

That matters for anything built on it: a peer-expiry timeout sized for a ten-second gap
would be two to eight times longer than it needs to be.

### The third device is no longer a clean control

In finding 12 an unlocked device transmitted for the full capture, which is what refuted
collective wind-down. Here the same device ran to 128.8s — 44 seconds after the last iPhone
left — and then stopped on its own without being touched.

That does not reinstate collective idling: it outlived both departures by a wide margin and
stopped long after, which looks like its own idle timeout once no peers remained. But it
is a weaker control than finding 12 implied, and worth saying so.

### Where this leaves peer expiry

Unchanged in direction, sharper in magnitude. Expire on the **`0x05` beacon**, with a
timeout on the order of a few seconds:

- **AWDL silence is not departure** — a device attends 3-9 of its 16 windows, and it keeps
  transmitting for seconds after it has already stopped sharing.
- **BLE presence is not sharing** — Nearby, Find My and AirPlay continue from a phone whose
  share sheet is closed (finding 12).
- **The AirDrop beacon is the signal**, it stops within a second or two of the user
  leaving, and it lives in the app where Bluetooth already belongs.

## 14. The discovery layer, decoded — device names, service types and port 8770

Service Response (tag 2) is the densest tag in the protocol — 444 AirDrop records in a
single 180s capture — and the one that makes a capture legible.

```
services advertised
  _airdrop._tcp.local                      444
  _applicationservicepairing._tcp.local    246
  _appsvcprepair._tcp.local                246

instances
  9e392c9db1dd._airdrop._tcp.local         -> 87b469cc-….local:8770
  91eae90ce21e._airdrop._tcp.local         -> 5b28e76c-….local:8770
  iPhone, iPhone (2)                       device names, in the clear
```

Counts cross-checked against `tshark -V` on the same capture: 444 / 246 / 246 exactly,
and port **8770** on all 444 AirDrop SRV records.

### AWDL does not carry mDNS verbatim

It carries the same records under its own encoding with a **fixed dictionary**, so the
strings every AirDrop frame would otherwise repeat cost two bytes:

```
0xC007 -> _airdrop._tcp.local        0xC00C -> local
0xC009 -> _airdrop                   0xC00A -> _tcp.local
0xC000 -> NULL, contributes nothing to the name
```

There is no negotiation and no per-frame table. The dictionary is static and shared, so a
decoder either knows these fifteen values or produces names that **still parse and are
wrong** — which is the failure mode to watch for, since nothing errors.

### Three traps, all of which parse cleanly when wrong

- **The name length includes the type byte that follows it.** Taking it at face value runs
  the name decoder one byte into the type field: the name gains a spurious trailing label
  and every later offset in the record is shifted.
- **SRV priority, weight and port are big-endian** — DNS's own layout, carried through
  unchanged, and the only big-endian fields in AWDL. Read little-endian, port 8770 becomes
  16418. Plausible, and wrong.
- **A record that will not parse ends the list.** Resyncing by scanning for the next
  plausible record manufactures entries that were never on the air; if the offsets are
  wrong they are wrong from that point on.

### What it gives us

An identity layer. Before this a capture was addresses; now it is *"iPhone (2) is
advertising AirDrop at `5b28e76c-….local:8770`"*. That matters for three things:

- **Correlating BLE with AWDL.** Findings 12 and 13 could only pair a BLE beacon with an
  AWDL sender by the timing of a departure. A device name and a stable instance identifier
  give a second, independent handle.
- **Knowing what to advertise.** `libawdl` must emit these records, and now we have real
  ones to match rather than a specification to interpret.
- **Port 8770**, read off the air. Worth noting our own GoOpenDrop config carries 8772.

---

## Setup

Moved to [SETUP.md](SETUP.md), with the rig, the build steps and the traps.


## 15. ★ The AP's channel IS in the AWDL slots — coexistence by time-sharing, observed

**This is the highest-value question in the research brief (§6.3), and the answer is yes.**

The brief asks: does a device associated to an access point put the AP's channel into its
AWDL channel sequence, and does it do so even when that channel is not a social channel?

`captures/transfer-attempt.pcap`, and every other capture taken tonight. One sender,
`be:35:be:c9:05:1f`, advertises this sequence — 640 times, byte-identical:

```
slot   0    1    2    3  4  5  6  7  8   9   10   11 12 13 14 15
chan  104   0   149   0  0  0  0  0  6   0   149   0  0  0  0  0
       ^
       the access point's channel
```

**Channel 104 is 5520 MHz, and 5520 MHz is `[redacted-ap]`** — confirmed by a scan the
same evening (`xx:xx:xx:xx:xx:xx  5520  -58  [redacted-ap]`). It is **not** an AWDL
social channel: only 6, 44 and 149 appear in Google's 263-country table, and our own notes
record that `libmosey` **rejects 104 as an AWDL channel outright**.

So the sequence carries it, and carries it differently from `p` and `s` — exactly the
possibility the brief flagged and nobody had demonstrated.

### It is a standing arrangement, not a transfer-time upgrade

Present in every capture of the evening, not only during the attempted transfer:

| capture | frames advertising `[6, 104, 149]` |
|---|---|
| `run-d-iphone.pcap` | 142 |
| `run-e-long.pcap` | 821 |
| `two-locks-awdl.pcap` | 905 |
| `transfer-attempt.pcap` | 640 |

The device keeps a slot for its AP whether or not anything is being sent. It is how it
stays associated, not something it negotiates when a transfer starts.

### The budget, in slots

Four of sixteen windows occupied, and each has a job:

| slots | channel | purpose |
|---|---|---|
| 1 (slot 0) | **104** | the infrastructure association |
| 2 (slots 2, 10) | 149 | AWDL, the regional social channel |
| 1 (slot 8) | 6 | the fixed cross-band rendezvous — finding 7 |
| 12 | — | absent |

**This is what "AWDL and Wi-Fi coexist on one radio" actually means.** Not two radios, not
DBS, not a firmware trick: the device schedules one window in sixteen for the AP and is
simply not on the AWDL channel then. 1/16 of the time is enough to hold an association.

### What it corrects on our side, and it is the whole BCM4383 problem

`tarishd` chooses **one band** and hands `libmosey` a single channel set, and `libmosey`
builds a 16/16 single-channel schedule (finding 8, measured). **We never reserve a slot for
the association at all.** So on a chip that cannot physically do two channels at once,
AWDL takes the radio and Wi-Fi dies — which is precisely the frankel behaviour recorded in
BUILD-NOTES 40 and 42, and which we treated as a hardware limitation.

It is not only a hardware limitation. Apple solves it in the **schedule**, on hardware that
also cannot hold two channels at once, by not being on the AWDL channel during slot 0. Our
stack cannot express that, because `libmosey` will not build a multi-channel sequence — and
that is now a requirement for `libawdl` rather than an optimisation.

The `AP Beacon alignment delta` field from finding 6 belongs to this mechanism: a device
time-sharing with an AP needs to know where that AP's beacon falls relative to its own
windows. It read 0 in the captures where nothing was time-sharing.

### Proven — see finding 18

Originally recorded as inferred, then as falsely proven (finding 16), and now established
by a controlled experiment with both states confirmed before either capture was read.

## 16. Slot 0's content changed — but NOT because of anything we did

**This entry is a correction. Its first version claimed a controlled result from an
experiment that was never performed.** What the capture shows is real; what caused it is
unknown.

I asked for both phones to be taken off Wi-Fi, started the capture, saw channel 104
disappear, and wrote it up as proof. The operator had not touched the phones. The control
did not happen.

```
with Wi-Fi      104,  0, 149, 0, 0, 0, 0, 0, 6, 0, 149, 0, 0, 0, 0, 0
without Wi-Fi     6,  0, 149, 0, 0, 0, 0, 0, 6, 0, 149, 0, 0, 0, 0, 0
                  ^
                  slot 0, and nothing else
```

**Channel 104 occurrences: zero**, across the whole capture. `be:35` had advertised it in
every previous capture of the evening — 142, 640, 821, 905 and 218 frames — and now
advertises `[6, 149]` only. Everything else is untouched: same 4-of-16 occupancy, same
slots 2 and 10 on 149, same slot 8 on 6.

### The absence is real; the cause is not known

It is **not** a sampling artefact. `be:35` carried 104 in 22% of its frames in the previous
capture; the chance of seeing none of it in 121 frames at that rate is **1.4e-13**. The
device genuinely stopped advertising the AP channel.

But nothing was deliberately changed. Candidate causes, none tested:

- the phone's association dropped on its own — moved, slept, roamed
- the AirDrop sheet closed, changing what the device schedules
- something else entirely

**So slot 0 changing its content is observed. That the association drives it is still the
inference from finding 15, not a measurement.**

### What the hypothesis would predict

If slot 0 is the association slot, it carries the AP's channel while associated and falls
back to channel 6 when not — and AWDL/Wi-Fi coexistence is one window in sixteen, 6.25% of
airtime, rather than DBS or a second radio. That remains the best explanation of everything
seen so far. It is not yet demonstrated.

### Three times now, the same mistake

I have built a conclusion on an assumed experimental condition three times in this session:
a transfer that never happened, a Wi-Fi disconnect that hit the wrong phone, and this one —
a disconnect that never occurred at all. Each time the data was real and my account of what
produced it was invented.

**The rule this needs: confirm the input state before interpreting the output**, not after.
Asking for a change and then reading the result as though the change was made is not an
experiment, it is a guess with a capture attached.

Two things to carry into the real test when it happens:

- **Verify the variable actually moved** — from the phone, not from the absence of an
  objection.
- **A 2.4 GHz association is invisible in the schedule.** Its channel would be 6, which is
  already the rendezvous slot, so it cannot be told apart from an unassociated device. Only
  a 5 GHz AP shows up distinctly, so any test of this must use a 5 GHz network.

### And it is the whole BCM4383 problem, now with a mechanism

`tarishd` picks one band, `libmosey` builds a 16/16 single-channel schedule (finding 8),
and **no slot is ever reserved for the association**. On a chip that cannot hold two
channels, AWDL therefore takes the radio and Wi-Fi dies — BUILD-NOTES 40 and 42, recorded
as a hardware limitation.

Apple appears to run on hardware with the same constraint and keep its association by
scheduling around it. If finding 15 holds, the capability we lack is in the scheduler
rather than the silicon, and `libmosey` will not express it — which would make
multi-channel scheduling with a reserved association slot a requirement for `libawdl`.
**Conditional on a control that has not yet been run.**

## 17. A 6 GHz association is invisible in the channel sequence

`k-mbprom5` appears in several captures advertising `[6, 149]` with **nothing in slot 0** —
no access point channel — which looked like evidence against finding 15, or like Macs
scheduling differently from iPhones.

Neither. The machine reports:

```
Channel: 53 (6GHz, 160MHz)    PHY Mode: 802.11be    Signal: -37 dBm
```

**It is associated on 6 GHz.** Every operating class observed in an AWDL *channel sequence*
is 2.4 GHz (`0x51`) or 5 GHz (`0x80`); nothing there encodes a 6 GHz channel. So slot 0
falls back to 6 as it would with no association at all.

> **Partly corrected by finding 22.** 6 GHz is not unrepresented in the protocol — it is
> carried in tags 32 and 33, which had no published meaning when this was written. What
> remains true is that it does not appear in the *channel sequence*, so slot 0 cannot show
> it and the association-slot test needs a 5 GHz network.

### Two bands are invisible here, for different reasons

- **2.4 GHz** — its channel is 6, which is already the rendezvous slot, so an associated
  device is indistinguishable from an unassociated one.
- **6 GHz** — no operating class exists for it in the sequence encoding.

Only a **5 GHz** association shows up distinctly. Any test of the association-slot
hypothesis must use one, and a device that appears to contradict it should have its band
checked before the hypothesis is doubted.

### A note on method

This was resolved by reading the Wi-Fi state of the machine the work is running on, after
proposing an experiment that would have required the operator to determine the band from
an iPhone's UI — which does not display it. The information was already to hand.

## 18. ★ PROVEN: slot 0 is the association slot

The controlled experiment, run properly. Both states confirmed by the operator **before**
either capture was analysed, and the prediction stated in advance.

`captures/assoc-connected.pcap` and `captures/assoc-disconnected.pcap`. Two iPhones with
AirDrop sheets open throughout; the only variable is whether they are associated to a
5 GHz access point.

```
connected      104, 0, 149, 0, 0, 0, 0, 0, 6, 0, 149, 0, 0, 0, 0, 0     166 frames
disconnected     6, 0, 149, 0, 0, 0, 0, 0, 6, 0, 149, 0, 0, 0, 0, 0     510 frames
                 ^
                 only slot 0 differs; every other slot is byte-identical
```

| state | slot 0 = 104 | slot 0 = 6 |
|---|---|---|
| connected to the 5 GHz AP | **166** | 0 |
| Wi-Fi off | **0** | **1020** |

**Slot 0 is the association slot.** It carries the access point's channel while the device
is associated and falls back to channel 6 — the 2.4 GHz social channel — when it is not.
The slot is never surrendered; only its content changes. Occupancy stays at 4 of 16, slots
2 and 10 stay on 149, slot 8 stays on 6.

### What this means

AWDL's coexistence with infrastructure Wi-Fi is **not** a firmware capability, a DBS
feature, or a second radio. **It is one window in sixteen, reserved permanently, whose
channel follows the association.** 6.25% of airtime is what holds a Wi-Fi link while AWDL
runs on the same chip.

### And it is the BCM4383 problem, with a mechanism and a fix

`tarishd` picks one band and `libmosey` builds a 16/16 single-channel schedule (finding 8,
measured), so **no slot is ever reserved for the association**. On a chip that cannot hold
two channels at once, AWDL therefore takes the radio and Wi-Fi dies — recorded in
BUILD-NOTES 40 and 42 as a hardware limitation.

Apple runs hardware under the same constraint and keeps its association by scheduling
around it. **The capability we lack is in the scheduler, not the silicon**, and `libmosey`
will not express it — which makes multi-channel scheduling with a reserved slot 0 a
requirement for `libawdl`, with this capture as the exact target to reproduce.

The `AP Beacon alignment delta` field (finding 6) belongs to this mechanism: a device
time-sharing with an AP needs to know where that AP's beacon falls relative to its own
windows.

### How this one was run, after three that were not

1. Operator confirmed both phones connected.
2. Capture taken, and **checked for the precondition before interpreting** — 166 frames
   carrying 104, so at least one phone was on the 5 GHz side of a dual-band SSID and the
   association was visible. Had it not been, the run would have been reported inconclusive.
3. Prediction stated in advance: slot 0 falls back to 6, everything else unchanged.
4. Operator confirmed Wi-Fi off on both.
5. Second capture taken and compared.

An earlier attempt produced the same *observation* with none of this and was withdrawn
(finding 16). The difference between the two is not the data; it is that this one could
have come out wrong.

## 19. The data plane, decoded — without ever capturing a file

The encapsulation AirDrop uses to carry a payload, obtained from frames that are not the
payload.

```
802.11 QoS Data  ->  LLC/SNAP  ->  AWDL data header  ->  IPv6  ->  UDP / ICMPv6
```

Cross-checked against `tshark -Y awdl_data` on `captures/datapath-wifi-off.pcap`: 44 frames
in both, ethertype `0x86dd` throughout in both, maximum sequence **416** in both.

### Why the file itself could not be captured, settled

Four attempts, and the answer is neither the path nor the bandwidth:

| attempt | result |
|---|---|
| 20 MHz, phones far (-85 dBm) | 23,117 Block Acks, **0** data frames |
| 80 MHz | almost no traffic — and the room was empty, so this proved nothing |
| 20 MHz, phones close (-49 dBm) | 35,895 Block Acks, **44** data frames |
| 40 MHz centred on 151 | 1,655 control frames — **worse**, not better |

**Multicast decodes; unicast does not.** All 44 data frames are addressed to
`33:33:00:00:00:fb` (`ff02::fb`, mDNS) or `33:33:00:00:00:16` (`ff02::16`, MLDv2).
Multicast cannot be rate-adapted, because there is no ACK to adapt against, so it goes out
at the lowest basic rate. The unicast payload rides high VHT rates that this adapter cannot
demodulate — which is also why every Block Ack arrives while the traffic being acknowledged
does not.

**Widening the monitor makes it worse on `mt76`.** Both 40 and 80 MHz reduced total capture
by an order of magnitude against 20 MHz. Driver behaviour, not protocol.

**And the sequence numbers prove the missing frames exist.** 44 captured frames carry
sequence numbers up to **416**, so roughly 416 were transmitted and we decoded a tenth.

### Why it did not matter

**The multicast frames use the same encapsulation a file transfer uses.** The rate differs;
the framing does not. So the header was recoverable from the frames we could read, and
`crates/libawdl/src/data.rs` decodes it.

An earlier hypothesis — that both phones being on one access point let AirDrop carry the
payload over the infrastructure link instead of AWDL — is **refuted**: with Wi-Fi off on
both, there were still 35,895 Block Acks. The payload rides AWDL.

### The header, and two traps in it

```
2 bytes  unnamed
2 bytes  sequence, LITTLE-endian    per-peer, monotonic
         short form: 2 bytes 0x0000
         long form:  0x03 <len> <len bytes>, TLVs, then 0x03 <len> again
2 bytes  ethertype, BIG-endian      0x86dd in everything observed
         then the IPv6 packet
```

- **The sequence is little-endian and the ethertype beside it is big-endian.** Read
  `0x86dd` the wrong way round and you get `0xdd86`, which matches nothing and reads as a
  framing bug rather than a byte-order one.
- **The long form's TLVs use a ONE-byte length**, unlike the two-byte form every action
  frame uses. The wrong tag width walks off the end of the frame.

### What is still missing

The payload bytes themselves, and therefore anything about how AirDrop chunks a file above
IP. That needs an adapter that can demodulate high-rate unicast VHT — a more capable radio,
not a different configuration. **The framing question is answered; the throughput question
is not.**

---

## 20. The two bytes everyone calls padding are a field, and only OWL zeroes them

Synchronization Parameters (tag 4) ends with two bytes after the embedded channel
sequence. OWL's `frame.h` comments them out as `/* uint8_t pad[2]; */` and Wireshark
renders them the same way. Across every capture in `captures/` that is wrong.

| | tag 4, last 2 bytes | tag 18, last 3 bytes |
|---|---|---|
| TLVs examined | 7054 | 7054 |
| non-zero | **2018 (29%)** | **0** |

Same captures, same frames, same senders. That contrast is the argument: if these were
uninitialised stack a builder forgot to clear, tag 18's three bytes would show it too, and
in 7054 samples not one does.

### What decides it

Not the frame — the sender's own state, and it tracks one bit of `flags`:

```
2a:f3:94:4d:96:79  flags=0x1800  slot0=102       tail 00 00   x166
be:35:be:c9:05:1f  flags=0x1800  slot0=102       tail 00 00   x197
16:50:71:fb:18:bb  flags=0x1800  slot0=6         tail 00 00   x517
d2:75:0e:61:4c:e2  flags=0x1000  slot0=absent    tail 00 4c   x164
6a:89:d8:a5:88:9b  flags=0x1000  slot0=absent    tail 20 64   x190
                                                 tail 00 4c   x20
```

A sender advertising `0x1800` puts its association channel in slot 0 and writes zero here.
A sender advertising `0x1000` leaves slot 0 empty and writes a value here. One device was
seen switching from `00 4c` to `20 64` within a single capture, so it is not fixed at boot.

`0x20 0x64` reads plausibly as a Legacy channel-sequence pair — qualifier `0x20`, channel
100 — for devices that were associated on 100/104 in the neighbouring captures. `0x00 0x4c`
does not: 76 is not a channel. **So there is a shape but not yet a decode, and it is
recorded as that rather than given a speculative name.**

### What was done about it

`SyncParams` carries the two bytes as `trailing` and puts back what it was given, so a
parsed frame re-encodes to the bytes it arrived as. `tests/build_sync.rs` pins it with an
Apple frame ending `00 4c`, which a builder writing zeros cannot reproduce. When
constructing a frame of our own we write zeros — what OWL does, and what every associated
Apple device does.

### A second thing this turned up

The radiotap parser was skipping the FLAGS byte, so nothing in this project had ever
checked `BADFCS`. A corrupt frame does not announce itself here — TLV lengths are
explicit, so flipped bits parse cleanly and contribute a plausible wrong value — which
means every capture-derived claim had an unexamined error term. It is parsed now, and the
answer is reassuring: **zero BADFCS frames across all 7054**, so nothing previously
concluded rests on corrupt input. Worth having asked.

## 21. The Legacy channel list is not channels — it is 40 MHz centres

A frame states its schedule **twice**: tag 4 embeds it in Legacy encoding, tag 18 repeats
it in OpClass encoding. That redundancy is what makes the undecoded Legacy qualifier byte
recoverable without any new captures — pair the two lists slot by slot and the qualifier is
sitting next to its own answer.

Over 62189 occupied slots, the entire observed mapping:

| qualifier | Legacy channel | tag 18 control channel | opclass | count |
|---|---|---|---|---|
| `0x1d` | 151, 46 | 149, 44 | 128 | 44319 |
| `0x1e` | 102, 151 | 104, 153 | 128 | 3782 |
| `0x2b` | 6 | 6 | 81 | 14088 |
| `0x00` | absent | absent | 0 | 142547 |

**The Legacy list carries the centre of the 40 MHz pair, not a channel anyone tunes to.**
`0x1d` means the control channel is two below, `0x1e` two above, `0x2b` means a 20 MHz
channel that is its own centre.

### Why this one matters more than its byte count

A peer advertising 151 is listening on **149 or 153**. Tuning to 151 meets nobody, and
nothing anywhere reports an error — the radio sits on an empty channel and the peer looks
unreachable. `ChannelSequence::control_channels()` resolves it; `channels` is the raw list
and should not be acted on directly.

### What is measured and what is not

The mapping is measured. A bit-level split into band / bandwidth / control-position fits
these three values neatly — `0x1d` and `0x1e` share their high bits and differ in the low
two — but **three values cannot determine three fields**, so that reading is not asserted.
80 MHz and 6 GHz slots have never appeared in a Legacy list, so `LegacyQualifier::Other`
returns no channel rather than guessing an offset.

## 22. Election v2's counters are a tenure as master, not a clock

Their values looked incoherent — 68364 next to 5 in one capture — which is why an earlier
version of this file called their meaning unresolved and declined to guess. Measured, they
are simple.

**`self_counter` counts how long this node has been master, in units of 192 Availability
Windows.** It advances by exactly one, only while the node claims mastership. One Apple
device's AW counter at successive increments read 15434, 15625, 15817, 16009 — 191, 192,
192 — and the capture timestamps put the interval at 3.15 s across nine consecutive
increments. 192 AWs of 16 TU is **3.145728 s**, and 192 is twelve complete sixteen-slot
cycles.

**`master_counter` is the counter of whoever the node names as master, relayed.** A
follower reproduced its master's 569, 570, 571, 572 exactly, one frame behind each change,
while its own counter sat frozen at 68364 for the full 28 seconds it followed.

So the incoherent values were never incoherent: a device that has been master for hours
reports a large number and one that just took the job reports a small one.

### What this does not change

It is still not the election's ordering term — see finding 9 and `beats`, where a node with
a counter 112 times larger yielded to one with a higher metric. Knowing what the counter
means makes it *emittable*, which is the point: a node can now advertise a correct tenure
instead of copying a number off an Apple device.

## 23. Tag 17 is not an AWDL format

The IEEE 802.11 Container carries a standard **VHT Capabilities element** — `0xbf`, twelve
bytes — verbatim. It is the one field in this whole protocol that did not need reverse
engineering, only recognising: IEEE 802.11-2020 §9.4.2.157 specifies it completely.

The captured Apple value decodes as a two-stream 80 MHz phone: maximum MPDU 11454, widths
20/40/80 with neither 160 nor 80+80, Rx LDPC, short GI at 80 MHz, A-MPDU exponent 7, and
MCS 0–9 on two spatial streams in both directions.

**The consequence for transmitting is the whole reason to care.** These bits describe the
radio, so they have to come from the radio — `libawdl-hal` — and not from a table copied
out of an Apple frame. Announcing capabilities the hardware does not have is an invitation
to a peer to use them.

## 24. Tag 7 is HT Capabilities, mostly in the 802.11 sense

Same shape of answer as finding 23. Bytes 2..5 are the IEEE 802.11-2020 §9.4.2.55 **HT
Capability Information** field and **A-MPDU Parameters**, and the two bytes after them are
the start of the Supported MCS Set. Two independent sources agree: OWL's
`awdl_ht_capabilities_tlv` names exactly those fields, and the values decode as sane radios.

```text
  00 00  6f 00  1f  ff ff  00 00                Apple, 9 bytes
  00 00  6f 88  1b  ff ff  00 00 ... 96 00 ...  Apple, 20 bytes
  00 00  6f 00  17  ff ff  00 00                libmosey, 9 bytes
         ^^^^^  ^^  ^^^^^
         info   A-MPDU   MCS 0-15
```

`0x006f` is LDPC, 40 MHz, SM power save disabled, short GI at both 20 and 40.
`0x886f` adds the 7935-octet A-MSDU and L-SIG TXOP protection. The A-MPDU byte differs
between all three — 16 µs, 8 µs and 4 µs minimum start spacing — which is the kind of
variation that only makes sense if these really are per-radio capability fields.

**A cross-check worth having:** the HT element says two spatial streams and so does the
VHT element in tag 17 of the same frame. One radio, described twice, agreeing. A mis-split
of either would show up as a disagreement, and `tests/build_election.rs` asserts it.

The tag is still **not a fixed struct** — 8, 9 and 20 bytes — and all the variation is in
the tail after byte 7, which nobody has decoded. The leading two bytes are `00 00`
everywhere and OWL calls them unknown too.

## 25. Tag 6 does not need to be solved, and here is the proof

Service Parameters is a hash of the services a node advertises. The field boundaries come
from OWL — three unnamed bytes, a 16-bit `sui`, a bitmask — and the captures support that
split. The mask is clearly per-service and stable:

```text
  _airdrop         bit 19, in every frame that advertises it
  _companion-link  bit 22, in all four
```

which reads like a Bloom filter over the service name. Twenty observations cannot recover
the function that produced them, and inventing one would put an unverifiable claim about
our own services on the air.

### Why that is fine

**`libmosey` sends this tag completely empty — `sui` 0, mask 0 — while advertising
`_airdrop`, and AirDrop to a Mac works.** Two blazer sessions are in `captures/` doing
exactly that, 1611 frames of it, and those are the same builds that transfer to a Mac
today.

So an Apple device does not require a populated Service Parameters to discover a peer or
accept a transfer from one. `ServiceParams::empty()` is what a transmitter should send, and
it is named for what it is rather than reached by `Default` so that the choice is visible.

**This is a measurement of what Apple tolerates, not of what Apple means.** It is the right
call today and the first place to look if a future peer starts filtering on this tag.

### The general shape of the remaining work

This is the second tag where the answer was "we do not need it" rather than "we decoded
it", and it is worth noticing the pattern: the bytes still opaque are increasingly ones
that are either radio-specific (so they belong to the HAL), or vendor-internal state that a
peer does not act on. The way to tell which is to transmit without them and watch.

## Open, not yet investigated

### AirDrop's non-contact code is Apple-to-Apple only — it does not reach us

**Corrected.** An earlier version of this note warned that recent iOS may require a
matching code before an AirDrop to a non-contact proceeds, and that our devices, being
non-contacts by definition, could start being refused after an iOS update.

Operator observation, and it settles it: **the code request only ever appears between two
iPhones.** It has never appeared for an Android peer — not for Tarish, and not for stock
Quick Share's AirDrop support either, which is Google's own privileged implementation
riding the same `wonder.ko` and `libmosey`. So it is gated on both ends being Apple
devices, and there is no interop cliff waiting for us.

**Why that is coherent.** The code is the bootstrap of a *persistent* trust relationship,
and that only means anything when both peers have durable cryptographic identities to bind
it to. Between Apple devices there is an Apple ID behind each end. A third-party peer has
nothing to bind, so it falls back to the per-transfer accept prompt — which is exactly what
Tarish already presents, and is arguably the more honest behaviour anyway.

It also appears once per device pair and never again, which is consistent with a trust
binding being stored rather than a check being repeated.

**What was wrong in my reasoning.** I traced the caching to our TLS certificate, which
`sharingd` regenerates on every start (`build_acceptor`, "generated fresh at each start",
deliberately not persisted). That would have meant a prompt after every daemon restart. The
chain was plausible and the premise was false — the prompt never applies to us, so nothing
about our certificate affects it.

### The certificate rotation is still real, and still worth a decision

Independent of the above. Two of our identities change on every restart:

- **mDNS instance name** — derived from `mosey0`'s MAC, which is fresh each AWDL session.
  Blazer appeared as `56:ba:4f:f6:3a:44`, `16:50:71:fb:18:bb` and `f6:49:75:da:e8:d4` in
  one evening.
- **TLS certificate** — generated at each start and never written to disk.

Apple's instance names rotate too, so that half matches. The certificate is a deliberate
choice with a real argument behind it in the code: *"a key that never touches storage
cannot be stolen from storage."* Nothing currently depends on identity continuity, so
nothing is broken.

**It is worth knowing that we have foreclosed the option**, though. Any future feature that
wants a peer to remember us — a trusted-device list, a one-time confirmation, a
reconnect-without-prompting — needs a stable identity, and we throw ours away twice per
restart. That should stay a decision rather than becoming an accident.
