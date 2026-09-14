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

## 26. Election v2's second address is the parent in the sync tree

An earlier note here called it "a second address whose role is not documented", observed
equal to the sender's own address in every frame checked. That check was too small.

```text
  distance   other == master   other != master   other == self
         0             10487                 0           10487
         1              7004                 0               0
         2                32               634               0
```

At distance 0 the parent is the node itself; at distance 1 the parent *is* the master. In
both cases the field looks like a copy of something else, which is why a sample that
contained only those two cases concluded it was redundant. At distance 2 it stops
coinciding.

### Proven, not inferred

If this is the next hop toward the master, the node it names must itself be advertising one
hop closer to the *same* master — and that is checkable in the same capture. Of the 634
frames where the two addresses differ, the named node was independently heard claiming
`distance − 1` to the identical master in **634 of 634**. No counterexample, and not one
case where the named node was never heard at all.

`ElectionParamsV2::parent_for` builds it. A node two hops out must name who it actually
heard the master through, because naming the master as its own parent describes a tree that
does not exist.

## 27. The Synchronization Parameters flags word has exactly two values, and bit 11 explains the trailing bytes

Finding 20 established that the two bytes after the channel sequence are not padding, and
left their presence unexplained. It is explained: **bit 11 of the flags word announces
their absence**, without exception.

```text
  flags    frames   trailing non-zero
  0x1800    13986                   0
  0x1000     4171                4171
```

Only those two values appear anywhere, across Apple, `libmosey` and OWL, in 18157 frames.
So the field is optional and its absence is declared — not padding some devices forget to
clear, and not uninitialised stack.

**What it contains is still unknown**, and this does not change that. `0x20 0x64` reads as
a Legacy channel pair for channel 100, which those devices had been associated on; `0x00
0x4c` does not, because 76 is not a channel. Shape, not decode.

**The practical consequence is that a transmitter never has to invent it.** Set bit 11 and
the field is legitimately absent, which is what every associated Apple device does.

## 28. Data Path State: the unnamed flag bits carry no fields, and the extended block is skippable

Two questions that mattered more than they looked, because Data Path State is a bitmap
followed by only the fields the bitmap claims — so a bit that carries a field we do not know
about puts every later offset wrong, silently.

**It does not.** The length is a linear function of the flags, so the per-bit cost can be
read straight off pairs of frames differing in one bit:

```text
  bit  6 (0x0040): 0 bytes      bit 10 (0x0400): 0 bytes      bit 13 (0x2000): 0 bytes
```

All three unnamed bits are booleans. The existing offset walk was never misaligned, which
is worth having established rather than assumed.

**The extended block is a fixed 18 bytes** when populated — four 32-bit values after two
zero bytes — and its own `extended_flags` bits 10 and 11 likewise cost nothing. The four
values vary per device and per frame and look like counters; they are not decoded.

They do not need to be. **`libmosey` sets `extended_flags` to 0 and sends no extended block
at all, and AirDrop works** — 5361 frames of it in `captures/`. `DataPathState::describing`
already omits it, so no change was needed, only the confidence that omitting it is correct.

## 29. Tag 35 exists, is rare, and nobody has said what it is — including us

Not in Wireshark's enumeration, not in the 2018 paper, not in OWL, and not previously in
these docs. Two bytes, always `01 01`, **66 frames out of 18157**, from three Apple devices
across three of sixteen captures.

What was measured:

- every one of the 66 sits within **7.5 s of an AWDL data frame**, and most within 0.07 s
- but data traffic does not produce it — `run-b-ch6.pcap` has **3438 data frames and not
  one tag 35**
- 64 of the 66 are in `transfer-attempt.pcap`, clustered in the seconds after the last data
  frame rather than during the transfer

So it is associated with data sessions and is not caused by them, and two bytes reading
`01 01` carry almost no information on their own. **The trigger is unknown and is left
that way.** It is recorded because "we have seen this and do not know it" is worth keeping
distinct from "we have never seen this", and because the next person to see tag 35 should
find this rather than rediscover it.

## 30. Tags 32 and 33 are shaped, not solved

Four distinct tag-33 values now, which is enough for the shape and not for the fields:

```text
  01 00 00 00 | 35 86 | 01 | 35 86 | 00 | 00 00 00 00     channel 53
  01 00 00 00 | 00 00 | 01 | 11 86 | 00 | 00 00 00 00     first pair empty, channel 17
  01 00 00 00 | 55 86 | 01 | 55 86 | 27 | 00 00 00 00     channel 85, and byte 9 is 0x27
```

Two `(channel, operating class)` pairs, the first of which can be empty while the second is
not. Every observed class is 134 — 6 GHz — and the channels 17, 53 and 85 are all valid
6 GHz control channels. Byte 9 was `0x27` on exactly one device and `0x00` on the rest.

The constant `01 00 00 00` prefix, the `01` separator and byte 9 are not decoded. **Three
channels from three devices cannot separate "constant" from "happens to be the same", and
that is the whole difficulty** — these tags only appear when a device is associated on
6 GHz, so the sample is small by construction.

This is the clearest case in the project of a gap that needs a capture rather than more
analysis: two captures of one device on **two different 6 GHz channels** would move the
bytes that are fields and leave the bytes that are constants alone.

## 31. The 6 GHz channel in tag 33 is the device's own association — proven against the OS

Finding 30 left tags 32 and 33 "shaped, not solved". The shape is now anchored to a
meaning, and the method is worth recording because it needed no new decoding at all.

A capture was taken on the Pi while the MacBook these notes are being written on was
transmitting AWDL. The frame's source address was matched against that machine's own
`awdl0` address — `ea:8e:0d:cc:09:73`, read from `ifconfig` on the same machine — so the
sender is identified rather than assumed. `system_profiler` on that machine reported
**"Channel: 53 (6GHz, 160MHz)"**, and its tag 33 carried **channel 53, operating class
134**. The device's own operating system and its AWDL frames agree.

Across three channels from five devices:

```text
  01 00 00 00 | 35 86 | 01 | 35 86 | 00 | 00 00 00 00   macOS, OS says 6 GHz ch 53
  01 00 00 00 | 00 00 | 01 | 11 86 | 00 | 00 00 00 00   iOS, no 6 GHz association
  01 00 00 00 | 55 86 | 01 | 55 86 | 27 | 00 00 00 00   ch 85, and byte 9 is 0x27
```

The first pair is the association and is **empty when there is none**; the second is
populated either way. Bytes 4..6 and 7..9 move with the channel; `01 00 00 00`, the `01`
separator and the trailing four zeros did not move once. That is a boundary established by
variation rather than by assumption. Byte 9 was `0x27` on exactly one device and is not
decoded, and tag 32's bytes 9..11 change within a single device inside 90 seconds — `c1 c0`,
`83 8a`, `01 00` — so they are live state, not a constant.

### Why these tags exist

**On a 6 GHz association, Data Path State publishes `infra_channel` as 0.** Verified on the
same MacBook, which was associated on channel 53 and reported zero. The channel sequence
cannot express 6 GHz either (finding 17). So tag 33 is the *only* place a 6 GHz association
is visible, which is presumably why Apple added a tag outside the published range for it.

## 32. An MDM-managed iPhone hides a real Mac and shows our Tarish device

Recorded because it is a confound, not because it is understood.

On 2026-09-12 a MacBook was set to AirDrop "Everyone", `sharingd` running, firewall off,
`awdl0` up, and **advertising `_airdrop._tcp.local` on port 8770** — all confirmed on the
machine itself and in the capture. Its schedule overlapped the iPhone's in 3 of 16 slots on
both 149 and 6, so the two could hear each other.

- the operator's **personal** iPhone saw the Mac
- an **MDM-managed** iPhone did not, with the VPN disabled and after a reboot
- the same MDM iPhone **did** see a Pixel running Tarish
- our own Pixel saw the Mac, which is what proves the Mac was discoverable at all

So AirDrop is not disabled on the managed phone, and the Mac is not misconfigured. The only
known difference between the two iPhones is the MDM profile. **The cause is not known and
is not guessed at here.**

### The consequence that matters

**Do not run identity or PIN experiments on the managed iPhone.** It hides a genuine Apple
peer for reasons we cannot see, which is exactly the kind of hidden variable that would make
a result about Apple's identity gating meaningless. The personal iPhone is the instrument for
those — see the open question on the non-contact code.

An operator theory that a locked-down VPN blocked identity resolution was **tested and
refuted**: disabling the VPN and restarting the phone changed nothing.

## 33. ★ The non-contact code is a TRUST BOOTSTRAP, and discovery is what it unlocks

The single most consequential observation in this project so far, and it came from a
frustrated operator working around a phone that would not cooperate rather than from any
planned experiment.

The managed iPhone of finding 32 could not see the MacBook — not with the VPN off, not after
a reboot. Then:

> **the operator sent a file from the Mac to the iPhone, the transfer required a PIN, and
> after that the iPhone could discover the Mac.**

Order matters here and it is the right way round. The code did not appear *because* the
devices knew each other; the devices knew each other *because* of the code. Discovery was
the effect, not the precondition.

### What this settles

`docs/GAPS.md` §1 carried two competing explanations for the non-contact code. One was a
version gate — Apple offering a new flow to peers announcing something recent, with v3.4
peers left on the legacy path. The other was written like this:

> *A competing explanation is that the code bootstraps persistent trust, which needs a
> durable identity to bind to — Apple devices carry an Apple-signed validation record and we
> structurally cannot.*

**That is what was just observed.** The code establishes a durable association between two
specific devices, and once established, each can find the other without further ceremony.

It also explains finding 32 without needing MDM at all: the personal iPhone could see the
Mac because it had been paired with it at some point; the managed iPhone could not because it
never had. The MDM profile may have tightened *when* the prompt is required, but the
mechanism is pairing, not a restriction.

### What it means for us — opt-in, not impossible

Announcing v10.0 does not get us into this flow, so the version experiment §1 recommends
would come back negative for a reason unrelated to the version. That much saves a build
cycle.

Two earlier drafts of this section were wrong in opposite directions and both are corrected
here. The first called our rotating identity an urgent problem. The second called the flow
structurally closed, on the grounds that an Apple identity is signed by hardware we cannot
replicate. **The signing part is true and the conclusion does not follow**, because the
identity does not have to be minted — it can be extracted from an Apple device the user owns.

The operator's own earlier project, `GoOpenDrop`, does exactly that, and its configuration
names the three artefacts:

```json
"apple_root_cert":              "certs/apple_root_ca.pem",
"extracted_certififcate":       "...",
"extracted_certkey":            "...",
"extracted_validation_recoed":  "..."
```

They go out as `SenderRecordData` on the client side and `ReceiverRecordData` on the server
side. **And it worked well enough that "Everyone" was not needed** — with a genuine extracted
record, and the associated email address added to the peer's contacts, *contacts-only* AirDrop
succeeded. That is a better outcome than Everyone mode, not a worse one: no ten-minute
timeout, and the receiver never has to open itself to the world.

This is already understood in the daemon, which says the record "cannot be generated, must be
extracted from a real Apple device, and expires yearly" and omits it deliberately. What is
missing is not knowledge but a **hook**.

### The feature this implies — DEFERRED by the operator, 2026-09-12

**Not being built now.** The decision is that "Everyone" mode is fine for the majority of
people, which it is: AirDrop works today in both directions with no identity at all. What
follows is the design, recorded so it does not have to be rediscovered — not a task.

An optional, user-supplied identity. Absent, everything behaves exactly as it does today —
ephemeral key, Everyone mode, no record. Present, the daemon sends the record and can be
discovered by contact.

Four things that make it shippable in a public project:

- **The credentials are never ours to ship.** They are Apple-issued, tied to one device and
  one Apple ID, and include a private key. A user extracts their own from hardware they own.
  The repository carries the code path and the public Apple root, never the artefacts.
- **The certificate must then be the extracted one**, which means persistence stops being a
  contradiction: today's ephemeral key is right for the anonymous path, and an identity the
  user deliberately installed is a different mode with a different answer. The existing
  argument — *a key that never touches storage cannot be stolen from storage* — keeps the
  default and does not govern a key the user chose to provide.
- **It expires yearly.** Not set-and-forget; the failure will look like AirDrop silently
  reverting to anonymous.
- **It is an identity, and it is somebody's.** Presenting an extracted record means presenting
  *that device's* identity, so it belongs to the person who owns both ends, not to a third
  party.

### The actual risk, and the only useful mitigation

The danger is not exclusion from the trusted flow. It is Apple making it **mandatory for
every peer**, which would end AirDrop interoperability for anyone without an extracted
identity — an operator concern recorded before this finding existed: *"worried with more
devices coming along, apple might enforce this and make it the only way ios to android work,
better be prepared."*

Nothing we build prevents that. **Noticing early** is what helps, which promotes the `/Ask`
non-200 response logging on the task list from a nicety to a monitoring feature: the first
sign would be Apple peers refusing our `/Ask` with a status we currently discard.

### What is proven and what is not

Proven: a PIN-confirmed transfer from the Mac preceded the iPhone's ability to discover it,
on a phone where discovery had repeatedly failed.

Not proven, and not guessed at: whether the association is bound to an Apple ID, to a device
key, or to something else; how long it survives; whether it is symmetric; and whether an
Apple device would ever offer this flow to a non-Apple peer at all. **The last of those is
the one that decides whether any of it matters to Tarish**, and it needs a deliberate test on
the *personal* iPhone, not the managed one.

## 34. ★ libawdl transmitted, and three Apple devices elected it master

First transmission, 2026-09-12. 60 seconds on channel 149 from a Raspberry Pi with an
MT7612U, one MIF per two PSFs, frames built entirely by `libawdl::beacon`.

The test was never "did `send()` succeed" — that only means the driver accepted bytes. The
test was whether a real peer **acts** on them, and the election is the cheapest oracle:
advertise a metric and an Apple device must either follow or beat it, and either way its own
frames change.

```text
who names whom as master:
  00:c0:ca:b0:60:4c  ->  (itself)             186     us
  ea:8e:0d:cc:09:73  ->  00:c0:ca:b0:60:4c    115     a MacBook, v10.0 macOS
  2e:14:bd:cc:e0:04  ->  00:c0:ca:b0:60:4c     47     an iPhone, v10.0 iOS
  8a:ca:5e:9c:a1:73  ->  00:c0:ca:b0:60:4c     13     an iPhone, v10.0 iOS
```

### The frame that proves it is not the one we sent

A device naming us in its master field could be many things. This one cannot:

```text
2e:14:bd:cc:e0:04   v1_dist=2  v2_dist=2
                    master_metric=530        the exact metric we advertised
                    master_counter=6         our tenure counter, at that moment
                    parent=ea:8e:0d:cc:09:73 the MacBook
```

**A two-hop synchronisation tree rooted at our node.** That device never heard us directly —
it is carrying our metric and our tenure counter, relayed through the Mac. It could only
hold those values by parsing our frame, believing it, and propagating it.

It also confirms two decodes from earlier the same day, by having Apple devices act on values
synthesised from them: the second address really is the next hop (finding 26), and
`master_counter` really is the master's own counter relayed (finding 22).

### What this does and does not establish

**Does:** the 802.11 header, the vendor-specific action wrapper, the twelve-byte fixed
header, Synchronization Parameters, both Election tags and the channel sequence are correct
enough for real Apple devices to parse, evaluate and act on. And the 22% of control-plane
bytes we cannot name did **not** prevent participation — tags 6, 32 and 33 were absent
entirely and nothing refused us.

**Does not:** anything about the data path, service discovery, or a transfer. Being elected
master of a synchronisation cluster is the control plane agreeing we exist. It is not AirDrop.

### The part that is a problem, not a result

**We won an election we cannot serve.** This crate has no TSF read on this hardware, so the
beacon transmits on a wall-clock timer while advertising a schedule of slots 0, 2, 8 and 10.
Three Apple devices anchored their synchronisation to a master whose clock is not a clock,
which can only have degraded their AWDL for that minute.

So the default metric is now [`METRIC_DECLINE`], 65 — what `libmosey` advertises, and a
claim not to want the job. `METRIC_COMPETE` still exists and is correct on a radio that can
anchor to a TSF. **Winning is the opt-in, not the default**, and the reason is written where
someone changing it will read it.

### Loose ends worth noting

- We transmit from the adapter's **burned-in MAC**. Every real AWDL device randomises; ours
  is a stable hardware identifier broadcast continuously.
- We advertise **device class 2**, which our own table calls "iOS". We are not iOS.
  `libmosey` also sends 2, so the value may mean something broader than the name suggests —
  but our label is at best unverified and at worst a misrepresentation.
- Our MIF is 317 bytes against Apple's mean of 626, because Apple sends **several** Service
  Response TLVs per frame and we send one.

## 35. A master does not synchronise to anyone — which is why it suits our hardware

Finding 34 set the default metric to decline the election, on the grounds that winning while
unsynchronised "can only have degraded" the cluster. **That was an assertion, not a
measurement**, and the operator challenged it. The challenge was right, and it produced a
better understanding than the original claim.

### The real defect, which was not the metric

Every frame in the first run carried **`aw_remaining = 0`**. Our own parser documents that
field as *"TU left in the current window — the field a joining node uses to work out where in
the schedule it has arrived"*. Telling every peer "my window ends right now", in every frame,
forever, is wrong at any metric.

The cause was that the beacon derived its timing from a **frame counter** rather than a clock:
`aw_counter` advanced by a fixed 16 per frame regardless of elapsed time, and `aw_remaining`
was hardcoded. Both now come from one monotonic reading per frame, so every timing field in a
frame describes the same instant.

```text
run 1, counter-derived:  aw_remaining  1 distinct value   always 0
run 3, clock-derived:    aw_remaining  16 distinct        0..15
a real MacBook:          aw_remaining  15 distinct        0..16
```

### The inversion worth keeping

**A follower must align to the master's TSF. A master does not align to anybody — it is the
reference.** So a master needs timing that is *self-consistent*, not timing that agrees with
someone else's, and a monotonic host clock supplies exactly that.

That makes master the role **available** to a radio with no TSF read, not the one out of
reach. What remains missing is precision rather than coherence: a host clock carries
scheduler jitter a MAC timer does not, so our windows wander more than Apple's. That is a
quality to measure, not a correctness bug.

There is also a reason for `libmosey`'s metric of 65 that is not timidity: a master has
obligations — it must actually be present in the windows it advertises — and that costs
power. A phone declining may be a battery decision.

### What is NOT established

Run 1 (broken timing, metric 530): three Apple devices followed us.
Run 3 (fixed timing, metric 530): the MacBook, at metric 510, did **not** follow — it stayed
its own master, and we ran as two clusters side by side.

Same metrics, opposite outcomes. **It is tempting and wrong to credit the timing fix**, because
the peer populations differed: run 1 had two iPhones present, one of them advertising 537,
above our 530. That is n=1 each way with an uncontrolled variable.

Settling it needs the same peers present in both configurations, which is a controlled run
nobody has done. Until then the honest statement is that our frames transmit and are acted
on — finding 34 proves that with a two-hop tree — and that **what decides whether a peer
follows us is not yet understood**.

## 36. Being elected is NOT reproducible on demand — and it is neither the metric nor the timing

Finding 34 records three Apple devices electing our node master on the first transmission.
That happened and the evidence is unambiguous — a two-hop tree relaying our metric and
tenure counter. **It has not been reproduced since**, and five controlled trials against a
fixed peer set say why it is not simply a matter of asking louder.

The peers, unchanged throughout: an iPhone (`6e:b5`, v10.0 iOS, metric **539**) and a
MacBook (`ea:8e`, v10.0 macOS, metric **510**, following the iPhone).

| trial | our config | outcome |
|---|---|---|
| A1 | metric 530, clock timing | iPhone master, Mac follows it, we are an island |
| B | metric 530, **`--legacy-timing`** | identical |
| A2 | metric 530, clock timing | identical |
| C | metric 65 (decline) | identical |
| **D** | **metric 600 — above every peer present** | **identical** |

All five are distinct captures, verified by hash and size. So:

- **Not the metric.** 600 beat every advertised value in the room and changed nothing. 65
  and 530 behaved the same as 600, which also means the negative control could not
  discriminate — an experiment worth noticing as uninformative rather than reporting as a
  result.
- **Not the timing mode.** Deliberately reproducing the original `aw_remaining = 0` defect
  in trial B produced no difference either. The tempting story from finding 35 — that
  fixing the timing cost us the election — is **refuted**.

### What is left, and not chosen between

Two candidates, neither tested:

1. **They cannot hear us reliably.** We transmit on a wall-clock timer, so our frames land
   in a peer's Availability Windows only by coincidence. The iPhone and MacBook are
   synchronised to *each other*, so their listening windows coincide and ours do not.
2. **An established cluster resists switching.** In finding 34 the devices may have been in
   a forming state; here a master and its follower were already locked together. AWDL may
   well have hysteresis, and abandoning a master for any louder stranger would be a poor
   design.

Both fit. Deciding between them needs evidence that a peer *received* a frame of ours
without acting on it, which no capture of the air can show — the cluster's own logs would.

### What this does not undo

The frames are right. Finding 34 proved that in a way a negative cannot retract: a device
two hops away carried our metric and our tenure counter, values it could only hold by
parsing our frame and believing it. **Being elected is evidence of correctness; not being
elected is not evidence against it.**

What changes is the claim's strength. "libawdl can be elected master" is true and
demonstrated once. "libawdl will be elected master" is **not** supported, and the deciding
variable is still unidentified.

## 37. We were followed when we overlapped LEAST — audibility is not the gate

Finding 36 left two candidates for why being elected is not reproducible. The first — that a
wall-clock transmitter lands in a synchronised peer's listening windows only by coincidence —
is now **refuted, and inverted**.

`awdl phase` folds each frame's timestamp onto the 262144 µs cycle and buckets it into
sixteen windows.

| run | our shared airtime with Apple peers | followed? |
|---|---|---|
| `tx-first` | 9%, 15%, 16% | **yes, all three** |
| `trial-D` | 37%, 50% | no |
| `trial-E` | 36%, **62%** | **yes, both** |
| `trial-FIX` | **66%** (follower), 18% (not) | one of two |

More overlap, less influence — and more overlap, more influence, depending on the run.
Whatever decides this, it is not whether they can hear us.

> **The figures above were recomputed after finding 41.** The originals — 4%, 12%, 12% and
> 32%, 56% — were folded onto a 262144 µs cycle that is four times too short, so they
> aliased four channel-sequence slots together and were meaningless as overlap. The
> conclusion survives the correction unchanged: the ordering is still not there.

### The instrument, and why its answer is trustworthy here

This radio reports **no TSFT at all** — 0 of 801 frames in every capture we hold — so the fold
uses the host's capture timestamp, which for a USB adapter is when the frame reached the
kernel rather than when it was on the air. That could easily have been too coarse to resolve
a 16 TU window, so the Apple senders were used as a control **before** reading anything into
our own numbers: in `two-iphones-awdl.pcap` three Apple devices each land in **3 of 16 slots**
with 68–85% mutual overlap. Known structure, clearly resolved. The instrument can see windows.

### What the same data suggests instead

The peers' own spread tracks the outcome better than ours does:

```text
  tx-first    Apple devices at 12/16 and 16/16 slots, 48-85% mutual   -> they adopted us
  trial-D     the MacBook down to 7/16, locked to the iPhone          -> it ignored us
  two-iphones Apple only, 3/16 each, 85% mutual                       -> fully settled
```

A device spread across most of the cycle looks like one that is *searching*; a device
concentrated in a few windows looks like one that has *settled*. The run where we were
adopted is the run where the peers were spread out.

**This is a correlation over three captures and it is not a finding.** It is, however, the
first hypothesis here that fits all the evidence including the inverted overlap result, and
it is testable: capture a peer as it joins a cluster and watch its occupancy narrow.

### A concrete defect it did expose

Our beacon transmits every sixteen windows — **exactly one cycle** — so it lands on a single
phase for a whole run, and which phase is decided by when the process happened to start. The
measurement confirms it: we occupy 3-4 of 16 slots, tightly.

That is not wrong by itself; Apple's settled devices are just as concentrated. What is wrong
is that **our phase has nothing to do with the schedule we advertise.** We announce slots 0,
2, 8 and 10 and then transmit wherever the start time put us. Fixing that needs no TSF and no
peer — our own cycle is our own reference — and it is the next change worth making.

## 38. ★ What decides whether Apple follows us is WINDOW BREADTH, not metric, timing or rate

Findings 36 and 37 eliminated the metric, the timing mode, and audibility-by-overlap. Four
more trials against the same fixed peer set — an iPhone at metric 539 and a MacBook at 510 —
isolate the variable that is left.

| trial | frames | windows we occupy | rate | followed? |
|---|---|---|---|---|
| D | 206 | 4/16 | 3.7/s | no |
| **E** | **1236** | **6/16** | **22.5/s** | **YES, both devices** |
| F | 618 | 3/16 | 11.2/s | no |
| **G** | **1236** | **3/16** | **22.5/s** | **no** |

**E and G have identical frame rates and opposite outcomes**, which rules out rate. E and F
share alignment and differ in both, G separates them. The only property E has that no other
trial has is **breadth: six of sixteen windows rather than three or four.**

### Why E had six, and why it was an accident

Trial E's beacon transmitted at the top of its loop and waited afterwards, so it fired in an
advertised window, slept one window, and fired again in the window *after* — which it does
not advertise. Half its frames were in the wrong place, visible in `awdl phase` as adjacent
pairs. **That bug is what won the election**, and fixing it in trial F and G lost it again.

### The rule this suggests

We must be present in windows where the peer is **listening**, and we do not know which
those are. Covering more of the cycle intersects more of them. That fits every trial
including the ones that looked contradictory:

```text
  tx-first   peers spread across 12-16/16, us at 3/16   -> they were listening everywhere, followed
  D          peers narrow (Mac 7/16), us 4/16           -> missed
  E          us 6/16                                     -> hit
  F, G       us 3/16, rate irrelevant                    -> missed
```

It also explains why the shared-airtime figure of finding 37 did not predict anything: that
measures overlap in **transmission**, and what matters is overlap with **reception**. A node
transmits in a few windows and may listen in more.

**This was a hypothesis from five trials with one success, and the sweep refuted it.** See
the correction below.

### The uncomfortable part

If breadth is what works, the honest reading is that **we succeed by being present more of
the time than we claim to be** — which is the opposite of a correct AWDL node, and costs
airtime on a shared channel. A real implementation earns the same result by synchronising:
knowing the master's TSF tells you exactly which windows the peers attend, so three windows
in the right places beat six in arbitrary ones.

So this is a measurement of what works, and simultaneously an argument for the TSF path
rather than a substitute for it.

## 39. Breadth is refuted too — and trial E remains unexplained

Finding 38 proposed that **window breadth** decides whether Apple devices follow us, on the
strength of trial E occupying six windows and winning where three- and four-window trials
lost. The sweep it called for was run, and the first point kills it.

`--windows 6` produces six windows spread evenly across the cycle, every one of them
advertised, verified on the air:

```text
  00:c0:ca:b0:60:4c  [▃..▃..▃.▃..▃..▃.]  891 frames in 6/16 slots   -> NOT followed
```

Six windows. Same metric 600, same peers, same rate band as E. The iPhone stayed master and
the MacBook stayed with it.

### Everything now eliminated

| candidate | how it died |
|---|---|
| the metric | 65, 530 and 600 all behaved identically (D, C, G) |
| the timing mode | `--legacy-timing` reproduced the original defect and changed nothing (B) |
| audibility by overlap | followed at 4-12% shared airtime, ignored at 32-56% (finding 37) |
| frame rate | E and G at identical rates, opposite outcomes |
| **window breadth** | **six evenly spread windows, not followed (this finding)** |

### What is left of trial E

E's six windows were **three advertised plus the three immediately after them** — adjacent
pairs, created by a loop that transmitted before waiting. W6's six are evenly spread and
honestly announced. So what E had that nothing else has is one of:

- transmitting in windows it did **not** advertise, or
- **clustering** — pairs of consecutive windows rather than isolated ones, or
- nothing at all, and the cluster happened to be in a receptive state that minute.

The third cannot be dismissed. Every deliberate attempt to reproduce E has failed, across
nine trials, and a single success that resists five separate explanations is exactly what a
coincidence looks like.

### The honest position

**We can transmit AWDL that Apple devices parse and act on — finding 34 proved that with a
two-hop tree carrying our own metric and tenure counter, and nothing since has undermined
it. We cannot yet say what makes them act on it.** That is an uncomfortable place to stop
and it is where the evidence is.

The next thing worth doing is not another guess at the variable. It is **reception**: a node
that can hear the cluster knows the master's TSF, its schedule, and whether its own frames
provoked anything — none of which can be inferred from the outside. `Radio::rx` is wired and
unused.

### A note on the instrument

Four harness bugs were found and fixed while running these trials, every one of which
produced either a confident wrong answer or a silent stall: a capture attached to an
interface that `bring_up` then destroyed; a failed capture leaving the previous trial's file
for `scp` to copy, so four trials reported byte-identical results; an ssh that returned
before its beacon exited, leaving two transmitters on one interface; and a wait loop built
on `pgrep -f` that matched its own command line and never finished. The measurements that
survive are the ones taken after each fix.

## 40. ★ The cluster's clock is recoverable WITHOUT a TSF — the peers tell us

Every timing problem in findings 34-39 traced back to the same thing: we transmit at a phase
decided by when our process started, because the adapter reports **no TSFT at all** — 0 of
801 frames in every capture. The obvious conclusion was that synchronisation needs different
hardware.

It does not. **The peers hand us their clock in every frame.**

Synchronization Parameters carries `aw_remaining`, the TU left in the sender's current
window, and `aw_counter`, which window it is. A frame arriving at our time `t` saying *"6 TU
left in window 4291"* places that window's boundary at `t + 6 TU` **on our own clock**, and
names it. Enough of those and the cluster's cycle phase falls out.

That is precisely what the field is for. This crate's parser has described it since the first
week — *"the field a joining node uses to work out where in the schedule it has arrived"* —
and it took building a transmitter that could not aim to notice the description was the
answer.

### CORRECTION: OWL already does this, and said so

An earlier version of this entry presented the mechanism as something nobody had noticed.
**That was wrong, and the operator asked the obvious question — was this not in OWL?** It is,
in `rx.c`:

```c
sync_err_tu = awdl_sync_error_tu(now, time_to_next_aw_master, aw_counter_master, &state->sync);
awdl_sync_update_last(now, time_to_next_aw_master, aw_counter_master, &state->sync);
```

and the anchoring arithmetic in `sync.c` is the same one derived here:

```c
state->last_update = now_usec - tu_to_usec(eaw_period - time_to_next_aw);
```

So the finding is that **we had not implemented it**, not that it was undiscovered. The
measurements below are still ours and still worth having — nobody had published what this
recovers from a real Apple cluster through a USB adapter's host timestamps — but the idea is
OWL's and the credit is theirs.

OWL also carries something we lacked: a **sync error metric**, `awdl_sync_error_tu`, with a
±3 TU threshold and a running count of measurements outside it. That is a better instrument
than a spread computed after the fact, because it scores every frame against the current
estimate as it arrives.

### It works on real Apple clusters

`awdl follow` recovers the master, its advertised slots and the cycle phase from captures
taken with no special setup:

| capture | anchors | spread | as a fraction of a 16384 µs window |
|---|---|---|---|
| `6ghz-A-ch53` | — | 3864 µs | 24% |
| `two-iphones-awdl` | 64 | 5153 µs | 31% |
| `dual-awdl` | — | 8358 µs | 51% |
| `assoc-connected` | — | 12401 µs | 76% |

It also independently reproduces Apple's schedule — `slots: [2, 8, 10] of 16` — from timing
data alone, which is a decent check that the recovery is reading what it thinks it is.

### Aim at the centre, not the boundary

An earlier version of `is_usable` demanded a spread under a quarter window and rejected every
real cluster above. **That bar was wrong**, and the tool's own output made it obvious: a
quarter window is the tolerance for aiming at a *boundary*, where half the error puts you in
the neighbouring slot. Aim at the window's **middle** and the margin is half a window either
side, so what must fit is *half* the spread. For the Apple cluster above that is 2576 µs
against 8192 µs of margin — comfortable.

So the rule is: **never aim at a slot boundary.** It is the single worst target in the cycle
and it is the one a naive implementation picks.

### Two traps worth keeping

- **The phase lives on a ring, so the average of a set of observations is not their centre.**
  A cluster whose phase sits near zero produces values at both 10 µs and 262100 µs; their
  arithmetic mean is half a cycle away — maximally wrong, and a plausible-looking number.
  `ClusterClock` takes a circular median and `tests/follow.rs` pins the case.
- **Only the master's own frames may anchor the clock.** A follower names the master
  correctly but carries its own `aw_counter`, which may not have converged; averaging it in
  blurs the thing being measured.

### ★ The thing reading OWL actually caught: our cycle was four times too short

OWL synchronises on **extended** AWs — `presence_mode * aw_period` — and its slot index is
`awdl_sync_current_eaw(...) % AWDL_CHANSEQ_LENGTH`. Apple frames carry `presence_mode: 4`.
So a channel-sequence slot is **four availability windows, 64 TU**, and a 16-slot cycle is
**1024 TU ≈ 1.05 s** — not the 262144 µs this project had used everywhere.

An earlier version of this section tested that and concluded OWL's grouping did *not* imply a
longer cycle. **That test was wrong**: it compared concentration at two periods using sixteen
buckets for both, so the bucket *width* differed fourfold and the two numbers were not
comparable. A replacement using equal bucket widths was also inconclusive, because
peak-to-mean scales with bucket count.

**Settled from field values instead, where no timing is involved at all.** Each frame carries
both its `aw_counter` and the schedule its sender advertises, so the correct indexing is
whichever puts a device's own frames inside its own advertised slots:

```text
  sender             frames   aw%16 hits   (aw/presence_mode)%16   slots
  02:3b:e8:75:9c:03     596          34%                    100%   [2, 8, 10]
  2a:f3:94:4d:96:79     166          39%                    100%   [0, 2, 8, 10]
  8a:c3:f7:4b:ce:de     194          43%                    100%   [0, 2, 8, 10]
  be:35:be:c9:05:1f     276          34%                    100%   [0, 2, 8, 10]
  d2:75:0e:61:4c:e2     165          35%                    100%   [2, 8, 10]
```

**100% against a 25% chance level, five devices, 1397 frames, no exceptions.** OWL is right
and this project was wrong.

### What it was costing us

Stepping one slot per availability window walks the cycle **four times too fast**, so
"transmit in slots 2, 8 and 10" landed somewhere different every cycle. Every transmit trial
in findings 34-39 was aiming at a schedule it could not hit — which is a far better
explanation of why peers ignored us than any of the five candidates those findings
eliminated, and it was invisible from the outside because the frames themselves were correct.

Folding on the true period also makes the measurements agree with the physics. Apple devices
in `two-iphones-awdl`, which looked like three loosely-related nodes at 3/16 slots, are four
slots each with **84-96% shared airtime** where the aliased fold reported 68-85%:

```text
  02:3b:e8:75:9c:03  [......▅▂......▅▁]   4/16 slots
  8a:c3:f7:4b:ce:de  [......▅▃......▅▂]   4/16 slots
  be:35:be:c9:05:1f  [......▅▁......▅▁]   4/16 slots
```

And clock recovery is much better than finding 40 first reported, because the spread was
being quoted against a single window rather than a slot: **5.9%, 7.9%, 12.8% and 18.9% of a
65536 µs slot** across four captures, against 32768 µs of margin when aiming at a slot centre.

### The lesson, stated plainly

Two heuristics on timing data gave confident wrong answers; one look at what the frames say
about themselves settled it in a line. **When the protocol carries a field that answers the
question, use the field.** That is the second time in this document the same mistake appears
— the first was reaching for timing when `aw_remaining` was sitting in the frame.

### What this unblocks

Everything findings 36-39 could not answer. A node that knows the cluster's phase can
transmit inside the windows the cluster actually attends rather than at an arbitrary offset —
which is the honest version of the "breadth" accident of trial E, and needs no extra airtime.
`Cluster::us_until_master_window` returns the target; wiring it into the beacon is the next
step, and it is small.

## 41. The timing fix, verified on the air

Finding 40's correction — that a channel-sequence slot is four availability windows — was
settled from field values. This is the check that it holds when transmitting.

**Before**, aiming at "slots 2, 8 and 10" while stepping one slot per availability window,
the beacon smeared across four to six slots of sixteen and never the advertised ones:

```text
  trial-D   [.........▂▅▅▂...]   4/16
  trial-E   [▃▃▃......▃▃....▃]   6/16
```

**After**, with a slot correctly treated as 64 TU:

```text
  trial-FIX [▅.....▅.▅.......]   3/16, and they are the three we advertise
```

Three slots, exactly the advertised `[2, 8, 10]`, holding across a 50-second capture. The
schedule we announce and the schedule we keep are now the same thing, which they had never
been in any earlier trial.

### And a peer followed

```text
  00:c0:ca:b0:60:4c  ->  (itself)            560     us
  3a:2b:df:c4:69:a6  ->  00:c0:ca:b0:60:4c   107     an Apple device, following us
  3a:2b:df:c4:69:a6  ->  6e:b5:ac:3f:d7:c6     2
  6e:b5:ac:3f:d7:c6  ->  (itself)              5
```

One of the two Apple devices present adopted us; the other did not. **That is better than
the nine consecutive failures of findings 36-39 and it is not a clean result**, so it is
recorded as one success rather than as a capability.

### What this does and does not settle

It **does** establish that the timing model is now right in practice as well as on paper,
and that a transmitter which keeps its advertised schedule can be adopted by a real Apple
device.

It **does not** identify what decides adoption. The recomputed overlap figures above show
peers following us at 9% shared airtime and at 66%, and ignoring us at 18% and at 50%. Five
candidates were eliminated in findings 36-39 and the timing error was a sixth confound
running underneath all of them — but removing it has not produced a rule, only a better
success rate on a sample of one.

The honest next step is still **reception**: `libawdl::follow` can now recover a cluster's
phase correctly, and a beacon that transmits in *the cluster's* windows rather than its own
is a different experiment from any run so far.

## 42. ★ Reading OWL in full: thirteen things it knows that we did not

Prompted by the operator — *"actually do read it now fully, i think its time"* — after OWL had
already corrected two claims in this document. It corrected more. OWL is 4278 lines of GPL-3
C by Milan Stute and the Open Wireless Link Project, and it is the reference this project
should have been checking against all along.

### The one that matters most: our election comparison may be backwards

```c
static int awdl_election_compare_master(a, b) {
	int result = compare(a->master_counter, b->master_counter);
	if (!result) result = compare(a->master_metric, b->master_metric);
	return result;
}
```

**Counter first, metric second** — the opposite of `ElectionParamsV2::beats`, which finding 9
settled as metric-first on the strength of a capture.

**The two claims are not about the same fields.** OWL compares `master_counter` and
`master_metric` — what a peer says about *its own top master*. Finding 9 compared
`self_metric` and `self_counter`. So the capture that "refuted counter-first" did not test
OWL's rule at all, and our `beats()` is a divergence from the reference implementation that
nobody decided to make.

It is not resolvable from the captures we hold: in the run that produced finding 9, the
losing device was **already following** when the capture began, so its independent election
state was never observed. **This is now the most important open question in the project** —
it decides whether our node can ever win an election correctly — and it needs a capture of a
device *joining* a cluster.

### What OWL does in the election that we do not do at all

- **Cycle prevention.** Reject a peer whose `sync_addr` is us: *"do not allow cycles in sync
  tree"*. Without it two nodes can name each other and the tree is not a tree.
- **Tree height limit**, `AWDL_ELECTION_TREE_MAX_HEIGHT 10`, rejecting a peer that would make
  the sync tree taller than that.
- **Tie-breaks, in order**: equal master metric → prefer the *shorter* tree; equal height →
  prefer the *larger* address. We had the address tie-break inferred and the height one not
  at all.
- **`sync_addr` and `master_addr` as separate state** — the immediate parent and the root.
  Independent confirmation of finding 26, arrived at from the code rather than from 634
  frames.
- **`AWDL_ELECTION_METRIC_INIT 60`.** OWL declines the election by default too, within five
  of `libmosey`'s 65. Three independent implementations choosing not to compete is worth
  noticing.

### Timing: OWL already had the rule I derived the hard way

```c
/* Schedule MIF in middle of sequence (if non-zero) */
if (awdl_chan_num(awdl_state->channel.current, ...) > 0)
    awdl_send_action(state, AWDL_ACTION_MIF);
/* schedule next in the middle of EAW */
ev_timer_rearm(loop, timer, usec_to_sec(next_aw + tu_to_usec(eaw_len / 2)));
```

Transmit in the **middle** of the slot, and only when the slot's channel is non-zero. That is
exactly the centre-aiming correction of finding 40 and the "only in advertised windows" fix of
finding 37, both of which were reached by trial and error over several hours.

### And the field we emit and ignore

**`action_frame_period` is the PSF interval.** OWL: `tlv->af_period = state->psf_interval`,
initialised to `PSF_INTERVAL_MASTER_TU 110`. Every Apple frame carries 110 and our beacon
copies it verbatim while pacing PSFs by an unrelated rule. The frame has been telling every
receiver how often we intend to send, and we were not honouring our own advertisement.

### Data-path rules we have not implemented

- **Multicast data only in EAW 0 or 10** — `awdl_is_multicast_eaw` returns `slot == 0 || slot
  == 10`. Not action frames, which is why our broadcast MIFs are not affected, but it
  constrains any data path we build.
- **Guard intervals at slot edges**: `AWDL_UNICAST_GUARD_TU 3`, `AWDL_MULTICAST_GUARD_TU 16`.
  A node refuses to start a transmission that close to a boundary. `awdl_can_send_in` returns
  a signed time so the caller knows whether to wait or whether it has just missed.
- **Per-peer `sync_offset`.** OWL keeps each peer's clock offset and asks *"are we on the same
  channel as this peer right now"* with the offset applied. We have a single cluster phase.
- **Peer timeout of 2 s** before a peer is dropped.

### One place we can check ourselves against them

OWL's idle schedule is slots `{0, 9, 10}` on the social channel and `{8}` on channel 6. Apple
measured is `{0, 2, 8, 10}`. Both agree on 0, 8 and 10; they differ on 2 against 9. Ours
follows Apple, which is the right call — but it is worth knowing OWL chose differently, since
it means the exact placement of the third and fourth slots is not something either project
established from first principles.

### The meta-lesson

Three claims in this document were wrong in ways OWL would have caught: that the trailing
bytes were padding (it comments them), that clock recovery was undiscovered (it implements
it), and that a slot is one availability window (its `schedule.c` says otherwise). **Check OWL
before claiming anything is new.** It is on the research Pi at `~/owl`, it is 4278 lines, and
reading it costs less than one wrong experiment.

## 43. ★ libawdl synchronises to a live Apple cluster

`awdl beacon --follow` listens, recovers the cluster's window phase from the frames it hears,
and transmits inside **the cluster's** windows instead of its own. On hardware:

```text
  ADOPTED cluster clock: master ee:93:7f:74:d7:33, slots [0, 1, 2, 8, 9, 10], spread 3091 us
```

3091 µs against a 65536 µs slot — **4.7%** — held for a whole seventy-second run without
dropping. The node identified a real Apple master, read its advertised schedule off the air,
and aimed at it. That is the first time anything in this project has been synchronised to
something it did not itself define.

### Two bugs on the way, both mine, both instructive

**Averaging hid drift.** The first version took a circular median over 64 anchors. It adopted
at 0 µs of spread and degraded to **156 ms** — more than two slots — across seventy seconds,
then kept transmitting with a confident, useless estimate because `adopted` was latched once
and never re-checked.

OWL does not average. `awdl_sync_update_last` re-anchors on **every** frame from the master,
which is drift-free by construction. A median is robust to jitter and blind to drift; the two
failure modes want opposite treatments. The resolution is to take the phase from the newest
anchor and use the history only to judge *health* — so jitter shows up in the spread while
drift cannot accumulate into the estimate. `median_phase_us` is kept alongside, because a
disagreement between it and `phase_us` larger than the spread is exactly the signature of
drift.

**And most of the jitter was self-inflicted.** The same clusters measured 3.8-12.4 µs-scale
spreads offline and **65-72 ms** live. The difference was not the radio: the loop polled with
a 20 ms receive timeout and stamped each frame when `rx` returned, so the poll interval went
straight into every anchor as quantisation — most of a slot of noise we were adding
ourselves. Dropping the poll to 2 ms took the spread from 65 ms to **3091 µs, a 21-fold
improvement**, and brought the live figure back in line with the offline one.

The real fix is `SO_TIMESTAMP`: ask the kernel *when the frame arrived* rather than asking the
clock *when we noticed*. The short poll is an approximation and is marked as one.

### What is still not shown

No peer adopted **us** in this run, and that was not the experiment — the point was whether we
could adopt *them*. Whether transmitting inside a cluster's own windows changes how it
responds is the next question, and it is now askable for the first time, because every
earlier trial was aiming at a schedule it could not hit.

## 44. ~~SETTLED: the election is decided by METRIC~~ — RETRACTED, see finding 45

The question FINDINGS 42 called the most important open one in the project. Answered with a
designed experiment and a control, which is the first time tonight that a hypothesis was
tested rather than inferred.

### Why it needed an experiment

OWL's `awdl_election_compare_master` is **counter first, metric second**. This crate's
`beats()` is metric-first. Finding 9 claimed a capture settled it, but that capture compared
`self_metric` and `self_counter` while OWL compares `master_counter` and `master_metric` — so
it never tested OWL's rule, and the divergence was an accident rather than a decision.

No capture held could settle it either: all of them begin with the devices already
synchronised, so a joining node's independent claim was never recorded.

### The design

We control our own metric and counter, so the two rules can be forced to predict **opposite**
outcomes. Both probes ran against the same room, with the operator taking two iPhones from
AirDrop-off to Everyone so they would join from cold.

| probe | our metric | our counter | metric-first predicts | counter-first predicts | **observed** |
|---|---|---|---|---|---|
| **A** | 600 (highest) | 1-16 (lowest) | they follow us | they ignore us | **three followed** |
| **B** | 50 (lowest) | 99999 (highest) | they ignore us | they follow us | **none followed** |

### Probe A, with the peers' own advertised values

```text
  sender               self_metric   self_counter      distance
  00:c0:ca:b0:60:4c    600           1..16             0          us
  de:d3:77:dd:f0:9f    510           72471..72474      0,1,2      followed us
  f6:30:bd:2d:9c:45    540           3287              1,2        followed us
  da:da:16:dd:96:92     65           111               0,1        followed us
```

`de:d3` carried a counter **4500 times larger than ours** and a lower metric, and adopted us
anyway. It was observed at distance 0 — claiming itself — so at that moment its
`master_counter` *was* 72471, which is OWL's own field. The rule is refuted on its own terms.

The transition was caught too, which is what the cold start was for: `de:d3` named itself in
10 frames and then named us in 138.

### Probe B, the control

```text
  00:c0:ca:b0:60:4c  ->  (itself)           140    us: metric 50, counter 99999
  da:da:16:dd:96:92  ->  f6:30:bd:2d:9c:45  109
  de:d3:77:dd:f0:9f  ->  f6:30:bd:2d:9c:45  120
  f6:30:bd:2d:9c:45  ->  (itself)           447
```

The same three devices, the same room, minutes apart: with the highest counter in the room
and the lowest metric, **not one of them followed us**. They organised around an Apple device
instead.

### ⚠ THE CONCLUSION BELOW IS RETRACTED — see finding 45

A replication against two iPhones showed the highest metric in the room achieving nothing,
and revealed that this experiment was **never controlled**: probe B ran after probe A, by
which time probe A had caused the devices to organise. Its negative is explained as well by
the cluster having settled as by our low metric. What survives is narrower and is in finding
45. The text below is kept as written so the error is legible.

### The conclusion

**Metric decides. The counter is not the primary key, and probably not a key at all.**
`ElectionParamsV2::beats` is correct as written, and the divergence from OWL is now a measured
one rather than an oversight. Finding 9 reached the right answer from weaker evidence.

What this does **not** say is that OWL is wrong as software — it interoperates, and a
counter-first rule still picks a master when every node agrees. It says Apple does not order
the election that way, so an implementation that wants to *win* against Apple devices must
compete on metric.

### And a note on method

This is the cleanest experiment in this document and the only one with a real control. The
five candidates eliminated in findings 36-39 were each tested by changing one thing and
watching; this changed one thing and **also ran the converse**, which is what turns "the
outcome differed" into "the variable is responsible". The difference cost one extra run.

## 45. ★ The variable is CLUSTER STATE, not metric — and finding 44 was uncontrolled

The operator asked to repeat the election experiment *"just to make 1000% sure"*. It did not
replicate, and the failure exposed a control I never had.

### The replication

Mac AirDrop off, two iPhones only, verified on the air before starting — `da:da` as master
with `ce:53` already following it, an **established** cluster.

```text
  REP A   our metric 600 (highest in the room)   -> nobody followed us
  REP B   our metric 50  (lowest in the room)    -> nobody followed us
```

Identical outcomes. Our metric made **no difference at all**, and in REP A we out-metricked
both peers (600 against 534 and 514) and was still ignored.

### What that exposes about finding 44

Probe B ran **after** probe A — and probe A is what made those devices organise. So by the
time we advertised a low metric they were a settled cluster, and the negative result is
explained equally well by settledness as by the metric. **The A/B was confounded by its own
first arm.** That is a textbook failure and I did not see it while writing the finding up as
the cleanest experiment in the document.

### The variable that fits every observation

| run | our metric | peers' state | adopted us? |
|---|---|---|---|
| `tx-first` | 530 | spread across 12-16/16 slots, unsettled | **yes, three** |
| `trial-D/F/G` | 65-600 | settled | no |
| `trial-E` | 600 | — | yes |
| `PROBE_A` | 600 | **cold-joining, AirDrop just switched on** | **yes, three** |
| `PROBE_B` | 50 | settled during probe A | no |
| `REP_A` | 600 | established pair | no |
| `REP_B` | 50 | established pair | no |

**Every adoption happened while the peers were forming or joining. Every refusal happened
against a settled cluster.** Metric spans 65 to 600 on both sides of that line and does not
separate them.

This is the hypothesis finding 38 reached from three captures and then dropped when a
breadth sweep refuted the *mechanism* it had guessed at. The observation was right; the
explanation was wrong.

### What is actually established now

- **A settled Apple cluster does not re-elect**, whatever we advertise. Six runs, metrics from
  65 to 600, no adoption.
- **A joining or unsettled device will adopt us**, and has done so in three separate runs
  including one that relayed our metric and tenure counter two hops.
- **Counter-first is still refuted** by the one observation that does not depend on any of
  this: `de:d3` carried a counter 4500 times ours, at distance 0 so it was its own
  `master_counter`, and adopted us anyway.
- **Metric-first is NOT established.** It may still be how the comparison works when a
  comparison happens at all — `beats()` stays as it is — but no run here demonstrates it.

### The method lesson, again and more expensively

Finding 44 called itself "the only experiment in this document with a real control". It had
a converse, which is not the same thing: the converse ran in a **changed environment that the
first arm had changed**. A control has to hold everything else fixed, and cluster state was
neither held fixed nor measured.

The operator's instinct to repeat is what caught it. A result that does not replicate against
a different device set was never a result.

## 46. ★ The 2×2, completed — and the forming window is under ten seconds

The design in `docs/PROTOCOL.md` was run to completion: four cells, one variable per
comparison, the outcome measure pre-registered as **≥20 frames from a non-us sender naming
our address as master**.

| cell | peers | our metric | cluster-state predicts | metric predicts | observed |
|---|---|---|---|---|---|
| FH | forming | 600 | adopt | adopt | **ADOPT** — 329 frames |
| FL | forming | 50 | adopt | refuse | **refuse** — 0 |
| SL | settled | 50 | refuse | refuse | **refuse** — 0 |
| SH | settled | 600 | refuse | adopt | **REFUSE** — 0 |

Read naively that table refutes both hypotheses at once, and for about ninety seconds
that is what this document said. It is wrong, and the thing that caught it was checking
whether the manipulation had actually taken.

### FL never delivered the forming condition — `awdl timeline` says so

The manipulation for "forming" is the operator switching AirDrop off and back on, so that
the peers join a room in which we are already transmitting as master. Whether that worked
is not a matter of trusting the procedure; it is visible in the capture.

```
FH   00:c0:ca:b0:60:4c  MMMMMMMMMM      <- us, master throughout
     82:da:96:76:6a:62  ..*fffffff      <- SILENT for 10s, then arrives and follows
     da:da:16:dd:96:92  ..*MMMMMMM      <- silent, then arrives

FL   00:c0:ca:b0:60:4c  MMMMMMMMMM...   <- us
     3e:67:df:44:e8:5d  ffffffffff...   <- already following from bucket 1
     da:da:16:dd:96:92  MMMMMMMMMM...   <- already master from bucket 1
```

**FH is the only cell in which the peers were forming.** In FL — as in SL and SH — the
cluster is established before the capture opens. So FL is void, for the fourth time, and
it says nothing about cluster state.

The difference from the previous three voids is that this one is *measured*. The peers
were genuinely restarted: `3e:67:df:44:e8:5d` is a fresh address, where every other cell
saw `82:da:96:76:6a:62`. AWDL addresses rotate per session, so a new address is proof the
phone brought AWDL down and back up. It simply finished doing so before we were looking.

### The measurement that came out of the failure

**Two iPhones re-establish master and follower in under ten seconds.** The harness needs
about that long between starting the beacon and attaching `tcpdump` — the interface is
recreated, then a 4 s settle, then capture. Any toggle performed *before* the run is
therefore always too early: the room is settled again by the time the first frame lands.

That is why four attempts in a row produced either an empty room or a settled one, and no
amount of widening the window fixed it — the window was never the problem, its starting
point was.

**The fix is to toggle mid-capture, not before it.** And the validity check is free: a
forming cell must show the peers *silent in the first buckets*, the `..*` signature above.
A cell whose peers are talking in bucket 1 is not a forming cell, whatever was done to the
phones beforehand.

### What survives

**The metric hypothesis stays refuted.** SH is untouched by any of this: settled peers, our
metric 600 — the highest in the room by a wide margin — and not one frame naming us. That
now sits on eight runs across metrics from 50 to 600 against settled peers, with zero
adoptions in any of them.

**The cluster-state hypothesis is neither confirmed nor refuted.** It survives contact with
FH, SL and SH; the cell that would discriminate it from a simpler rule has not been run.

### The sharper hypothesis, for the next run to attack

Every adoption on record — FH, `tx-first`, `PROBE_A` — has the same shape: **a device
entering a room adopts whoever is already claiming master there, and a device already in a
cluster does not re-elect, whatever it hears.** That is stronger than "cluster state
matters" and it predicts FL's outcome either way, which is exactly why FL has to be run
properly to tell them apart.

Until then, the operational consequence is unchanged and is the useful part: **to be
adopted, be transmitting before the peer arrives.** Losing an election we never get to
contest is not a defect in `beats()`.

## 47. ★ `awdl bytemap` — which opaque bytes are gaps and which are just zero

`coverage` splits bytes into named and opaque, and **opaque conflates two situations that
want completely different work**:

- a byte taking 44 values across the corpus is carrying information we do not understand.
  Copying Apple's value is a guess that will be wrong on some device.
- a byte that has been `0x00` in all 37,829 frames needs no understanding to reproduce.

Counting both as opaque makes the 2,003,899-byte figure a worse work queue than it looks.
`awdl bytemap captures/*.pcap [tag]` measures the difference: per tag and per TLV length,
how many distinct values each byte offset ever took.

### The trap this immediately walked into — constant is NOT padding

Tag 24's map reads

```
tag 24  len 40   n=37829   Election Parameters v2
     0  ++++++++++++++2.3...+3..+3..........++2.
        constant 26..35 = 00 00 00 00 00 00 00 00 00 00
```

A ten-byte run of zeros looks like a reserved block to be labelled and forgotten. **It is
not.** Bytes 26–27 are the high half of `self_metric`, a fully named `u32` that never
exceeds 65535 — and 22–23 are the high half of `master_metric` for the same reason. Only
28–35 are the actual `unknown_28` block.

So a constant run is evidence *only for bytes coverage already calls opaque*, and only
after checking it does not straddle a named field. Reclassifying on constancy alone would
have quietly relabelled the high halves of two of the most important fields in the protocol
as padding. The u32 fields of a protocol carrying small numbers are mostly zeros, and zeros
are what this measurement finds.

### Tag 16 Arpa, fully accounted — Apple's host name is a UUID v4

```
tag 16  len 40   n=10038   Arpa
     0  ..++++++++.++++..+++.4+++.++++++++++++..
        constant 0..1 = 03 24        constant 10..10 = 2d
        constant 15..16 = 2d 34      constant 20..20 = 2d
        constant 25..25 = 2d         constant 38..39 = c0 0c
```

Every byte of that is now explained. `0x24` = 36, the length of a UUID string; four `2d`
dashes at offsets 10, 15, 20, 25 are exactly the `8-4-4-4-12` positions counting from the
string start at offset 2; offset 16 is constant `34` = ASCII `'4'`, the **version nibble of
a UUID v4**; offset 21 takes exactly four values, which is the variant nibble (`8 9 a b`);
and `c0 0c` is a DNS compression pointer to offset 12. 1 + 1 + 36 + 2 = 40.

The prediction was made from the dash positions; decoding the bytes confirmed it:

```
14ca8109-4388-4ebc-925f-27b8a1ea8c97      02:3b:e8:75:9c:03
5aaca6e6-f79c-41bd-939f-4c8b28715f47      8a:c3:f7:4b:ce:de
24b2a2df-68d6-4892-8d05-851dfa216349      be:35:be:c9:05:1f
```

Version nibble `4` in all three, variants `9`, `9`, `8` — which is why offset 21 takes
exactly four values and not sixteen. Apple's AWDL host name is `<UUID v4>.local`.

It follows that **the host name is as good an identifier as the MAC address, and no
better**: a v4 UUID is random, so this is a rotating pseudonym rather than anything about
the device. Nothing here survives an AWDL restart, which is consistent with finding 46,
where a phone came back with a new address after a toggle.

### Tag 7 is a standard element we are barely crediting

```
tag 7   len 8    n=900     constant 0..7  = 00 00 ce 11 1b ff 00 00
tag 7   len 9    n=29144   only offsets 2 and 4 vary, 2 values each
tag 7   len 20   n=7195    constant 0..19 = 00 00 6f 88 1b ff ff 00 00 00 ...
```

Two of its three shapes are **completely invariant** and the third varies in two bytes.
`coverage` credits it 5 named bytes of 20 and calls the other 227,201 opaque — but this is
an IEEE 802.11 HT Capabilities element, the same situation as tag 17's VHT, which finding
23 resolved by reading 802.11-2020 rather than reverse engineering anything. Tag 7 is the
cheapest large win on the board: spec work, no guessing, 227,201 bytes.

### The corpus contains our own transmissions, and they read as certainty

```
tag 16  len 10   n=2509    constant = 03 06 "tarish"      c0 0c
tag 16  len 15   n=900     constant = 03 0b "raspberrypi" c0 0c
tag 12  len 13   n=7553    constant 0..12 = 04 03 51 41 00 95 00 00 c0 ca b0 60 4c
```

That last one ends in `c0 ca b0 60 4c` — the ALFA's own MAC. Those 7,553 samples are our
beacon, and of course they never vary: we send the same bytes every time. **A shape that is
invariant only because we generate it is evidence about us, not about AWDL**, and any
confidence drawn from its sample count is circular. The same applies to the `tarish` and
`raspberrypi` host names.

Splitting the corpus by sender before trusting an invariant is the obvious fix and is not
done yet.

### What it cannot tell you

Constant across this corpus is not constant across the protocol. These captures come from a
handful of Apple models, one Pixel and one Pi. A field every one of them happens to share
reads as padding here and is not. Weigh a run of dots by its `n`: 37,829 samples is
evidence, tag 35's 66 is barely a hint.

## 48. ★ Tag 7's "undecoded tail" was a truncated MCS set — 227,201 bytes to 74,478

`awdl bytemap` said tag 7 was two shapes of pure constant and one that varied in two
bytes, which is not what an undecoded field looks like. Following that up resolved the tag
without reverse engineering anything.

### What it was recorded as

Three lengths — 8, 9 and 20 — with five named bytes and the rest opaque, documented as *"a
fixed named part, and a variable tail nobody has decoded"*. The differing lengths were read
as **evidence** for that shape: if the tail were part of the same field it would be the
same size.

### What it is

One structure that stops in three different places. AWDL sends a **truncated IEEE
802.11-2020 §9.4.2.55.4 Supported MCS Set**, and every octet present is in the standard
order:

```
00 00 | 6f 88 | 1b | ff ff 00 00 00 00 00 00 00 00 | 96 00 | 01 | 00 00
 ?      info   AMPDU  Rx MCS bitmask, octets 0-9     rate    tx   rsvd
```

- octets 0-9 — Rx MCS bitmask. `ff ff` then zeros: MCS 0-15, two spatial streams
- octets 10-11 — **Rx Highest Supported Data Rate, `0x0096` = 150 Mb/s**
- octet 12 — Tx MCS parameters. `0x01`: Tx MCS set defined, Tx and Rx sets equal
- octets 13-15 — reserved, and reserved-valued. The 16th is truncated away

The 9-byte form carries MCS octets 0-3 and the 8-byte form octets 0-2. Same field, three
truncation points, which is exactly what a length that "varies by device" looks like when
the structure is variable-length by design.

### Why this is not a story fitted to the bytes

Three independent fields land where the standard puts them, and each one is separately
checkable:

- **150 Mb/s is a rate HT can express** — two streams at 20 MHz with a short guard
  interval, or one at 40 MHz — and it agrees with the info word in the same TLV, where
  40 MHz and both short guard intervals are set.
- **`0x01` is a legal Tx MCS parameter byte**, and its meaning (Tx set defined, equal to
  Rx) is consistent with the Rx bitmask beside it.
- **The reserved octets are zero.**

A wrong layout does not produce a legal data rate, a coherent Tx parameter byte and
correctly-zeroed reserved octets by accident. Compare finding 23, where tag 17's VHT body
went the same way: a published standard, read rather than reverse engineered.

### What it cost and what is left

| | before | after |
|---|---|---|
| tag 7 named | 45.0% | **82.0%** |
| tag 7 floor | 5/20 | **6/8** |
| tag 7 opaque bytes | 227,201 | **74,478** |
| control-plane total | 79.8% | **81.4%** |

What remains opaque is the two leading bytes, `00 00` in every frame measured and named by
no source. Constant is not the same as understood — finding 47 — so they stay opaque rather
than being called padding.

### The lesson worth keeping

**A varying length was treated as evidence of a separate field, and it was evidence of a
variable-length field.** The reading was never tested against the obvious alternative, and
the obvious alternative was in a published standard we had already used once, for tag 17.

The ratchet from finding 46's commit is what pointed here: the *average* said tag 7 was 45%
and unremarkable, while the **floor** said 5/20 and put it second-worst on the board. Tag 7
was picked for exactly that reason, and the floor was right.

## 49. ★ Tag 12's extended block — a relayed counter, a clock, and an AW counter

Tag 12 was the largest opaque block on the board: 658,512 bytes, 51.2% named, floor 21/47.
It is now 309,702 and 77.1%, floor 35/47, and the method is worth more than the result.

### Do not stare at the bytes — measure them against a byte you already know

The 47-byte shape ends in four 32-bit values that no source names. Staring at them
produced a confident wrong answer inside five minutes: three consecutive samples from one
device gave `D - 192*B = 5120` and `E - B = 499`, both exact, which looks like a
structure. Run against the whole corpus, **neither relation held** — they were two short
windows of one device fitted to three points.

What worked was different. Tag 24's `master_counter` ticks every 192 Availability Windows
(finding 22), which is 3.145728 s. That makes it a **ruler**, and the question becomes how
fast each unknown moves against it.

### The layout

```text
  27..29  extended_flags     u16   0x117d | (k << 10), k in 0..3
  29..31  always 00 00       u16
  31..35  master_counter     u32   relayed -- EQUAL to tag 24's in 100% of 24,915 frames
  35..39  millisecond clock  u32   3145.766 ms per tick measured vs 3145.728 theoretical
  39..43  AW counter         u32   exactly 192 per tick; 16-bit valued, wraps at 65536
  43..47  not identified     u32   advances 1.0 to 3.2 per tick, varying by session
```

**The field boundary was two bytes out at first**, and the error was self-concealing:
`UMI_OPTIONS` is set with a length of 4, so the extended flags word starts at 27, not 23.
Read two bytes early, the flags word looks exactly like the low half of a 32-bit counter
whose high half is conveniently zero — which is why `A` appeared to be a counter taking
only four values. Decoding the *flags* properly is what explained it: `0x117d | (k << 10)`
is a two-bit subfield in an otherwise constant word, stable per device.

### How each identification was made, and how strong it is

**`master_counter`, certain.** Compared *within the same frame* against tag 24, so there is
no sampling skew to explain a match away: equal in **100% of 24,915 frames**. It matches
the sender's own `self_counter` in only 56.4% — exactly the split expected, since those
coincide when and only when the sender is the master. So a node that invents this value is
lying about somebody else.

**The millisecond clock, strong.** Adjacent frames are the wrong measurement: two frames
either side of a tick give ΔB = 1 with almost no elapsed time, so an adjacent-pair test
measures sampling jitter. Over long spans it averages out — median **3145.766 ms per tick**
against 3145.728, six independent sessions inside 0.01%.

**The AW counter, strong.** Exactly 192 per tick over the span in 7 of 12 sessions, and the
five misses are the same sessions where the clock is also off, i.e. spans with a
disturbance in them. One device held `D - 192*B` **exactly constant across ~500 frames in
seven separate sessions**; the rest cluster on two or three adjacent values, which is where
in the tick the frame went out. It is *not* tag 4's `aw_counter` — those two are equal in
**0%** of frames carrying both, so it counts the same thing from a different origin.

### Two analysis bugs, both of which produced plausible numbers

- **Pooling rows per sender across captures.** The same MAC appears in captures taken days
  apart, so a span could straddle a session boundary where the device's clock restarts. It
  showed up as a **negative** millisecond rate, which is the only reason it was caught.
  Keyed per capture, the rates snap to 3145.5-3145.8.
- **Hand-decoding `0x000215f6` as 137206.** It is 136694. The wrong value made the first
  interval 2634 ms instead of 3146, which weakened the clock hypothesis rather than
  strengthening it — an arithmetic slip that happened to argue against the right answer.

### What is still opaque in tag 12

The extended flags word (2 bytes), the two zero bytes beside it, the UMI options blob, and
the last 32-bit value. That last one advances, but between 1.0 and 3.2 per tick depending
on the session, so it is neither a clock nor a tick counter. A frame or event count is the
obvious guess and has not been tested.

## 50. ★ Corpus-internal analysis is exhausted — the rest needs the transmitter

Tags 32 and 33 were picked as the next target on the strength of finding 48: a 6 GHz
operating class and channel are nameable fields sitting inside 150,966 opaque bytes, and
the reasoning was that tag 7 had gone the same way. **The estimate was wrong, and so was
the one that followed it.** This records why, because the wrong projection is the useful
part.

### What tags 32 and 33 actually contain

The class/channel pairs were already decoded — `0x86` = operating class 134, `0x35` =
channel 53, confirmed against a MacBook's own `system_profiler` and against the capture
named `6ghz-A-ch53`. What is left is not a field waiting to be read:

```
tag 32  bytes 6..9   04 08 02   constant in ALL 5,460 TLVs, every device
        bytes 9,10   only 7 distinct pairs: 01 00, 18 18, 83 8a, c0 c0, c1 c0, db da, f0 f0
        bytes 11,12  always zero
tag 33  bytes 0..4   01 00 00 00, never moved
        byte  6      01, never moved
        byte  9      three values: 0x00, 0x20, 0x27
```

Six or seven distinct values across 37,829 frames is an **enum or a bitmap**, not a counter
and not a clock. That rules out every hypothesis the ruler method of finding 49 can test,
which is why that method found nothing here.

### `awdl correlate`, and the negative result it produced

The method that cracked tag 12 is now a command: match every 1-, 2- and 4-byte window of
every tag against every field already understood, **inside the same frame**, so no story
about timing is needed to explain a match.

Run against the whole corpus, every row above 50% is a **known field at its own offset**:

```
t5[3..5]     ev2.distance         100.0%     <- tag 5's distance byte
t4[29..33]   sync.aw_counter       96.2%     <- aw_counter's own location
t12[31..33]  ev2.master_counter    95.8%     <- finding 49, rediscovered independently
t24[36..38]  ev2.self_counter      85.9%     <- self_counter's own location
```

It re-finds everything we know and **nothing we do not**. That is the result: within this
corpus, every field identifiable by comparison against another field has been identified.

### The filter that had to be built twice, and the nonsense it was producing

The first version reported four 100% matches for tag 33 and they were all worthless: a
constant zero byte agreeing with a field that is zero most of the time. Requiring both
sides to take three distinct values removed those — and was still not enough.
`sync.ap_beacon_delta` takes **1293** distinct values while sitting at zero in most frames,
so it matched any mostly-zero byte at 84-96%, and eleven such rows crowded out the real
ones.

The fix is to score only over the frames where the known field is **off its modal value**.
Two fields that are genuinely the same agree there too; two that merely share a popular
value collapse. Every `ap_beacon_delta` row went to nothing, and the real identities were
unaffected. Without that filter this command is an engine for confident nonsense, which is
worse than no command.

### What this means for the remaining 15.1%

The opaque bytes fall into three groups and only one of them is reachable from a desk:

| | bytes | route |
|---|---|---|
| a hash we cannot compute — tag 6 | 348,377 | **none.** Finding 25 settled this |
| constant-zero bytes named by no spec | ~450,000 | the transmitter |
| low-cardinality device-stable bitmaps | ~250,000 | the transmitter |
| already identified, waiting on nothing | 0 | — |

**The transmitter is the only remaining instrument.** For the constant-zero bytes the
experiment is direct: send frames with them set to garbage and see whether Apple peers
still sync and adopt. If behaviour does not change, they are proven ignored, and choosing
zero becomes knowledge rather than imitation — which is exactly the bar finding 47 set and
that no amount of staring at a corpus can clear.

### The projection that was wrong, twice

"Tags 32/33 are worth 150,966 bytes" counted the opaque total and assumed it was
decodable. "Steps 1 and 2 reach ~88% with no hardware" compounded it. The true figure for
both steps together is **zero bytes**. The right lesson is not to estimate a decode from
the size of the unknown: finding 48 was cheap because a published standard described the
field, and nothing published describes these.

## 51. ★ The data plane — and the second link-local the kernel gives you for free

libawdl could join a cluster, hold a schedule and be elected master, and could not carry a
byte. `data.rs` parsed the encapsulation; nothing built it, and `grep TUNSETIFF` found
nothing.

### The encapsulation, measured across 428 frames

```
802.11 QoS Data, 26 bytes   88 00 | dur | dst | src | 00:25:00:ff:94:73 | seq | 06 00
LLC/SNAP, 8                 aa aa 03 | 00 17 f2 | 08 00
AWDL data header, 8         03 04 | seq LE | 00 00 | 86 dd
then IPv6
```

Every constant was invariant in all 428 AWDL data frames in `captures/`: bytes 0,1 of the
header are `03 04`, the BSSID is `00:25:00:ff:94:73`, the ethertype is IPv6 and **never**
IPv4, and the long form the parser supports appears **0 times**. Recorded with the sample
size, because 428 frames from a few Apple devices and one Pixel is not the protocol.

**The SNAP is not a standard one, and that is a trap with teeth.** A normal SNAP carries OUI
`00:00:00` then an ethertype. AWDL carries **Apple's** OUI `00:17:f2` and protocol ID
`0x0800` — so the two bytes sitting where the ethertype belongs say *IPv4* while every frame
is IPv6, and the real ethertype is four bytes further on. `decapsulate` therefore **checks**
the SNAP instead of skipping eight bytes: most QoS Data in these captures belongs to other
vendors, and skipping blind lands the ethertype in somebody else's payload.

### Addresses are computed, never advertised

AWDL carries no addresses anywhere. A peer's IPv6 is the **modified EUI-64** of its AWDL
MAC, which is how a sender knows where to send with no resolution step at all. Verified
against a captured frame: source MAC `8a:c3:f7:4b:ce:de`, IPv6 source
`fe80::88c3:f7ff:fe4b:cede`.

Two transformations, and doing one of them is the easy mistake: `ff:fe` goes in the middle
**and** bit 1 of the first octet flips (`0x8a` → `0x88`). Skip the flip and the address is
well-formed, belongs to nobody, and fails silently.

### The test with nowhere to hide

A real 130-byte frame — an mDNS A query for `Android_0637B1C2.local` to `ff02::fb` — is
decapsulated and then **rebuilt from its parts, requiring byte equality**. A wrong constant
cannot survive that. Its IPv6 header is checked against itself too: stated payload length 48
plus the 40-byte fixed header is exactly the 88 bytes present.

### ★ The kernel adds a second link-local, and prefers it

`hal::tun` opens `/dev/net/tun` with `TUNSETIFF`. `awdl0` appears:

```
69: awdl0: <POINTOPOINT,MULTICAST,NOARP> mtu 1500 state DOWN
    link/none
```

Bring it up and assign the derived address, and it has **two**:

```
inet6 fe80::88c3:f7ff:fe4b:cede/64 scope link              <- ours
inet6 fe80::66b6:3871:d3dc:2e0d/64 scope link stable-privacy
```

Peers compute the EUI-64 address and send to it, so traffic arrives — and the kernel may
pick the **stable-privacy** address as the source for our replies, which then come from an
address the peer has never heard of. Discovery would work and every answer would be
dropped, which is indistinguishable from a protocol bug.

`addr_gen_mode` reads back as **0**, meaning EUI-64, and that looks like the right setting.
It is not: a TUN has **no hardware address** — `link/none` — so EUI-64 has nothing to derive
from and the kernel falls back to stable-privacy. The fix is mode **1** (none), set **before
the interface comes up**, because that is the only time it is read:

```bash
sysctl -w net.ipv6.conf.awdl0.addr_gen_mode=1
ip link set awdl0 up
ip -6 addr add fe80::88c3:f7ff:fe4b:cede/64 dev awdl0 scope link
```

Then `ip -6 addr show awdl0` lists exactly one address. Verified on the Pi.

`IFF_NO_PI` belongs in the same family: without it every read carries four bytes of flags
and protocol, the IPv6 version nibble lands in the wrong place, and it presents as the peer
sending garbage.

### Two process notes from building it

**`cfg(target_os = "linux")` means the development machine never compiles it.** A clean
`cargo build` on macOS proves nothing about `tun.rs` — it is excluded. It had to be built on
the Pi, and was.

**`cargo: command not found` over SSH is not a missing toolchain.** Non-interactive SSH gets
no login PATH, so `~/.cargo/bin` is absent — the same trap `CLAUDE.md` documents for
`bf-run`. The first "clean build" on the Pi was cargo not existing, and an empty grep read
as success. Then a `rsync crates/` with a trailing slash flattened the crate directories
into the tree root, and the stale `target/` from that layout kept reporting a missing method
that was present in the source. `cargo clean` resolved it.

### What is still missing

The parts, not the pipe. There is no loop yet that reads the tun, encapsulates, injects, and
does the reverse — and doing it properly needs `poll()` on both descriptors, because a
blocking read on either starves the other.

## 52. ★ The data plane runs — kernel packets on the air, read back by our own parser

`awdl datapath <mon> <our-mac> [name] [secs]` closes the loop: one `poll` over the tun and
the raw socket, encapsulating in one direction and decapsulating in the other.

### The run

```
sysctl -w net.ipv6.conf.awdl0.addr_gen_mode=1
ip link set awdl0 up
ip -6 addr add fe80::2c0:caff:feb0:604c/64 dev awdl0 scope link
ping6 -c 3 -I awdl0 ff02::1
```

```
tx   48B -> 33:33:00:00:00:02      router solicitation, sent by the kernel on link-up
tx  104B -> 33:33:00:00:00:01      the pings
...
sent             6   kernel -> radio
received         0   radio -> kernel
no route         0
own              0
not ours         0
not awdl      7234   everything else on the channel
```

The multicast mapping is right in both cases — `ff02::1` to `33:33:00:00:00:01`, `ff02::2`
to `33:33:00:00:00:02` — and it was never hard-coded; `dst_mac_for_ipv6` derived it from
the packet.

**The proof is reading the air back with our own parser**, not the counter:

```
--- 2952 frames: 69 AWDL action, 4 AWDL data, 2879 other 802.11
AWDL data plane: 4 frames (4 multicast), 496 payload bytes, highest seq 4
  carries IPv6   4
```

Four of the six (the capture was shorter than the run) came back off the air as well-formed
AWDL data frames. The same code that decodes Apple's encapsulation decodes ours, which is a
stronger statement than a round-trip against ourselves would be.

Incidentally: 69 action frames from three senders — `06:a9:3e:a7:66:1b`,
`8e:98:6f:eb:2e:ce`, `ae:e8:8d:d4:c9:31` — so there were live Apple devices in the room
throughout.

### What the run does NOT show

`ping6` reported `3 received, 0% packet loss`, and that is **not** a round trip. The kernel
loops multicast back to itself on a local interface; no peer answered. `received 0` is the
honest number, and it is expected — nothing in the room was sending data frames addressed
to us or to a group we joined.

### ★ A claim I wrote and the measurement refuted

The loop drops frames whose source is our own MAC, and the comment explaining why said that
without it "every packet we send is immediately re-injected into the kernel, which answers
it, which sends it again", and that "the first version of this looped a single mDNS query
into thousands of frames."

**That last sentence was invented.** It never happened. It is the kind of detail that makes
a comment persuasive, and it was fabricated to justify a filter I had written on general
principle.

The measurement says `own 0`: on the MT7612U the monitor interface does **not** hear its own
injections, so the filter earned nothing here. It stays, because whether an adapter loops
back is adapter-dependent and a feedback loop is far worse than a redundant comparison — but
the comment now says that, and the counter is printed so the next adapter can be checked
instead of assumed.

### Architecture note

`poll` went into `libawdl-hal::poll` rather than the CLI. The CLI has no `libc` dependency
and should not acquire one to run a loop; syscalls belong in the HAL. `EINTR` is reported as
"neither descriptor ready" rather than as an error, because a signal arriving during a poll
is not a failure — treating it as one means resizing a terminal kills the data plane.

### What is still missing

Nothing has been received from a peer, because nothing has been sent to us. That needs the
control plane and the data plane running **together**: `awdl beacon` holds the cluster and
`awdl datapath` carries the traffic, and today they are separate processes contending for
one radio. Joining them is the next piece, and it is also the point at which mDNS over AWDL
becomes testable against a real Apple device.

## 53. ★ One process, both planes — and data frames land 30 microseconds after a beacon

`awdl beacon --datapath awdl0` runs the control plane and the data plane in one loop. They
had to merge rather than run side by side, for two reasons and only the second is obvious.

**Two processes cannot both inject on one phy.** The mt76 answers the second with `EAGAIN`
and writes nothing to dmesg — the same trap `rawsock` already documents for a managed vif
left up.

**An AWDL peer listens only during its availability windows.** A data frame sent the moment
the kernel hands it over goes out while the peer is deaf, and the sender sees a successful
transmit and no reply. That is indistinguishable from the peer ignoring us, and it is the
failure this project has misdiagnosed more than any other.

So outbound packets are **queued, not sent on arrival**, and drained immediately after each
beacon — which is by construction inside a window the cluster attends.

### Measured, because the claim is worthless otherwise

A 40-second run, `ping6 -c 5 -I awdl0 ff02::1`, capturing on the same monitor interface:

```
sent 39 MIF, 76 PSF, 0 failed
datapath: 9 sent in-window, 0 delivered, 0 unroutable, 0 dropped, 0 still queued
cluster: 25 anchors, master Some(06:37:6f:45:5c:68), spread 99418 us, adopted=false
```

Then, for each data frame of ours on the air, the time since our previous beacon:

```
0.03  0.03  0.03  0.03  0.03  0.04  0.05  0.08   ms
within one extended AW (65.536 ms) of a beacon of ours: 8/8
median 0.03 ms
```

**Thirty microseconds.** An extended availability window is 65.536 ms, so every data frame
went out in the same window as the beacon that preceded it, with three orders of magnitude
to spare. `crates/libawdl-cli/examples/inwindow.rs` is the measurement.

### The queue's two deliberate limits

**Bounded at 64, dropping the OLDEST.** An unbounded queue turns a burst the radio cannot
keep up with into unbounded memory and ever-staler packets. On a link where a packet may
wait a whole cycle, the stale end is the part worth losing.

**Four packets per window visit.** One beacon plus a few data frames fits an extended
window; draining a full queue into one window would overrun it and transmit into the next
slot — which is precisely the mistake that cost three build cycles in finding 48's
neighbourhood, and it would be self-inflicted here.

The tun is read only from the gap *between* windows, polled with a zero timeout and capped
at four packets per visit. A blocking read there means going deaf and missing the window,
and missing a window is worse than a packet waiting one more cycle.

### `0 delivered`, and why that is the expected number

Nothing arrived from a peer. It should not have: we advertised metric 65 and declined the
election, `adopted=false`, so no Apple device had any reason to send us anything. The
receive path is exercised only by frames addressed to us or to a group we are in, and
neither existed.

**That is the next experiment, not a defect.** It needs us to be in a cluster — which
finding 46 says means transmitting before the peer arrives — and then an mDNS query on
`ff02::fb` that a real device answers. At that point the receive counter becomes the
measurement that matters, and libawdl is doing the whole job `libmosey` does today.

## 54. The interface configures itself — and Linux needed no routing help at all

`awdl beacon --datapath awdl0` now brings the interface up itself instead of printing three
commands to paste. `Tun::configure(mac)` is one function because the **order** is the whole
content:

```
1.  addr_gen_mode = 1     BEFORE up -- read once, at that moment
2.  IFF_UP
3.  the derived address
```

Step 3 before step 2 is fine. Step 1 after step 2 is not, and fails **silently** — which is
exactly why these are not three things for a caller to sequence.

`IFF_UP` is set read-modify-write, via `SIOCGIFFLAGS` then `SIOCSIFFLAGS`. Writing the flags
word wholesale would clear `MULTICAST`, and a link whose entire purpose is mDNS to `ff02::fb`
cannot lose that.

### The run, with nothing configured by hand

```
  --datapath awdl0: up on fe80::2c0:caff:feb0:604c, IPv6 queued and drained in-window

76: awdl0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500
    inet6 fe80::2c0:caff:feb0:604c/64 scope link     <- and only this one
addr_gen_mode: 1
```

**Exactly one address.** The stable-privacy twin from finding 51 is gone, which is the proof
that step 1 landed before step 2.

### ★ A correction: routing was never a problem on Linux

The module note said a route without an `ip rule` is never consulted, and offered
`ip -6 route add … table 200` plus `ip -6 rule add iif awdl0 table 200` as the Linux
equivalent of the Android trap.

**That was wrong.** `ip -6 route show dev awdl0` after configuring:

```
fe80::/64 proto kernel metric 256 pref medium
```

The kernel installs it the moment the address is added. No table, no rule, nothing to add.
The fwmark problem is real and is *Android's* — carrying it across to Linux sent a reader
looking for a fault that does not exist, which is its own kind of expensive.

### The duplicated EUI-64 rule, and the test that guards it

`libawdl_hal::tun` needs the link-local rule and the HAL does not depend on the protocol
crate — reasonably, since it is four lines. So it exists twice, and a divergence would put
the interface on an address **no peer computes**: the peer would discover us and never get a
reply. A test in the CLI, which depends on both, holds the copies against each other over
four MACs including the awkward ones (`ff:ff:ff:ff:ff:ff`, and `02:…` where the flipped bit
goes to zero).

That is the cheapest possible guard for a duplication that is otherwise invisible until it
is a field failure.

## 55. ★ Two bugs kept us out of every cluster — and one may have skewed the 2×2

`--follow` was reporting cluster-clock spreads of 188,932 µs and 367,798 µs against a
65,536 µs slot, with `adopted=false`. Both causes are now fixed and the spread is **1,519
µs**.

### Bug 1 — `self.master` was assigned from every frame

```rust
self.master = Some(e.master);   // unconditionally
```

A room with two clusters names two different masters, so this flapped on alternate frames.
And the anchoring test is `self.master == Some(src)` — so **both** masters' frames anchored
the clock, pooling offsets measured against two unrelated timelines.

The rule is AWDL's own: follow the better metric. A weaker cluster is now ignored rather
than averaged in, an *equal* metric does not displace the incumbent (or two matched clusters
flap forever), and when the master genuinely changes the old anchors are **discarded** —
they were measured against a different cluster's timeline. `master_changes` is now reported,
because a run that changes master repeatedly is not synchronising to anything and the
symptom without that counter is a spread figure that looks like jitter.

This took the master changes from constant to 1 per run, and the run began briefly adopting
at 28,297 µs before degrading again — which said the remaining fault was elsewhere.

### Bug 2 — one frame per pass, in a room sending 270 a second ★

`arrived_us` is stamped when `rx` returns, so it measures **when we noticed**, not when the
frame landed. The loop read a single frame per iteration. A capture counted ~270 AWDL frames
per second while the loop iterates every few milliseconds, so any hiccup left a backlog in
the socket buffer — and every frame behind it was stamped late by however long the queue
was.

That is not jitter, it is a queue, and it grows. It showed up as spread, which reads as
drift, which reads as "the estimate degraded".

Draining the socket each pass — bounded at 32 so a saturated channel cannot hold the loop
past its next window — fixed it outright:

| | before | after |
|---|---|---|
| spread, run 1 | 248,450 µs | **2,489 µs** |
| spread, run 2 | 285,558 µs | **1,519 µs** |
| adopted | false | **true** |
| master changes | 1-2 | 1 |

Two orders of magnitude, and the estimate now holds for the whole run.

`SO_TIMESTAMP` remains the correct fix — ask the kernel when the frame arrived rather than
asking the clock when we got to it. Draining keeps the queue short enough that the question
matters much less, which is why it is not urgent.

### ★ What this means for the 2×2, and it is uncomfortable

Findings 45 and 46 concluded that a settled Apple cluster does not re-elect, from eight runs
across metrics 50 to 600 with zero adoptions. **Every one of those runs was made with a
cluster clock this badly degraded**, which means our frames were aimed at windows computed
from a phase estimate wrong by hundreds of milliseconds — most likely landing while the
peers were on another channel.

"The peer ignored us" and "the peer never heard us" are indistinguishable from our side, and
that is exactly the confusion this repository keeps paying for.

This does **not** overturn the conclusion. FH succeeded with the same defect, and a peer that
never heard us should not have adopted us either. But the negative results are much weaker
than they looked, and the honest position is that **the settled-cluster question is open
again** and worth re-running now that `adopted=true` is achievable. The re-run is cheap and
the outcome measure is unchanged.

> **Re-run, and the conclusion held** — three valid trials, preconditions checked, REFUSE
> each time. See finding 57.

## 56. ★ Ask the kernel when the frame arrived — the transmit/listen tension was a bug

Finding 55 fixed the cluster clock by draining the receive queue every pass. That worked
and broke something else, and the pair is worth recording together because the second
failure was invisible in the number the first one fixed.

### Draining fixed the clock and starved the transmitter

```
              frames sent      spread      adopted
before            86 / 30s   285,558 us      false
after draining     7 / 75s     1,519 us      true
```

A beautiful clock and nothing on the air to use it. In a room sending ~270 frames a second
there is always another frame, so the loop spent its time receiving and almost never reached
the transmit branch. **Receiving is what makes the next transmission well-aimed; it is not
the job.**

Bounding the drain by the slack before the next window helped and did not fix it, because
the real cost was elsewhere.

### Aiming at a slot centre means missing the slot

`us_until_master_window` took the minimum of `us_until_slot_centre` over the master's slots.
That returns the time to the **next** centre — so overshooting a centre by one microsecond
waits a full 1.049 s cycle. With a phase that re-anchors on every frame, the target moves out
from under you and every window is missed by a hair.

A window is 65 ms wide and the entire point of knowing the phase is to transmit inside it.
**If we are already in one of the master's slots, the answer is now.** Aiming at the centre
is for when we are outside.

That restored the frame rate — and the clock immediately went bad again, oscillating between
9 ms and 105 ms as the transmit side got busier. Which is the real shape of the problem:
every millisecond spent transmitting is a millisecond the receive queue grows.

### The fix is not a balance, it is `SO_TIMESTAMP` ★

`arrived_us` was being read from the process clock after `recv` returned, which measures
**when we got round to the frame**. A backlog adds itself to every frame behind it, so the
clock's quality was a function of how busy the transmitter was — two things that have no
business being coupled.

Asking the kernel for the arrival time decouples them completely. A frame read late still
carries the time it landed.

```
              frames sent      spread      adopted
kernel time      57 / 30s      5,378 us      true
                 45 / 30s      9,043 us      true
```

Both numbers good at once, for the first time. The code comment had named `SO_TIMESTAMP` as
"the real fix" two commits earlier while shipping the approximation; it took the
approximation failing in a new direction to make it worth doing.

The kernel stamps in `CLOCK_REALTIME` and the loop thinks in microseconds since its own
`Instant`, so one base captured at start converts between them. The two drift, but far below
the millisecond scale that matters, and the one thing that would break it — an NTP step —
appears as a discontinuity rather than as slow rot.

### The lesson, which is the same one as finding 47

A measurement that improves the number you are looking at can wreck the number you are not.
`spread` went from 285,558 µs to 1,519 µs and the run became *useless*, and nothing in that
figure said so. The frame count was in the same log, one line above.

## 57. ★ The settled-cluster result survives a properly controlled test

Finding 55 reopened the question: every run behind "a settled Apple cluster does not
re-elect" had been made with a cluster clock wrong by hundreds of milliseconds, so our
frames were probably landing while the peers were on another channel. *"Ignored us"* and
*"never heard us"* are indistinguishable from our side.

Re-run with the clock fixed, the frame rate restored, and every precondition checked: **the
conclusion holds.**

### Being adopted was voiding the run that measured it ★

The first attempt voided itself, and the reason is the sharpest self-inflicted wound in this
project so far.

A peer naming US master set `self.master` to our own address. Only the master's own frames
anchor the clock, and our own frames are filtered out — so from that moment the estimate
froze at zero observations and `adopted` went false. **Success turned itself into a void
run.**

It also explains every `master Some(00:c0:ca:b0:60:4c), 0 anchors` line in the preceding
logs, which had been read as a tracker bug. They were peers adopting us.

`Cluster::for_us(addr)` now records a frame naming us in `adopters` and steps over it rather
than following it, and the beacon prints the count unconditionally — zero included, because
it is the outcome measure of every election experiment here and a missing line reads as
"not looked at".

### The harness checks its own preconditions now

Every void run in this project looked like a result until something extra was checked by
hand afterwards. `scripts/compete-trial.sh` checks first and prints VOID with the reason
instead of a number:

```
frames sent >= 40           a starved transmitter cannot be adopted
adopted = true              a bad phase lands frames while the peer is elsewhere
spread < 32768 us           under half a slot
our address in the capture  the beacon's counter is not evidence it reached the air
```

It also captures the room **before** the run, because a trial against an empty or churning
room measures nothing and reads as a clean refusal afterwards.

### Three valid trials

Room settled throughout: `4e:90:de:c0:5a:51` master from the first bucket, with
`aa:a0:36:e4:79:8a` as an independent second master.

| trial | frames sent | spread | naming us | verdict |
|---|---|---|---|---|
| proper | 119 | 4,366 µs | **14** | REFUSE |
| rep1 | 156 | **363 µs** | 0 | REFUSE |
| rep2 | 155 | 9,457 µs | 0 | REFUSE |

**REFUSE, three times**, at metric 600 against a settled cluster, with us correctly
synchronised and transmitting at full rate — conditions none of the original eight runs met.

### The 14, and why it is not a result

The first trial had `4e:90:de:c0:5a:51` name us master in 14 frames while naming itself in
108. That is not zero and it was tempting: the threshold is 20, it was the first run after
the clock fix, and a story about partial adoption writes itself.

**It did not replicate.** Two further trials gave zero. Finding 44 died exactly this way —
a clean-looking effect in one run that a converse survived and a replication killed — which
is why rule 6 exists and why the threshold was not moved to fit.

Worth keeping as an open observation rather than a finding: what makes a settled peer name
a stranger as master in 11% of its frames for one 60-second window and never again? The
honest answer is that one occurrence is not enough to say.

### What this settles

Finding 45's conclusion stands, and now rests on evidence that is actually controlled. The
operational consequence is unchanged and is the useful part: **to be adopted, be
transmitting before the peer arrives.** A settled cluster does not re-elect for a better
metric — not at 600, not when it can hear us clearly, not when our frames land in its own
windows.

## 58. `awdl stats` has been counting other people's Wi-Fi as AWDL data frames

Hunting for two iPhones that were not on the air, a 30-second capture on channel 6 reported:

```
--- 2597 frames: 0 AWDL action, 120 AWDL data, 2477 other 802.11
AWDL data plane: 120 frames (2 multicast), 67381 payload bytes, highest seq 64820
```

Data frames with **no** action frames beside them, which does not happen — a device carrying
AWDL data is a device in a cluster, and a cluster advertises itself constantly. The
convenient reading was there and had a story ready: the peers are on channel 6, we have been
transmitting into an empty channel, and that explains two void trials.

**It was false.** The senders were `dc:4f:22:aa:af:7e`, `dc:4f:22:aa:b5:09`, and four
addresses sharing the tail `05:d6:b4:1e:d6` — an access point and two unrelated clients.
The AWDL BSSID `00:25:00:ff:94:73` appeared **zero** times.

### The bug

`classify` did this:

```rust
body80211.get(24 + qos + 8..).and_then(DataHeader::parse)
```

It stepped over eight bytes **assuming** LLC/SNAP and parsed whatever followed. `DataHeader`
is deliberately permissive — two bytes, a sequence, a form marker, an ethertype — so **any**
QoS Data frame long enough came back as AWDL.

`decapsulate`, written in finding 51, checks the SNAP precisely because most QoS Data belongs
to somebody else. Its own doc comment says so. `classify` predates it and was never updated,
so the new careful path and the old careless one coexisted, and `awdl stats` used the
careless one.

With the SNAP checked: **0 AWDL data frames on channel 6, 0 on channel 149.** The room was
genuinely empty, which is the boring and correct explanation for two void trials.

### What gave it away

The sequence number. Real AWDL sequences in these captures are in the hundreds — the
data-plane fixture in `tests/datapath.rs` carries 483. **64820** is not a sequence, it is
whatever two bytes happened to sit at that offset in somebody's TCP stream.

A count can be wrong quietly. A count with an absurd number attached to it announces itself,
which is an argument for reporting more than the count.

### Where this leaves earlier numbers

The data-plane constants in finding 51 are unaffected: that work used a throwaway analysis
that checked the SNAP for exactly this reason, and it found 428 frames where the broken
classifier would have claimed far more. Re-reading `6ghz-A-ch53.pcap` with the fix gives 24
data frames, highest sequence 892 — which matches what that analysis found.

What *is* suspect is every `AWDL data` count `awdl stats` has printed, across every capture,
for as long as the command has existed.

## 59. ★★ THE POSITIVE CONTROL — two iPhones adopted us as master, 1,223 frames

The first unambiguous adoption in this project's record, and the first ever run with all four
preconditions actually met: a verified-empty starting room, a correct cluster clock, a full
frame rate, and known peer metrics.

Capture: `captures/fh-adopt.pcap`.

### The run

We transmit at metric 600 into a room measured empty — six consecutive 8-second windows,
zero AWDL frames. Then, 180 seconds in, the operator switches AirDrop on, on both iPhones.

```
00:c0:ca:b0:60:4c  MMMMMMMMMMMMMMMMMMMMMMMMMMMMMM   us, master throughout
22:dd:ca:10:6b:b7  ..................*fffffffffff   silent 18 buckets, arrives, FOLLOWS
da:da:16:dd:96:92  ..................*fffffffffff   same
```

That is the forming signature of finding 46, unmistakable at 10-second buckets: silent,
transition, following.

| peer | its metric | frames naming **us** master |
|---|---|---|
| `22:dd:ca:10:6b:b7` | 537 | **981** |
| `da:da:16:dd:96:92` | 540 | **242** |

**1,223 frames against a pre-registered threshold of 20.** Two real Apple devices, both with
metrics inside the measured Apple range, both deferring to our 600 and following us as the
root of the cluster.

### What it establishes

**We can win an AWDL election against Apple hardware.** Not synchronise to one — be elected
by it. OWL cannot: `AWDL_ELECTION_METRIC_INIT 60` with a counter that never moves makes an
OWL node a structural follower. libmosey sends metric 1.

**The operational rule from finding 46 is confirmed and is the whole story**: a device
*entering* a room adopts whoever is already claiming master there. Be transmitting before the
peer arrives and a higher metric is honoured. Three valid trials in finding 57 show the same
metric against a *settled* cluster does nothing at all. Same frames, same metric, opposite
outcome — the only variable is who was there first.

**And it is the positive control the reserved-byte experiment needs.** A perturbation
experiment requires a condition where the unperturbed case reliably succeeds, or a refusal
means nothing. This is that condition, and it is now reproducible on demand.

### ★ The live counter said zero, and it was blind rather than wrong

The beacon reported `adopted by 0 peer(s), 0 frame(s) naming us master` for the run whose
capture contains 1,223 such frames.

The receive path — drain, parse, `cluster.observe` — was gated behind `--follow`, and this
run had no `--follow` because there was nothing to follow in an empty room. So we never
listened, never observed, and counted nothing.

**A zero reads as a measurement.** "We heard nothing" and "we were not listening" are the
same number, and that is the second time tonight the same shape of confusion has cost
something: finding 55's *"the peer ignored us"* versus *"the peer never heard us"*.

Listening is now unconditional. Following is about whose phase we **aim** at, which is a
separate decision and still `--follow`'s job.

### Method notes worth keeping

**Three runs were lost to cue latency before this one worked.** There is no push
notification, so a "switch them on now" message reaches the operator whenever they next look,
and a 170-second window cannot absorb that. The fix was to stop cueing: open a **300-second**
window and ask for an off-wait-on cycle at any point inside it. The timeline then shows when
it happened, so the run is interpretable regardless of latency, and the operator is not
racing a clock they cannot see.

**"AirDrop off" is not instant but is fast.** The phones kept transmitting for a few seconds
after being switched off — a 12-second pre-capture caught 146 frames of tail and read as "the
room is not empty". Six 8-second windows afterwards were all zero. Sample until quiet rather
than sampling once.

**AWDL addresses rotate per session, and one device does not.** The same phone appeared as
`7a:db:23:79:5a:0e`, then `96:3e:b7:87:06:e3`, then `22:dd:ca:10:6b:b7` across three
sessions, while `da:da:16:dd:96:92` has been stable all night and across the earlier 2x2.
Anything keyed on a peer address must tolerate the first and must not assume the second.

## 60. ★ `SO_RCVTIMEO` of zero means NO timeout, and it starved the transmitter twice

Finding 56 decoupled the cluster clock from transmit load with `SO_TIMESTAMP`. Finding 59's
counter bug then made listening unconditional. Both were right, and together they produced a
beacon that sent **41 frames in 60 seconds** where it should send about 170.

### The bug

The drain loop asks for successive reads with no waiting:

```rust
radio.rx(if drained == 0 { budget_ms } else { 0 })
```

and `Nl80211::rx` implemented the timeout with `SO_RCVTIMEO`. **A `timeval` of
`{tv_sec: 0, tv_usec: 0}` disables the timeout entirely** — the read then blocks until a
frame arrives. "Timeout 0" reads like "return immediately" and means the exact opposite.

In a silent room the first read times out normally and the loop exits, so nothing hangs. In a
room with a peer sending a few frames a second, every drain pass after the first **blocked
until that peer's next frame** — long enough to sail past the 65 ms window we were waiting
for, which then costs a full 1.049 s cycle.

`MSG_DONTWAIT` is what actually means do not wait.

```
                      frames in 60s      rate
SO_RCVTIMEO(0)                   41     0.68/s
MSG_DONTWAIT                    172     2.87/s
```

2.87/s is exactly the predicted rate: one frame per advertised window, three advertised
windows per cycle.

### What it cost

A 7-minute control run, which should have reproduced finding 59's adoption, was
**out-transmitted 2884 frames to 151** by a peer at metric 522 — and got one frame of
adoption instead of 1,223. It read as "a lower metric beat us", which would have been a
genuinely interesting and completely false finding about AWDL.

### The harness did not catch it, and now does

`compete-trial.sh` required `frames sent >= 40`. A 420-second run sent 151 and passed. A flat
count cannot express "starved" — the threshold is now a **rate**, `2/s`, against the run
length. The healthy figure is 2.87/s and anything under 2 means we will lose to any peer
transmitting normally, whatever our metric says.

### The pattern, three times now

| | fixed | broke |
|---|---|---|
| finding 55 | cluster clock, 285 ms → 1.5 ms | transmit rate, 86 → 7 frames |
| finding 56 | decoupled them with `SO_TIMESTAMP` | — |
| finding 59 | the blind adoption counter | transmit rate again, 172 → 41 |

Receiving and transmitting compete for one loop and one radio, and **every change to one has
silently cost the other.** The lesson is not "be careful": it is that the two numbers have to
be read together, every time, which is why the trial harness now refuses a run on either.

## 61. ★ How an iPhone's AWDL actually wakes — and why it blocked the garbage A/B

The experiment of finding 60's tooling — does an Apple peer still adopt us when tag 24's
eight measured-constant bytes carry garbage — **did not complete.** One clean control, no
clean treatment, across roughly a dozen runs. The reason is worth more than the result would
have been, because it is a property of the peers rather than of our code.

### The control, which is solid

`captures/c1-control-adopt.pcap`. Room verified silent, us sole master at metric 600, full
frame rate:

| peer | metric | frames naming **us** master |
|---|---|---|
| `72:01:e2:fd:9d:57` | 521 | 379 |
| `ae:a8:5e:5b:44:15` | 510 | 53 |
| `3e:c9:51:72:8f:1a` | 510 | 35 |
| | | **467, three peers** |

All three arrived and went to `f` — follower. The live counter agreed with the capture.

### The taxonomy of wakes — measured, not assumed

**An idle iPhone does not advertise AWDL at all.** Wi-Fi on, AirDrop set to Everyone, phone
sitting on a desk: **zero** frames. Five separate checks across two runs. AWDL is brought up
on demand and torn down again, so "AirDrop is on" is not a state visible on the air.

**What actually wakes it, and what state it wakes into:**

| trigger | wakes AWDL? | arrives as |
|---|---|---|
| cold boot, or Wi-Fi on from fully off | **yes** | **follower** — adopts a better metric |
| Photos → Share → AirDrop sheet | **yes**, strongly | **master** — claims, and holds it |
| AirDrop set to Everyone, phone idle | **no** | — |
| Wi-Fi off→on while already warm | **no** | — |
| Continuity with a nearby Mac | **yes** | follower |

The third row is the one that cost the most time. AirDrop *receiving* is bootstrapped by
**BLE**: a receiver waits for a sender's Bluetooth advertisement and only then raises AWDL.
We transmit AWDL and never BLE, so we cannot wake a receiver at all — it has to be woken by
something else before it can hear us.

**And the trap: the only reliable on-demand wake creates a rival.** Opening the share sheet
makes that phone a *sender*, which claims master and keeps claiming — and the second phone
then follows *it* rather than us. Runs B2, A3, T2 and T4 all died this way, with a peer at
metric 522-532 out-transmitting us and capturing the other phone.

Two devices that will not wake independently, where waking one turns it into the competitor,
cannot produce a controlled forming cell on demand.

### Continuity, not AirDrop, is what usually holds AWDL up

The services those phones advertise are `_applicationservicepairing` and `_appsvcprepair` —
Handoff and Universal Clipboard, **not** `_airdrop`. So a phone near a signed-in Mac keeps
AWDL alive for Continuity regardless of the AirDrop setting, and switching AirDrop off does
nothing. **Airplane mode is the only switch that reliably stops it**, and that is now the
reset step.

### What would make this work next time

**A third device as the waker**, so the woken rival is not one of the two peers being
measured. Or **much longer windows**: in the control the peers settled into following us
after ~30 s, so the question may be whether a rival eventually defers to metric 600 given
minutes rather than seconds — T4 only gave it 100 s and the rival was still claiming.

Or, best: **send BLE**. The app half of Tarish already does BLE advertising for Quick Share.
A sender-shaped BLE advertisement would wake a receiver into follower state on demand, which
is exactly the wake we cannot currently produce — and it is the same mechanism real AirDrop
uses.

### What is banked regardless

The `--garbage` tooling, its tests against the encoded bytes, the harness preconditions, and
this taxonomy. The question itself is **open, not answered negatively** — no treatment run
ever ran under conditions where a refusal would have meant anything.

## 62. The BLE beacon is correct and does not do what I claimed — twice

An AirDrop BLE beacon was built on the Pi to solve finding 61's blocker: we could not wake a
peer into follower state on demand. Two opposite claims were made about it within an hour,
and both were wrong.

### The beacon itself is right

`btmon` decodes what we transmit using BlueZ's own parser:

```
Flags: 0x1a — LE General Discoverable, Simultaneous LE and BR/EDR
Company: Apple, Inc. (76)
  Type: AirDrop (5)
  Data[18]: 000000000000000001000000000000000000
```

**BlueZ labels it "Type: AirDrop (5)" independently**, which is a far better check than our
own reading of our own bytes. The layout from `tarish-app/docs/BLE-DISCOVERY.md` is
confirmed.

Two defects had to be fixed first, and neither showed up as an error:

- **no AD Flags structure.** The first version sent only the manufacturer AD
- **`ADV_NONCONN_IND` (0x03)** rather than a connectable `ADV_IND` (0x00)

And one trap that made everything look fine when nothing was happening: with `bluetoothd`
running and advertising already enabled, **`LE Set Advertising Parameters` and
`LE Set Advertise Enable` both return `0x0C` Command Disallowed** while
`LE Set Advertising Data` returns success. Checking only the last one — which is what
`hcitool` prints most visibly — reports a working beacon that is not transmitting. Disable
advertising first, then set parameters, then data, then enable, and check **every** status.

### Claim 1, wrong: "the beacon wakes a sleeping device"

Enabling it appeared to bring a Mac's AWDL up, and one off/on cycle supported it. Repeated
against an interface that was actually **down**, three cycles and twelve samples gave zero in
every phase. A BLE beacon **cannot** bring up an AWDL interface that is down.

### Claim 2, also wrong: "so BLE does not wake devices"

The operator, who implemented this in GoOpenDrop, said flatly that BLE alone is enough. That
was the right correction to take seriously, and it is why the AD Flags and `ADV_IND` defects
were found at all — the prior was that our code was broken, not that Apple was.

### What is actually true, and it is neither

**The devices' AWDL state is governed by their own settings, not by our beacon.** A phone
with AirDrop set to **Everyone** transmits with the beacon off (147, 123 frames) and with it
on (120, 124, 154) — no measurable difference. Setting AirDrop to Everyone is what brings it
up; our beacon changes nothing we can detect.

The likely reason, from our own documentation: **our four identity slots are all zero.** A
receiver in contacts-only mode is *supposed* to ignore that, and contacts-only is the iOS
default. An identity-less beacon can only ever reach a device in Everyone mode — which is a
real constraint on any AirDrop implementation without extracted Apple credentials, and worth
knowing before building on it.

### ★ "Everyone" expires after ten minutes

iOS reverts AirDrop from Everyone to Contacts Only on a timer. This is the single most
useful operational fact from the session: it retroactively explains several void runs in
which peers were present and cooperative early on and then silently stopped appearing,
with nothing on our side having changed.

`_airdrop` appearing in a device's advertised service list tracks that setting, so the
peer's AirDrop state is **visible from the air** — no need to ask anyone to check a phone.

## 63. ★★ APPLE VALIDATES TAG 24'S "RESERVED" BYTES — the first field we know they check

Tag 24's `unknown_28` is eight bytes that have been `00` in all 37,829 frames measured, named
by no specification. Finding 47 set the rule that constant is not the same as understood, and
finding 60 built `--garbage` to settle it the only way it can be settled: send something else
and see whether Apple peers still behave.

**They do not.** Those bytes are read.

### The crossover

One iPhone, `72:01:e2:fd:9d:57`. Room verified silent before each run, us sole master at
metric 600, peer woken into our room by setting AirDrop to Everyone, garbage confirmed on the
air by reading our own frames back out of each capture.

| run | flag | window | peer metric | **frames naming us master** |
|---|---|---|---|---|
| K1 | control | 4 min | 532 | **146** |
| K5 | `--garbage t24` | 4 min | 537 | **0** |
| K6 | control | 4 min | 528 | **241** |
| K4 | `--garbage t24` | 16 min | 536 | **0** |

Controls 146 and 241. Treatments 0 and 0. Alternating order, so drift cannot masquerade as
the effect. Captures: `captures/garbage-K{1,4,5,6}.pcap`.

In both treatments the peer showed `following 0` for the entire run — it never deferred to
anything, not merely not to us.

### The duration confound, and why it is dead

K4 ran 16 minutes against K1's 4, so "a peer left unchallenged for longer simply entrenches"
was a live alternative — its 5546 master claims against K1's 465 fit that story. K5 was run at
**K1's exact four-minute window** and still gave zero, with the peer present for 17 of 24
buckets. The duration explanation is gone; K6 then replicated the control at the same window.

### What it means, stated carefully

**Those eight bytes are not ignorable.** Two readings, which this experiment cannot separate:

- Apple **validates** them as reserved, and a non-zero value makes the frame or the tag
  invalid
- our **layout is wrong**, and bytes 28..36 carry a field Apple reads that we have mislabelled
  as unknown

Either way the operational conclusion is identical: a transmitter must send zeros there, and
`unknown_28` is now a field we know matters rather than one we carry for round-tripping.

**The named fields around it were untouched** — `self_metric` at 24..28 and `self_counter` at
36..40 were verified intact in every treatment capture, and the TLV length never changed. So
this is not a parse shift.

### The assumption it inverts

The whole experiment was designed on the premise that measured-constant bytes are *probably*
reserved and safe to fill. The result says the opposite: **they are constant because they are
required.** That reframes the remaining ~450,000 opaque bytes — tag 5's three, tag 16's flags
byte, tag 4's byte 28 and trailing pair — from "candidates for free coverage" to "suspects,
each of which must be tested the same way".

It also means the honest coverage ceiling is lower than finding 50 estimated, and for a better
reason: some of those bytes are not ours to choose at all.

### Method note

This took about twelve hours across two sessions, and roughly fifteen runs voided before four
counted. Every void had a named cause — cue latency, peers that would not wake, a peer woken
as a rival, a stale competitor, our own transmitter starved by `SO_RCVTIMEO(0)`, and an
adoption counter gated behind `--follow`. The four that counted are the ones where every
precondition was checked **before** the outcome was read.

## 64. ★★ Bisecting tag 24's block by asking the peer — there is a FIELD at offset 28

Finding 63 established that filling tag 24's eight-byte `unknown_28` with `0xa5` makes an
Apple peer refuse to adopt us. That was true and its interpretation — "Apple validates a
reserved block" — was wrong. Setting **one byte at a time** takes the answer apart.

### The method

Every other result in this file was obtained by reading bytes off the air. This one is
different: it **asks the peer a question and reads its answer in behaviour.** Set one byte,
leave the other seven as Apple sends them, and see whether the device still elects us. Each
run is a single bit of information about a field nobody documents.

The outcome measure is unchanged and pre-registered: ≥20 frames from a non-us sender naming
our address as master, against controls of 146 and 241.

### Results, one byte at a time, all `0x01`

```
offset within unknown_28:   0    1    2    3    4    5    6    7
                          REJ  REJ    ?    ?    ?    ?    ?  ACC
```

| probe | adoption | note |
|---|---|---|
| whole block = `a5` | **0**, **0** | finding 63 |
| byte 0 = `01` | **0** | short exposure, 2 buckets |
| byte 1 = `01` | **0** | 18 buckets, 1707 master frames, `following 0` — strong |
| byte 7 = `01` | **172** | adoption, squarely in the control range |

**So it is not a reserved block.** There is a field of at least two bytes beginning at
offset 28, and byte 35 lies outside it.

### Two wrong conclusions, in sequence

**"Apple validates the reserved bytes"** — finding 63's framing. True that they are read;
wrong that the block is the unit.

**"Only byte 0 matters"** — written after byte 7 was accepted, and contradicted by the very
next probe when byte 1 was also rejected. One accepted offset does not establish a boundary,
and generalising from it was the same mistake finding 63 made one level down.

The honest statement each time was narrower than the one reached for, which is worth
recording because the pull is always toward the tidier claim.

### What it probably is

Every other field in tag 24 is a **u32** — `master_counter`, `distance`, `master_metric`,
`self_metric`, `self_counter`. A u32 at offset 28 would occupy block bytes 0-3 and leave 4-7
as padding, which fits every observation so far. Testing byte 4 decides it: accepted means
the field is at most four bytes and the u32 reading holds; rejected means it runs further and
the idea is dead.

### Why this matters beyond coverage

A byte proven ignorable is a byte a transmitter may choose. A byte proven **read** is
something else entirely: it is a field, and a field has a meaning we do not know. Calling all
eight `unknown_28` hid that behind a name which says there is nothing to see.

It also revises what `--garbage` is for. It was built to convert opaque bytes into free
coverage; it turns out to be a **probe for finding fields**, which is the more valuable
instrument.

## 65. ★★★ A u32 nobody has named, found by asking an iPhone seven yes/no questions

Tag 24's `unknown_28` was eight bytes that OWL calls reserved, that every capture shows as
zero, and that finding 63 showed an Apple peer refuses to accept garbage in. Probing it one
byte at a time located a **four-byte field** inside it.

### The probe results

One byte set to `0x01`, the other seven left as Apple sends them. Outcome measure unchanged:
frames from a non-us sender naming our address as master, against controls of **146** and
**241**.

```
offset in block:   0     1     2     3   |   4     5     6     7
TLV offset:       28    29    30    31   |  32    33    34    35
                 REJ   REJ     ?   REJ   | ACC     ?     ?   ACC
                   0     0     -     0   |  86     -     -   172
                                    └──── boundary ────┘
```

**Bytes 31 and 32 are an adjacent reject/accept pair**, which places the boundary exactly
there. No inference, no curve fitting — two neighbouring bytes with opposite answers.

That gives:

| TLV bytes | what it is |
|---|---|
| **28..32** | a **`u32` the peer reads**. Non-zero values are refused |
| 32..36 | four bytes **proven ignored** |

A `u32` at 28 is the shape every other field in this tag already has — `master_counter`,
`distance`, `master_metric`, `self_metric`, `self_counter`.

Byte 30 was never probed. It sits between two rejected bytes and is assumed to belong to the
field, not measured.

### What this is, and what it is not

**It is a field whose existence and size are established and whose meaning is not.** Apple
sends zero, the corpus is all zero, and every value tried is refused. That is enough to say a
transmitter must send zero; it is not enough to name it. `unknown_28` keeps its honest name
rather than becoming `reserved`, which would assert precisely the thing this disproved.

### The method is the result

Every other decode in this file came from reading bytes off the air. This one came from
**asking a device questions and reading its behaviour**. Seven runs, each worth one bit,
against a pre-registered measure with a positive control.

`--garbage` was built to convert opaque bytes into free coverage. It turned out to be an
instrument for **finding fields**, which is worth more — and it works on any byte we can
choose, in any tag.

### Coverage, and an honest note on how it moved

Bytes 32..36 now count as named, on a basis that appears nowhere else in this project: not
that we know what they mean, but that a peer was **measured ignoring them**. The module's
test is whether we could choose a correct value without copying one, and for a proven-ignored
byte every value is correct. It is the weakest way to satisfy that test and it does satisfy
it.

Tag 24: **80.0% to 90.0%**, floor 32/40 to 36/40.

The four bytes at 28..32 stay opaque, and they are now the most interesting four bytes in the
tag: read by Apple, sized, located, unnamed.

### ★ Replicated on a second handset, and the peers preferred each other

`PROTOCOL.md` rule 6 asks for a different device set. A second iPhone was brought in,
`e6:a6:d9:00:90:34`, and both phones run together:

| run | flags | frames naming us master |
|---|---|---|
| X1 | control | **714** — `e6:a6` x520, `72:01` x194 |
| X2 | `--garbage t24` | **0** |

Taken minutes apart with the same two handsets, same room, garbage verified on the air.

The detail worth keeping is what the peers did *instead* in X2:

```
72:01:e2:fd:9d:57  ->  e6:a6:d9:00:90:34    833     iPhone 1 followed iPhone 2
e6:a6:d9:00:90:34  ->  (itself)             632     iPhone 2 claimed master
```

Two devices advertising metrics **514** and **525** formed a cluster with each other rather
than accept our **600**. They did not merely decline to follow us — they preferred a
materially worse master. A frame with that `u32` non-zero is not weighed and lost; it is not
counted at all.

Captures: `captures/t24-X1.pcap`, `captures/t24-X2.pcap`.

### What values it accepts — two tried, both refused

`0x80` at byte 28 was refused as well, with the strongest exposure of any probe: the peer sat
for 18 buckets, claimed master 3217 times, and showed `following 0`.

```
byte 28 = 0x01   REJECTED
byte 28 = 0x80   REJECTED     bit 0 and bit 7, as different as two bytes get
```

**That is support for "must be zero", not proof of it.** Two values out of 256, and the
informative outcome would be a value that *passes* — which there is no way to guess at. The
honest statement is: every value tried is refused, and a transmitter must send zero.

Testing more values has poor returns. **The method is better spent elsewhere**: it found a
field in tag 24, and the same probe works on any byte we can choose. Tag 12's unidentified
`u32` at the end of its extended block, tag 7's two leading bytes, and tags 32/33's
low-cardinality unknowns are all candidates, and each one that turns out to be *read* is
another field located.

## 66. Tag 7's leading bytes — INCONCLUSIVE, and recorded as such

`--garbage t7` sets tag 7's two leading bytes, `00 00` in every frame ever captured and the
only part of HT Capabilities that IEEE 802.11-2020 does not account for (finding 48). Two
runs:

| run | frames naming us master | peer exposure |
|---|---|---|
| W1 | 24 | 2 buckets |
| W2 | **2** | 4 buckets, intermittent |
| *controls* | *146, 241* | *good* |

W1 cleared the pre-registered threshold of 20 — just. W2 did not. **The result does not
replicate and no conclusion is drawn.**

### Why this is not "they are read"

Tag 24's treatments gave **0, 0, 0, 0**, including one run with 18 buckets of exposure and
3217 peer master-frames. Tag 7's gave 24 and 2. Those are different shapes: a clean zero
under good exposure, versus two small numbers under poor exposure. Reading the second as a
refusal would be reading noise.

### Why it is not "they are ignored" either

Both numbers sit far below the controls, and 2 is below threshold. The honest position is
that **neither run had enough peer exposure to measure anything**, and the obvious next step
is a run where the peer stays for several minutes.

Worth noting what did not work: the operator disabled screen lock and set AirDrop to Everyone
expecting ten minutes of presence, and the peer still appeared only in buckets 5-6 and 22-23.
**Screen-lock state does not keep an iPhone's AWDL on the air** — add that to finding 61's
taxonomy.

### The discipline

The temptation was to take W1's 24, call tag 7 ignored, and bank another 74,478 bytes. Rule 6
exists for exactly this, finding 44 died of exactly this, and the 14-frame anomaly in finding
57 was exactly this. Two runs disagreeing is not a result, whichever one is more convenient.

## 67. ★★ Tag 24 is MANDATORY — a malformed one is treated exactly as an absent one

Finding 65 left a puzzle the operator put plainly: *why would they choose a worse master than
us?* In X2 two iPhones advertising metrics **514** and **525** formed a cluster with each
other rather than take our **600**.

It is strange because every frame we send also carries **tag 5**, Election Parameters v1,
claiming that same 600. If tag 24 were merely discarded, tag 5 should still have entered us
into the election.

### The experiment

Send **no tag 24 at all** and claim 600 through tag 5 alone. Everything else byte-identical —
asserted in the test, not assumed.

```
valid tag 24       ->  adopted    714 frames (X1, two peers)
malformed tag 24   ->  refused      0        (X2, K5, K4, and the byte probes)
NO tag 24          ->  refused      0        (Y1)
```

Confirmed on the air: 2084 tag-4s in the capture, our 1199 frames and the peers' 885, and tag
24 appears exactly 885 times — none of them ours.

### What it establishes

**A node without a valid Election Parameters v2 is not a candidate.** Not a weak one — not
one at all. That is why the peers preferred a materially worse master: from their side there
was no third option.

**A malformed tag 24 is equivalent to an absent tag 24.** The two treatments are
indistinguishable in outcome, which collapses the three mechanisms finding 65 left open. It
does not matter whether the receiver drops the TLV, drops the frame, or misparses a
discriminator: whatever it does, the result is that we are not counted.

**Tag 5 is vestigial for election purposes.** Apple sends it, `libmosey` sends it, OWL sends
it, and on an iOS v10.0 device it does not get you elected on its own. Anything implementing
AWDL must send a well-formed tag 24, and the `u32` at offset 28 must be zero.

### Caveats, stated rather than buried

One run. Peer exposure was 4-5 buckets, shorter than X1's control — though finding 63's K8b
produced 138 frames of adoption from about two buckets, so short exposure does not by itself
produce a zero. Worth one replication before it is leaned on hard.

And it is one device family: two iPhones on iOS v10.0. A Mac or an older device may differ,
and the corpus cannot say because **every device in it sends tag 24** — which is precisely
why this needed a transmitter to find out.

## 68. Tag 6 is optional for election — and its structure only partly yields

### Tag 6 is not required to be elected

`libawdl` sends **no tag 6 at all** — `state_tlvs` is documented as "the measured PSF set
minus tag 6, which we cannot fill". And peers have adopted us **146, 241 and 714** times
across the day.

So Service Parameters is **optional for the election**, which is the exact opposite of tag 24
(finding 67, where a missing or malformed one disqualifies you entirely). Two tags, both
carried by every Apple device, and only one of them is load-bearing for mastership.

**This also means the `--garbage` probe cannot test tag 6.** The instrument measures
adoption, and adoption does not consult this tag. Answering "does a wrong tag 6 matter"
requires a *discovery* measure — does the peer list us in AirDrop, does it query us over mDNS
— which is a different experiment from the one built today. A plan to probe it was proposed
and withdrawn for exactly this reason.

### What the corpus does say about its structure

```
len  9:  00 00 00 | 58 01 | 00 00 | 00 00 00 00
len 13:  00 00 00 | ab 00 | 20 00 | 18 80 20 40 02 10
len 15:  00 00 00 | ae 00 | 30 00 | 18 88 01 20 40 02 02 10
```

**The u16 at offset 3 is the `sui` — Service Update Indicator.** OWL names it in
`awdl_service_params_tlv` and this repository's own `state.rs` already recorded that split;
the analysis below arrived at the same field from behaviour alone, which is corroboration
rather than discovery. It should have been read before it was rediscovered.

It is **non-decreasing in 100% of 46,491 transitions**, and constant within
a capture for nearly every sender — `02:3b:e8` holds 11801 across 267 frames, `22:dd:ca`
holds 1180 across 985, OWL sends 0. It moves rarely (11845 to 11849 in one capture). That is
the profile of a **generation counter for the advertised service set**: it changes when the
services change, not per frame.

**The u16 at offset 5 is not a length or a popcount.** `0x0030` maps to tails of both 6 and 8
bytes and `0x0000` to tails of 2, 3 and 4. Tail length tracks popcount for 0, 1 and 3 set
bits and breaks at 2, 4 and 5.

A Bloom-filter reading — `[3 reserved][u32 bitmask][one byte per set bit]` — was tested
against the whole corpus and **refuted**: 5,438 hits against 41,159 misses, with the
values-minus-popcount difference spread across -9 to +3. It is not that shape.

### Where that leaves it

Finding 25's assessment mostly stands: the three leading bytes are unnamed, the bitmask after
the `sui` is a hash we cannot compute, and none of it matters for anything we currently do.

The `sui` is now **named in coverage** — 2 bytes of every tag 6, taking it from **0% to
16.1%** and the control plane to **89.9%**. That is on firmer ground than the proven-ignored
bytes elsewhere: OWL names the field, the corpus confirms its behaviour across 46,491
transitions, and OWL sends 0 for it, so a value we can choose is demonstrated rather than
assumed.

## 69. ★ Tag 12's unidentified u32 is ignored — and we had to build a block to ask

Finding 49 decoded tag 12's extended block and identified three of its four 32-bit values:
a relayed `master_counter`, a millisecond clock, and an Availability Window counter. The
fourth resisted — it advances between 1.0 and 3.2 per counter tick, which is neither a clock
nor a tick counter.

**The receiver does not read it.**

### The obstacle, and what it cost to get past

`libawdl` sends a **13-byte tag 12 with no extended block at all** — and is elected master
regardless. So there was nothing to perturb. Asking the question required teaching the beacon
to emit a block it had never needed, which is the first time an experiment here has required
*adding* capability rather than corrupting what we already sent.

`extended_flags` is the value we cannot derive. Apple sends `0x117d | (k << 10)`, device
stable, which looks like a capability word. **OWL and `libmosey` send `0x0000`**, so zero is
a value a real implementation uses — and that made it the honest default rather than copying
Apple's bits and hoping. The control proved the choice sound.

### The pair

Same two iPhones, same room, minutes apart, block otherwise byte-identical:

| run | last u32 | frames naming us master |
|---|---|---|
| E1 | `00 00 00 00` | **918** — `72:01` x740, `e6:a6` x178 |
| E2 | `a5 a5 a5 a5` | **574** — `72:01` x445, `e6:a6` x129 |

Both adopt, both far above the threshold of 20. Our own frames read back off the air confirm
the garbage in E2 and its absence in E1.

E1's 918 is the highest adoption count of the entire session, and E2 is lower — but a single
pair says nothing about magnitude, and both are unambiguous adoptions. The claim is binary
and that is all it is: **the value of that u32 does not affect whether a peer elects us.**

### What it buys

Four bytes of every 47-byte tag 12, **165,208 opaque bytes**. Tag 12 goes from 77.6% to
**84.9%**, floor 35/47 to 39/47, and the control plane from 89.9% to **90.9%**.

Named on the by-now familiar weakest basis: not that we know what it means, but that a peer
was measured ignoring it. What remains opaque in tag 12 is the `extended_flags` word, the two
zero bytes beside it, and the UMI options blob.

### The contrast that makes this worth something

Tag 24's `u32` at offset 28 and tag 12's `u32` at the end of its extended block are both
four-byte values nobody has named, both zero in every Apple frame ever captured. One is read
and disqualifies you if wrong; the other is ignored entirely. **Nothing in any capture
distinguishes them** — they look identical on the air. Only a transmitter can tell them
apart, and that is the whole argument for having built one.

## 70. ★★ The adoption counter starves exactly when the room gets interesting

This is an instrument defect, and it is recorded first because every finding in the E-series
is read off that instrument.

Run E3b's beacon reported **`adopted by 1 peer(s), 14 frame(s)`**. The packet capture of the
same run, same seconds, held **2,123 frames from three peers** naming us master. Two orders
of magnitude, and in the direction that reads as *the peers ignored us* — which would have
inverted the finding it was measuring.

### Why the earlier runs looked trustworthy

E1 and E2 agreed with their own captures to within one frame (918 vs 918, 574 vs 574). That
agreement was luck, not correctness:

In E1 and E2 **every peer named us master.** `Cluster::observe` counts such a frame and
returns early, deliberately, so `self.master` is never set, the cluster clock never becomes
usable, and `adopted` stays false. The listener's drain budget is computed as:

```rust
let slack_us = match cluster.us_until_master_window(now_us) {
    Some(w) if adopted => w,
    _                  => b.us_until_next_advertised_window(now_us),
};
let max_drain = if slack_us < 4_000 { 0 } else { 32 };   // the bug
```

With `adopted == false` the slack is measured against **our own** advertised windows, which
are sparse (slots 2, 8, 10 of 16), so the branch was almost never taken and the drain was
generous.

E3b had a **competing cluster** — `e6:a6` at metric 538, followed by `72:01` for 1,892
frames. We adopted its clock, `slack_us` began measuring time to *that* master's window, and
a master with frequent slots holds it under 4 ms nearly always. `max_drain` went to zero and
stayed there. Zero does not mean "read one frame and move on"; it means **do not attempt a
read at all**.

So the counter is reliable when we are unopposed and blind when we are not — the precise
inverse of when the measurement matters.

### The fix

`max_drain` is 4 rather than 0 when a window is imminent, with `budget_ms` still 0. `rx(0)`
is `MSG_DONTWAIT` (finding 60), so a queued frame costs microseconds and an empty queue
returns immediately and breaks. Transmission timing is unaffected.

### The rule this leaves behind

**The capture is the measurement; the beacon's own counter is a convenience.** A passive
`tcpdump` on a second interface has no transmit duty to trade against, and it was right in
all three runs. Where the two disagree, the capture wins — and a disagreement is itself a
signal worth chasing, because it took a real defect to produce one.

---

## 71. ★★ Tag 12's extended flags word is ignored too — the block is now fully ours

Finding 69 proved the last of tag 12's four 32-bit values is not read. The two fields left
opaque were the `extended_flags` word and the two always-zero bytes beside it — four bytes at
the head of the extended block.

**Neither is read.**

### The probe

`--garbage ext12-head` fills offsets 13–16 of the tag 12 value with `0xa5`, leaving the three
identified counters intact. Read back off the air from our own frames, so the encoder is
confirmed rather than assumed:

```
04 83 51 41 00 95 00 00 c0 ca b0 60 4c a5 a5 a5 a5 00 87 01 00 14 ae 04 00 20 49 00 00 ...
                                        ^^^^^^^^^^^ extended_flags + the zero pair
                                                    ^^^^^^^^^^^ master_counter, intact
```

### The series

Same metric, same room, tag 24 master address tallied from the capture in every row:

| run | tag 12 bytes 13–16 | frames naming us master | peers |
|---|---|---|---|
| E1 control | correct (`0x0000` + zeros) | 918 | 2 |
| E2 | last u32 garbage | 574 | 2 |
| **E3b** | **`extended_flags` + pad garbage** | **2,123** | **3** |

E3b is the highest adoption of the whole series, with a third peer joining. The claim stays
binary — magnitude across runs reflects exposure and who was awake, not field quality — but
the decision rule established by the tag 24 bisection is unambiguous: a field that is *read*
produces an exact **zero** (finding 65's rejects, finding 67's absent tag 24), never
thousands.

### A voided run, recorded because voiding it was the right call

E3 ran first and produced only our own 1,199 frames — no peer arrived at all. The garbage was
confirmed on air, so it was tempting to read the zero as a rejection. It is not a rejection;
it is an empty room, and it is indistinguishable from one only if you do not check who else
transmitted. E3b reopened the question into a room verified to contain peers.

### What it buys

**206,806 opaque bytes.** Tag 12 goes from 84.8% to **92.8%**, floor 39/47 to **43/47**, and
the control plane from 90.9% to **92.1%**.

`extended_flags` is still not *understood* — we could not say what bit 3 means, and Apple's
`0x117d | (k << 10)` is device-stable in a way that looks like a capability word. But finding
47's standard is whether we can choose a correct value without copying one, and a field the
receiver demonstrably does not read can be filled by construction. OWL and `libmosey` both
send `0x0000`, which was already the honest default; now it is a measured one.

**Tag 12's extended block is fully accounted for.** What remains opaque in tag 12 is only the
UMI options blob.

### The score after a day of asking

Of every reserved or unnamed field we could reach and perturb — tag 4's `reserved_28` and its
trailing pair, tag 5 in its entirety, tag 16, tag 24's bytes 32–35, tag 12's trailing u32,
and now tag 12's `extended_flags` and pad — **exactly one is actually read**: the u32 at tag
24 offset 28 (finding 65). Everything else is decoration that a receiver never consults.

That specificity is what makes it a finding rather than a guess about how strict Apple is.
The interesting part is that nothing in any capture distinguishes the one from the others:
all of them are zero in every Apple frame ever recorded. Only a transmitter can tell them
apart.

---

## 72. The settled-cluster confound, caught by a control rather than by reasoning

**Status: the Z-series is INCOMPLETE.** One cell of four is unmeasured and the finding it
would produce is not claimed here. What *is* established is the trap, and it is worth more
than the cell was.

### The question

Tag 24's `unknown_28` is the only field a receiver was ever caught reading (finding 65).
Two points on its curve are known: zero is accepted, `0xa5a5a5a5` is refused. Nothing in
between. `--garbage t24@0=01` sets it to **1** — the smallest possible non-zero. If 1 is
refused the field is validated as zero; if accepted, the refusals were about magnitude and
it bisects into a counter or a version.

### What happened

The first treatment run came back a clean REFUSE. Every validity check passed: 419 frames
sent, synchronised at 15,966 us spread, two peers present, the perturbation confirmed on
air. It would have been entirely reasonable to write it up.

The timeline said `72:01 MMM` / `e6:a6 fff` — **the peers were already a settled cluster
before the run started.** So a control was run into the same settled room, minutes later,
changing nothing at all:

| run | room | byte 28 | frames naming us master |
|---|---|---|---|
| Z1b | settled, no entry | `1` | 0 |
| Z0ctl | settled, no entry | **`0` — correct** | **0** |
| Z0d | **peer entered** | `0` — correct | **1,265** |
| Z1d/e/f | no entry, then empty | `1` | *void* |

**The control refused just as completely as the treatment.** A settled cluster does not
re-elect whatever you advertise — it is in this repository's own spec, it cost eight runs to
establish the first time, and it was still nearly enough to manufacture a finding from a
room that would have refused anything.

Z0d is the same room with the operator toggling AirDrop off and back on inside the capture:
1,265 frames from both peers. The procedure works, the transmitter is fine, and the only
difference is whether a peer had an occasion to elect anyone.

### The check that was missing, and the check that was wrong

Rule 10 already said to establish the condition during the capture. Nothing enforced it, so
three consecutive treatment runs voided on it while being read by eye.

`compete-trial.sh` now counts entry events and VOIDs at zero. The first implementation
tested whether a peer's timeline *starts* with dots — and scored the good control as 0,
because the commonest entry shape is `MMM...fff`: present, gone, returned. The test is a
dot with presence somewhere after it, anywhere in the line. Validated against the runs
above: Z0d scores 2, the three voids score 0.

### Why this is the more useful half

A REFUSE is only evidence if a peer in the same room would have said yes to a correct
frame. Every `--garbage` result in findings 63-71 rests on that, and most of them were run
when peers were arriving anyway — which is luck, not design. The E-series controls were run
because the *manipulation* needed a control, not because the room did.

**Pair every election probe with a same-room control, and require an entry event in both.**
Not "check the room looks busy": two peers transmitting steadily is exactly what a settled
cluster looks like, and it refuses everything.

---

## 73. ★★★ Tag 24's read `u32` is validated as EXACTLY zero — one is refused as hard as garbage

Finding 65 found the one field in this protocol that a receiver checks: the `u32` at tag 24
offset 28. It established that zero is accepted and `0xa5a5a5a5` is refused, which leaves
the obvious question — is the check *"must be zero"*, or is it a range, a version, a counter
whose plausible values happen to start at zero?

**It is "must be zero".** The smallest possible non-zero value, `1`, is refused exactly as
completely as garbage.

### The design

`--garbage t24@0=01` sets byte 28 to `0x01`, making the `u32` equal to 1 and leaving every
other byte of the frame untouched. Paired against a control identical in all respects, run
into the same room, with the same two iPhones, minutes apart.

**Every run required a peer to ENTER during the capture** — see finding 72, which is the
reason this took nine runs to get four usable cells. A settled cluster refuses correct
frames as readily as garbage, and three treatment runs voided on it before the harness was
taught to check.

| run | order | byte 28 | peers entered | frames naming us master |
|---|---|---|---|---|
| Z0d | control first | `0` | 2 | **1,265** |
| Z1g | treatment second | `1` | 2 | **0** |
| Z1h | **treatment first** | `1` | 2 | **0** |
| Z0k | **control second** | `0` | 2 | **688** |

A complete 2x2: both arms replicated, and the order counterbalanced across the two pairs
(rule 4), which matters because the room changes over an evening. Every cell had two peers
enter during its own capture, and every cell had its byte 28 read back off the air.

Two controls adopt, at 1,265 and 688 frames. Two treatments refuse, at 0 and 0. There is no
overlap and nothing marginal about it.

### What the peers did instead

This is the part that makes it a decision rather than a failure to hear us. In both
treatment runs the two iPhones arrived, saw us advertising metric **600** — far above the
510–541 Apple devices advertise — and **elected each other**: `72:01` followed `e6:a6` for
2,458 frames in one run and 2,319 in the other. They were awake, they were listening, they
had a candidate claiming the highest metric on the air, and they picked the weaker peer.

In the control, the same two devices entering the same room followed *us*, 1,265 frames.

### What is NOT established

- **One device pair.** Rule 6 asks for a different device set and this has not had one. The
  two iPhones here are the same pair that produced findings 63 through 71, so a systematic
  quirk of these two handsets would not have shown up in any of it.
- **Nine runs produced four cells.** Five voided — three because no peer entered the
  capture, two because the phones never came back on the air. The voids are recorded in
  finding 72 and none of them was scored.
- **Only two non-zero values have ever been tried** — `1` and `0xa5`-filled. They span three
  orders of magnitude and both fail, but 2 of 2^32 is not a proof that the accepted set is
  exactly {0}.

### Why this stays OPAQUE in the coverage metric

It is tempting to call the field named: we know what to send, we measured it, and we can
fill it by construction without copying anything. That is the same standard that promoted
tag 12's `extended_flags` (finding 71).

**The asymmetry is real and worth keeping.** An *ignored* field cannot hurt us in any
context, so choosing zero is safe forever. This field is *read*, and we know exactly one
accepted value out of four billion, with no idea of the rule that makes it acceptable. If
some state we have not entered requires a different value, an ignored field would shrug and
this one would cost us the election silently. Counting it as understood would assert the
thing we just failed to learn.

So the number stays honest: tag 24 remains 36/40, and this is the single largest opaque
region in the control plane that a transmitter can reach — 313,660 bytes.

### The shape of the whole result

Of every reserved or unnamed field a transmitter can reach and perturb, exactly one is read,
and that one demands a specific value. Everything else — tag 4's `reserved_28` and trailing
pair, tag 5 entirely, tag 16's flags byte, tag 12's extended block, tag 24's own bytes
32..36 — is decoration. All of them are zero in every Apple frame ever captured. **Nothing
distinguishes the strict one from the ignored ones by listening.** That is the argument for
having built a transmitter, stated as compactly as it can be.

---

## 74. ★★ Tag 24's zero requirement is NOT version-gated — and v10.0 does not break election

The operator asked whether a version number could be why we are not selected. It is the best
hypothesis anyone had for finding 73, and it is wrong — which is worth more than another
confirmation would have been, because it was the explanation that made the most sense.

### Why it was a good question

We announce **v3.4** in tag 21. Every Apple device announces **v10.0**:

```
us            34 02     AWDL 3.4, device class 2
both iPhones  a0 02     AWDL 10.0, device class 2
```

Six major versions, inherited from `libmosey` and OWL, which both send the same number.
**Every probe in findings 63 through 73 was run by a node claiming v3.4**, so every
"the peer ignores this field" could have meant "the peer ignores this field *from an ancient
node*". And it fit finding 73 exactly: a field that is required-zero from an old peer and
carries meaning from a current one is an ordinary way for a protocol to grow, and it would
explain why that one field out of every reserved region we probed is the only one read.

### The 2x2

Same room, same two iPhones, every cell with a verified entry event and both treatments read
back off the air:

| | byte 28 = `0` | byte 28 = `1` |
|---|---|---|
| **v3.4** | ADOPT — 1,265 and 688 | REFUSE — 0 and 0 |
| **v10.0** | **ADOPT — 1,317** | **REFUSE — 0** |

**The requirement is version-independent.** Announcing v10.0 does not unlock the field; the
same single byte refuses us just as completely.

### Two things this buys beyond the negative

**Announcing v10.0 does not break election.** 1,317 adoptions, the best figure of the
session, against 1,265 and 688 for v3.4. GAPS section 1 has warned since it was written that
raising the version is a capability claim rather than a cosmetic change — that warning stands
for everything above the link layer, but for *election specifically* it now has a measurement:
nothing got worse. `--version 10.0` exists and the beacon prints what it announces.

**The garbage series is not confounded by version.** That mattered for far more than this
finding. Findings 63, 69 and 71 all concluded "the peer ignores this" from a v3.4 node, and
if strictness were version-conditional, every one of them would have needed re-running under
v10.0 before it could be trusted. One cell of this 2x2 — v10.0 adopting normally with clean
fields — is the evidence that the peer's treatment of us does not change with the number we
announce.

### What is still unexplained

Why that `u32` is checked at all. It is zero in every Apple frame ever captured, it is
adjacent to four bytes that are provably ignored, and no value we have tried except zero is
accepted. It is not a version gate, not a range, and not padding. The honest state is that we
know exactly what to send and have no idea why.

---

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
