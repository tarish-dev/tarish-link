# What Apple sends, what libmosey sends, what OWL sends

*The specification for `libawdl`'s transmitter, derived from captures rather than from a
paper.*

Regenerate any row with `awdl profile <capture>`; this document is assembled from that
command's output, so adding captures improves it rather than dating it.

**Sources.** Apple: `assoc-connected.pcap` (an iPhone on a 5 GHz AP and a Mac on 6 GHz).
`libmosey`: `blazer-mix.pcap`, a Pixel 10 Pro running our own stack. OWL:
`owl-transmitting.pcap`, seemoo-lab OWL on a Pi with an ALFA.

---

## The table

| | **Apple** | **libmosey** | **OWL** |
|---|---|---|---|
| tags emitted | **11–13** | 10 | 9 |
| **2** Service Response | yes, 1–3 services | yes, `_airdrop` only | **NONE** |
| **4** Sync Parameters | yes | yes | yes |
| **5** Election | yes | yes | yes |
| **6** Service Parameters | yes | yes | yes |
| **7** HT Capabilities | yes | yes | yes |
| **12** Data Path State | yes, **AP channel populated** | yes, **no association** | yes |
| **16** Arpa (host name) | yes, `<uuid>.local` | **MISSING** | yes, `raspberrypi.local` |
| **17** 802.11 Container | yes | yes | **MISSING** |
| **18** Channel Sequence | yes | yes | yes |
| **21** Version | **v10.0** | **v3.4** | **v3.4** |
| **24** Election v2 | yes | yes | yes |
| **32/33** 6 GHz | yes *when on 6 GHz* | **MISSING** | **MISSING** |
| availability window | 16 TU | 16 TU | 16 TU |
| channel sequence | **3–6 of 16**, multi-channel | **16/16, one channel** | **16/16, one channel** |
| — slot 0 | the AP's channel | not reserved | not reserved |
| — slot 8 | channel 6, always | absent | absent |
| self metric | **510 – 537** | **1** | 60 |
| self counter | moving (4→32, 68866→68867) | **0, never moves** | **0, never moves** |
| PSF : MIF | ~0 : 1 | 0 : 1 | **524 : 900** |

---

## How much of this do we actually understand?

**78% of the control-plane bytes, and the other 22% we copy.** Run `awdl coverage
captures/*.pcap` to regenerate this; it is measured, not estimated. It was 63% before the
decoding pass recorded in findings 21-25.

Two claims get conflated and only one of them is strong:

- *"We can reproduce any frame byte for byte."* True. Every tag with a parser carries its
  unknown fields raw and puts them back unchanged, and `tests/build_*.rs` pin that against
  real captures.
- *"We understand the protocol."* **Not true, and the first claim is no evidence for it.**
  A field carried raw round-trips perfectly while telling us nothing.

The difference is exactly what a transmitter runs into. Echoing a frame needs only the
first. *Composing* one needs the second, because every byte we cannot name is a byte we
have to invent — and the tempting way to invent it is to copy whatever Apple sent, which
is cargo-culting with no signal when it is wrong.

| tag | | named | note |
|---|---|---|---|
| 2 | Service Response | 100% | it is DNS, and a documented encoding |
| 17 | 802.11 Container | 100% | a standard VHT Capabilities element — finding 23 |
| 18 | Channel Sequence | 100% | |
| 21 | Version | 100% | |
| 16 | Arpa | 97% | the flags byte is not named |
| 4 | Synchronization Parameters | 93% | the flags word, byte 28, the trailing pair — finding 21 |
| 5 | Election Parameters | 86% | |
| 24 | Election Parameters v2 | 80% | only the 8 reserved bytes at offset 28 — findings 22, 26 |
| 12 | Data Path State | 50% | the extended block and UMI options are opaque |
| 7 | HT Capabilities | 43% | 802.11 fields named, the variable tail is not — finding 24 |
| 33 | 6 GHz channels | 24% | |
| 32 | 6 GHz info | 15% | |
| 6 | Service Parameters | **0%** | shape known, contents are a hash — and **it does not matter**, finding 25 |
| 35 | *unrecognised* | **0%** | not in any published table, 2 bytes, `01 01` |

Counting Service Response flatters the figure to 86.9%: it is 40% of all bytes on the air
and it is the one thing that was already specified elsewhere. The number that matters for
building a transmitter is the 78%.

### "Are you sure of them in every frame?"

A separate question, and the lengths column answers it. Some tags have one shape in all
18157 frames and some do not:

- **Invariant** — 4 (73 bytes), 5 (21), 17 (14), 18 (41), 21 (2), 24 (40). One shape each,
  every frame, every vendor. These are fixed structs and can be treated as such.
- **Variable** — 12 (15 or 47, by whether the device is associated), 16 (15 or 40),
  32 (13), 33 (14), 2 (35 distinct lengths, which is expected of DNS records).
- **Not a struct at all** — **tag 6 appears in eight different lengths** (9, 10, 11, 13 and
  four more) and **tag 7 in three** (8, 9, 20). Whatever these are, they are not a fixed
  layout, and the published names for them describe nothing we have confirmed.

### What that means for sequencing

The transmitter is not blocked on the remaining 37% — a frame carrying tags 4, 5, 18, 21,
24, 12, 16, 17 and 2 has the shape of a real one, and the fastest way to learn whether the
opaque bytes matter is to send a frame without them and watch a real peer. But it should be
done knowing that is the experiment being run, rather than in the belief that the protocol
is decoded. It is not.

## The gaps that matter, in order

### 1. Version: everyone but Apple announces v3.4 — and this is NOT a cheap change

Apple devices announce **v10.0**. Both `libmosey` and OWL announce **v3.4** — the same
number, which suggests a shared lineage or a value nobody revisited. Six major versions of
drift, and any version-gated behaviour on the Apple side sees us as ancient.

An earlier version of this document called announcing v10.0 "the cheapest single change on
the list". **That was wrong.** A version number is a capability claim: announce v10.0 and
Apple may expect behaviour we do not implement, trading a known limitation for an unknown
failure. It is one field to change and a large surface to be judged against.

> **An open question this raises.** Recent iOS shows a matching code before an AirDrop to a
> non-contact, once per device pair, and only ever between two Apple devices — never for
> Tarish and never for stock Quick Share. The operator notes it did not exist years ago, and
> asks whether the version is the gate: a new flow offered to peers announcing something
> recent, with older peers left on the legacy path.
>
> **Plausible, and untested.** A competing explanation is that the code bootstraps
> *persistent* trust, which needs a durable identity to bind to — Apple devices carry an
> Apple-signed validation record and we structurally cannot. That fits the layering better:
> the code lives in the TLS `/Ask` exchange while tag 21 is a Wi-Fi link-layer field, and
> gating an application-layer trust decision on a link-layer version would be unusual.
>
> The synthesis may be both: a version gate, but on an **AirDrop-layer** version in the
> plists rather than on tag 21.
>
> **ANSWERED, 2026-09-12 — it is the trust bootstrap, not the version.** An iPhone that
> could not see a MacBook at all was sent a file *from* that Mac; the transfer required a
> PIN; and afterwards the iPhone could discover the Mac. Discovery was the effect of the
> code, not its precondition. See FINDINGS 33.
>
> This inverts the recommendation below. Announcing v10.0 is still worth doing on its own
> merits, but it is **no longer the decisive test** — and if run as one it would come back
> negative for a reason unrelated to the version. The thing standing between us and this
> flow is that we have no durable identity for a peer to remember: our mDNS instance name
> follows a rotating MAC and our TLS certificate is regenerated at every start. That was
> recorded as a deliberate decision; it is now a decision with a known cost.
>
> Stock Quick Share does not separate the hypotheses — Google announces v3.4 *and* holds no
> Apple validation record, so either would explain its exclusion. What it does show is that
> a full, well-resourced implementation on the same AWDL version has not cleared the gate
> either.
>
> **The model string is not the gate — tested on hardware, 2026-09-11.** `sharingd` grew a
> `persist.tarish.model` override so the claim could be changed without a rebuild, and blazer
> advertised `MacBookPro18,3` as `ReceiverModelName` in both `/Discover` and `/Ask` — the two
> places a sender reads the receiver's identity before it decides what to prompt. An iPhone
> sent a video to it and the transfer ran normally: no code, nothing different from any
> earlier run.
>
> The treatment really was applied, which is worth stating because a negative result is only
> as good as the proof that the independent variable moved. The daemon was restarted *after*
> the property was set and reads it once at thread start; `persist.tarish.model` is absent
> from `property_contexts` and so carries the default label; `tarishsharingd` is permitted to
> read that label — `security_compute_av` via `/sys/fs/selinux/access` returns
> `allowed=0x40412`, exactly `read|getattr|map|open`, against `allowed=0` for a control pair
> that should be denied — and no AVC denial fired at startup.
>
> What this refutes is the **model string alone**. It cannot refute the model as one term in
> a conjunction: a device claiming to be a MacBook while carrying no Apple-signed identity
> may fail an earlier check and never reach a model comparison at all. It also only moves the
> *receiver's* claim, which is the right direction — the code appears on the sender, about the
> receiver — but says nothing about what a sender announcing a Mac model would see.
>
> So two hypotheses remain, and they are the two that were always harder: an AirDrop-layer
> version, or the Apple-signed identity.
>
> **The decisive test needs `libawdl` transmitting**, since only then do we control tag 21.
> Announce v10.0, otherwise unchanged, and see whether the flow changes. That is a good
> reason to build the transmitter, and a reason not to change the version casually before
> then.

### 2. The channel sequence is the big one

Apple occupies **3 to 6 of 16 slots** and spreads them:

```
slot   0    1    2    3  4  5  6  7  8   9   10   11 12 13 14 15
chan  104   0   149   0  0  0  0  0  6   0   149   0  0  0  0  0
       ^                              ^
       the AP's channel               the cross-band rendezvous
```

Both `libmosey` and OWL emit **16/16 on a single channel**. Three consequences, all measured:

- **No association slot**, so AWDL takes the whole radio and Wi-Fi dies on a chip that
  cannot hold two channels — the BCM4383 behaviour recorded as a hardware limit in
  BUILD-NOTES 40/42. Apple runs the same constraint and schedules around it.
- **No channel-6 rendezvous**, so a device on 2.4 GHz and one on 5 GHz never meet. Every
  Apple device keeps slot 8 on channel 6, in 556 of 556 sequences observed.
- **Permanently on-channel**, which is maximal availability and maximal power draw. Apple
  is absent 10–13 slots of 16.

**This cannot be fixed at the integration layer** — finding 8 measured `libmosey` refusing
to build a multi-channel sequence even when handed two bands. It is the single strongest
reason `libawdl` has to exist.

### 3. Election: we forfeit by advertising nothing

Apple advertises metric **510–537** and a **moving** counter. `libmosey` advertises metric
**1** and counter **0**, unchanged across every frame in every capture; OWL advertises 60
and 0.

Elections are decided on **metric**, not counter (finding 9 — a device with counter 68364
yielded to one with 608 and a higher metric). So a metric of 1 means never winning, which
for a phone may be the right posture — but it should be a decision. Counter 0 against a
peer's moving value is a field nobody maintains.

### 4. What OWL is missing that `libmosey` gets right

- **Service Response (tag 2).** OWL emits **zero**. A peer can synchronise with it
  perfectly and still find nothing to talk to. `libmosey` emits `_airdrop._tcp.local`.
- **802.11 Container (tag 17).** Absent from OWL, present in both others.
- **PSF ratio.** OWL sends 524 PSF to 900 MIF. Apple and `libmosey` send almost none —
  9 PSF in 278 frames in one capture, zero in others. OWL is far noisier than the devices
  it imitates.

### 5. What `libmosey` is missing that OWL gets right

- **Arpa (tag 16)** — the host name. OWL sends `raspberrypi.local`; Apple sends
  `<uuid>.local`; `libmosey` sends nothing. This is where a human-readable device name
  would come from.

### 6. The 6 GHz tags track the association

The Mac in `assoc-connected.pcap` is associated on **6 GHz channel 53** and emits tags
**32 and 33** carrying exactly that. The iPhone in the same capture is on 5 GHz channel 104,
puts 104 in slot 0, and emits **neither** tag.

So 32/33 are how a 6 GHz association is advertised, because the channel sequence's operating
classes cover only 2.4 and 5 GHz. Neither `libmosey` nor OWL emits them at all.

---

## Therefore, for `libawdl`

Ordered by how much each buys:

1. **Build a real schedule.** ✅ `ChannelSequence::apple_shaped`, with
   `SyncParams::encode` to put it on the wire — both pinned by byte equality against
   captured Apple and `libmosey` frames in `tests/build_sync.rs`.

   The measured shape is **four occupied slots out of sixteen**: slot 0 for the
   association, slots 2 and 10 on the regional social channel, slot 8 on channel 6, and
   absent for the other twelve. An earlier version of this line said "the rest on the
   regional social channel", which is not what Apple does and is worth being exact about:
   filling the spare twelve slots keeps the radio on the air three times longer per cycle
   for no gain, because peers schedule against the slots they were told about. `libmosey`
   does fill all sixteen — `LIBMOSEY` in `tests/fixture_sync.rs` is that frame.

   This is the one that fixes AWDL/Wi-Fi coexistence and cross-band discovery, and no
   configuration of `libmosey` can do it.
2. **Decide on the version deliberately.** Announcing v10.0 is a capability claim, not a
   cosmetic field — see §1. It is also the only way to test whether the non-contact code
   flow is version-gated, so it is worth doing as an *experiment* with a way back.
3. **Emit Service Response** — ✅ `service::encode_records`.
4. **Emit Arpa** with a real host name — ✅ `Arpa::encode`, compression pointer and all.
5. **Advertise a credible metric and a counter that moves.** ✅ `ElectionParams::claiming`
   and `ElectionParamsV2::claiming`, both tags, as every real device sends them. The metric
   is the caller's to choose; the counter is passed in rather than invented, because its
   meaning is still unresolved and it is not the election's ordering term.
6. **Emit tag 17**, and 32/33 when associated on 6 GHz. ✅ for 17 —
   `Ieee80211Container`, which turned out to carry standard 802.11 elements rather than a
   format of AWDL's own: one VHT Capabilities element, 12 bytes. Its bits describe the
   radio, so they belong to the HAL and are carried opaquely. 32/33 not yet built.
7. **Send PSF sparingly** — match Apple's ratio, not OWL's.

Also done, and not on the original list because it was assumed rather than planned: **the
frame itself.** `action::encode_body` and `dot11::management_header` assemble a complete
action frame, pinned by taking a captured Apple frame apart and rebuilding it byte for byte.

### What is still missing to be a participant

- **Tags 6 (Service Parameters) and 7 (HT Capabilities)** — undecoded, not merely unbuilt.
  Tag 7 is 9 bytes from one device and 20 from another, so it is not a fixed struct, and
  emitting bytes we cannot describe would be guessing on the air.
  `tests/build_frame.rs` asserts the missing set is exactly `{6, 7, 32, 33}`, so it cannot
  grow unnoticed.
- **Tags 32/33** — conditional on a 6 GHz association, not unconditionally missing.
- **The transmitter.** Everything above builds bytes; nothing has yet put one in the air.
  That is `libawdl-hal`'s side, and it is the next real milestone — it is also what §1's
  version experiment needs.

Everything above is observable in `captures/`, and every claim in this document can be
re-derived with `awdl profile`.

## What this table does not cover

**Transmit correctness.** Emitting the right bytes and being *accepted* are different bars,
and nothing here has been on the air from `libawdl`. The table says what to send; only an
Apple device can say whether it worked.
