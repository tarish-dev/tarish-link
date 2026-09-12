# The hardware abstraction layer

*A contract between an AWDL implementation and the radio underneath it — written for
the person who owns the driver.*

---

## The problem, stated plainly

AirDrop-compatible sharing runs on Pixels and nowhere else. Not because the protocol is
exotic, but because two files ship only in Google's vendor image:

| | what it is |
|---|---|
| `libmosey_daemon_ffi.so` | closed userspace library. Speaks AWDL: election, synchronisation, peer tables, channel sequence |
| `wonder.ko` | kernel module. A **virtual** `mac80211` wiphy layered on `wondertap0`, a raw radiotap interface the Broadcom driver exposes |

Note the second row carefully, because it is usually misread: **`wonder.ko` is not the
chip driver.** `bcmdhd` is. `wonder.ko` is a shim that turns a FullMAC chip's raw tap
into something `mac80211` can drive. AWDL therefore does not require `wonder.ko` — it
requires monitor mode, injection, channel control and timing. We have run AWDL on a
Raspberry Pi with an ALFA AWUS036ACM and no Google code of any kind.

So the dependency is not on silicon. It is on **two pieces of software that only one
company ships.** Everything above the radio can be portable. This is where the line goes.

```text
   share sheet, transfers, AirDrop and Quick Share protocols     portable, ours
   AWDL protocol engine            <- replaces libmosey          portable, ours
  ─────────────────────────── THE HAL ───────────────────────────
   driver + firmware                                             vendor
```

## What a vendor must provide

Eight operations. This list is **not a wishlist** — it mirrors the vendor command set of
`wonder.ko`, recovered from the module's own symbols on a shipping device. Google shipped
a product on exactly this surface, which is the best available evidence both that it is
sufficient and that nothing larger is needed.

| Operation | Why AWDL needs it |
|---|---|
| `capabilities` | lets the stack pick a mode instead of failing |
| `set_regulatory` | decides which social channel is legal, and whether you may transmit at all |
| `set_channel` | immediate switch |
| `tx` with pinned rate | sync frames must have predictable air time |
| `rx` with **TSF per frame** | a frame without a timestamp is nearly useless for sync |
| `mac_address` | randomised, per AWDL |
| **`tsf`** | read the MAC counter the cluster is synchronised to |
| **`set_channel_schedule`** | execute a channel sequence anchored to TSF, in the MAC |

The last two are the ones that matter, and the ones mainline Linux does not have.

## Three tiers, and what each costs

`Caps::tier()` returns one of these before a line of protocol code runs.

### Tier 1 — `HwTimed` ★ target this

The radio reads out its MAC TSF and accepts a channel schedule anchored to it. Window
boundaries are met by the MAC, not the CPU. This is what Apple does and what `wonder.ko`
exposes.

**Result:** synchronisation that holds under CPU load, and interoperation with Apple
devices at full rate.

### Tier 2 — `SoftTimed`

Transmit and channel switching work; timing is done by the host. This is where OWL sits,
and where our reference `nl80211` backend sits.

**Result:** it works, and synchronisation is only as good as the scheduler. Degrades
under load, which is exactly when sharing tends to happen.

### Tier 3 — `Observer`

Receive and decode only. Cannot be discovered, cannot join a cluster. Useful for
analysis; not a product.

## The specific gaps in mainline Linux

Our `nl80211` backend reaches Tier 2 and cannot reach Tier 1. Two primitives are missing,
and both exist in `wonder.ko`:

```
wonder_vendor_cmd_get_mac_tsf                read the MAC TSF
wonder_vendor_cmd_set_channel_schedule_req   channel list + SWITCH_TIME / TSF_OFFSET
```

A vendor wanting Tier 1 exposes those two, by any mechanism — an `nl80211` vendor
command, a debugfs node, an ioctl. **The HAL does not care how.** It cares that the
numbers are the MAC's and not the host's.

> Substituting the host clock for the MAC TSF produces a number that looks plausible,
> drifts slowly, and fails only once a cluster will not hold — days after the mistake.
> `Radio::tsf` returns `Unsupported` rather than a host timestamp for this reason.

## Timing budget

AWDL's Availability Window is 16 TU = **16384 µs**. Sequences are 16 slots.

- **Channel switch latency** comes straight out of the budget. 5000 µs spends a third of
  a slot deaf. State it, and measure it rather than quoting it.
- **TSF precision** finer than a few hundred µs, or window boundaries stop meaning
  anything.
- **Active monitor mode is not optional.** Without link-layer ACKs the peer retransmits
  each frame up to seven times. That presents as a working-but-slow link, not a failure,
  and it is the single most misdiagnosed condition in this area.

## Things that will waste your week

Each of these was paid for on real hardware.

**The managed interface on the same phy must be down.** Otherwise `mt76` refuses to
transmit and refuses to change channel while reporting success: every injection returns
`EAGAIN`, `dmesg` says nothing, and `aireplay-ng -9` gets 30/30 on the same radio at the
same moment. Flipping the primary interface to `type monitor` instead of adding a
separate vif fails identically.

**A channel being listed does not mean you may transmit on it.** In regulatory domain
`country 00`, channels 44 and 149 are present and flagged no-IR. A capability probe that
checks presence will report a radio as capable and then fail in the field. Set the
regulatory domain *before* probing.

**The phy index is not stable.** An adapter enumerated as `phy2` came back as `phy1`
after a reboot. Hardcoding it fails with `No such device (-19)`, which reads like the
adapter is missing.

**rfkill soft-blocks every radio at boot** until a country is set, and `ip link set up`
then fails with `Operation not possible due to RF-kill`.

## The probe, run on real hardware

`cargo run --release --example probe -- <managed-iface> <monitor-iface>` asks a radio what
it can do. On a Raspberry Pi 400 with an ALFA AWUS036ACM (`mt76x2u`), mainline Linux:

```
phy            phy1
address        00:c0:ca:b0:60:4c

TRANSMIT-capable AWDL social channels: [6, 44, 149]

active monitor (ACKs rx)  yes
injection                 yes
MAC TSF readable          NO
TSF channel schedule      NO
fixed TX rate             NO

==> tier: SoftTimed
    to reach HwTimed, this radio still needs:
      - MAC TSF cannot be read
      - no TSF-anchored channel schedule — windows must be met by the CPU
      - TX rate cannot be pinned per frame
```

**That is the entire conversation a vendor needs to have.** Three named primitives on their
own chip, with everything else already passing — not a specification to interpret.

It also confirms the tier model against reality rather than against intent: mainline
`nl80211` reaches `SoftTimed` and cannot reach `HwTimed`, and the missing pieces are exactly
the ones `wonder.ko` adds (`get_mac_tsf`, `set_channel_schedule_req`, `set_fixed_tx_rate`).

> **One bug this found that compiling never would.** The backend invoked `iw` by bare name.
> It ships in `/usr/sbin`, which is absent from a non-login shell's PATH on Debian, so it
> worked interactively and failed from a service or any programmatically started process —
> reporting `No such file or directory` for a tool that plainly existed. `ip` in `/sbin` has
> the same problem. Both now resolve by absolute path. Worth knowing before a vendor meets
> it.

## Verifying a backend

A vendor backend is correct when it produces the same results as the reference one on the
same captures. `crates/libawdl` parses independently of any radio, and its output has been
checked frame-for-frame against Wireshark's dissector — 278 of 6584 frames identified as
AWDL by both, with identical tag histograms. That is the bar: not "it runs", but "it
agrees with an independent implementation on recorded evidence".

`Caps::gaps_to_hw_timed()` returns the missing primitives as a list, phrased to be handed
to whoever owns the driver. That is deliberate. An unimplementable specification gets
ignored; a specification that says *these four things are missing* gets worked on.
