# Running libawdl on a phone — ON HOLD

*Written 2026-09-14 and deliberately parked. Everything here is preparation for a track that
has not started; nothing in it is needed for the work on the Pi.*

## Why it is on hold and not abandoned

libawdl works on the Pi: control plane, data plane, elections, a netdev carrying IPv6.
Getting it onto a Pixel is a **separate** problem whose difficulty is unknown, and the
unknown is one measurement wide. Parked because device time is better spent on experiments
that need a cooperative Apple peer, which is the one resource the Pi cannot substitute for.

## The framing that makes this cheap — libawdl sits ALONGSIDE libmosey

Operator's decision, and it changes the shape of the whole track: **libmosey is not being
removed.** libawdl does not have to replace anything to be useful on a phone, so there is no
migration, no flag day, and no risk to Tarish's working AirDrop.

The consequence worth remembering: **receiving needs no injection and no exclusivity.** That
makes phase 1 below essentially free.

## The gate — one measurement

`wonder.ko` is bound to **mac80211 and cfg80211** (`lsmod` shows both), and libmosey drives
it over plain netlink as `wiphy_name: "wonder"`, `iface_name: "wonder0"` — see
`../grapheneos/docs/MOSEY-ABI.md`. So it presents a real nl80211 device, and libawdl's
existing HAL (`Nl80211` + AF_PACKET on a monitor vif) may work unchanged.

**But `../grapheneos/docs/OWL-PATH.md` expects the opposite.** Its cost table for the
vendor-command route includes *"adapt OWL off monitor-injection"*, i.e. the recorded
assumption is that monitor injection is unavailable on the phone and wonder's own vendor
commands are the path — OUI `0x001A11`, subcommands `0x01`-`0x08` and `0x0F`, including
`get_mac_tsf` and `set_channel_schedule_req`.

That is an expectation, not a measurement, and it is the whole gate:

```
can we add a monitor interface on the "wonder" wiphy, and does AF_PACKET injection succeed?
```

- **yes** → the port is nearly free; libawdl's HAL already does exactly this
- **no**  → we drive wonder's vendor commands instead. A real project, but with an ABI that
  is already documented rather than one that has to be recovered

## Measured on blazer, 2026-09-17 — the capability half of the gate is answered

Probed on the attached Pixel 10 Pro (userdebug, root). See FINDINGS 86 for the full evidence.

- `wonder` is a real mac80211/cfg80211 wiphy and `iw phy wonder info` lists **monitor** mode.
  `iw` and `tcpdump` ship on the phone, so **Phase 1 (listen) needs no cross-compile**.
- wonder.ko's vendor commands (OUI 0x001A11), from its own symbol table, include
  **`get_mac_tsf`** and **`set_channel_schedule_req`** with a working TSF-anchored path
  (`"Found TSF: %u"`, `"Switch TSF: 0x..."`). This is the HwTimed tier — the exact capability
  finding 81 said the ALFA lacks. MOSEY-ABI's "channel_schedule not implemented" was the
  wondertap-**inactive** message, not the whole story.

So the *hardware* gate is passed: blazer can read the MAC TSF and run a TSF-anchored schedule.
Two things remain untested and are the next steps:

1. **Injection** on `wonder` (the AF_PACKET half of the gate above) — Phase 2.
2. **Invoking the vendor commands from our own code** — the `libawdl-hal` wonder backend
   (NL80211_CMD_VENDOR messages for `get_mac_tsf` / `set_channel_schedule_req`).

## Three phases

### Phase 1 — listen only. Free, and does not disturb libmosey

Open a monitor interface on the phone's radio and decode what it sees, while libmosey runs
normally. No injection, no exclusivity, no build change, nothing removed.

Worth doing for its own sake: it validates the parser against the **target** hardware rather
than an ALFA, and it lets libawdl's view be diffed against libmosey's behaviour on the same
frames. That is the cheapest confidence check available before trusting libawdl with
anything on a phone.

### Phase 2 — the injection probe

```
iw phy wonder interface add mon type monitor
```

then one AF_PACKET send. Needs libmosey **not mid-session** for a few seconds — not removed.
Expect the mt76-style trap to have an analogue here: on the Pi, a second vif up on the same
phy makes every send return `EAGAIN` with nothing in dmesg (`rawsock`'s module note). If the
phone behaves the same way, a running `tarishd` holding `mosey0` will look like a hardware
failure.

### Phase 3 — transmit, and the full stack

Only meaningful once phase 2 has answered. If injection works, `awdl beacon --datapath`
should run close to unchanged.

## What has to exist first

**A binary.** `libawdl` has zero dependencies and `libawdl-hal` needs only `libc`, so this is
small either way:

| | route | good for |
|---|---|---|
| probe | `aarch64-unknown-linux-musl`, static | crude, quick, works for syscall-level tools on Android |
| shipping | a Soong module, as `tarish-daemon` does it — `host_supported`, `system_ext_specific` | anything that lives on the device permanently |

**A userdebug build with root adb.** `gos-build.sh -t permissive` exists for this.

**Probably SELinux permissive** for the probe, since an ad-hoc binary has no domain. Reviewed
policy later, via `gos-sepolicy.sh`, if this becomes permanent.

## What is NOT a blocker

**Coverage.** 84.9% of control-plane bytes named is far more than a probe needs, and the
remaining 15.1% is a hash that cannot be computed plus bytes that need on-air experiments —
which are exactly the experiments device time should go to instead.

## Resuming

The next concrete step, needing no phone, is:

1. add the `aarch64-unknown-linux-musl` target and check it builds
2. add `awdl probe`: enumerate wiphys, report whether `wonder` is present and what it
   supports, stop short of transmitting

Then phase 1 is an `adb push` and one line.
