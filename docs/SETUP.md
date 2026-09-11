# Bringing up the rig

Raspberry Pi 400, Debian 13, **ALFA AWUS036ACM** (MT7612U, `mt76x2u`). The Pi's own
Broadcom radio is not usable for this and stays down.

The adapter reports:

```
Device supports active monitor (which will ACK incoming frames)
```

which is the capability that matters. Without link-layer ACKs a peer retransmits each
frame up to seven times, and that presents as a working-but-slow link rather than as a
failure — the single most misdiagnosed condition in this area.

## Every session

```sh
./tools/awdl-up.sh 149      # or 6, or 44
```

Four things it handles, each of which costs an hour if you meet it cold:

| | |
|---|---|
| **rfkill soft-blocks every radio at boot** | `ip link set up` fails with `Operation not possible due to RF-kill` |
| **The regulatory domain reverts to `country 00`** | 44 and 149 become `PASSIVE-SCAN`/no-IR: the radio may listen but not transmit. Only channel 6 stays open |
| **The phy index is not stable** | `phy2` before a reboot, `phy1` after. Hardcoding it fails with `No such device (-19)`, which reads like the adapter is missing |
| **The managed interface must be DOWN** | see below |

### The one that fails as a success

`mt76` will not transmit from a monitor vif while another vif on the same phy is up, and
will not let you change channel either. It does not say so. OWL reports
`Channel 44 is available for frame injection`, creates `awdl0`, and then every `send()`
returns `EAGAIN`:

```
ERROR: unable to inject packet (send: Resource temporarily unavailable)
```

`dmesg` is silent. The adapter is fine — `aireplay-ng -9` gets **30/30, 100%** on the
same radio at the same moment. Flipping the primary interface to `type monitor` instead
of adding a separate `mon0` fails identically.

## Building OWL

```sh
sudo apt install git cmake build-essential libpcap-dev libev-dev \
                 libnl-3-dev libnl-genl-3-dev libnl-route-3-dev pkg-config
git clone --recursive https://github.com/seemoo-lab/owl
cd owl && mkdir build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release && make -j4
sudo cp daemon/owl /usr/local/bin/
```

`libnl-route-3-dev` is the one every guide omits. Without it `cmake` fails with
`Could not find nlroute_LIBRARY using the following names: nl-route-3`.

Run it against the monitor vif, not the managed interface:

```sh
sudo owl -N -i mon0 -c 149 -v      # -N: we set monitor mode ourselves
```

## Capturing

No Rust is needed on the Pi for this. Capture there, analyse anywhere:

```sh
sudo tcpdump -i mon0 -w awdl.pcap -s 0
```

```sh
awdl stats awdl.pcap      # on any machine
```

**A capture is evidence; a live run is an anecdote.** Every finding in `FINDINGS.md`
names the capture behind it.

## GoOpenDrop, if you want AirDrop end to end

Not required for protocol work, and it has two problems worth knowing before you spend
an afternoon on it.

**It will not build against a current Go toolchain** as pinned. Its 2022
`golang.org/x/net` fails to link on Go 1.24 with
`invalid reference to syscall.recvmsg`. `go get golang.org/x/net@latest && go mod tidy`
fixes it; nothing else needed. Build natively — the bundled scripts target Arm5/Arm7 and
a Pi 400 on Debian 13 is aarch64.

**It needs extracted Apple keys and will not self-sign.** `keys/` wants
`certificate.pem`, `key_noenc.pem` and `validation_record.cms` from
[airdrop-keychain-extractor](https://github.com/seemoo-lab/airdrop-keychain-extractor).
Discovery and the BLE beacon work without them; `/Ask` is refused.

> **It wedged the Pi.** Running it as root took the machine to 155-380 ms ping latency
> and then stopped answering SSH entirely — ICMP still replied in 3 ms and TCP port 22
> still completed a handshake, but sshd never sent its banner. It restarts the BLE and
> WLAN interfaces as root, and the likeliest cause is a USB reset wedging the `mt76x2u`
> stack, but that is unverified. It needed a power cycle. Have console access before you
> run it.
