#!/bin/bash
# One election trial with the peer woken BY US over BLE.
#
# Last night this experiment needed a human to toggle two phones, and eleven of about a
# dozen runs voided: cue latency, phones that would not wake, phones that woke as rivals,
# stale peers from the previous run. None of those failures was about the thing being
# measured.
#
# An AirDrop BLE beacon wakes an Apple device's AWDL from cold. Measured: beacon off for
# 140 s gives zero AWDL frames across two samples; beacon on gives 31 and 48. So the peer's
# arrival is now ours to schedule, which is what makes a controlled forming cell possible.
#
# TWO DEFECTS made this look impossible at first, and both were in our beacon:
#   - no AD Flags structure. Apple's stack ignores an advertisement without one
#   - ADV_NONCONN_IND (0x03) instead of a connectable ADV_IND (0x00)
# With either wrong the HCI commands still return success and nothing happens.
set -u
PI=${PI:-pi@raspberrypi.local}
MON=${MON:-mon0}
MANAGED=${MANAGED:-wlx00c0cab0604c}
OURMAC=${OURMAC:-00:c0:ca:b0:60:4c}
CHAN=${CHAN:-149}
METRIC=${METRIC:-600}
SECS=${SECS:-150}
CAPS=${CAPS:-120}
LABEL=${LABEL:-x}
FLAGS=${FLAGS:-}
R=/tmp/bt_$LABEL

ssh -o ConnectTimeout=10 "$PI" "
set -u
cd ~/tarish-libawdl
st() { sudo hcitool -i hci0 cmd \$@ 2>&1 | tail -1 | awk '{print \$4}'; }
sudo killall awdl tcpdump 2>/dev/null

# 1. BLE OFF, and wait for the room to go quiet. Sampling until quiet, not once: a device
#    keeps transmitting for some seconds after its trigger stops.
st 0x08 0x000A 00 >/dev/null
for try in 1 2 3 4 5 6; do
  sudo timeout 15 tcpdump -i $MON -w $R.q.pcap -s0 2>/dev/null
  n=\$(./target/release/awdl stats $R.q.pcap 2>&1 | grep -oE '[0-9]+ AWDL action' | grep -oE '^[0-9]+')
  echo \"  quiet check \$try: \${n:-0} frames\"
  [ \"\${n:-0}\" = 0 ] && break
done

# 2. our beacon into the verified-empty room
nohup sudo ./target/release/awdl beacon $MANAGED $MON $CHAN $SECS 2 --metric $METRIC --tenure 99999 $FLAGS > $R.log 2>&1 < /dev/null &
for i in \$(seq 1 15); do ip link show $MON >/dev/null 2>&1 && break; sleep 1; done
sleep 4

# 3. capture, then wake the peer INTO it. Order matters: we must already be master.
nohup sudo timeout $CAPS tcpdump -i $MON -w $R.pcap -s0 > /dev/null 2>&1 < /dev/null &
sleep 3
st 0x08 0x000A 00 >/dev/null
st 0x08 0x0006 A0 00 A0 00 00 00 00 00 00 00 00 00 00 07 00 >/dev/null
st 0x08 0x0008 1B 02 01 1A 17 FF 4C 00 05 12 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 >/dev/null
echo \"  BLE wake -> \$(st 0x08 0x000A 01)\"
sleep \$(( $CAPS + 20 ))
"

fetch() { ssh -o ConnectTimeout=10 "$PI" "cd ~/tarish-libawdl && $1" 2>/dev/null; }
echo
echo "===== $LABEL  flags='$FLAGS' ====="
fetch "./target/release/awdl timeline $R.pcap 10 2>&1 | sed -n '3,10p'"
fetch "./target/release/awdl stats $R.pcap 2>&1 | grep -A6 'election (per sender' | head -6"
LOG=$(fetch "cat $R.log")
echo "$LOG" | grep -E '^sent|^adopted by'

SENT=$(echo "$LOG" | grep -oE '^sent [0-9]+ MIF, [0-9]+ PSF' | grep -oE '[0-9]+' | awk '{n+=$1} END {print n+0}')
MIN=$(awk -v s="$SECS" 'BEGIN {print int(s*2)}')
PEERS=$(fetch "./target/release/awdl stats $R.pcap 2>&1 | grep -A8 'senders:' | grep -cE '^  [0-9a-f]{2}:'")
NAMED=$(fetch "./target/release/awdl stats $R.pcap 2>&1 | grep -E '\->  *$OURMAC' | awk '{n+=\$NF} END {print n+0}'")
echo
V=""
[ "${SENT:-0}" -ge "$MIN" ] || V="$V frames_sent=${SENT:-0}<$MIN(starved)"
[ "${PEERS:-0}" -ge 2 ] || V="$V no_peer_woke"
if [ -n "$V" ]; then echo "VOID:$V"; else echo "VALID — frames naming us master: ${NAMED:-0}"; fi
