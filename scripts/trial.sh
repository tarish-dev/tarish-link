#!/bin/bash
# One trial: beacon, capture, fetch.
#   LABEL=W6 FLAGS="--metric 600 --windows 6" ./trial.sh
#
# FOUR harness bugs are designed out here, every one of which produced a confident wrong
# answer or a silent stall:
#   1. bring_up deletes and recreates mon0, so a tcpdump attached beforehand captures on a
#      dead interface. The beacon starts first and we wait for the interface to exist.
#   2. A tcpdump that fails to attach leaves the previous trial's file for scp to copy, so
#      four trials once reported byte-identical results. Unique remote names, and the file
#      must be non-empty.
#   3. The ssh returned before the beacon exited, so the next trial's beacon ran alongside
#      it -- two transmitters, different schedules, one interface. We now WAIT ON THE PID.
#   4. `pgrep -f 'awdl beacon'` matches this very script's own command line, so a wait loop
#      built on it never finishes. Hence the PID, not a pattern.
#   5. The condition was established BEFORE the run, and two iPhones re-form a cluster in
#      under 10s -- less than this script's own startup -- so a "forming" cell captured a
#      settled room four times running, once convincingly enough to refute a hypothesis.
#      The script now announces CAPTURE OPEN so the operator acts into the window, and
#      prints the timeline so the cell's validity is checked rather than assumed.
set -eu
: "${LABEL:?set LABEL}"
FLAGS="${FLAGS:-}"
# Durations are overridable: a "forming" cell has to stay open long enough for a phone
# to actually bring AWDL up after AirDrop is switched on, which took longer than a 50s
# window in one run and voided the cell.
BEACON_S="${BEACON_S:-70}"
CAP_S="${CAP_S:-50}"
PI=pi@raspberrypi.local
OUT="/path/to/tarish-libawdl/captures/trial-${LABEL}.pcap"
REMOTE="/tmp/trial_${LABEL}.pcap"

ssh -o ConnectTimeout=10 "$PI" "
  set -u
  cd ~/tarish-libawdl
  sudo rm -f -- '$REMOTE'
  sudo ./target/release/awdl beacon wlx00c0cab0604c mon0 149 $BEACON_S 2 $FLAGS > '/tmp/t_${LABEL}.log' 2>&1 &
  BPID=\$!
  for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    if ip link show mon0 >/dev/null 2>&1; then break; fi
    sleep 1
  done
  sleep 4
  echo "CAPTURE OPEN \$(date +%H:%M:%S) -- act NOW, the condition must be established inside the window"
  sudo timeout $CAP_S tcpdump -i mon0 -w '$REMOTE' -s 0 2>/dev/null || true
  wait \$BPID 2>/dev/null || true
  if [ ! -s '$REMOTE' ]; then echo 'TRIAL FAILED: no capture'; exit 3; fi
  tail -2 '/tmp/t_${LABEL}.log'
"
scp -q -o ConnectTimeout=10 "$PI:$REMOTE" "$OUT"
cd /path/to/tarish-libawdl
echo "--- $LABEL  $(shasum -a 256 "$OUT" | cut -c1-10)  $(wc -c < "$OUT" | tr -d ' ')B"
./target/release/awdl phase "$OUT" 2>/dev/null | grep "00:c0:ca" || true
./target/release/awdl stats "$OUT" 2>&1 | grep -A5 "who names whom" | tail -4
# Rule 7: the cell is void unless the manipulation took. For a forming cell the peers must
# be SILENT in the opening buckets and then transition in. Peers talking in bucket 1 are
# settled peers, whatever was done to the phones beforehand. Four FL runs died here.
echo "--- validity (forming cells: peers must start silent, look for ..* )"
./target/release/awdl timeline "$OUT" 2>&1 | sed -n '3,9p'
