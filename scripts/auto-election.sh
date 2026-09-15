#!/bin/bash
# UNATTENDED ELECTION TRIALS. Cycles three arms and scores each against the same
# pre-registered gate the interactive harness uses.
#
#   control    --metric 600                   one constant metric, what we have always sent
#   floor      --metric 600 --metric-floor 3   65 first, then step — finding 77's shape
#   windows    --metric 600 --windows 8        8 slots of 16 instead of 3 — finding 75/76
#
# The point is n. Finding 78 rests on ONE valid floor run against two controls, and finding
# 75 measured spontaneous takeovers at roughly one attempt in three, so a single success
# proves nothing and only alternation over many trials separates the arms.
#
# TWO FAILURES OF THE FIRST OVERNIGHT ATTEMPT ARE DESIGNED OUT HERE:
#
#   The starvation check parsed the beacon's "sent N MIF" summary, which the beacon prints
#   only when it EXITS -- and this harness kills it before then. So SENT read 0 and all 66
#   trials voided as starved. Trial 1 was a real result destroyed by it: 2 peers, 0 entry
#   events, 117 frames naming us master, an ADOPT on the control arm, capture deleted with
#   it. Frames are now counted from the capture, which is the honest measure anyway.
#
#   The phones left the air after ten minutes -- iOS reverts to Contacts Only on its own and
#   an idle handset then advertises no AWDL at all -- so trials 3 to 44 all read "empty
#   room" and the trial budget was gone in an hour. The harness now WAITS for the room
#   instead of spending a trial on it.
#
# A trial is VOID, never counted, when a precondition fails: no peer, a peer entering or
# rotating its AWDL MAC mid-run (which is how run FL2 produced a meaningless ADOPT), or our
# own transmitter starved. Results append to $OUT/results.tsv.
set -u
MON=${MON:-mon0}
MANAGED=${MANAGED:-wlx00c0cab0604c}
OURMAC=${OURMAC:-00:c0:ca:b0:60:4c}
CHAN=${CHAN:-149}
METRIC=${METRIC:-600}
TRIALS=${TRIALS:-48}
SECS=${SECS:-240}
CAPS=${CAPS:-210}
SETTLE=${SETTLE:-75}
MAXWAIT=${MAXWAIT:-45}
OUT=${OUT:-/tmp/auto}
BIN=./target/release/awdl

mkdir -p "$OUT"
[ -f "$OUT/results.tsv" ] || printf 'trial\tarm\tpeers\tentry\tsent\tnamed_us\tverdict\tincumbent\tinc_metric\tnote\n' > "$OUT/results.tsv"

peers_in() {
  $BIN stats "$1" 2>&1 | sed -n '/^senders:/,/^[a-z]/p' | grep -cvE "^senders:|$OURMAC|^[a-z]"
}

for i in $(seq 1 "$TRIALS"); do
  case $((i % 3)) in
    1) ARM=control; FLAG="" ;;
    2) ARM=floor;   FLAG="--metric-floor 3" ;;
    0) ARM=windows; FLAG="--windows 8" ;;
  esac
  R="$OUT/t${i}_${ARM}"
  sudo killall awdl tcpdump 2>/dev/null
  sleep "$SETTLE"
  sudo rm -f "$R".*

  # Wait for the room rather than burning a trial on an empty one.
  PEERS=0
  W=0
  while [ "$W" -lt "$MAXWAIT" ]; do
    sudo rm -f "$R.pre.pcap"
    sudo timeout 20 tcpdump -i "$MON" -w "$R.pre.pcap" -s0 2>/dev/null
    PEERS=$(peers_in "$R.pre.pcap")
    [ "${PEERS:-0}" -ge 1 ] && break
    W=$((W + 1))
    sleep 40
  done
  if [ "${PEERS:-0}" -lt 1 ]; then
    printf '%s\t%s\t0\t-\t-\t-\tVOID\t-\t-\tno peer after %s min of polling\n' "$i" "$ARM" "$MAXWAIT" >> "$OUT/results.tsv"
    continue
  fi

  INC=$($BIN stats "$R.pre.pcap" 2>&1 | grep -E '\->  \(itself\)' | sort -k4 -rn | head -1 | awk '{print $1}')
  INCM=$($BIN read "$R.pre.pcap" 2>/dev/null | awk -v inc="$INC" '
    /^#[0-9]+ / { for(j=1;j<=NF;j++) if($j=="->"){s=$(j-1); break} }
    /v2 distance/ { for(j=1;j<=NF;j++) if($j=="self") m=$(j+1); if(s==inc){split(m,a,"#"); print a[1]; exit} }')

  nohup sudo $BIN beacon "$MANAGED" "$MON" "$CHAN" "$SECS" 2 --follow --metric "$METRIC" --tenure 99999 $FLAG > "$R.log" 2>&1 < /dev/null &
  sleep 6
  sudo timeout "$CAPS" tcpdump -i "$MON" -w "$R.pcap" -s0 2>/dev/null
  sleep 6
  sudo killall awdl 2>/dev/null

  SENT=$($BIN stats "$R.pcap" 2>&1 | sed -n "/^senders:/,/^[a-z]/p" | grep -E "^  $OURMAC" | awk '{print $2}')
  ENTRY=$($BIN timeline "$R.pcap" 2>&1 | grep -E '^[0-9a-f]{2}:' | grep -v "$OURMAC" | awk '{print $2}' | grep -cE '[.][.]*[A-Za-z*]')
  NAMED=$($BIN stats "$R.pcap" 2>&1 | grep -E "\->  *$OURMAC" | awk '{n+=$NF} END {print n+0}')
  RPEERS=$(peers_in "$R.pcap")

  V=ADOPT; NOTE=""
  [ "${NAMED:-0}" -ge 20 ] || V=REFUSE
  if [ "${RPEERS:-0}" -lt 1 ]; then V=VOID; NOTE="room emptied during the run"; fi
  if [ "${ENTRY:-0}" -ge 1 ]; then V=VOID; NOTE="peer entered or rotated MAC — not a settled test"; fi
  if [ "${SENT:-0}" -lt $((CAPS * 2)) ]; then V=VOID; NOTE="transmitter starved: ${SENT:-0} frames on air"; fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$i" "$ARM" "${RPEERS:-0}" "${ENTRY:-0}" "${SENT:-0}" "${NAMED:-0}" "$V" "${INC:--}" "${INCM:--}" "$NOTE" >> "$OUT/results.tsv"

  # Keep every SCORED capture. A REFUSE is evidence; only voids are discarded.
  if [ "$V" = VOID ]; then rm -f "$R.pcap"; else gzip -f "$R.pcap" 2>/dev/null; fi
  rm -f "$R.pre.pcap"
done
sudo killall awdl tcpdump 2>/dev/null
echo "DONE $(date -u +%H:%M)" >> "$OUT/results.tsv"
