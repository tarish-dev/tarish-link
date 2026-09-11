#!/bin/sh
# Capture BLE and AWDL simultaneously, so a device's departure can be timed on both.
#
#   ./dual-capture.sh [seconds] [channel]
#
# THE POINT: AWDL absence is ambiguous. A device occupies only 3-9 of its 16
# availability windows, so a peer is legitimately not transmitting most of the
# time -- 'gone' and 'in a window it does not attend' look identical. BLE
# advertises continuously, so absence there means absence.
#
# Whichever stream stops first when a device leaves is the detector Apple can
# actually be using.
SECS=${1:-120}
CHAN=${2:-149}

sh ~/awdl-up.sh $CHAN >/dev/null 2>&1

sudo btmon -w /tmp/dual-ble.pcap >/dev/null 2>&1 &
BLE=$!
# DUPLICATE FILTERING MUST BE OFF. bluetoothctl scan on enables it, and the
# controller then reports each unchanged advertisement once per ~16s -- which is
# fine for presence and useless for timing a departure. hcitool --duplicates
# reports every one.
sudo timeout $SECS hcitool lescan --duplicates >/dev/null 2>&1 &
SCAN=$!
sudo timeout $SECS tcpdump -i mon0 -w /tmp/dual-awdl.pcap -s 0 >/dev/null 2>&1

sleep 2
sudo kill $BLE 2>/dev/null
wait $SCAN 2>/dev/null
echo "awdl: $(ls -la /tmp/dual-awdl.pcap | awk '{print $5}') bytes"
echo "ble:  $(ls -la /tmp/dual-ble.pcap | awk '{print $5}') bytes"
