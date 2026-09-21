# Provenance

`tarish-link` (tlink) is an **independent reimplementation** of AWDL — Apple's peer-to-peer
Wi-Fi layer — in Rust. It is not a wrapper around, and contains no source copied from,
Google's `libmosey`, Apple's software, or any GPL project.

## How it was built

The implementation was informed by public, lawful sources:

- **Published research** on AWDL, notably the Open Wireless Link (OWL) project and its papers.
- **Wireshark's AWDL dissector**, consulted to interpret frame layouts.
- **Our own over-the-air packet captures** of real Apple devices and of Google's `libmosey`
  in operation (see `awdl/captures/` in the integration repo).
- **Observed runtime behaviour** of `libmosey` (timing, channel schedules, election metrics).

From those sources we recovered **protocol facts** — frame formats, TLV layouts, the election
algorithm, availability-window scheduling, channel sequences — and wrote original code to
implement them. Protocol facts (what a byte means on the wire) are not themselves
copyrightable; the expression here is ours.

## What this explicitly is not

- Not a fork or derivative of `libmosey`. The binary links no Google AWDL library; it drives
  the vendor radio shim (`wonder.ko`) directly over netlink.
- Not derived from OWL or Wireshark source. Those were **studied**, not copied. tlink is
  Rust; both are C. Where a bring-up sequence was recovered, it was recovered from *our own
  captures of the wire and of `libmosey`'s behaviour*, not from another project's code.

## Attribution

We gratefully acknowledge the OWL authors and the Wireshark AWDL dissector contributors,
whose public work made the protocol legible. Any errors in our understanding are ours.

## Licence

tlink is licensed under the Apache License 2.0 — see [LICENSE](LICENSE). Every crate in the
workspace inherits that licence (`license.workspace = true`).
