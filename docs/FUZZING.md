# Two harnesses for Tarish

Both are stable-toolchain Rust with no dependencies, so they run anywhere `cargo` does
and need no device, no nightly and no cargo-fuzz.

## 1. `mutation_fuzz.rs` — the AWDL parsers

Drop it in **`tarish-link/crates/tlink/tests/mutation_fuzz.rs`**.

```
cargo test -p tlink --test mutation_fuzz -- --nocapture                 # 300k iterations
FUZZ_ITERS=20000000 cargo test --release -p tlink --test mutation_fuzz -- --nocapture
RUSTFLAGS="-C overflow-checks=on" FUZZ_ITERS=50000000 cargo test --release -p tlink \
    --test mutation_fuzz -- --nocapture                                 # overnight
```

Seeds come from `captures/*.pcap` (radiotap link type only, both byte orders). Each
iteration mutates a real frame — bit flips, interesting bytes, little-endian length
fields nudged or maxed, truncation, insertion, deletion, splicing two captures — and
pushes it through the receive path: `Radiotap::parse`, `FrameControl`/`Dot11`,
`decapsulate`, `DataHeader`, the block-ack parsers, `ActionFrame::parse`, every TLV, the
typed decoders for tags 2/4/5/6/12/16/18/21/24, `coverage::of_tlv`, and then
`Cluster::observe_at` with the projection calls that follow it.

Panics are caught, deduplicated by site and message, and the input that caused each is
written to `target/fuzz-crashers/`. The test fails if any site is reachable. `FUZZ_SEED`
sets the PRNG seed; the run is deterministic for a given seed and iteration count.

Run it in **debug** as well as release: debug keeps overflow checks on, and arithmetic
overflow on a value from the air is a crash in tarishd.

Result on commit `5f0d849` (22 Sep 2026): 689,874 seeds, 20,000,000 iterations,
overflow checks on, zero panics. 3.2M inputs reached action-frame parsing, 2.8M reached
the cluster clock, 1.6M reached the v2 election parser.

### Worth adding later
- Seed from `tarish-daemon`'s side too, once a Cargo shim exists for `sharingd`.
- Point it at `tlink-session`'s frame handling, not only the parsers.
- Keep a corpus directory and feed survivors back in, so coverage compounds between runs.

## 2. `plist_bomb_test.rs` — the `/Ask` body reader

Append to **`tarish-daemon/sharingd/src/plist.rs`** (it expects `super::parse`), or put
it in a `rust_test` that can see the module. Verified to compile against the current
`plist.rs`.

Against today's parser: `a_real_shaped_body_still_parses` passes,
`a_body_that_reuses_references_is_refused_not_expanded` fails in ~0.5 s. It fails
rather than hangs because the parse runs on a second thread behind a timeout.

`plistbomb_repro.rs` is the standalone measuring version:

```
rustc -O plistbomb_repro.rs -o plistbomb   # expects ../../tarish-daemon/... — fix the #[path]
./plistbomb 32 5     # 406-byte body -> ~2.1 GB, ~3 s
./plistbomb 64 5     # 726-byte body -> killed at 3.9 GB and climbing
```

### The fix the test assumes
One budget for the whole parse, not per container: a count of objects materialised,
shared across recursion, that refuses the document when spent. `MAX_DEPTH` and
`MAX_ELEMENTS` bound one chain and one container; neither bounds the product, which is
what reusing references multiplies. Ten thousand is generous — real AirDrop bodies hold
tens of objects.

The same shape applies anywhere else a document can point at its own parts. Worth a
look at the CPIO reader and the Quick Share payload assembler for the same question:
what does the total cost to me, rather than to any single record?
