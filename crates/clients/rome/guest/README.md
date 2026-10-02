# guest-rome

The ZisK guest for Rome protocol's zk-rollup lane.
Unlike this fork's other clients (`reth`, `ethrex`,
`ziskethone`), which prove one Ethereum block, `guest-rome` proves **one finalized batch**: a
contiguous range of blocks `first..=last`, bound to the batch's own data-availability bytes.

## What it proves

Given a batch's public input and one execution witness per block, the guest:

1. Recomputes the inbox accumulator `acc` over the batch's chunk bodies (`keccak(body_i)` → an
   indexed-leaf Merkle root → `acc = keccak(chain_id ‖ batch ‖ open_slot ‖ expected_count ‖ root ‖
   forced_root)`) — the same functions the on-chain program and off-chain readers use
   (`rome-zk-layouts`, `rome-zk-merkle`), with keccak's cost paid through ZisK's accelerated hook
   (`alloy-primitives`'s `native-keccak` feature) rather than the software path those crates fall back to
   off a Solana target.
2. Decodes the chunk bodies (frame reassembly, pure-Rust `zstd` decompress, RLP) and checks the decoded
   blocks equal the witnessed blocks — number, timestamp, and every transaction's encoded bytes — so the
   proof binds "the sequencer executed exactly these DA bytes", not merely "executed some valid chain".
3. Chains and stateless-validates each block in order (`parent_hash` continuity from the batch's own
   `parent_header`, contiguous numbering, a one-sided timestamp drift bound against the batch's own
   `open_unix_ts`), reusing `guest-reth`'s own recovery/validation path — the same reth v2.1.0 stateless
   validator already proved end to end on real BPF/ZisK.
4. **Asserts every derivation-rule-fixed header field, per block, before stateless-validating that
   block**: `mixHash`/`prevRandao`, `beneficiary`, `extraData`,
   `withdrawalsRoot`, `parentBeaconBlockRoot`, `blobGasUsed`, `excessBlobGas` must each equal
   `rome_zk_executor_api::canonical_header_rule(chain_id, number, fee_recipient)`'s value — the ONE
   shared rule the sequencer's block env and `rome-zk-derive`'s payload-attributes construction also
   build from — and `gas_limit` must equal what the DA stream's decoded block actually carries (checked
   in `src/channel.rs`). Before this, a stateless validator proved consensus-validity, not
   derivation-canonicality: a host could commit a different (still consensus-valid) value for any of
   these fields and the guest would accept it.
5. Commits the public-values-v2 layout (208 bytes: chain id, block range, drift inputs, summed gas,
   parent/last-block hashes, state root, and both inbox commitments), packed into ZisK's 64-word output
   ABI.

## Input shape (wire v2)

Two bincode frames, read in order (`ziskos::io::read::<T>()`, which does its own bincode decode — see
`src/run.rs`'s doc for why raw slices are avoided on the commit side):

- `RomePublicInput` — chain/batch identity, the drift-bound inputs, the raw chunk bodies, the block
  immediately before the range (`parent_header`), and the range's own sealed blocks. **v2 drops the v1
  `chain_config` field**: the chain's rules are baked into this ELF at compile time instead (see "Chain
  rules are baked into the ELF, not host-supplied" below) — a host that could supply its own
  `chain_config` could claim a different chain's rules for the same batch, still consensus-valid, still
  accepted by a plain stateless validator.
- `RomeWitnessInput` — one `ExecutionWitness` per block, same order.

`rome-zk-prover-input` (host-only) builds these from a live batch and reth-verifier
`debug_executionWitness` reads.

## Chain rules are baked into the ELF, not host-supplied

`src/chain_config.rs` embeds the chain's genesis file at compile time via
`include_str!(env!("ROME_CHAIN_GENESIS"))` — `ROME_CHAIN_GENESIS` is set by this repo's ROOT
`.cargo/config.toml` (not the bin crate's own one: `guest-rome`'s host tests run from
`crates/clients/rome/guest`, a different directory than the real ELF build
`bin/guests/stateless-validator-rome`, and cargo's `[env]` resolution walks UP from the invoking
directory — only a config file at an ancestor of BOTH reaches both). Tiber's own genesis lives at
`chains/tiber-200101.genesis.json`, matching the canonical genesis file (checked
by `chain_config::tests::embedded_config_matches_the_rome_zk_tiber_genesis_byte_for_byte`, which skips
with an explicit message when the parent workspace is absent). **The chain's fee
recipient is the embedded genesis's own `coinbase` field** — `Address::ZERO` on
Tiber — never a second, independently-settable env var: a chain that wants a different fee recipient
changes its genesis file, the one place `rome-zk-derive` and the sequencer also read it from.

`run::execute_checked` asserts `public.chain_id` against the embedded config's own chain id
(`ChainConfigIdMismatch`) before anything else touches it. This ELF's vkey is per-chain (the registry's
`["registry", chain_id]` entry already binds a vkey to one chain), so a proof produced
under this ELF can only ever claim Tiber's own rules — there is no separate on-chain commitment of the
config to verify; the vkey IS the commitment.

**ELF sha256:** `ac5bf47fe0703059401651acdb73b53f6d6cc9bff1cd252ede08f8ea5200c021` — confirmed identical
from two different checkout directories via `./build-elf.sh` (`--remap-path-prefix`
alone was NOT enough to get here — see that script's own header doc: Cargo's own path-derived
per-package metadata hash, baked into every mangled symbol name, ignores `--remap-path-prefix` entirely,
so the script also stages both path-dependency roots into a fixed canonical directory before invoking
`cargo-zisk`). The previously recorded value here, `ea602c3438dca26cb06ca408395ad1278259a95833e31ef6cb3548c81f823485`,
came from a bare `cargo-zisk build --release` (no remap, no staging) and was exactly the non-reproducible
hash: three different build directories on the same machine produced three different
values (`ea602c34…`, `e4e350d3…`, `47ef8db8…`) for byte-identical source. A change to this ELF's own
code, or to any dependency version `bin/guests/stateless-validator-rome`'s Cargo.lock pins, changes this
hash — re-run `./build-elf.sh` from two directories and recompute it whenever either changes rather than
trusting this value stale.

## Why `rome-zk-layouts`/`rome-zk-merkle`/`rome-zk-channel` are path dependencies, not git

These crates are consumed as path dependencies at
`../../../../../crates/<name>`. The fork must be checked out as
`.fork/` inside the workspace that supplies those crates.
Copying the full workspace, including the nested checkout,
preserves this relative layout.

A pinned git dependency was considered, but access from the
build runner was not established or tested. The path dependencies
retain the existing build layout.

## Build and test

This crate only builds nested as `.fork/` under the workspace supplying its path dependencies (see the top-level
README, "Building `guest-rome` / `zec-rome`"), with the `third_party/ziskethone` submodule initialized
even though this crate does not use it directly — it is part of loading this repo's workspace at all:

```sh
cd <rome-zk-worktree-root>/.fork
git submodule update --init third_party/ziskethone   # if not already done
cd crates/clients/rome/guest
cargo test          # host tests: no ziskos I/O touched (src/run.rs's execute(), not run())
```

The actual ELF (`bin/guests/stateless-validator-rome`) is a **standalone** cargo package (like its
`stateless-validator-reth` sibling — not a member of this repo's top-level workspace). Build it with the
committed `build-elf.sh`, not a bare `cargo-zisk build` — the bare form embeds
this checkout's own absolute path (and `$CARGO_HOME`/`$ZISK_HOME`'s) into the ELF's panic-location
strings, so the SAME source built from two different directories produces two different sha256 hashes:

```sh
cd bin/guests/stateless-validator-rome
./build-elf.sh
~/.zisk/bin/ziskemu -e target/elf/riscv64ima-zisk-zkvm-elf/release/zec-rome -i <input.bin> -m
```

## Real execution

Run against a real batch (chain 200101, batch 3930, blocks 39181..=39190 — all ten
blocks empty) built by `rome-zk-prover-input`: **576,056 steps, 0.0131 s** under `ziskemu`.
Every committed public-values field matched that crate's own host-computed expectation, and
`last_block_hash`/`state_root` (only known after a real execution) matched the Tiber verifier's own values
for block 39190, fetched independently.

This first real run panicked before it committed anything: `ziskos`'s public-output mechanism is a
64-slot, 32-bit register file (`zkvm_io::set_output`'s own `assert!(id < 64, ...)`, `OUTPUT_WORD_SIZE =
size_of::<u32>()`) — 256 raw bytes total, not the 512 bytes `run()`'s first commit call assumed
(`w.to_le_bytes()`, 8 bytes per word, 64 words = 512 bytes = 128 register slots, past the real 64-slot
limit). Fixed by committing `(w as u32).to_le_bytes()` (4 bytes) per word instead — each `pack_zisk_
outputs` word already fits in a `u32` by construction, so nothing is lost; the 512-byte, 64-`u64`-word
buffer the on-chain verifier reads (`header::zisk_committed_hash`) is the *prover's* own packaging of
those same 64 raw registers into one SNARK field element apiece, external to this guest's own
`commit_slice` calls.

Four mutations on the real input were each refused by name under `ziskemu`:
a wrong witness, a flipped chunk-body byte, `max_drift_secs = 0`, and a replaced parent header.
A fifth probe, lowering `max_drift_secs` to a small nonzero value,
did not refuse on this particular idle batch.

### Reproducible ELF execution (sha256 above)

Same real input, same honest batch: **596,486 steps, 0.0137 s**. Every committed public-values field
still matches byte for byte (`parent_hash`/`last_block_hash`/`state_root`/`inbox_commitment`/
`forced_outcome_commitment` all identical to the earlier results). The step count is NOT the
576,056 a naive "nothing behavioral changed" assumption would predict — checked directly rather than
assumed: reading the fee recipient from the genesis replaced `chain_config.rs`'s `option_env!("ROME_FEE_RECIPIENT")`
compile-time constant lookup with a real JSON field read (`embedded_genesis().coinbase`), and the
header-rule assertions were also added between the two measured runs above, so some
delta versus 576,056 is expected on its own. What was NOT expected: `embedded_chain_config()` and
`embedded_fee_recipient()` are both called every guest run, and an early version of this fix parsed the
embedded genesis JSON **twice** per run (once per accessor, no caching) — measured directly at 616,349
steps, a ~20,000-step regression from a redundant parse of a small file. Fixed with a `OnceLock` memoizing
the one parse both accessors read from; 596,486 is the memoized, final figure.

## Known deviation from `guest-reth`'s own input shape

`RethInputPublic` carries a host-precomputed `public_keys` field so the reth guest never runs k256
signature recovery itself. `RomePublicInput` carries no such field — each
block's signers are recovered **in-guest** via `guest_reth::recover_signers`, at real extra step cost per
block relative to that shortcut. Left as an open question / a candidate follow-up (see `src/chain.rs`'s
module doc), not silently worked around.
