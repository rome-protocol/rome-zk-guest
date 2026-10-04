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
   `rome_zk_executor_api::canonical_header_rule_with_withdrawals(chain_id, number, fee_recipient, withdrawals)`'s
   value, where `withdrawals` is the block's slice of the batch's deposits (see "Deposits"; empty without deposits) — the ONE
   shared rule the sequencer's block env and `rome-zk-derive`'s payload-attributes construction also
   build from — and `gas_limit` must equal what the DA stream's decoded block actually carries (checked
   in `src/channel.rs`). Before this, a stateless validator proved consensus-validity, not
   derivation-canonicality: a host could commit a different (still consensus-valid) value for any of
   these fields and the guest would accept it.
5. Commits the public-values-v2 layout (208 bytes: chain id, block range, drift inputs, summed gas,
   parent/last-block hashes, state root, and both inbox commitments), packed into ZisK's 64-word output
   ABI.

## Input shape (wire v3)

Two bincode frames, read in order (`ziskos::io::read::<T>()`, which does its own bincode decode — see
`src/run.rs`'s doc for why raw slices are avoided on the commit side):

- `RomePublicInput` — chain/batch identity, the drift-bound inputs, the raw chunk bodies, the block
  immediately before the range (`parent_header`), and the range's own sealed blocks. **v2 drops the v1
  `chain_config` field**: the chain's rules are baked into this ELF at compile time instead (see "Chain
  rules are baked into the ELF, not host-supplied" below) — a host that could supply its own
  `chain_config` could claim a different chain's rules for the same batch, still consensus-valid, still
  accepted by a plain stateless validator. **v3 appends the batch's deposit range after `blocks`**:
  `settlement_program`, `deposit_from`, `deposit_hash_from` and `deposits` (each record is
  `{ sender, recipient, amount_gwei }`; its index is `deposit_from + k`). `da::commitment_with_deposits`
  extends the queue's hash chain over them and folds the result into `forced_root`, hence into `acc`;
  an empty range keeps today's constant, so a batch without deposits has the same `acc` and the same
  public values as before. The guest never refuses a record on its content.
- `RomeWitnessInput` — one `ExecutionWitness` per block, same order.

`rome-zk-prover-input` (host-only) builds these from a live batch and reth-verifier
`debug_executionWitness` reads.

## Deposits

A deposit is a record in the settlement program's queue. The batch's range of them is public input
(`deposit_from`, `deposit_hash_from`, `deposits`). The guest does three things with it:

1. **Binds it into `acc`.** `da::commitment_with_deposits` extends the queue's hash chain from
   `deposit_hash_from` over the records, builds `forced_root` from the result, and folds that into `acc`.
   When the range is empty, `forced_root` is the constant it always was.
2. **Reads the stream rule.** A block in the data-availability stream may carry a fifth field, the queue
   position after that block (`deposits_end`). Where a block has none, the previous value stands, and `from`
   stands before block 0. A fifth field must be strictly above the previous value, and the last value must
   equal `deposit_from + deposits.len()`. A fifth field in a deposit-free batch therefore ends above the
   range and is refused.
3. **Checks the block bodies.** Block `i` takes the deposits between its previous value and its own, as
   withdrawals: `{ index: deposit_from + k, validator_index: 0, address: recipient, amount: amount_gwei }`.
   The block's header must carry the withdrawals root of exactly those withdrawals
   (`canonical_header_rule_with_withdrawals`), and its body must carry them.

Each refusal has a name, and the emulator shows it as `rome guest refused: <name>: ...`:
`DepositsEndRefused` (an equal or decreasing fifth field), `DepositsEndMismatch` (the stream ends somewhere
other than `to`), `WithdrawalsMismatch` (a body's withdrawals are not its slice), and `HeaderRuleViolated`
with `field withdrawals_root` (a header's root is not its slice's root).

The guest never refuses a record on its content, and never applies `max_per_block` or `max_per_batch`. A
range the settlement program has bound must always be provable, because a finalized batch cannot be
abandoned.

A batch without deposits has the same public values as before this change. The reset6 batch 1 run below
commits the same 208 bytes as the real proof of that batch.

## Chain rules are baked into the ELF, not host-supplied

`src/chain_config.rs` embeds the chain's genesis file at compile time via
`include_str!(env!("ROME_CHAIN_GENESIS"))`. `ROME_CHAIN_GENESIS` is set by this repo's ROOT
`.cargo/config.toml` (not the bin crate's own one: `guest-rome`'s host tests run from
`crates/clients/rome/guest`, a different directory than the real ELF build
`bin/guests/stateless-validator-rome`, and cargo's `[env]` resolution walks UP from the invoking
directory, so only a config file at an ancestor of BOTH reaches both). The checked-in default is
`chains/tiber-200101.genesis.json`, an example chain. For your own chain you do not edit that file:
`build-elf.sh --genesis <your genesis.json>` copies your genesis into its staging directory and points a
generated copy of the config at it. **The chain's fee recipient is the embedded genesis's own `coinbase`
field**, never a second, independently-settable env var: a chain that wants a different fee recipient
changes its genesis file, the one place `rome-zk-derive` and the sequencer also read it from.

`run::execute_checked` asserts `public.chain_id` against the embedded config's own chain id
(`ChainConfigIdMismatch`) before anything else touches it. An ELF's verification key belongs to one chain
(the registry's `["registry", chain_id]` entry binds a key to one chain), so a proof produced under this ELF
can only ever claim the rules of the genesis it was built with. There is no separate on-chain commitment of
the config; the key is the commitment.

### Building the ELF for your chain

```sh
bin/guests/stateless-validator-rome/build-elf.sh \
  --genesis /path/to/your/rendered/genesis.json \
  --expect-chain-id <your chain id>
```

`--expect-chain-id` is optional. When given, the script stops with a message naming both ids if the
genesis' `config.chainId` differs. At the end it prints the ELF path, the ELF's sha256, and the sha256 and
chain id of the genesis that was embedded, after checking that the genesis bytes are really inside the ELF.

The build also checks the genesis' `alloc` balances, on every build path including a plain `cargo build` of
this crate (the check is in `build.rs`). A genesis that gives more than one account a non-zero balance is
refused with `GenesisFundedAccountLimit`, naming the accounts. A genesis with one funded account builds, and
the build prints it as `genesis-balance: address=… wei=… lamports=…` (1 lamport = 1e9 wei); `build-elf.sh`
repeats that line in its summary as `genesis_balance=`, so the balance can be compared with the chain's vault
before the ELF's key is registered. A genesis with no funded account prints `genesis-balance: none`. The check
only reads the genesis, so the ELF is the same with or without it.

Two builds of the same sources from two different checkout directories give the same sha256, because:

- the build runs from a staging directory at a fixed path (see the script's own header for why the real
  path would otherwise leak into the ELF through cargo's per-package metadata hash);
- your genesis is copied to a fixed name inside that staging directory, so neither its name nor its location
  matters, only its bytes;
- `bin/guests/stateless-validator-rome/Cargo.lock` is committed and the script refuses to run when it no
  longer matches the sources, so the dependency versions do not depend on what crates.io holds on the day.
  To refresh it on purpose, run `cargo metadata` (without `--locked`) in that directory with the `zisk`
  toolchain, which re-resolves only what changed, and commit the result. `cargo update` would move every
  dependency to its newest version.

Why a generated config and not a command-line option: `cargo-zisk build` does not pass `--config` through,
and `ROME_CHAIN_GENESIS` is set with `force = true` so that a stray environment variable cannot silently
change the chain. The staged copy of the config is the one place left that keeps every build input in the
staging tree.

**Example.** The default build (the example genesis, ZisK 1.2.0-alpha, rome-zk-evm v0.2.0 at commit
`0e76f155140f47b8c13be3f89ff5baab3c644120`, this guest with deposits) gives ELF sha256
`b68f8f068c08ca4998a25dda307a2610ce21f6d6e4410f11da61812c8615e58a` and programVK
`0x4258973dbd9edf658f2aed241c217d563e95338ad67bfaaebf30848b42f0dc77`. Built against rome-zk-evm v0.1.3 the
same sources gave sha256 `74cfbeb5cb6c52530be5b083229731bed0c63f390e5a649cb3072133cd085fff` and the same
programVK. The two ELFs have the same size and the same code and read-only data; the 992 bytes that differ
are all in the symbol and string tables, where the names the compiler gives each crate carry a hash that
changed with the four rome-zk crates between the two releases. That is why the hash moved and the programVK
did not. The v0.1.3 build also matched a build against the private tree it was exported from, run
from different directories. Your sha256 will differ, because your genesis does. A change to this ELF's own
code or to a dependency version in the lock changes the hash, so recompute it rather than trusting a number
written down here.

### What happens next

Send the ELF's sha256 to Rome. The program verification key for an ELF comes from
`cargo-zisk setup -e <ELF>`, which needs the ZisK proving key on the machine and about 37 GB of RAM
(measured: 36,559,840 KiB peak, 37 seconds for the example ELF; no proof is needed). Rome rebuilds your ELF, computes the key and registers it for your chain.

The ZisK version is pinned to **1.2.0-alpha**. Another version builds a different ELF.

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
cd <your rome-zk-evm checkout>/.fork
git submodule update --init third_party/ziskethone   # if not already done
cd crates/clients/rome/guest
cargo test          # host tests: no ziskos I/O touched (src/run.rs's execute(), not run())
```

The host tests read the chain id and fee recipient from the embedded genesis, so they pass for any chain.
To run them against your genesis instead of the default one:

```sh
GUEST_CHECK_GENESIS_JSON=/path/to/your/genesis.json \
cargo --config 'env.ROME_CHAIN_GENESIS.value="/path/to/your/genesis.json"' \
      --config 'env.ROME_CHAIN_GENESIS.force=true' \
      --config 'env.ROME_CHAIN_GENESIS.relative=false' test
```

`GUEST_CHECK_GENESIS_JSON` is optional: with it, a test also compares the embedded copy with the genesis the chain
started from.

The actual ELF (`bin/guests/stateless-validator-rome`) is a **standalone** cargo package (like its
`stateless-validator-reth` sibling — not a member of this repo's top-level workspace). Build it with the
committed `build-elf.sh` (see "Building the ELF for your chain" above), not a bare `cargo-zisk build` — the bare form embeds
this checkout's own absolute path (and `$CARGO_HOME`/`$ZISK_HOME`'s) into the ELF's panic-location
strings, so the SAME source built from two different directories produces two different sha256 hashes:

```sh
cd bin/guests/stateless-validator-rome
./build-elf.sh --genesis <your genesis.json> --expect-chain-id <your chain id>
~/.zisk/bin/ziskemu -e target/elf/riscv64ima-zisk-zkvm-elf/release/zec-rome -i <input.bin> -m
```

## Real execution

Run against a real batch (chain 200101, batch 3930, blocks 39181..=39190 — all ten
blocks empty) built by `rome-zk-prover-input`: **576,056 steps, 0.0131 s** under `ziskemu`.
Every committed public-values field matched that crate's own host-computed expectation, and
`last_block_hash`/`state_root` (only known after a real execution) matched the example chain's verifier's own values
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

### Reproducible ELF execution (the example ELF before deposits)

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

### Deposits: emulator acceptance (example ELF above)

Run with `ziskemu -e zec-rome.elf -i <input.bin> -m -o <out.bin>` on the example ELF. The committed output
is 256 bytes: the 208 public bytes, then 48 zero bytes. The four inputs are wire v3 and come from the public
rome-zk-evm release v0.2.0 (commit `0e76f155140f47b8c13be3f89ff5baab3c644120`), directory
`fixtures/prover-input`, with each sidecar's values as the expectation. The reset6 expectation is also the
public values inside that batch's real proof (`txv1-dev-reset6-batch-1.plonk.bin` in the same directory).

| Input file | sha256 |
|---|---|
| `txv1-dev-reset6-batch-1.bin` | `6288ed73f9ee27c1390bc2a19382e22515d087bec82cb9c9c2ac0a15f2a31bbd` |
| `txv1-dev-batch-3930.bin` | `d7c0b97961364881d4380b9c9f0b99d0dbb5337d29389b1c1f8d65b781eb55c0` |
| `synthetic-deposits-small.bin` | `2e6e090f0cc10ae453291ce2d2dfc4cd3bc8b00687fe5188a708f5c804df5ae9` |
| `synthetic-deposits-full.bin` | `1ab754da90528761ecbeeb2a1f8bc4078136f48c1f281c19ff7ecb0eb0295041` |

| Input | Blocks | Deposits | Steps | Result |
|---|---|---|---|---|
| reset6 batch 1 | 60 | 0 | 3,048,250 | the 208 bytes of the real proof of that batch, byte for byte |
| batch 3930 | 10 | 0 | 597,615 | matches its sidecar |
| synthetic small | 3 | 3 | 283,404 | matches its sidecar |
| synthetic full | 60 | 240 | 7,630,115 | matches its sidecar |

Steps per deposit. The full batch and reset6 batch 1 both have 60 blocks, so the difference is the cost of
240 deposits: (7,630,115 - 3,048,250) / 240 = about 19,090 steps. That figure also carries the cost of the
withdrawal credits in the block execution, which the empty reset6 blocks do not have. The small batch, set
against a straight line through the two deposit-free runs (about 107,500 steps fixed plus about 49,000 per
empty block), gives about 9,600. A full 60-block batch is 4 deposits per block; at 256 deposits the same
arithmetic gives about 7.9 million steps.

Each of these changes to the small synthetic input is refused by name under `ziskemu` (nothing is
committed): a missing withdrawal, an extra withdrawal, a wrong recipient, amount or index
(`WithdrawalsMismatch`); a deposit moved to the wrong block, in the stream (`HeaderRuleViolated`, field
`withdrawals_root`) or in the bodies (`WithdrawalsMismatch`); a fifth field with no deposits in the range, an
end value above or below `to` (`DepositsEndMismatch`); an equal or decreasing value, or a fifth field on
block 0 equal to `from` (`DepositsEndRefused`). A fifth field added to deposit-free batch 3930 is refused as
`DepositsEndMismatch`.

## Known deviation from `guest-reth`'s own input shape

`RethInputPublic` carries a host-precomputed `public_keys` field so the reth guest never runs k256
signature recovery itself. `RomePublicInput` carries no such field — each
block's signers are recovered **in-guest** via `guest_reth::recover_signers`, at real extra step cost per
block relative to that shortcut. Left as an open question / a candidate follow-up (see `src/chain.rs`'s
module doc), not silently worked around.
