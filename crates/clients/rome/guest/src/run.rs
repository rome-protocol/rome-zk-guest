//! Orchestration: the five checks in order, then the public-values-v2
//! commit. [`execute`] is the whole guest's logic with no `ziskos` dependency (host-testable, same split
//! `rome-zk-bench-decode` uses); [`run`] is the ~10-line ZisK entrypoint over it — reads the two input
//! frames, calls [`execute`], commits the 64-word ZisK output buffer.

use crate::da;
use crate::error::RomeGuestError;
use crate::input::{RomePublicInput, RomeWitnessInput};
use crate::{chain, channel};

/// The whole guest, minus the ZisK I/O itself — runs each check in order, with one named refusal
/// (via `RomeGuestError`'s `Display`, since the caller `.expect()`s it) or the 208-byte public-values-v2
/// blob on success.
pub fn execute(
    public: &RomePublicInput,
    witness: &RomeWitnessInput,
) -> [u8; rome_zk_layouts::public_values::PUBLIC_VALUES_LEN] {
    execute_checked(public, witness).unwrap_or_else(|e| panic!("rome guest refused: {e}"))
}

fn execute_checked(
    public: &RomePublicInput,
    witness: &RomeWitnessInput,
) -> Result<[u8; rome_zk_layouts::public_values::PUBLIC_VALUES_LEN], RomeGuestError> {
    // (1) Shape checks.
    if public.open_unix_ts < 0 {
        return Err(RomeGuestError::NegativeOpenTs);
    }
    if public.max_drift_secs == 0 {
        return Err(RomeGuestError::MaxDriftSecsZero);
    }
    if public.blocks.is_empty() {
        return Err(RomeGuestError::EmptyBlockRange);
    }
    if witness.witnesses.len() != public.blocks.len() {
        return Err(RomeGuestError::WitnessCountMismatch {
            blocks: public.blocks.len(),
            witnesses: witness.witnesses.len(),
        });
    }
    if public.chunk_bodies.len() != public.expected_count as usize {
        return Err(RomeGuestError::ExpectedCountMismatch {
            given: public.chunk_bodies.len(),
            expected: public.expected_count,
        });
    }

    // (2) DA binding: acc over the chunk bodies, accelerated keccak.
    let (_root, forced_root, inbox_commitment) = da::commitment(
        public.chain_id,
        public.batch,
        public.open_slot,
        public.expected_count,
        &public.chunk_bodies,
    );

    // (3) Channel binding: decode must equal the witnessed blocks, block for block.
    let decoded = channel::decode(&public.chunk_bodies);
    channel::check_equal(&decoded, &public.blocks)?;

    // (4) Chain rules are baked into this ELF — never host-supplied: `RomePublicInput`
    // (wire v2) no longer carries a `chain_config` field at all. `public.chain_id` is asserted against
    // the embedded config's own chain id so a proof under this ELF's vkey can only ever claim ITS
    // chain's rules — the per-chain registry entry already binds vkey to chain, so no
    // separate on-chain commitment of the config is needed.
    let embedded_config = crate::chain_config::embedded_chain_config();
    if embedded_config.chain_id != public.chain_id {
        return Err(RomeGuestError::ChainConfigIdMismatch {
            embedded: embedded_config.chain_id,
            public: public.chain_id,
        });
    }
    let fee_recipient = crate::chain_config::embedded_fee_recipient();

    // (5) Per-block chaining, drift bound, header-rule assertion, stateless validation (guest-reth's own
    // path).
    let chain_spec = guest_reth::get_chain_spec(&embedded_config);
    let (last_block_hash, gas_used) = chain::chain_and_execute(
        &public.blocks,
        &witness.witnesses,
        &public.parent_header,
        chain_spec,
        public.open_unix_ts as u64,
        public.max_drift_secs,
        public.chain_id,
        fee_recipient,
    )?;

    // (6) Commit public values v2.
    let first_number = public.blocks[0].header.number;
    let last_number = public.blocks[public.blocks.len() - 1].header.number;
    let state_root = public.blocks[public.blocks.len() - 1].header.state_root;
    let pv = rome_zk_layouts::public_values::PublicValues {
        chain_id: public.chain_id,
        first_number,
        last_number,
        open_unix_ts: public.open_unix_ts as u64,
        max_drift_secs: public.max_drift_secs,
        gas_used,
        parent_hash: chain::header_hash(&public.parent_header).0,
        last_block_hash: last_block_hash.0,
        state_root: state_root.0,
        inbox_commitment,
        forced_outcome_commitment: forced_root,
    };
    Ok(rome_zk_layouts::public_values::write(&pv))
}

/// The ZisK entrypoint (`bin/guests/stateless-validator-rome/src/main.rs` calls this): two reads (public,
/// then witness — `ziskos::io::read::<T>()` itself does the bincode decode, same two-frame framing
/// `guest-reth`'s own `run()` uses), [`execute`], then `pack_zisk_outputs` + `commit_slice` per word's raw
/// little-endian bytes.
///
/// **`commit_slice`, not `commit` (verified against `ziskos::io::io` source, not assumed):**
/// `ziskos::io::commit<T>` bincode-encodes `T` first — bincode's standard configuration varint-encodes
/// integers, so `commit(&word)` would NOT reliably produce a fixed 8-byte-per-word layout. `commit_slice`
/// appends raw bytes with no encoding step, which is what the 64-fixed-LE-`u64`-word ABI
/// `header::zisk_committed_hash` reads needs — the same choice `rome-zk-bench-decode`'s own entrypoint
/// already made (its README: "commits `acc` ... then `block_count` ... as two raw slices").
///
/// **4 bytes per word, not 8 (verified against `ziskos::io::zkvm_io::write_output`'s
/// real source, real `ziskemu` execution — not assumed):** `ziskos`'s own public-output mechanism is a
/// hardware register file of exactly 64 **32-bit** slots (`set_output`'s own `assert!(id < 64, ...)`,
/// `zkvm_io::OUTPUT_WORD_SIZE = size_of::<u32>()`), so the guest may commit at most `64 * 4 = 256` raw
/// bytes in one run — not 512. `pack_zisk_outputs` returns `[u64; 64]` because the ON-CHAIN reading side
/// (`header::zisk_committed_hash`, `zk-plonk-verifier`'s `publicValues`) sees a 512-byte, 64-`u64`-word
/// buffer — but that 512-byte encoding is the PROVER's own packaging of the 64 raw 32-bit registers into
/// one SNARK field element apiece (an artifact of `cargo-zisk prove`, external to this guest's own code),
/// not what `commit_slice` itself accepts. Committing `w.to_le_bytes()` (8 bytes) 64 times panicked at
/// real `ziskemu` execution with `Maximum number of public outputs: 64` — the cursor had advanced past
/// slot 64 by the 33rd word. Each `pack_zisk_outputs` word is already `<= u32::MAX` by construction (its
/// own doc), so truncating to `u32` here loses nothing.
pub fn run() {
    let public: RomePublicInput = ziskos::io::read();
    let witness: RomeWitnessInput = ziskos::io::read();
    let pv_bytes = execute(&public, &witness);
    let words = rome_zk_layouts::public_values::pack_zisk_outputs(&pv_bytes);
    for w in words {
        ziskos::io::commit_slice(&(w as u32).to_le_bytes());
    }
}
