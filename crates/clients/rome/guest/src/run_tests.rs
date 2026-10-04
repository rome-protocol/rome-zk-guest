//! Host tests of the whole guest logic: the stream rule on synthetic streams, the real recorded batches
//! (reset6 batch 1 and batch 3930) through `execute` to exactly the 208 bytes their sidecars record, and
//! stream mutations on a real batch refused by name.
//!
//! The recorded `.bin` files are wire v2 (no deposit fields). Each is migrated to v3 here, in the test, with
//! an empty deposit range. The fixtures live in the parent rome-zk tree (`fixtures/prover-input`), which
//! this crate already needs for its path dependencies.

use super::*;
use crate::input::{BlockRlp, HeaderRlp};
use alloy_consensus::Header;
use reth_ethereum_primitives::Block;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../../../fixtures/prover-input"
);

/// The wire v2 public input, as the recorded `.bin` files carry it (everything in v3 but the deposit range).
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RomePublicInputV2 {
    chain_id: u64,
    batch: u64,
    open_slot: u64,
    open_unix_ts: i64,
    max_drift_secs: u64,
    expected_count: u32,
    chunk_bodies: Vec<Vec<u8>>,
    #[serde_as(as = "HeaderRlp")]
    parent_header: Header,
    #[serde_as(as = "Vec<BlockRlp>")]
    blocks: Vec<Block>,
}

/// Reads one recorded batch: the two `write_slice` frames (8-byte little-endian length, payload, zero padding
/// to 8 bytes), the public one migrated to v3 with no deposits, and the sidecar's expected 208 bytes.
fn load(name: &str) -> (RomePublicInput, RomeWitnessInput, Vec<u8>) {
    let raw = std::fs::read(format!("{FIXTURES}/{name}.bin")).expect("read the recorded batch");
    let public_len = u64::from_le_bytes(raw[0..8].try_into().unwrap()) as usize;
    let public_bytes = &raw[8..8 + public_len];
    let witness_at = 8 + public_len + (8 - public_len % 8) % 8;
    let witness_len =
        u64::from_le_bytes(raw[witness_at..witness_at + 8].try_into().unwrap()) as usize;
    let witness_bytes = &raw[witness_at + 8..witness_at + 8 + witness_len];

    let (v2, _): (RomePublicInputV2, usize) =
        bincode::serde::decode_from_slice(public_bytes, bincode::config::standard())
            .expect("the recorded public frame decodes as wire v2");
    let public = RomePublicInput {
        chain_id: v2.chain_id,
        batch: v2.batch,
        open_slot: v2.open_slot,
        open_unix_ts: v2.open_unix_ts,
        max_drift_secs: v2.max_drift_secs,
        expected_count: v2.expected_count,
        chunk_bodies: v2.chunk_bodies,
        parent_header: v2.parent_header,
        blocks: v2.blocks,
        settlement_program: [0u8; 32],
        deposit_from: 0,
        deposit_hash_from: [0u8; 32],
        deposits: vec![],
    };
    let witness = RomeWitnessInput::deserialize(witness_bytes);

    let sidecar: serde_json::Value = serde_json::from_slice(
        &std::fs::read(format!("{FIXTURES}/{name}.json")).expect("read the sidecar"),
    )
    .expect("the sidecar is JSON");
    let h32 = |k: &str| -> [u8; 32] {
        hex::decode(sidecar[k].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    };
    let pv = rome_zk_layouts::public_values::PublicValues {
        chain_id: sidecar["chain_id"].as_u64().unwrap(),
        first_number: sidecar["first_number"].as_u64().unwrap(),
        last_number: sidecar["last_number"].as_u64().unwrap(),
        open_unix_ts: sidecar["open_unix_ts"].as_u64().unwrap(),
        max_drift_secs: sidecar["max_drift_secs"].as_u64().unwrap(),
        gas_used: sidecar["gas_used"].as_u64().unwrap(),
        parent_hash: h32("parent_hash"),
        last_block_hash: h32("last_block_hash"),
        state_root: h32("state_root"),
        inbox_commitment: h32("inbox_commitment"),
        forced_outcome_commitment: h32("forced_outcome_commitment"),
    };
    (
        public,
        witness,
        rome_zk_layouts::public_values::write(&pv).to_vec(),
    )
}

#[test]
fn reset6_batch_1_returns_exactly_the_208_bytes_in_its_sidecar() {
    let (public, witness, expected) = load("txv1-dev-reset6-batch-1");
    assert_eq!(expected.len(), 208);
    assert_eq!(execute(&public, &witness).to_vec(), expected);
}

#[test]
fn batch_3930_returns_exactly_the_208_bytes_in_its_sidecar() {
    let (public, witness, expected) = load("txv1-dev-batch-3930");
    assert_eq!(expected.len(), 208);
    assert_eq!(execute(&public, &witness).to_vec(), expected);
}

// ---- stream mutations on a real batch, through the whole guest ------------------------------------

/// A zstd frame holding `data` as raw (stored) blocks: a decoder-valid stream with no compressor, which the
/// guest's pure-Rust decoder reads like any other frame.
fn zstd_stored(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x28, 0xB5, 0x2F, 0xFD];
    out.push(0xE0); // single segment, an 8-byte content size, no checksum
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    let mut chunks: Vec<&[u8]> = data.chunks(128 * 1024).collect();
    if chunks.is_empty() {
        chunks.push(&[]);
    }
    let last = chunks.len() - 1;
    for (i, c) in chunks.into_iter().enumerate() {
        let header = ((c.len() as u32) << 3) | u32::from(i == last); // raw block, last flag
        out.extend_from_slice(&header.to_le_bytes()[..3]);
        out.extend_from_slice(c);
    }
    out
}

/// Decodes the batch's channel stream, lets `mutate` change it, and writes it back as new chunk bodies.
fn restream(public: &mut RomePublicInput, mutate: impl FnOnce(&mut Vec<rome_zk_channel::Block>)) {
    let mut blocks = channel::decode(&public.chunk_bodies);
    mutate(&mut blocks);
    let compressed = zstd_stored(&alloy_rlp::encode(&blocks));
    let frames = rome_zk_channel::cut_frames(
        public.chain_id,
        public.batch,
        &compressed,
        rome_zk_channel::DEFAULT_MAX_FRAME_BODY_LEN,
    );
    public.chunk_bodies = frames.iter().map(|f| f.to_bytes()).collect();
    public.expected_count = frames.len() as u32;
}

fn a_deposit() -> DepositInput {
    DepositInput {
        sender: [0x44; 32],
        recipient: [0x55; 20],
        amount_gwei: 7,
    }
}

#[test]
fn restreaming_without_a_change_still_gives_the_recorded_stream_rule_result() {
    // Guards the helper: an unchanged stream re-encoded must still pass the stream rule (it stops later,
    // in stateless validation only if something else were wrong; here it must reach the end).
    let (mut public, witness, expected) = load("txv1-dev-batch-3930");
    restream(&mut public, |_| {});
    // The re-encoded stream changes `acc` (bytes 144..176, the inbox commitment), nothing else.
    let got = execute_checked(&public, &witness).expect("an unchanged stream is accepted");
    assert_eq!(got[..144], expected[..144]);
    assert_eq!(got[176..], expected[176..]);
    assert_ne!(got[144..176], expected[144..176]);
}

/// A fifth field in a deposit-free batch: the stream ends above the range's end.
#[test]
fn a_fifth_field_in_a_deposit_free_batch_is_refused_by_name() {
    let (mut public, witness, _) = load("txv1-dev-batch-3930");
    restream(&mut public, |blocks| {
        let last = blocks.len() - 1;
        blocks[last].deposits_end = Some(1);
    });
    assert_eq!(
        execute_checked(&public, &witness),
        Err(RomeGuestError::DepositsEndMismatch { last: 1, to: 0 })
    );
}

/// A fifth field equal to the previous value (here `from`, before block 0) is refused by name.
#[test]
fn an_equal_fifth_field_is_refused_by_name() {
    let (mut public, witness, _) = load("txv1-dev-batch-3930");
    restream(&mut public, |blocks| blocks[0].deposits_end = Some(0));
    assert_eq!(
        execute_checked(&public, &witness),
        Err(RomeGuestError::DepositsEndRefused {
            block_index: 0,
            previous: 0,
            got: 0
        })
    );
}

/// A decreasing fifth field is refused by name.
#[test]
fn a_decreasing_fifth_field_is_refused_by_name() {
    let (mut public, witness, _) = load("txv1-dev-batch-3930");
    public.deposit_from = 5;
    public.deposits = vec![a_deposit(); 2];
    restream(&mut public, |blocks| {
        blocks[0].deposits_end = Some(7);
        blocks[1].deposits_end = Some(6);
    });
    assert_eq!(
        execute_checked(&public, &witness),
        Err(RomeGuestError::DepositsEndRefused {
            block_index: 1,
            previous: 7,
            got: 6
        })
    );
}

/// An end value other than `to`: the range has a deposit and the stream never reaches it, or passes it.
#[test]
fn an_end_value_other_than_to_is_refused_by_name() {
    let (mut public, witness, _) = load("txv1-dev-batch-3930");
    public.deposits = vec![a_deposit()];
    // No fifth field at all: the stream stays at `from` = 0, the range ends at 1.
    assert_eq!(
        execute_checked(&public, &witness),
        Err(RomeGuestError::DepositsEndMismatch { last: 0, to: 1 })
    );
    // A fifth field past the range.
    restream(&mut public, |blocks| blocks[3].deposits_end = Some(2));
    assert_eq!(
        execute_checked(&public, &witness),
        Err(RomeGuestError::DepositsEndMismatch { last: 2, to: 1 })
    );
}

// ---- the stream rule and the slices, on synthetic streams -----------------------------------------

fn stream(ends: &[Option<u64>]) -> Vec<rome_zk_channel::Block> {
    ends.iter()
        .enumerate()
        .map(|(i, e)| rome_zk_channel::Block {
            number: i as u64 + 1,
            timestamp: 1_757_000_000 + i as u64,
            gas_limit: 40_000_000,
            txs: vec![],
            deposits_end: *e,
        })
        .collect()
}

fn deposit(n: u8, amount_gwei: u64) -> DepositInput {
    DepositInput {
        sender: [n; 32],
        recipient: [n.wrapping_add(0x80); 20],
        amount_gwei,
    }
}

/// Three deposits over three blocks with an empty block between, from a non-zero `from`: each block gets
/// its slice, as `{ index: from + k, validator_index: 0, address: recipient, amount: amount_gwei }`.
#[test]
fn each_block_gets_its_slice_of_the_deposits_as_withdrawals() {
    let deposits = [deposit(1, 100), deposit(2, 200), deposit(3, 300)];
    let blocks = stream(&[Some(41), None, Some(43), None]);
    let got = withdrawals_per_block(&blocks, 40, 43, &deposits).unwrap();
    let w = |k: u64| Withdrawal {
        index: 40 + k,
        validator_index: 0,
        address: Address::from(deposits[k as usize].recipient),
        amount: deposits[k as usize].amount_gwei,
    };
    assert_eq!(got, vec![vec![w(0)], vec![], vec![w(1), w(2)], vec![]]);
}

#[test]
fn a_deposit_free_stream_gives_empty_slices() {
    let got = withdrawals_per_block(&stream(&[None, None]), 9, 9, &[]).unwrap();
    assert_eq!(got, vec![vec![], vec![]]);
}

/// The same range cut at different blocks gives different slices: a deposit moved to another block moves
/// its withdrawal with it, which the header and body checks of `chain_and_execute` then refuse.
#[test]
fn a_deposit_in_the_wrong_block_changes_the_slices() {
    let deposits = [deposit(1, 100)];
    let early = withdrawals_per_block(&stream(&[Some(1), None]), 0, 1, &deposits).unwrap();
    let late = withdrawals_per_block(&stream(&[None, Some(1)]), 0, 1, &deposits).unwrap();
    assert_eq!(early[0].len(), 1);
    assert!(early[1].is_empty());
    assert!(late[0].is_empty());
    assert_eq!(late[1], early[0]);
}

#[test]
fn an_equal_or_decreasing_value_is_refused_by_name() {
    let deposits = [deposit(1, 1), deposit(2, 2), deposit(3, 3)];
    // Equal to the previous fifth field.
    assert_eq!(
        withdrawals_per_block(&stream(&[Some(2), Some(2)]), 0, 2, &deposits),
        Err(RomeGuestError::DepositsEndRefused {
            block_index: 1,
            previous: 2,
            got: 2
        })
    );
    // Below the previous one.
    assert_eq!(
        withdrawals_per_block(&stream(&[Some(3), None, Some(2)]), 0, 3, &deposits),
        Err(RomeGuestError::DepositsEndRefused {
            block_index: 2,
            previous: 3,
            got: 2
        })
    );
    // On the first block, equal to `from`.
    assert_eq!(
        withdrawals_per_block(&stream(&[Some(4)]), 4, 4, &[]),
        Err(RomeGuestError::DepositsEndRefused {
            block_index: 0,
            previous: 4,
            got: 4
        })
    );
}

#[test]
fn an_end_value_other_than_to_is_refused_by_name_on_a_synthetic_stream() {
    let deposits = [deposit(1, 1), deposit(2, 2)];
    assert_eq!(
        withdrawals_per_block(&stream(&[Some(1), None]), 0, 2, &deposits),
        Err(RomeGuestError::DepositsEndMismatch { last: 1, to: 2 })
    );
    assert_eq!(
        withdrawals_per_block(&stream(&[None, None]), 0, 2, &deposits),
        Err(RomeGuestError::DepositsEndMismatch { last: 0, to: 2 })
    );
    assert_eq!(
        withdrawals_per_block(&stream(&[Some(3)]), 0, 2, &deposits),
        Err(RomeGuestError::DepositsEndMismatch { last: 3, to: 2 })
    );
}

/// A record is never refused on its content or on a cap: a zero amount, the zero address, and far more
/// deposits in one block than any `max_per_block` or `max_per_batch` the program could hold.
#[test]
fn a_deposit_record_is_never_refused_on_its_content_or_a_cap() {
    let mut deposits = vec![
        DepositInput {
            sender: [0; 32],
            recipient: [0; 20],
            amount_gwei: 0,
        },
        DepositInput {
            sender: [0xFF; 32],
            recipient: [0xFF; 20],
            amount_gwei: u64::MAX,
        },
    ];
    deposits.extend((0..1_000u32).map(|i| deposit(i as u8, u64::from(i))));
    let to = deposits.len() as u64;
    let got = withdrawals_per_block(&stream(&[Some(to)]), 0, to, &deposits).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].len(), 1_002);
    assert_eq!(got[0][0].amount, 0);
    assert_eq!(got[0][1].amount, u64::MAX);
}
