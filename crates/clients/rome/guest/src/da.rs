//! DA binding: `chunk_hashes = keccak(body_i)` → indexed-leaf
//! Merkle root → `acc = rome_zk_layouts::acc(...)` — the SAME functions the on-chain program, off-chain
//! `zk_inbox_client::reference_commitment` and `rome-zk-derive` use (never reimplemented here).
//!
//!
//! **Accelerated keccak:** `rome_zk_merkle::HashV` is hash-agnostic by design so a caller
//! supplies the hash function; `rome_zk_merkle::keccak256` itself dispatches on `target_os` (syscall
//! on-chain, software `sha3` elsewhere) and the ZisK riscv target is neither, so it would fall through to
//! the software path, measured at 49 steps/byte, rather than the accelerated one. This module
//! instead passes [`accelerated_keccak`] through the same `HashV` trait: it calls
//! `alloy_primitives::keccak256`, which — because `guest-rome`'s `alloy-primitives` dependency enables the
//! `native-keccak` feature (the same feature `guest-reth`'s own `Cargo.toml` turns on) — resolves to the
//! ZisK-accelerated keccak hook on the riscv target and to a plain software keccak natively (host tests),
//! with no third code path and no change to `rome-zk-layouts`/`rome-zk-merkle` themselves.

use crate::input::DepositInput;
use rome_zk_layouts::deposit::{self, DepositRecord};
use rome_zk_merkle::HashV;

/// `alloy_primitives::keccak256`-backed [`HashV`]: concatenates the (always small — 1 to 6 parts) input
/// slices into one buffer and hashes once, since `alloy_primitives::keccak256` itself only takes a single
/// byte slice (unlike `solana_program::keccak::hashv`'s multi-part form `rome_zk_merkle::keccak256`
/// wraps). The concatenation is negligible next to the hash itself for every caller in this module (a
/// chunk body, two 32-byte hashes, or a handful of `u64`/`u32` fields).
pub fn accelerated_keccak(parts: &[&[u8]]) -> [u8; 32] {
    if let [single] = parts {
        return alloy_primitives::keccak256(single).0;
    }
    let mut buf = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
    for p in parts {
        buf.extend_from_slice(p);
    }
    alloy_primitives::keccak256(&buf).0
}

/// Chooses the hash implementation `commitment` uses. Defaults to [`accelerated_keccak`],
/// the production choice; `bench-software-keccak` (off by default, used only by
/// `bin/guests/bench-rome-dahash` for software-vs-accelerated measurements) swaps in
/// `rome_zk_merkle::keccak256`'s software path instead, so the SAME `commitment` logic can be measured
/// both ways without a second implementation.
fn hash_fn() -> fn(&[&[u8]]) -> [u8; 32] {
    #[cfg(feature = "bench-software-keccak")]
    {
        rome_zk_merkle::keccak256
    }
    #[cfg(not(feature = "bench-software-keccak"))]
    {
        accelerated_keccak
    }
}

/// `(root, forced_root, acc)` over `chunk_bodies`, exactly `zk_inbox_client::reference_commitment`'s
/// formula (that crate cannot be a dependency here — it pulls `solana-client`/tokio, unbuildable for the
/// ZisK target — so this recomputes the same three calls directly against `rome-zk-merkle`/
/// `rome-zk-layouts`, the crates `reference_commitment` itself is built from).
///
/// This is the deposit-free commitment: the empty-range case of [`commitment_with_deposits`]. It stays
/// as its own function so `bin/guests/bench-rome-dahash` keeps measuring the same stage unchanged.
pub fn commitment(
    chain_id: u64,
    batch: u64,
    open_slot: u64,
    expected_count: u32,
    chunk_bodies: &[Vec<u8>],
) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let (root, forced_root, acc, _deposit_to) = commitment_with_deposits(
        chain_id,
        batch,
        open_slot,
        expected_count,
        chunk_bodies,
        &[0u8; 32],
        0,
        &[0u8; 32],
        &[],
    );
    (root, forced_root, acc)
}

/// `(root, forced_root, acc, deposit_to)` over `chunk_bodies` and the batch's deposit range
/// `[deposit_from, deposit_to)`, where `deposit_to = deposit_from + deposits.len()`.
///
/// The hash chain is extended from `deposit_hash_from` over `deposits` with
/// `rome_zk_layouts::deposit::chain_through` (indices `deposit_from + k`), and `forced_root` is
/// `rome_zk_layouts::deposit::forced_root(deposit_from, deposit_to, deposit_hash_from, h_to)`: the
/// existing empty constant when the range is empty (so a deposit-free batch has the `acc` it has always
/// had), the two-lane root otherwise. `acc` is then the unchanged `rome_zk_layouts::acc`.
///
/// No record is refused on its content here (no check on recipient, amount or count): a range the
/// settlement program bound must always be provable. `deposit_from + deposits.len()` must fit a `u64`;
/// the caller (`run::execute_checked`) refuses a range that does not before calling this.
#[allow(clippy::too_many_arguments)]
pub fn commitment_with_deposits(
    chain_id: u64,
    batch: u64,
    open_slot: u64,
    expected_count: u32,
    chunk_bodies: &[Vec<u8>],
    settlement_program: &[u8; 32],
    deposit_from: u64,
    deposit_hash_from: &[u8; 32],
    deposits: &[DepositInput],
) -> ([u8; 32], [u8; 32], [u8; 32], u64) {
    let h = hash_fn();
    let chunk_hashes: Vec<[u8; 32]> = chunk_bodies.iter().map(|body| h.hashv(&[body])).collect();
    let leaves: Vec<[u8; 32]> = chunk_hashes
        .iter()
        .enumerate()
        .map(|(i, hash)| rome_zk_merkle::indexed_leaf(&h, i as u32, hash))
        .collect();
    let root = rome_zk_merkle::root(&h, &leaves);

    let records: Vec<DepositRecord> = deposits
        .iter()
        .map(|d| DepositRecord {
            sender: d.sender,
            recipient: d.recipient,
            amount_gwei: d.amount_gwei,
        })
        .collect();
    let deposit_to = deposit_from.wrapping_add(records.len() as u64);
    let hash_to = deposit::chain_through(
        &h,
        settlement_program,
        chain_id,
        deposit_from,
        deposit_hash_from,
        &records,
    );
    let forced_root =
        deposit::forced_root(&h, deposit_from, deposit_to, deposit_hash_from, &hash_to);

    let acc = rome_zk_layouts::acc(
        &h,
        chain_id,
        batch,
        open_slot,
        expected_count,
        &root,
        &forced_root,
    );
    (root, forced_root, acc, deposit_to)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`accelerated_keccak`] must agree with `rome_zk_merkle::keccak256`'s
    /// off-chain (software `sha3`) path byte-for-byte — the two are different implementations of the same
    /// hash function and must never silently diverge; no third code path is introduced.
    #[test]
    fn accelerated_keccak_agrees_with_the_software_path_on_one_part() {
        let body = b"rome-zk chunk body: the quick brown fox jumps over the lazy dog";
        let sw = rome_zk_merkle::keccak256(&[body]);
        let hw = accelerated_keccak(&[body]);
        assert_eq!(sw, hw);
    }

    #[test]
    fn accelerated_keccak_agrees_with_the_software_path_on_multiple_parts() {
        let a = 7u32.to_le_bytes();
        let b = [0x11u8; 32];
        let sw = rome_zk_merkle::keccak256(&[&a, &b]);
        let hw = accelerated_keccak(&[&a, &b]);
        assert_eq!(sw, hw);
    }

    /// `commitment`'s `acc` over the real batch fixture's chunk bodies must equal
    /// the fixture's recorded on-chain `acc`.
    ///
    #[test]
    fn commitment_reproduces_the_real_fixtures_on_chain_acc() {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../../../fixtures/inbox/txv1-dev-batch-2043.json"
        ))
        .expect("read the committed real-batch fixture");
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let chunk_bodies: Vec<Vec<u8>> = v["chunk_bodies_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| hex::decode(h.as_str().unwrap()).unwrap())
            .collect();
        let expected_acc = hex::decode(v["acc"].as_str().unwrap()).unwrap();
        let (_root, _forced_root, acc) = commitment(
            v["chain_id"].as_u64().unwrap(),
            v["batch"].as_u64().unwrap(),
            v["open_slot"].as_u64().unwrap(),
            v["expected_count"].as_u64().unwrap() as u32,
            &chunk_bodies,
        );
        assert_eq!(acc.to_vec(), expected_acc, "acc mismatch");
    }

    /// Mutation: flipping one byte of the real fixture's chunk body must break the acc match.
    #[test]
    fn corrupting_the_fixture_chunk_body_breaks_the_acc_match() {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../../../fixtures/inbox/txv1-dev-batch-2043.json"
        ))
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let mut chunk_bodies: Vec<Vec<u8>> = v["chunk_bodies_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| hex::decode(h.as_str().unwrap()).unwrap())
            .collect();
        let last = chunk_bodies[0].len() - 1;
        chunk_bodies[0][last] ^= 0xff;
        let expected_acc = hex::decode(v["acc"].as_str().unwrap()).unwrap();
        let (_root, _forced_root, acc) = commitment(
            v["chain_id"].as_u64().unwrap(),
            v["batch"].as_u64().unwrap(),
            v["open_slot"].as_u64().unwrap(),
            v["expected_count"].as_u64().unwrap() as u32,
            &chunk_bodies,
        );
        assert_ne!(acc.to_vec(), expected_acc);
    }

    // ---- deposits ----

    const SP: [u8; 32] = [0x33; 32];

    fn sw() -> fn(&[&[u8]]) -> [u8; 32] {
        rome_zk_merkle::keccak256
    }

    fn acc_fn() -> fn(&[&[u8]]) -> [u8; 32] {
        accelerated_keccak
    }

    fn inputs() -> Vec<DepositInput> {
        vec![
            DepositInput {
                sender: [0x11; 32],
                recipient: [0x22; 20],
                amount_gwei: 1_000_000_000,
            },
            DepositInput {
                sender: [0x44; 32],
                recipient: [0x55; 20],
                amount_gwei: 2,
            },
            DepositInput {
                sender: [0x66; 32],
                recipient: [0x77; 20],
                amount_gwei: u64::MAX,
            },
        ]
    }

    fn records(d: &[DepositInput]) -> Vec<DepositRecord> {
        d.iter()
            .map(|d| DepositRecord {
                sender: d.sender,
                recipient: d.recipient,
                amount_gwei: d.amount_gwei,
            })
            .collect()
    }

    /// The accelerated and the software keccak agree on every deposit formula: the leaf, the chain
    /// (one step and a whole range), the commitment and `forced_root` (with and without a range).
    #[test]
    fn accelerated_and_software_keccak_agree_on_the_deposit_formulas() {
        let d = inputs();
        let r = records(&d);
        let seed_sw = deposit::queue_seed_hash(&sw(), &SP, 7);
        let seed_hw = deposit::queue_seed_hash(&acc_fn(), &SP, 7);
        assert_eq!(seed_sw, seed_hw);

        let leaf_sw = deposit::leaf(
            &sw(),
            &SP,
            7,
            4,
            &d[0].sender,
            &d[0].recipient,
            d[0].amount_gwei,
        );
        let leaf_hw = deposit::leaf(
            &acc_fn(),
            &SP,
            7,
            4,
            &d[0].sender,
            &d[0].recipient,
            d[0].amount_gwei,
        );
        assert_eq!(leaf_sw, leaf_hw);
        assert_eq!(
            deposit::chain_next(&sw(), &seed_sw, &leaf_sw),
            deposit::chain_next(&acc_fn(), &seed_hw, &leaf_hw)
        );

        let to_sw = deposit::chain_through(&sw(), &SP, 7, 4, &seed_sw, &r);
        let to_hw = deposit::chain_through(&acc_fn(), &SP, 7, 4, &seed_hw, &r);
        assert_eq!(to_sw, to_hw);
        assert_eq!(
            deposit::deposits_commitment(&sw(), 4, 7, &seed_sw, &to_sw),
            deposit::deposits_commitment(&acc_fn(), 4, 7, &seed_hw, &to_hw)
        );
        assert_eq!(
            deposit::forced_root(&sw(), 4, 7, &seed_sw, &to_sw),
            deposit::forced_root(&acc_fn(), 4, 7, &seed_hw, &to_hw)
        );
        assert_eq!(
            deposit::forced_root(&sw(), 4, 4, &seed_sw, &seed_sw),
            deposit::forced_root(&acc_fn(), 4, 4, &seed_hw, &seed_hw)
        );
        assert_eq!(
            deposit::forced_root(&acc_fn(), 4, 4, &seed_hw, &seed_hw),
            rome_zk_layouts::forced_empty_root(&acc_fn())
        );
    }

    /// For a synthetic range, `acc` and `forced_root` equal the host value `rome-zk-layouts` computes
    /// with software keccak, and the returned `deposit_to` is `from + count`.
    #[test]
    fn a_synthetic_range_matches_the_rome_zk_layouts_host_value() {
        let d = inputs();
        let r = records(&d);
        let bodies: Vec<Vec<u8>> = vec![vec![1, 2, 3, 4], vec![5, 6, 7]];
        let h_from = deposit::queue_seed_hash(&sw(), &SP, 200101);
        let (root, forced_root, acc, deposit_to) =
            commitment_with_deposits(200101, 12, 345, 2, &bodies, &SP, 0, &h_from, &d);

        let hosts: Vec<[u8; 32]> = bodies.iter().map(|b| sw().hashv(&[b])).collect();
        let leaves: Vec<[u8; 32]> = hosts
            .iter()
            .enumerate()
            .map(|(i, x)| rome_zk_merkle::indexed_leaf(&sw(), i as u32, x))
            .collect();
        let want_root = rome_zk_merkle::root(&sw(), &leaves);
        let h_to = deposit::chain_through(&sw(), &SP, 200101, 0, &h_from, &r);
        let want_forced = deposit::forced_root(&sw(), 0, 3, &h_from, &h_to);
        let want_acc = rome_zk_layouts::acc(&sw(), 200101, 12, 345, 2, &want_root, &want_forced);

        assert_eq!(root, want_root);
        assert_eq!(forced_root, want_forced);
        assert_eq!(acc, want_acc);
        assert_eq!(deposit_to, 3);
        assert_ne!(forced_root, rome_zk_layouts::forced_empty_root(&sw()));
    }

    /// The same three-record range as `rome-zk-layouts`' independently computed golden values
    /// (Python keccak): chain id 7, program `[0x33; 32]`, `forced_root` for `[0, 3)` and `[1, 3)`.
    #[test]
    fn forced_root_matches_the_layouts_golden_values() {
        let d = inputs();
        let hx = |b: &[u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let seed = deposit::queue_seed_hash(&sw(), &SP, 7);
        let (_r, forced, _a, to) = commitment_with_deposits(7, 1, 1, 0, &[], &SP, 0, &seed, &d);
        assert_eq!(to, 3);
        assert_eq!(
            hx(&forced),
            "34f7c42e5502c795aea99b9dc9b34a1095ea347f975609863ac1d0351b8dfee8"
        );
        // From the middle: h_1 is the chain value after the first record.
        let h1 = deposit::chain_through(&sw(), &SP, 7, 0, &seed, &records(&d)[..1]);
        assert_eq!(
            hx(&h1),
            "8c6b4a978661d6d251ed888e8f89a4cf6b18dfdfe9cd1d1a472d6196273cdf86"
        );
        let (_r, forced, _a, to) = commitment_with_deposits(7, 1, 1, 0, &[], &SP, 1, &h1, &d[1..]);
        assert_eq!(to, 3);
        assert_eq!(
            hx(&forced),
            "0f101d970e8e9e8ff754ad5c5d86950026a3353ee17449c9191511cbbeb245dc"
        );
    }

    /// An empty range gives the deposit-free commitment byte for byte, whatever the program, the
    /// start index and the hash are: `commitment` is that wrapper.
    #[test]
    fn an_empty_range_is_the_deposit_free_commitment() {
        let bodies: Vec<Vec<u8>> = vec![vec![9, 9, 9]];
        let plain = commitment(5, 6, 7, 1, &bodies);
        for (sp, from, hash) in [([0u8; 32], 0u64, [0u8; 32]), ([0x33; 32], 17, [0xab; 32])] {
            let (root, forced, acc, to) =
                commitment_with_deposits(5, 6, 7, 1, &bodies, &sp, from, &hash, &[]);
            assert_eq!((root, forced, acc), plain);
            assert_eq!(to, from);
        }
        assert_eq!(plain.1, rome_zk_layouts::forced_empty_root(&sw()));
    }
}
