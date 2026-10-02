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
pub fn commitment(
    chain_id: u64,
    batch: u64,
    open_slot: u64,
    expected_count: u32,
    chunk_bodies: &[Vec<u8>],
) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let h = hash_fn();
    let chunk_hashes: Vec<[u8; 32]> = chunk_bodies.iter().map(|body| h.hashv(&[body])).collect();
    let leaves: Vec<[u8; 32]> = chunk_hashes
        .iter()
        .enumerate()
        .map(|(i, hash)| rome_zk_merkle::indexed_leaf(&h, i as u32, hash))
        .collect();
    let root = rome_zk_merkle::root(&h, &leaves);
    let forced_root = rome_zk_layouts::forced_empty_root(&h);
    let acc = rome_zk_layouts::acc(
        &h,
        chain_id,
        batch,
        open_slot,
        expected_count,
        &root,
        &forced_root,
    );
    (root, forced_root, acc)
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
}
