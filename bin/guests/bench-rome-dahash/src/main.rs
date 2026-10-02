//! Measurement harness for `guest-rome`'s DA-hash stage (`da::commitment`) alone, isolated
//! from channel decode and block execution — build with/without `guest-rome`'s `bench-software-keccak`
//! feature and diff `ziskemu -m`'s step counts (software keccak vs the ZisK-accelerated path).
//! This harness leaves the production guest's `run()` unchanged.
#![no_main]
ziskos::entrypoint!(main);

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct BenchInput {
    chain_id: u64,
    batch: u64,
    open_slot: u64,
    expected_count: u32,
    chunk_bodies: Vec<Vec<u8>>,
}

fn main() {
    let input: BenchInput = ziskos::io::read();
    let (_root, _forced_root, acc) = guest_rome::da::commitment(
        input.chain_id,
        input.batch,
        input.open_slot,
        input.expected_count,
        &input.chunk_bodies,
    );
    ziskos::io::commit_slice(&acc);
}
