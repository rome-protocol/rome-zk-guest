//! Channel binding: the decoded DA bytes must equal the witnessed
//! blocks' own bodies, block for block — the check that makes an `always` proof mean "the sequencer
//! executed exactly the DA bytes" rather than merely "executed some valid chain".

use alloy_eips::eip2718::Encodable2718;
use reth_ethereum_primitives::Block;

use crate::error::RomeGuestError;

/// `Frame::from_bytes` each chunk body → `reassemble` (accepts any frame order, refuses a foreign
/// `channel_id` or a missing frame by name) → `decode_stream_pure` (pure-Rust `ruzstd`, the ZisK target
/// has no C toolchain) → `Vec<rome_zk_channel::Block>`. Panics (named, via `RomeGuestError`'s own
/// `Display`) on any stage failure — `rome_zk_channel::ChannelError` already carries named variants
/// (`ChannelIdMismatch`, `MissingFrame`, `DuplicateFrame`), reused via `.expect()` rather than
/// wrapped a second time.
pub fn decode(chunk_bodies: &[Vec<u8>]) -> Vec<rome_zk_channel::Block> {
    let frames: Vec<rome_zk_channel::Frame> = chunk_bodies
        .iter()
        .map(|b| {
            rome_zk_channel::Frame::from_bytes(b)
                .expect("channel decode: a chunk body is not a valid frame")
        })
        .collect();
    let compressed = rome_zk_channel::reassemble(&frames).expect(
        "channel decode: reassemble failed (foreign channel_id, missing, or duplicate frame)",
    );
    rome_zk_channel::decode_stream_pure(&compressed)
        .expect("channel decode: ruzstd decompress or RLP decode failed")
}

/// Checks `decoded[i]` against the witnessed `blocks[i]` for every `i`:
/// `number`, `timestamp`, and the RLP/EIP-2718-encoded tx list, byte for byte. The count itself is
/// checked first (`ChannelBlockCountMismatch`) so an index-out-of-range never happens.
pub fn check_equal(
    decoded: &[rome_zk_channel::Block],
    blocks: &[Block],
) -> Result<(), RomeGuestError> {
    if decoded.len() != blocks.len() {
        return Err(RomeGuestError::ChannelBlockCountMismatch {
            decoded: decoded.len(),
            expected: blocks.len(),
        });
    }
    for (i, (d, b)) in decoded.iter().zip(blocks.iter()).enumerate() {
        if d.number != b.header.number {
            return Err(RomeGuestError::ChannelBlockMismatch {
                index: i,
                field: "number",
            });
        }
        if d.timestamp != b.header.timestamp {
            return Err(RomeGuestError::ChannelBlockMismatch {
                index: i,
                field: "timestamp",
            });
        }
        // `gas_limit` comes from the stream — the derivation
        // rule does not fix it, but it must still be the one the DA bytes actually carry, not whatever
        // the host-supplied witnessed block happens to say. A +1 mutation on the
        // batch-3930 input committed a different `last_block_hash` with the honest `state_root`.
        if d.gas_limit != b.header.gas_limit {
            return Err(RomeGuestError::ChannelBlockMismatch {
                index: i,
                field: "gas_limit",
            });
        }
        if d.txs.len() != b.body.transactions.len() {
            return Err(RomeGuestError::ChannelBlockMismatch {
                index: i,
                field: "tx_count",
            });
        }
        for (dtx, btx) in d.txs.iter().zip(b.body.transactions.iter()) {
            let mut encoded = Vec::new();
            btx.encode_2718(&mut encoded);
            if dtx.as_ref() != encoded.as_slice() {
                return Err(RomeGuestError::ChannelBlockMismatch {
                    index: i,
                    field: "txs",
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `gas_limit` defaults to 40,000,000 — every existing caller's decoded fixture already uses that
    /// value, so a test only needs to override it explicitly when exercising the gas_limit check itself.
    fn sample_reth_block(number: u64, timestamp: u64) -> Block {
        Block {
            header: alloy_consensus::Header {
                number,
                timestamp,
                gas_limit: 40_000_000,
                ..Default::default()
            },
            body: Default::default(),
        }
    }

    /// An empty-block channel decode must equal an empty witnessed range with no mismatch.
    #[test]
    fn check_equal_accepts_matching_empty_blocks() {
        let decoded = vec![rome_zk_channel::Block {
            number: 5,
            timestamp: 1_757_000_005,
            gas_limit: 40_000_000,
            txs: vec![],
            deposits_end: None,
        }];
        let blocks = vec![sample_reth_block(5, 1_757_000_005)];
        assert_eq!(check_equal(&decoded, &blocks), Ok(()));
    }

    /// Mutation: a timestamp mismatch is refused by name, not silently accepted.
    #[test]
    fn check_equal_refuses_a_timestamp_mismatch_by_name() {
        let decoded = vec![rome_zk_channel::Block {
            number: 5,
            timestamp: 1_757_000_005,
            gas_limit: 40_000_000,
            txs: vec![],
            deposits_end: None,
        }];
        let blocks = vec![sample_reth_block(5, 1_757_000_006)];
        assert_eq!(
            check_equal(&decoded, &blocks),
            Err(RomeGuestError::ChannelBlockMismatch {
                index: 0,
                field: "timestamp"
            })
        );
    }

    /// A `gas_limit` mismatch between the decoded DA bytes and the witnessed header is refused by
    /// name. This test checks a +1 mutation of the witnessed header's gas limit;
    /// before this check was added, `check_equal` never looked at `gas_limit` at all.
    #[test]
    fn check_equal_refuses_a_gas_limit_mismatch_by_name() {
        let decoded = vec![rome_zk_channel::Block {
            number: 5,
            timestamp: 1_757_000_005,
            gas_limit: 40_000_000,
            txs: vec![],
            deposits_end: None,
        }];
        let mut b = sample_reth_block(5, 1_757_000_005);
        b.header.gas_limit = 40_000_001; // +1 gas-limit mutation
        assert_eq!(
            check_equal(&decoded, &[b]),
            Err(RomeGuestError::ChannelBlockMismatch {
                index: 0,
                field: "gas_limit"
            })
        );
    }

    /// Mutation: a block-count mismatch is refused by name.
    #[test]
    fn check_equal_refuses_a_count_mismatch_by_name() {
        let decoded = vec![];
        let blocks = vec![sample_reth_block(5, 1_757_000_005)];
        assert_eq!(
            check_equal(&decoded, &blocks),
            Err(RomeGuestError::ChannelBlockCountMismatch {
                decoded: 0,
                expected: 1
            })
        );
    }
}
