//! Wire input for the `rome` guest: two bincode frames,
//! written by `ziskos::io::read()`/read by the host via `ZiskStdin::write_slice` — same framing
//! `guest-reth` uses (`RethInputPublic`/`RethInputWitness`), two separate reads so the (large) witness
//! is never held in memory while the (small) public input's own binding checks run.
//!
//! `rome-zk-prover-input` (the host generator) constructs these same two structs
//! independently — see that crate's README for why a cross-repo dependency on this crate was not used.

use alloy_consensus::Header;
use alloy_rlp::{Decodable, Encodable};
use reth_ethereum_primitives::Block;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{serde_as, DeserializeAs, SerializeAs};

/// RLP-compat serde adapter for a single [`Header`] (bincode has no native support for reth/alloy's
/// header type; every consumer of this wire format — the guest and `rome-zk-prover-input` — encodes it
/// as its canonical RLP bytes, exactly the pattern `guest-reth`'s own `BlockRlp` uses for `Block`).
pub struct HeaderRlp;

impl SerializeAs<Header> for HeaderRlp {
    fn serialize_as<S: Serializer>(source: &Header, serializer: S) -> Result<S::Ok, S::Error> {
        let mut buf = Vec::with_capacity(source.length());
        source.encode(&mut buf);
        buf.serialize(serializer)
    }
}

impl<'de> DeserializeAs<'de, Header> for HeaderRlp {
    fn deserialize_as<D: Deserializer<'de>>(deserializer: D) -> Result<Header, D::Error> {
        let buf = Vec::<u8>::deserialize(deserializer)?;
        Header::decode(&mut buf.as_slice()).map_err(serde::de::Error::custom)
    }
}

/// RLP-compat serde adapter for a single [`Block`] (same rationale as [`HeaderRlp`]; identical shape to
/// `guest-reth`'s private `BlockRlp`, redefined here since that one is not `pub`).
pub struct BlockRlp;

impl SerializeAs<Block> for BlockRlp {
    fn serialize_as<S: Serializer>(source: &Block, serializer: S) -> Result<S::Ok, S::Error> {
        let mut buf = Vec::with_capacity(source.length());
        source.encode(&mut buf);
        buf.serialize(serializer)
    }
}

impl<'de> DeserializeAs<'de, Block> for BlockRlp {
    fn deserialize_as<D: Deserializer<'de>>(deserializer: D) -> Result<Block, D::Error> {
        let buf = Vec::<u8>::deserialize(deserializer)?;
        Block::decode(&mut buf.as_slice()).map_err(serde::de::Error::custom)
    }
}

/// The batch's public input (wire v2): everything needed
/// to re-derive the DA commitment, decode the channel, and chain `first..=last` — everything but the
/// (large) per-block execution witnesses, which arrive as a second, separate read ([`RomeWitnessInput`]).
///
/// **v2 drops `chain_config`:** v1 carried a host-supplied `chain_config`, which let a
/// prover claim a different chain id/hardfork schedule/EIP-1559 params for the same batch, still
/// consensus-valid, still accepted — a stateless validator proves consensus-validity, not
/// derivation-canonicality. The chain's rules are baked into this ELF at compile time instead
/// ([`crate::chain_config`]); `run::execute_checked` asserts `public.chain_id` against the EMBEDDED
/// config's own chain id (`ChainConfigIdMismatch`), never a value this struct carries.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RomePublicInput {
    pub chain_id: u64,
    pub batch: u64,
    pub open_slot: u64,
    /// The batch account's own committed `Clock::unix_timestamp` — refused if negative
    /// (`RomeGuestError::NegativeOpenTs`), never a real on-chain reading otherwise.
    pub open_unix_ts: i64,
    pub max_drift_secs: u64,
    pub expected_count: u32,
    /// Raw chunk-account bodies, idx order — each one exactly one `rome_zk_channel::Frame::to_bytes()`
    /// encoding (19-byte frame header + compressed body slice).
    pub chunk_bodies: Vec<Vec<u8>>,
    /// The block immediately before `blocks[0]`; its hash anchors the first `parent_hash` check.
    /// This parent block is never re-executed.
    #[serde_as(as = "HeaderRlp")]
    pub parent_header: Header,
    /// The sealed blocks `first..=last`, in order, as the verifier serves them (header + body) — the
    /// guest recovers each block's signers itself via `guest_reth::recover_signers`.
    /// This contract carries no host-precomputed `public_keys` field, unlike `RethInputPublic` — see this
    /// crate's README for the resulting step-count tradeoff.
    #[serde_as(as = "Vec<BlockRlp>")]
    pub blocks: Vec<Block>,
}

impl RomePublicInput {
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serde::encode_to_vec(self, bincode::config::standard())
            .expect("RomePublicInput bincode encode cannot fail")
    }

    pub fn deserialize(bytes: &[u8]) -> Self {
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .expect("RomePublicInput bincode decode failed — malformed guest input")
            .0
    }
}

/// The batch's witness input: one execution witness per block, same
/// order as `RomePublicInput::blocks`. Kept as a second frame (never merged into the first struct) so a
/// host that only wants the public-input's binding facts (`rome-zk-prover-input --out`'s printed summary)
/// never has to hold the (much larger) witnesses in memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RomeWitnessInput {
    pub witnesses: Vec<alloy_rpc_types_debug::ExecutionWitness>,
}

impl RomeWitnessInput {
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serde::encode_to_vec(self, bincode::config::standard())
            .expect("RomeWitnessInput bincode encode cannot fail")
    }

    pub fn deserialize(bytes: &[u8]) -> Self {
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .expect("RomeWitnessInput bincode decode failed — malformed guest input")
            .0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header(number: u64) -> Header {
        Header {
            number,
            gas_used: 21_000,
            timestamp: 1_757_000_000 + number,
            ..Default::default()
        }
    }

    /// A `Header` round-trips through the bincode/RLP adapter byte-for-byte (field
    /// equality) — this is the wire the guest and `rome-zk-prover-input` must agree on.
    #[test]
    fn header_round_trips_through_bincode_rlp_adapter() {
        let h = sample_header(11);
        #[serde_as]
        #[derive(Serialize, Deserialize)]
        struct Wrap(#[serde_as(as = "HeaderRlp")] Header);
        let bytes =
            bincode::serde::encode_to_vec(Wrap(h.clone()), bincode::config::standard()).unwrap();
        let (Wrap(back), _): (Wrap, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(back, h);
    }

    /// `RomePublicInput` round-trips end to end (the shape `rome-zk-prover-input` writes and
    /// the guest reads).
    #[test]
    fn public_input_round_trips() {
        let input = RomePublicInput {
            chain_id: 200101,
            batch: 2043,
            open_slot: 96134,
            open_unix_ts: 1_789_337_436,
            max_drift_secs: 60,
            expected_count: 1,
            chunk_bodies: vec![vec![1, 2, 3]],
            parent_header: sample_header(10),
            blocks: vec![],
        };
        let bytes = input.serialize();
        let back = RomePublicInput::deserialize(&bytes);
        assert_eq!(back.chain_id, input.chain_id);
        assert_eq!(back.batch, input.batch);
        assert_eq!(back.open_unix_ts, input.open_unix_ts);
        assert_eq!(back.parent_header, input.parent_header);
        assert_eq!(back.chunk_bodies, input.chunk_bodies);
    }
}
