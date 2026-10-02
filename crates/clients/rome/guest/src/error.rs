//! Named refusals: the zkVM has no exit but a panic, so every check below produces a
//! distinct, named message — never a bare `unwrap()` — so a mutation that should refuse is provable by
//! matching the panic string, exactly like `rome-zk-bench-decode`'s own mutation tests do.

use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum RomeGuestError {
    /// `open_unix_ts` must be a real Solana clock reading — a batch account can never carry
    /// a negative one (`OpenBatch`'s own refusal), so seeing one here means the input itself is bogus.
    NegativeOpenTs,
    /// `max_drift_secs` must be a real, non-zero chain-config bound (`Some(0)` is
    /// unconstructable on chain and refused as defense in depth).
    MaxDriftSecsZero,
    /// `blocks` must cover at least one block — an empty batch is not a valid execution.
    EmptyBlockRange,
    /// `witnesses.len() != blocks.len()` — the host must supply exactly one witness per block.
    WitnessCountMismatch { blocks: usize, witnesses: usize },
    /// The recomputed `expected_count` (the number of chunk bodies given) disagrees with the batch
    /// account's own `expected_count` field.
    ExpectedCountMismatch { given: usize, expected: u32 },
    /// The channel decoder recovered a different number of blocks than the witnessed range.
    ChannelBlockCountMismatch { decoded: usize, expected: usize },
    /// One decoded channel block disagrees with the witnessed block at the same index, in the named
    /// field — this is the binding that makes an `always` proof mean "the sequencer executed exactly the
    /// DA bytes".
    ChannelBlockMismatch { index: usize, field: &'static str },
    /// `public.chain_id` disagrees with the chain id embedded in this ELF's own baked-in genesis config
    /// — a proof under this chain's vkey can only ever claim its chain's rules.
    ChainConfigIdMismatch { embedded: u64, public: u64 },
    /// `blocks[i].header.parent_hash` does not chain to the previous block's hash (or, for `i == 0`, to
    /// `keccak(rlp(parent_header))`).
    ParentChainBroken { index: usize },
    /// One of the derivation RULE's fixed header fields (`mixHash`/`prevRandao`, `beneficiary`,
    /// `extraData`, `withdrawalsRoot`, `parentBeaconBlockRoot`, `blobGasUsed`, `excessBlobGas`) disagrees
    /// with `rome_zk_executor_api::canonical_header_rule`'s value for this block.
    /// A stateless validator proves consensus-validity, not derivation-canonicality, so
    /// every rule-fixed field must be asserted here, never merely consensus-bounded. Checked BEFORE
    /// stateless validation of the same block.
    HeaderRuleViolated { index: usize, field: &'static str },
    /// `blocks[i].header.number != first + i` — the batch's block range is not contiguous.
    NonContiguousBlockNumber {
        index: usize,
        expected: u64,
        got: u64,
    },
    /// `blocks[i].header.timestamp > open_unix_ts + max_drift_secs` (the one-sided drift
    /// bound).
    DriftBoundExceeded {
        index: usize,
        timestamp: u64,
        bound: u64,
    },
    /// Stateless validation itself (reth's own path, reused unmodified) refused the block.
    StatelessValidationFailed { index: usize, reason: String },
}

impl fmt::Display for RomeGuestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NegativeOpenTs => write!(f, "NegativeOpenTs: open_unix_ts is negative — not a real Clock reading"),
            Self::MaxDriftSecsZero => write!(f, "MaxDriftSecsZero: max_drift_secs must be non-zero"),
            Self::EmptyBlockRange => write!(f, "EmptyBlockRange: blocks must contain at least one block"),
            Self::WitnessCountMismatch { blocks, witnesses } => write!(
                f,
                "WitnessCountMismatch: {blocks} blocks but {witnesses} witnesses"
            ),
            Self::ExpectedCountMismatch { given, expected } => write!(
                f,
                "ExpectedCountMismatch: {given} chunk bodies given, batch account expects {expected}"
            ),
            Self::ChannelBlockCountMismatch { decoded, expected } => write!(
                f,
                "ChannelBlockCountMismatch: channel decoded {decoded} blocks, witnessed range has {expected}"
            ),
            Self::ChannelBlockMismatch { index, field } => {
                write!(f, "ChannelBlockMismatch: index {index}, field {field}")
            }
            Self::ChainConfigIdMismatch { embedded, public } => write!(
                f,
                "ChainConfigIdMismatch: embedded chain id {embedded} != public.chain_id {public}"
            ),
            Self::ParentChainBroken { index } => write!(f, "ParentChainBroken: index {index}"),
            Self::HeaderRuleViolated { index, field } => {
                write!(f, "HeaderRuleViolated: index {index}, field {field}")
            }
            Self::NonContiguousBlockNumber { index, expected, got } => write!(
                f,
                "NonContiguousBlockNumber: index {index}, expected number {expected}, got {got}"
            ),
            Self::DriftBoundExceeded { index, timestamp, bound } => write!(
                f,
                "DriftBoundExceeded: index {index}, timestamp {timestamp} exceeds bound {bound}"
            ),
            Self::StatelessValidationFailed { index, reason } => write!(
                f,
                "StatelessValidationFailed: index {index}: {reason}"
            ),
        }
    }
}

impl std::error::Error for RomeGuestError {}
