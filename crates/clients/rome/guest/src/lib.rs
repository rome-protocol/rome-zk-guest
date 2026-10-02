//! `guest-rome`: the ZisK guest that proves one finalized batch.
//! Unlike `guest-reth` (one block, keccak(header) committed, no DA binding), this guest
//! covers a whole batch's block range `first..=last`: it binds the batch's inbox DA bytes (chunk bodies)
//! to the executed blocks via the channel decoder, chains + stateless-validates each block in order
//! (reusing `guest-reth`'s own recovery/validation path unmodified), and commits the public
//! values v2 (208 bytes, packed into ZisK's 64-word output ABI).
//!
//! Module split (mirrors `rome-zk-bench-decode`'s host-testable-core / thin-entrypoint pattern):
//! - [`input`] — the wire contract (`RomePublicInput`, `RomeWitnessInput`), RLP-compat bincode adapters.
//! - [`da`] — DA binding: `acc` over the chunk bodies, with ZisK-accelerated keccak.
//! - [`channel`] — decode + block-for-block equality against the witnessed blocks.
//! - [`chain`] — parent-hash chaining, contiguous numbering, the drift bound, per-block header-rule
//!   assertion, stateless validation.
//! - [`chain_config`] — the chain's rules, baked into the ELF at compile time: no more
//!   host-supplied `chain_config`.
//! - [`error`] — named refusals (every check's failure mode, panicked with its own name in [`run::execute`]).
//! - [`run`] — orchestration: [`run::execute`] (no `ziskos` dependency, host-testable) and [`run::run`]
//!   (the ZisK entrypoint `bin/guests/stateless-validator-rome` calls).

pub mod chain;
pub mod chain_config;
pub mod channel;
pub mod da;
pub mod error;
pub mod input;
pub mod run;

pub use error::RomeGuestError;
pub use input::{RomePublicInput, RomeWitnessInput};
pub use run::{execute, run};
