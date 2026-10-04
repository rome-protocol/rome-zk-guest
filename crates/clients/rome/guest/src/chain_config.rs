//! The chain's rules are baked into the guest at compile time: a stateless
//! validator proves consensus-validity, not derivation-canonicality — a host-supplied `chain_config`
//! previously let a prover claim a different chain id, hardfork
//! schedule, or EIP-1559 params for the SAME batch, still consensus-valid, still accepted. Baking the
//! genesis config into the ELF at build time closes that: a proof under this ELF's vkey can only ever
//! claim ITS chain's rules, and the per-chain registry entry (`["registry", chain_id]`) already binds
//! vkey to chain, so no separate on-chain commitment of the config is needed.
//!

use std::sync::OnceLock;

use alloy_genesis::{ChainConfig, Genesis};
use alloy_primitives::Address;

/// The chain's genesis file, embedded at compile time. `ROME_CHAIN_GENESIS` is set by this repo's root
/// `.cargo/config.toml` (see that file's own doc for why the root, not the bin crate, needs to set it),
/// and `bin/guests/stateless-validator-rome/build-elf.sh --genesis PATH` points it at your chain's genesis
/// for one build. The checked-in default is `chains/tiber-200101.genesis.json`, an example chain. The
/// `embedded_config_matches_the_deployment_genesis` test checks the embedded copy against the chain's genesis.
const EMBEDDED_GENESIS_JSON: &str = include_str!(env!("ROME_CHAIN_GENESIS"));

/// Parses the embedded genesis file once and caches it — [`embedded_chain_config`] and
/// [`embedded_fee_recipient`] are both called every guest run (`run::execute_checked`), and a JSON parse
/// on the zkVM's step-metered path is not free: an un-cached version of this function measurably
/// increased the honest-input step count in a `ziskemu` run by parsing the same small file twice.
/// Caching avoids that repeated parse; both accessors read the same cached genesis.
/// `OnceLock` is
/// `Sync`-safe but this guest is single-threaded regardless (one `run()` call per ZisK execution).
fn embedded_genesis() -> &'static Genesis {
    static GENESIS: OnceLock<Genesis> = OnceLock::new();
    GENESIS.get_or_init(|| {
        serde_json::from_str(EMBEDDED_GENESIS_JSON).expect(
            "ROME_CHAIN_GENESIS: embedded genesis file failed to parse as a genesis document",
        )
    })
}

/// The chain's fee recipient (`header.beneficiary`/`coinbase`) has one source:
/// the genesis `coinbase` field itself (all zeros when the genesis has none), not a second,
/// independently-settable `ROME_FEE_RECIPIENT` build-time env var that could silently disagree with the
/// genesis this same ELF embeds. A build that wants a different fee recipient changes the genesis file,
/// the one place `rome-zk-derive` and the sequencer also read it from (their own loaded genesis) — never
/// a second knob only this guest understood.
pub fn embedded_fee_recipient() -> Address {
    embedded_genesis().coinbase
}

/// Returns the embedded genesis's `config` object — the same shape `guest_reth::get_chain_spec` already
/// consumes, so the call site changes only where the config COMES from, not how it is used.
pub fn embedded_chain_config() -> ChainConfig {
    embedded_genesis().config.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The embedded genesis document as plain JSON, read independently of the `Genesis` type the accessors
    /// use, so the tests below compare the accessors against what the file itself says.
    fn embedded_json() -> serde_json::Value {
        serde_json::from_str(EMBEDDED_GENESIS_JSON).expect("embedded genesis must be valid JSON")
    }

    /// The embedded config carries the chain id written in the genesis file this build embeds — whichever
    /// chain that is (200101 for the checked-in example genesis, another id when the build names another
    /// genesis through `ROME_CHAIN_GENESIS`).
    #[test]
    fn embedded_chain_config_carries_the_genesis_chain_id() {
        let expected = embedded_json()["config"]["chainId"]
            .as_u64()
            .expect("the embedded genesis must have a numeric config.chainId");
        assert_ne!(expected, 0, "a genesis chain id of 0 is not a chain");
        assert_eq!(embedded_chain_config().chain_id, expected);
    }

    /// The embedded genesis's own `coinbase` field is the fee recipient (all zeros when the genesis has no
    /// `coinbase`, which is what `alloy_genesis` also assumes) — it is the genesis file driving it, not a
    /// second env var.
    #[test]
    fn embedded_fee_recipient_is_the_genesis_coinbase() {
        let expected = match embedded_json().get("coinbase").and_then(|v| v.as_str()) {
            Some(text) => text
                .parse::<Address>()
                .expect("the embedded genesis's coinbase must be an address"),
            None => Address::ZERO,
        };
        assert_eq!(embedded_fee_recipient(), expected);
        assert_eq!(embedded_fee_recipient(), embedded_genesis().coinbase);
    }

    /// The embedded config must match the canonical genesis config.
    /// The test checks equality by
    /// comparing each side's re-serialized JSON (a value-level, not textual, comparison: field order and
    /// whitespace in either file are not the fact being pinned). Skips LOUD (not silently, not a hard
    /// failure) when the parent workspace is not present alongside this fork checkout — this crate's own
    /// tests must still pass in the fork's standalone CI, which checks out only this repo.
    #[test]
    fn embedded_config_matches_the_deployment_genesis() {
        // The deployment's own genesis file, if the environment names one: this check compares the embedded copy
        // with the genesis the chain was started from, and skips when no such file is given.
        let Some(rome_zk_genesis_path) = std::env::var_os("GUEST_CHECK_GENESIS_JSON") else {
            eprintln!(
                "SKIPPED: embedded_config_matches_the_deployment_genesis — set \
                 GUEST_CHECK_GENESIS_JSON to the chain's genesis.json to run this check."
            );
            return;
        };
        let raw = std::fs::read_to_string(&rome_zk_genesis_path)
            .expect("GUEST_CHECK_GENESIS_JSON must name a readable genesis file");
        let rome_zk_genesis: Genesis =
            serde_json::from_str(&raw).expect("the deployment genesis.json must parse");

        let embedded = embedded_chain_config();
        let embedded_json =
            serde_json::to_value(&embedded).expect("embedded ChainConfig must serialize");
        let rome_zk_json = serde_json::to_value(&rome_zk_genesis.config)
            .expect("rome-zk's ChainConfig must serialize");
        assert_eq!(
            embedded_json, rome_zk_json,
            "the genesis embedded in this guest has drifted from the deployment's genesis.json — the \
             embedded copy must be re-synced"
        );
    }
}
