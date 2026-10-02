//! `ExecutionClient` wiring for `guest-rome`. Unlike `input-reth` this crate does not
//! fetch from an Ethereum RPC directly — a rome batch's input is a Solana zk-inbox read (chunk bodies +
//! batch account) plus a reth-verifier `debug_executionWitness` fetch, built by `rome-zk-prover-input`.
//! That host generator needs Solana RPC client dependencies this fork does not carry, and would
//! pull this fork's guest types the other way around.

use anyhow::Result;
use async_trait::async_trait;
use zisk_sdk::ZiskStdin;

pub use guest_rome as guest;
use input_core::{BlockStats, ExecutionClient, InputStats, RpcConfig};

#[derive(Default)]
pub struct RomeClient;

#[async_trait]
impl ExecutionClient for RomeClient {
    fn name(&self) -> &'static str {
        "rome"
    }

    fn display_name(&self) -> &'static str {
        "Rome"
    }

    async fn from_rpc(
        &self,
        _config: &RpcConfig,
        _block_number: u64,
    ) -> Result<(ZiskStdin, BlockStats)> {
        anyhow::bail!(
            "rome inputs are built by rome-zk-prover-input (rome-zk repo), not fetched by a single-block \
             RPC call — a rome guest input covers a whole batch's block range plus its inbox chunk \
             bodies, which is a Solana read, not an Ethereum JSON-RPC one"
        )
    }

    fn run(&self) {
        guest_rome::run();
    }

    fn input_stats(&self, stdin: &ZiskStdin) -> Result<Option<InputStats>> {
        let buf = stdin.read_data();
        let public = guest_rome::RomePublicInput::deserialize(input_core::first_frame(&buf)?);
        let first = public.blocks.first().map(|b| b.header.number).unwrap_or(0);
        let tx_count: usize = public
            .blocks
            .iter()
            .map(|b| b.body.transactions.len())
            .sum();
        let gas_used: u64 = public.blocks.iter().map(|b| b.header.gas_used).sum();
        Ok(Some(InputStats {
            block_number: first,
            tx_count,
            gas_used,
        }))
    }
}
