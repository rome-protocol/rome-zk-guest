//! Per-block chaining, drift bound, and stateless validation:
//! `parent_hash` continuity, contiguous block numbers, the one-sided drift bound, and — reused, never
//! re-derived — `guest_reth`'s own `recover_signers` + `verify_signatures` + `validate_block_stateless`
//! path (already proved on BPF/ZisK for chain 200100).
//!
//! **Difference from `guest-reth`'s input shape:** `RethInputPublic`
//! carries a host-precomputed `public_keys: Vec<UncompressedPublicKey>` field so the guest never has to
//! run k256 signature recovery itself. `RomePublicInput` carries no
//! such field — each block's signers are recovered IN-GUEST via `guest_reth::recover_signers`, which costs
//! real extra steps per block relative to the host-precomputed shortcut. Left as an open question / a
//! candidate follow-up optimization (add a `public_keys: Vec<Vec<UncompressedPublicKey>>` field), not
//! silently worked around.

use std::sync::Arc;

use alloy_eips::eip4895::Withdrawal;
use alloy_primitives::{keccak256, Address, B256};
use alloy_rlp::Encodable;
use alloy_rpc_types_debug::ExecutionWitness;
use reth_chainspec::ChainSpec;
use reth_ethereum_primitives::Block;
use rome_zk_executor_api::{canonical_header_rule_with_withdrawals, HeaderRule};

use crate::error::RomeGuestError;

/// `keccak(rlp(header))` — the same hash a block's own `parent_hash` field must equal to chain to it.
/// Used once, to anchor `blocks[0]`'s `parent_hash` check against the input's `parent_header` (which is
/// never itself re-executed).
pub fn header_hash(header: &alloy_consensus::Header) -> B256 {
    let mut buf = Vec::with_capacity(header.length());
    header.encode(&mut buf);
    keccak256(&buf)
}

/// Asserts every rule-fixed field of `header` against `rule`. A stateless validator proves
/// consensus-validity, not derivation-canonicality: each of these
/// fields is host-supplied and only consensus-bounded otherwise, so a host could commit a different
/// (still consensus-valid) value for any of them and a plain stateless validator would accept it. Called
/// per block by `chain_and_execute`, before stateless validation of that same block.
///
fn check_header_rule(
    header: &alloy_consensus::Header,
    rule: &HeaderRule,
    index: usize,
) -> Result<(), RomeGuestError> {
    if header.mix_hash != rule.prev_randao {
        return Err(RomeGuestError::HeaderRuleViolated {
            index,
            field: "prev_randao",
        });
    }
    if header.beneficiary != rule.beneficiary {
        return Err(RomeGuestError::HeaderRuleViolated {
            index,
            field: "beneficiary",
        });
    }
    if header.extra_data != rule.extra_data {
        return Err(RomeGuestError::HeaderRuleViolated {
            index,
            field: "extra_data",
        });
    }
    if header.withdrawals_root != Some(rule.withdrawals_root) {
        return Err(RomeGuestError::HeaderRuleViolated {
            index,
            field: "withdrawals_root",
        });
    }
    if header.parent_beacon_block_root != Some(rule.parent_beacon_block_root) {
        return Err(RomeGuestError::HeaderRuleViolated {
            index,
            field: "parent_beacon_block_root",
        });
    }
    if header.blob_gas_used != Some(rule.blob_gas_used) {
        return Err(RomeGuestError::HeaderRuleViolated {
            index,
            field: "blob_gas_used",
        });
    }
    if header.excess_blob_gas != Some(rule.excess_blob_gas) {
        return Err(RomeGuestError::HeaderRuleViolated {
            index,
            field: "excess_blob_gas",
        });
    }
    Ok(())
}

/// Validates and executes `blocks[0..]` against `witnesses[0..]` in order, chaining `parent_hash` from
/// `parent_header` (or the previous block's own returned hash), checking contiguous numbering, the
/// one-sided drift bound (`timestamp <= open_unix_ts + max_drift_secs`, checked arithmetic), and — per
/// block, before stateless validation of that block — every rule-fixed header field against
/// `rome_zk_executor_api::canonical_header_rule_with_withdrawals(chain_id, header.number, fee_recipient,
/// withdrawals[i])`, and the block body's own withdrawals against `withdrawals[i]` (`withdrawals[i]` is
/// block `i`'s slice of the deposit range, empty for a block with no deposit);
/// then runs stateless validation via `guest_reth`'s own path. Returns `(last_block_hash,
/// gas_used_sum)` on success.
#[allow(clippy::too_many_arguments)]
pub fn chain_and_execute(
    blocks: &[Block],
    withdrawals: &[Vec<Withdrawal>],
    witnesses: &[ExecutionWitness],
    parent_header: &alloy_consensus::Header,
    chain_spec: Arc<ChainSpec>,
    open_unix_ts: u64,
    max_drift_secs: u64,
    chain_id: u64,
    fee_recipient: Address,
) -> Result<(B256, u64), RomeGuestError> {
    if witnesses.len() != blocks.len() {
        return Err(RomeGuestError::WitnessCountMismatch {
            blocks: blocks.len(),
            witnesses: witnesses.len(),
        });
    }
    if blocks.is_empty() {
        return Err(RomeGuestError::EmptyBlockRange);
    }
    if withdrawals.len() != blocks.len() {
        return Err(RomeGuestError::WithdrawalSliceCountMismatch {
            blocks: blocks.len(),
            slices: withdrawals.len(),
        });
    }

    let first_number = blocks[0].header.number;
    let mut prev_hash = header_hash(parent_header);
    let mut gas_used: u64 = 0;
    let mut last_hash = prev_hash;

    for (i, (block, witness)) in blocks.iter().zip(witnesses.iter()).enumerate() {
        let header = &block.header;

        if header.parent_hash != prev_hash {
            return Err(RomeGuestError::ParentChainBroken { index: i });
        }
        let expected_number = first_number + i as u64;
        if header.number != expected_number {
            return Err(RomeGuestError::NonContiguousBlockNumber {
                index: i,
                expected: expected_number,
                got: header.number,
            });
        }
        let bound = open_unix_ts
            .checked_add(max_drift_secs)
            .expect("open_unix_ts + max_drift_secs overflow — inputs out of range");
        if header.timestamp > bound {
            return Err(RomeGuestError::DriftBoundExceeded {
                index: i,
                timestamp: header.timestamp,
                bound,
            });
        }
        let rule = canonical_header_rule_with_withdrawals(
            chain_id,
            header.number,
            fee_recipient,
            &withdrawals[i],
        );
        check_header_rule(header, &rule, i)?;
        // The body must carry exactly this block's slice of the deposit range: the header's root above
        // is only a commitment to it, and the body is what execution applies.
        if block.body.withdrawals.as_ref().map(|w| w.as_slice()) != Some(withdrawals[i].as_slice())
        {
            return Err(RomeGuestError::WithdrawalsMismatch { index: i });
        }

        let public_keys = guest_reth::recover_signers(&block.body.transactions).map_err(|e| {
            RomeGuestError::StatelessValidationFailed {
                index: i,
                reason: format!("signature recovery: {e}"),
            }
        })?;
        let recovered =
            guest_reth::verify_signatures(block.clone(), chain_spec.clone(), public_keys).map_err(
                |e| RomeGuestError::StatelessValidationFailed {
                    index: i,
                    reason: format!("signature verification: {e}"),
                },
            )?;
        let block_hash =
            guest_reth::validate_block_stateless(recovered, witness.clone(), chain_spec.clone())
                .map_err(|e| RomeGuestError::StatelessValidationFailed {
                    index: i,
                    reason: format!("stateless validation: {e}"),
                })?;

        gas_used = gas_used
            .checked_add(header.gas_used)
            .expect("gas_used sum overflow — batch gas out of range");
        prev_hash = block_hash;
        last_hash = block_hash;
    }

    Ok((last_hash, gas_used))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_eips::eip4895::Withdrawals;
    use rome_zk_executor_api::canonical_header_rule;

    const CHAIN_ID: u64 = 200_101;
    const FEE_RECIPIENT: Address = Address::ZERO;

    fn header(number: u64, timestamp: u64, parent_hash: B256) -> alloy_consensus::Header {
        alloy_consensus::Header {
            number,
            timestamp,
            parent_hash,
            ..Default::default()
        }
    }

    /// A header that satisfies EVERY rule-fixed field for `(CHAIN_ID, number, FEE_RECIPIENT)` — the
    /// starting point every header-rule mutation test flips exactly one field of, so a test failure can
    /// only be attributed to that field. Each test applies one
    /// mutation at a time to an otherwise-honest header.
    fn honest_header(number: u64, timestamp: u64, parent_hash: B256) -> alloy_consensus::Header {
        let rule = canonical_header_rule(CHAIN_ID, number, FEE_RECIPIENT);
        alloy_consensus::Header {
            number,
            timestamp,
            parent_hash,
            mix_hash: rule.prev_randao,
            beneficiary: rule.beneficiary,
            extra_data: rule.extra_data,
            withdrawals_root: Some(rule.withdrawals_root),
            parent_beacon_block_root: Some(rule.parent_beacon_block_root),
            blob_gas_used: Some(rule.blob_gas_used),
            excess_blob_gas: Some(rule.excess_blob_gas),
            ..Default::default()
        }
    }

    fn block(number: u64, timestamp: u64, parent_hash: B256) -> Block {
        Block {
            header: header(number, timestamp, parent_hash),
            body: Default::default(),
        }
    }

    /// A post-Shanghai block with no withdrawals: the body carries `Some([])`, as every real block does.
    fn empty_withdrawals_body(
    ) -> alloy_consensus::BlockBody<reth_ethereum_primitives::TransactionSigned> {
        alloy_consensus::BlockBody {
            withdrawals: Some(Withdrawals::default()),
            ..Default::default()
        }
    }

    fn honest_block(number: u64, timestamp: u64, parent_hash: B256) -> Block {
        Block {
            header: honest_header(number, timestamp, parent_hash),
            body: empty_withdrawals_body(),
        }
    }

    /// An empty `blocks` slice is refused by name (`EmptyBlockRange`), not an
    /// index-out-of-range panic.
    #[test]
    fn chain_and_execute_refuses_an_empty_block_range() {
        let parent = header(9, 1_757_000_000, B256::ZERO);
        let chain_spec = reth_chainspec::ChainSpec::default();
        let err = chain_and_execute(
            &[],
            &[],
            &[],
            &parent,
            Arc::new(chain_spec),
            1_757_000_100,
            60,
            CHAIN_ID,
            FEE_RECIPIENT,
        );
        assert_eq!(err, Err(RomeGuestError::EmptyBlockRange));
    }

    /// Mutation: `witnesses.len() != blocks.len()` is refused by name before any block is touched.
    #[test]
    fn chain_and_execute_refuses_a_witness_count_mismatch() {
        let parent = header(9, 1_757_000_000, B256::ZERO);
        let b = block(10, 1_757_000_001, header_hash(&parent));
        let chain_spec = reth_chainspec::ChainSpec::default();
        let err = chain_and_execute(
            &[b],
            &[vec![]],
            &[],
            &parent,
            Arc::new(chain_spec),
            1_757_000_100,
            60,
            CHAIN_ID,
            FEE_RECIPIENT,
        );
        assert_eq!(
            err,
            Err(RomeGuestError::WitnessCountMismatch {
                blocks: 1,
                witnesses: 0
            })
        );
    }

    /// Mutation: a `parent_hash` that does not chain to `parent_header` is refused by name, before
    /// stateless validation ever runs (so this test needs no real witness).
    #[test]
    fn chain_and_execute_refuses_a_broken_parent_chain() {
        let parent = header(9, 1_757_000_000, B256::ZERO);
        let b = block(10, 1_757_000_001, B256::repeat_byte(0xAB)); // wrong parent_hash
        let witness = ExecutionWitness::default();
        let chain_spec = reth_chainspec::ChainSpec::default();
        let err = chain_and_execute(
            &[b],
            &[vec![]],
            &[witness],
            &parent,
            Arc::new(chain_spec),
            1_757_000_100,
            60,
            CHAIN_ID,
            FEE_RECIPIENT,
        );
        assert_eq!(err, Err(RomeGuestError::ParentChainBroken { index: 0 }));
    }

    /// Mutation: a timestamp past `open_unix_ts + max_drift_secs` is refused by name, before stateless
    /// validation runs.
    #[test]
    fn chain_and_execute_refuses_a_drift_bound_violation() {
        let parent = header(9, 1_757_000_000, B256::ZERO);
        let b = block(10, 1_757_000_200, header_hash(&parent)); // far past open_unix_ts + drift
        let witness = ExecutionWitness::default();
        let chain_spec = reth_chainspec::ChainSpec::default();
        let err = chain_and_execute(
            &[b],
            &[vec![]],
            &[witness],
            &parent,
            Arc::new(chain_spec),
            1_757_000_100,
            60,
            CHAIN_ID,
            FEE_RECIPIENT,
        );
        assert_eq!(
            err,
            Err(RomeGuestError::DriftBoundExceeded {
                index: 0,
                timestamp: 1_757_000_200,
                bound: 1_757_000_160
            })
        );
    }

    /// Changing only `beneficiary` must be rejected:
    /// an otherwise-honest header (every other rule field correct) with the
    /// wrong `beneficiary` is refused by name, before stateless validation ever runs.
    #[test]
    fn chain_and_execute_refuses_a_beneficiary_rule_violation() {
        let parent = honest_header(9, 1_757_000_000, B256::ZERO);
        let mut b = honest_block(10, 1_757_000_001, header_hash(&parent));
        b.header.beneficiary = Address::repeat_byte(0xAB);
        let witness = ExecutionWitness::default();
        let chain_spec = reth_chainspec::ChainSpec::default();
        let err = chain_and_execute(
            &[b],
            &[vec![]],
            &[witness],
            &parent,
            Arc::new(chain_spec),
            1_757_000_100,
            60,
            CHAIN_ID,
            FEE_RECIPIENT,
        );
        assert_eq!(
            err,
            Err(RomeGuestError::HeaderRuleViolated {
                index: 0,
                field: "beneficiary"
            })
        );
    }

    /// A flipped `mix_hash` is rejected: `prev_randao` is the field checked first,
    /// so this is also the guard against any wrong `mixHash`/`prevRandao` value.
    #[test]
    fn chain_and_execute_refuses_a_prev_randao_rule_violation() {
        let parent = honest_header(9, 1_757_000_000, B256::ZERO);
        let mut b = honest_block(10, 1_757_000_001, header_hash(&parent));
        b.header.mix_hash = B256::repeat_byte(0xCD); // a flipped mix_hash/prevRandao
        let witness = ExecutionWitness::default();
        let chain_spec = reth_chainspec::ChainSpec::default();
        let err = chain_and_execute(
            &[b],
            &[vec![]],
            &[witness],
            &parent,
            Arc::new(chain_spec),
            1_757_000_100,
            60,
            CHAIN_ID,
            FEE_RECIPIENT,
        );
        assert_eq!(
            err,
            Err(RomeGuestError::HeaderRuleViolated {
                index: 0,
                field: "prev_randao"
            })
        );
    }

    /// An `extra_data = "evil"` mutation is rejected.
    #[test]
    fn chain_and_execute_refuses_an_extra_data_rule_violation() {
        let parent = honest_header(9, 1_757_000_000, B256::ZERO);
        let mut b = honest_block(10, 1_757_000_001, header_hash(&parent));
        b.header.extra_data = alloy_primitives::Bytes::from_static(b"evil");
        let witness = ExecutionWitness::default();
        let chain_spec = reth_chainspec::ChainSpec::default();
        let err = chain_and_execute(
            &[b],
            &[vec![]],
            &[witness],
            &parent,
            Arc::new(chain_spec),
            1_757_000_100,
            60,
            CHAIN_ID,
            FEE_RECIPIENT,
        );
        assert_eq!(
            err,
            Err(RomeGuestError::HeaderRuleViolated {
                index: 0,
                field: "extra_data"
            })
        );
    }

    /// A `withdrawals_root` that is not the rule's `EMPTY_WITHDRAWALS` constant is refused by name.
    #[test]
    fn chain_and_execute_refuses_a_withdrawals_root_rule_violation() {
        let parent = honest_header(9, 1_757_000_000, B256::ZERO);
        let mut b = honest_block(10, 1_757_000_001, header_hash(&parent));
        b.header.withdrawals_root = Some(B256::repeat_byte(0xEF));
        let witness = ExecutionWitness::default();
        let chain_spec = reth_chainspec::ChainSpec::default();
        let err = chain_and_execute(
            &[b],
            &[vec![]],
            &[witness],
            &parent,
            Arc::new(chain_spec),
            1_757_000_100,
            60,
            CHAIN_ID,
            FEE_RECIPIENT,
        );
        assert_eq!(
            err,
            Err(RomeGuestError::HeaderRuleViolated {
                index: 0,
                field: "withdrawals_root"
            })
        );
    }

    /// Also refused when `withdrawals_root` is simply absent (`None`) — a v1-shaped (pre-Shanghai)
    /// header cannot pass as this chain's honest one either.
    #[test]
    fn chain_and_execute_refuses_a_missing_withdrawals_root() {
        let parent = honest_header(9, 1_757_000_000, B256::ZERO);
        let mut b = honest_block(10, 1_757_000_001, header_hash(&parent));
        b.header.withdrawals_root = None;
        let witness = ExecutionWitness::default();
        let chain_spec = reth_chainspec::ChainSpec::default();
        let err = chain_and_execute(
            &[b],
            &[vec![]],
            &[witness],
            &parent,
            Arc::new(chain_spec),
            1_757_000_100,
            60,
            CHAIN_ID,
            FEE_RECIPIENT,
        );
        assert_eq!(
            err,
            Err(RomeGuestError::HeaderRuleViolated {
                index: 0,
                field: "withdrawals_root"
            })
        );
    }

    /// A non-ZERO `parent_beacon_block_root` is refused by name (this chain has no beacon
    /// chain behind it).
    #[test]
    fn chain_and_execute_refuses_a_parent_beacon_block_root_rule_violation() {
        let parent = honest_header(9, 1_757_000_000, B256::ZERO);
        let mut b = honest_block(10, 1_757_000_001, header_hash(&parent));
        b.header.parent_beacon_block_root = Some(B256::repeat_byte(0x12));
        let witness = ExecutionWitness::default();
        let chain_spec = reth_chainspec::ChainSpec::default();
        let err = chain_and_execute(
            &[b],
            &[vec![]],
            &[witness],
            &parent,
            Arc::new(chain_spec),
            1_757_000_100,
            60,
            CHAIN_ID,
            FEE_RECIPIENT,
        );
        assert_eq!(
            err,
            Err(RomeGuestError::HeaderRuleViolated {
                index: 0,
                field: "parent_beacon_block_root"
            })
        );
    }

    /// A non-zero `blob_gas_used` is refused by name (no blobs on this chain).
    #[test]
    fn chain_and_execute_refuses_a_blob_gas_used_rule_violation() {
        let parent = honest_header(9, 1_757_000_000, B256::ZERO);
        let mut b = honest_block(10, 1_757_000_001, header_hash(&parent));
        b.header.blob_gas_used = Some(1);
        let witness = ExecutionWitness::default();
        let chain_spec = reth_chainspec::ChainSpec::default();
        let err = chain_and_execute(
            &[b],
            &[vec![]],
            &[witness],
            &parent,
            Arc::new(chain_spec),
            1_757_000_100,
            60,
            CHAIN_ID,
            FEE_RECIPIENT,
        );
        assert_eq!(
            err,
            Err(RomeGuestError::HeaderRuleViolated {
                index: 0,
                field: "blob_gas_used"
            })
        );
    }

    /// A non-zero `excess_blob_gas` is refused by name (no blobs on this chain).
    #[test]
    fn chain_and_execute_refuses_an_excess_blob_gas_rule_violation() {
        let parent = honest_header(9, 1_757_000_000, B256::ZERO);
        let mut b = honest_block(10, 1_757_000_001, header_hash(&parent));
        b.header.excess_blob_gas = Some(1);
        let witness = ExecutionWitness::default();
        let chain_spec = reth_chainspec::ChainSpec::default();
        let err = chain_and_execute(
            &[b],
            &[vec![]],
            &[witness],
            &parent,
            Arc::new(chain_spec),
            1_757_000_100,
            60,
            CHAIN_ID,
            FEE_RECIPIENT,
        );
        assert_eq!(
            err,
            Err(RomeGuestError::HeaderRuleViolated {
                index: 0,
                field: "excess_blob_gas"
            })
        );
    }

    /// A different `fee_recipient` argument must change what `beneficiary` is accepted as — the rule's
    /// `beneficiary` comes from the caller, never a hardcoded `Address::ZERO` baked into this function.
    #[test]
    fn chain_and_execute_accepts_a_non_zero_fee_recipient_when_the_header_matches_it() {
        let fee_recipient = Address::repeat_byte(0x77);
        let rule = canonical_header_rule(CHAIN_ID, 10, fee_recipient);
        let parent = honest_header(9, 1_757_000_000, B256::ZERO);
        let mut header = header(10, 1_757_000_001, header_hash(&parent));
        header.mix_hash = rule.prev_randao;
        header.beneficiary = fee_recipient;
        header.extra_data = rule.extra_data;
        header.withdrawals_root = Some(rule.withdrawals_root);
        header.parent_beacon_block_root = Some(rule.parent_beacon_block_root);
        header.blob_gas_used = Some(rule.blob_gas_used);
        header.excess_blob_gas = Some(rule.excess_blob_gas);
        let b = Block {
            header,
            body: empty_withdrawals_body(),
        };
        let witness = ExecutionWitness::default();
        let chain_spec = reth_chainspec::ChainSpec::default();
        // Every header-rule field now matches; the run proceeds to (and fails inside) stateless
        // validation instead — proving the header-rule check itself accepted a non-ZERO fee recipient
        // when the header actually carries it, rather than always demanding ZERO.
        let err = chain_and_execute(
            &[b],
            &[vec![]],
            &[witness],
            &parent,
            Arc::new(chain_spec),
            1_757_000_100,
            60,
            CHAIN_ID,
            fee_recipient,
        );
        assert!(
            matches!(err, Err(RomeGuestError::StatelessValidationFailed { index: 0, .. })),
            "expected the header-rule check to pass and fail later in stateless validation, got {err:?}"
        );
    }

    // ---- the withdrawals rule: the header root and the body both follow the block's slice -------------

    fn withdrawal(index: u64, recipient_byte: u8, amount: u64) -> Withdrawal {
        rome_zk_executor_api::deposit_withdrawal(
            index,
            Address::repeat_byte(recipient_byte),
            amount,
        )
    }

    /// The slice a block's header root and body are honestly built from in the tests below.
    fn slice() -> Vec<Withdrawal> {
        vec![withdrawal(7, 0x11, 1_000), withdrawal(8, 0x22, 2_000)]
    }

    /// A block whose header root is the honest root of `header_for` and whose body carries `body`.
    fn block_with_withdrawals(
        header_for: &[Withdrawal],
        body: Option<Vec<Withdrawal>>,
    ) -> (Block, alloy_consensus::Header) {
        let parent = honest_header(9, 1_757_000_000, B256::ZERO);
        let rule = canonical_header_rule_with_withdrawals(CHAIN_ID, 10, FEE_RECIPIENT, header_for);
        let mut header = honest_header(10, 1_757_000_001, header_hash(&parent));
        header.withdrawals_root = Some(rule.withdrawals_root);
        let body = alloy_consensus::BlockBody {
            withdrawals: body.map(Withdrawals::new),
            ..Default::default()
        };
        (Block { header, body }, parent)
    }

    fn run_with_slice(
        block: Block,
        parent: &alloy_consensus::Header,
        slice: Vec<Withdrawal>,
    ) -> Result<(B256, u64), RomeGuestError> {
        chain_and_execute(
            &[block],
            &[slice],
            &[ExecutionWitness::default()],
            parent,
            Arc::new(reth_chainspec::ChainSpec::default()),
            1_757_000_100,
            60,
            CHAIN_ID,
            FEE_RECIPIENT,
        )
    }

    /// An honest block (header root and body both follow the slice) passes both checks and goes on to
    /// stateless validation, which fails here only because the witness is empty.
    #[test]
    fn a_block_with_its_honest_withdrawals_passes_the_rule_and_the_body_check() {
        let (b, parent) = block_with_withdrawals(&slice(), Some(slice()));
        let err = run_with_slice(b, &parent, slice());
        assert!(
            matches!(
                err,
                Err(RomeGuestError::StatelessValidationFailed { index: 0, .. })
            ),
            "expected both withdrawals checks to pass, got {err:?}"
        );
    }

    /// A missing withdrawal in the body (the header root still the honest one) is refused by name.
    #[test]
    fn a_missing_withdrawal_is_refused_by_name() {
        let mut body = slice();
        body.pop();
        let (b, parent) = block_with_withdrawals(&slice(), Some(body));
        assert_eq!(
            run_with_slice(b, &parent, slice()),
            Err(RomeGuestError::WithdrawalsMismatch { index: 0 })
        );
    }

    /// An extra withdrawal in the body is refused by name.
    #[test]
    fn an_extra_withdrawal_is_refused_by_name() {
        let mut body = slice();
        body.push(withdrawal(9, 0x33, 3_000));
        let (b, parent) = block_with_withdrawals(&slice(), Some(body));
        assert_eq!(
            run_with_slice(b, &parent, slice()),
            Err(RomeGuestError::WithdrawalsMismatch { index: 0 })
        );
    }

    /// A wrong recipient, amount or index in the body is each refused by name.
    #[test]
    fn a_wrong_recipient_amount_or_index_is_refused_by_name() {
        for mutate in [
            (|w: &mut Withdrawal| w.address = Address::repeat_byte(0x99)) as fn(&mut Withdrawal),
            |w| w.amount += 1,
            |w| w.index += 1,
            |w| w.validator_index = 1,
        ] {
            let mut body = slice();
            mutate(&mut body[1]);
            let (b, parent) = block_with_withdrawals(&slice(), Some(body));
            assert_eq!(
                run_with_slice(b, &parent, slice()),
                Err(RomeGuestError::WithdrawalsMismatch { index: 0 })
            );
        }
    }

    /// A body with no withdrawals list at all is refused even where the slice is empty: a post-Shanghai
    /// block carries `Some([])`.
    #[test]
    fn a_body_without_a_withdrawals_list_is_refused_by_name() {
        let (b, parent) = block_with_withdrawals(&[], None);
        assert_eq!(
            run_with_slice(b, &parent, vec![]),
            Err(RomeGuestError::WithdrawalsMismatch { index: 0 })
        );
    }

    /// A deposit in the wrong block: the block carries (header root and body) a withdrawal the stream
    /// puts in another block, so its slice is empty. The header rule refuses it by name.
    #[test]
    fn a_deposit_in_the_wrong_block_is_refused_by_name() {
        let (b, parent) = block_with_withdrawals(&slice(), Some(slice()));
        assert_eq!(
            run_with_slice(b, &parent, vec![]),
            Err(RomeGuestError::HeaderRuleViolated {
                index: 0,
                field: "withdrawals_root"
            })
        );
        // The other way round: the stream gives this block a slice the block does not carry.
        let (b, parent) = block_with_withdrawals(&[], Some(vec![]));
        assert_eq!(
            run_with_slice(b, &parent, slice()),
            Err(RomeGuestError::HeaderRuleViolated {
                index: 0,
                field: "withdrawals_root"
            })
        );
    }

    /// One withdrawals slice per block: a different count is refused by name, never an index panic.
    #[test]
    fn a_wrong_number_of_withdrawal_slices_is_refused_by_name() {
        let (b, parent) = block_with_withdrawals(&[], Some(vec![]));
        let err = chain_and_execute(
            &[b],
            &[],
            &[ExecutionWitness::default()],
            &parent,
            Arc::new(reth_chainspec::ChainSpec::default()),
            1_757_000_100,
            60,
            CHAIN_ID,
            FEE_RECIPIENT,
        );
        assert_eq!(
            err,
            Err(RomeGuestError::WithdrawalSliceCountMismatch {
                blocks: 1,
                slices: 0
            })
        );
    }
}
