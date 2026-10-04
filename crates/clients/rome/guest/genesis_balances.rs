//! The genesis balance rule, shared by `build.rs` (every build of this crate) and, under `cfg(test)`,
//! this crate's unit tests (`src/lib.rs` includes this file by path).
//!
//! A chain whose genesis pre-funds accounts has native balance that nothing on the settlement side
//! backs. The ELF's key is registered for that genesis, so the build allows exactly one funded account
//! and prints it. The party registering the key then checks that balance against the chain's vault.
//! A genesis with more than one non-zero balance is refused.

use std::fmt;

/// Wei per lamport: 1 lamport = 1e9 wei.
const WEI_PER_LAMPORT_DIGITS: usize = 9;

/// The one account with a non-zero balance.
#[derive(Debug, PartialEq, Eq)]
pub struct FundedAccount {
    pub address: String,
    /// The balance in wei, in plain decimal.
    pub wei: String,
    /// Whole lamports (wei / 1e9, rounded down), in plain decimal.
    pub lamports: String,
    /// The part of the balance below one lamport, in wei, in plain decimal ("0" when exact).
    pub remainder_wei: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum GenesisBalanceError {
    /// More than one account carries a non-zero balance. Holds the addresses, in file order.
    MoreThanOneFundedAccount(Vec<String>),
    /// A balance is not a number the genesis format allows.
    UnreadableBalance { address: String, value: String },
    /// The file has no `alloc` object, or an entry in it is not an object.
    MalformedAlloc,
}

impl fmt::Display for GenesisBalanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MoreThanOneFundedAccount(addrs) => write!(
                f,
                "GenesisFundedAccountLimit: the genesis gives {} accounts a non-zero balance ({}); \
                 at most one is allowed",
                addrs.len(),
                addrs.join(", ")
            ),
            Self::UnreadableBalance { address, value } => write!(
                f,
                "GenesisBalanceUnreadable: alloc entry {address} has balance {value:?}, which is not \
                 a 0x-hex or decimal integer"
            ),
            Self::MalformedAlloc => write!(
                f,
                "GenesisAllocMalformed: `alloc` is missing or is not an object of objects"
            ),
        }
    }
}

/// Returns the single funded account, or `None` when every balance is zero.
pub fn check(genesis: &serde_json::Value) -> Result<Option<FundedAccount>, GenesisBalanceError> {
    let alloc = match genesis.get("alloc") {
        // A genesis with no allocations at all has no funded account.
        None | Some(serde_json::Value::Null) => return Ok(None),
        Some(serde_json::Value::Object(map)) => map,
        Some(_) => return Err(GenesisBalanceError::MalformedAlloc),
    };

    let mut funded: Vec<(String, String)> = Vec::new();
    for (address, entry) in alloc {
        let entry = entry
            .as_object()
            .ok_or(GenesisBalanceError::MalformedAlloc)?;
        let wei = match entry.get("balance") {
            None | Some(serde_json::Value::Null) => continue,
            Some(serde_json::Value::String(s)) => to_decimal(s),
            Some(serde_json::Value::Number(n)) => to_decimal(&n.to_string()),
            Some(_) => None,
        };
        let wei = wei.ok_or_else(|| GenesisBalanceError::UnreadableBalance {
            address: address.clone(),
            value: entry["balance"].to_string(),
        })?;
        if wei != "0" {
            funded.push((address.clone(), wei));
        }
    }

    match funded.len() {
        0 => Ok(None),
        1 => {
            let (address, wei) = funded.remove(0);
            let (lamports, remainder_wei) = split_lamports(&wei);
            Ok(Some(FundedAccount {
                address,
                wei,
                lamports,
                remainder_wei,
            }))
        }
        _ => Err(GenesisBalanceError::MoreThanOneFundedAccount(
            funded.into_iter().map(|(a, _)| a).collect(),
        )),
    }
}

/// The line `build-elf.sh` copies into its summary. Starts with `genesis-balance:`.
pub fn summary_line(funded: &Option<FundedAccount>) -> String {
    match funded {
        None => "genesis-balance: none".to_string(),
        Some(f) => {
            let mut line = format!(
                "genesis-balance: address={} wei={} lamports={}",
                f.address, f.wei, f.lamports
            );
            if f.remainder_wei != "0" {
                line.push_str(&format!(" remainder_wei={}", f.remainder_wei));
            }
            line
        }
    }
}

/// `0x`-hex or decimal text to plain decimal text without leading zeros. `None` if it is neither.
fn to_decimal(text: &str) -> Option<String> {
    let t = text.trim();
    let digits: Vec<u32> = if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X"))
    {
        // Empty hex ("0x") is how some genesis files write zero.
        let mut acc: Vec<u32> = vec![0]; // little-endian decimal digits
        for c in hex.chars() {
            let d = c.to_digit(16)?;
            let mut carry = d;
            for x in acc.iter_mut() {
                let v = *x * 16 + carry;
                *x = v % 10;
                carry = v / 10;
            }
            while carry > 0 {
                acc.push(carry % 10);
                carry /= 10;
            }
        }
        acc.reverse();
        acc
    } else {
        if t.is_empty() {
            return None;
        }
        t.chars()
            .map(|c| c.to_digit(10))
            .collect::<Option<Vec<_>>>()?
    };
    let s: String = digits
        .iter()
        .map(|d| char::from_digit(*d, 10).unwrap())
        .collect();
    let s = s.trim_start_matches('0');
    Some(if s.is_empty() {
        "0".to_string()
    } else {
        s.to_string()
    })
}

/// Splits a decimal wei amount into whole lamports and the wei left over.
fn split_lamports(wei: &str) -> (String, String) {
    let norm = |s: &str| {
        let s = s.trim_start_matches('0');
        if s.is_empty() {
            "0".to_string()
        } else {
            s.to_string()
        }
    };
    if wei.len() <= WEI_PER_LAMPORT_DIGITS {
        return ("0".to_string(), norm(wei));
    }
    let cut = wei.len() - WEI_PER_LAMPORT_DIGITS;
    (norm(&wei[..cut]), norm(&wei[cut..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const A: &str = "0xCec1437293cC15964200D9E7667f7d29Ee92E11c";
    const B: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
    const C: &str = "0x4200000000000000000000000000000000000016";

    #[test]
    fn two_non_zero_balances_are_refused_by_name() {
        let g = json!({"alloc": {A: {"balance": "0x1"}, B: {"balance": "1000000000"}}});
        let err = check(&g).unwrap_err();
        assert_eq!(
            err,
            GenesisBalanceError::MoreThanOneFundedAccount(vec![A.into(), B.into()])
        );
        let text = err.to_string();
        assert!(text.starts_with("GenesisFundedAccountLimit:"), "{text}");
        assert!(text.contains(A) && text.contains(B), "{text}");
    }

    #[test]
    fn zero_balances_build_and_print_none() {
        let g = json!({"alloc": {A: {"balance": "0x0"}, B: {"balance": "0"}, C: {"balance": "0x", "code": "0x00"}, "0x01": {}}});
        let r = check(&g).unwrap();
        assert_eq!(r, None);
        assert_eq!(summary_line(&r), "genesis-balance: none");
        assert_eq!(check(&json!({"config": {}})).unwrap(), None);
        assert_eq!(check(&json!({"alloc": {}})).unwrap(), None);
    }

    #[test]
    fn one_balance_builds_and_is_printed_in_wei_and_lamports() {
        // Tiber's dev balance: 0x33b2e3c9fd0803ce8000000 wei = 1e27 wei = 1e18 lamports.
        let g = json!({"alloc": {A: {"balance": "0x33b2e3c9fd0803ce8000000"}, C: {"balance": "0x0", "code": "0x00"}}});
        let r = check(&g).unwrap();
        let f = r.as_ref().unwrap();
        assert_eq!(f.address, A);
        assert_eq!(f.wei, "1000000000000000000000000000");
        assert_eq!(f.lamports, "1000000000000000000");
        assert_eq!(f.remainder_wei, "0");
        assert_eq!(
            summary_line(&r),
            format!("genesis-balance: address={A} wei=1000000000000000000000000000 lamports=1000000000000000000")
        );
    }

    #[test]
    fn a_balance_below_one_lamport_and_a_fraction_are_reported() {
        let g = json!({"alloc": {A: {"balance": 999_999_999u64}}});
        let f = check(&g).unwrap().unwrap();
        assert_eq!(
            (f.lamports.as_str(), f.remainder_wei.as_str()),
            ("0", "999999999")
        );
        let g = json!({"alloc": {A: {"balance": "1000000001"}}});
        let r = check(&g).unwrap();
        assert!(summary_line(&r).ends_with("wei=1000000001 lamports=1 remainder_wei=1"));
    }

    #[test]
    fn full_width_balances_convert_exactly() {
        let max = format!("0x{}", "f".repeat(64));
        let f = check(&json!({"alloc": {A: {"balance": max}}}))
            .unwrap()
            .unwrap();
        assert_eq!(
            f.wei,
            "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        );
        assert_eq!(
            f.lamports,
            "115792089237316195423570985008687907853269984665640564039457584007913"
        );
        assert_eq!(f.remainder_wei, "129639935");
    }

    #[test]
    fn unreadable_balances_are_refused_by_name() {
        for bad in [
            json!("0xzz"),
            json!(""),
            json!("12e3"),
            json!(true),
            json!(-1),
        ] {
            let err = check(&json!({"alloc": {A: {"balance": bad}}})).unwrap_err();
            assert!(
                matches!(err, GenesisBalanceError::UnreadableBalance { .. }),
                "{err}"
            );
            assert!(err.to_string().starts_with("GenesisBalanceUnreadable:"));
        }
        assert_eq!(
            check(&json!({"alloc": []})).unwrap_err(),
            GenesisBalanceError::MalformedAlloc
        );
        assert_eq!(
            check(&json!({"alloc": {A: 1}})).unwrap_err(),
            GenesisBalanceError::MalformedAlloc
        );
    }

    #[test]
    fn the_embedded_genesis_passes() {
        let g: serde_json::Value =
            serde_json::from_str(include_str!(env!("ROME_CHAIN_GENESIS"))).unwrap();
        check(&g).expect("the genesis this crate is built for must satisfy the rule");
    }
}
