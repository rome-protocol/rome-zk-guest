//! Chain selection cannot be silently overridden. `ROME_CHAIN_GENESIS` is set by
//! this repo's root `.cargo/config.toml` with `force = true`.
//! It names the genesis file `src/chain_config.rs` embeds via
//! `include_str!(env!("ROME_CHAIN_GENESIS"))`. This build script prints WHICH file, its sha256, and the
//! chain id it carries as a build warning on every build — so a wrong-chain build is visible in ordinary
//! build output, not only discoverable by reading the ELF afterward — and re-runs whenever that env var
//! or the file it names changes, rather than caching a stale embed silently.
//!
//! It also enforces the genesis balance rule (`genesis_balances.rs`): a genesis with more than one
//! non-zero balance is refused, and the one allowed balance is printed as a `genesis-balance:` line.
use std::path::Path;

use sha2::{Digest, Sha256};

// The balance rule lives in its own file so this crate's unit tests run the same code.
#[path = "genesis_balances.rs"]
mod genesis_balances;

fn main() {
    let genesis_path =
        std::env::var("ROME_CHAIN_GENESIS").expect("ROME_CHAIN_GENESIS must be set — see this crate's own root .cargo/config.toml (rome-zk repo root and this fork's root both set it, force = true)");
    let contents = std::fs::read(&genesis_path)
        .unwrap_or_else(|e| panic!("ROME_CHAIN_GENESIS={genesis_path}: read failed: {e}"));

    let sha256 = Sha256::digest(&contents);
    let sha256_hex = hex_encode(&sha256);

    let genesis: serde_json::Value = serde_json::from_slice(&contents)
        .unwrap_or_else(|e| panic!("ROME_CHAIN_GENESIS={genesis_path}: not valid JSON: {e}"));
    let chain_id = genesis
        .get("config")
        .and_then(|c| c.get("chainId"))
        .and_then(|v| v.as_u64())
        .unwrap_or_else(|| {
            panic!("ROME_CHAIN_GENESIS={genesis_path}: config.chainId missing/non-numeric")
        });

    // A genesis that funds more than one account is refused on every build path, including a plain
    // `cargo build` of this crate. The single funded account, if any, is printed for the vault check.
    let funded = match genesis_balances::check(&genesis) {
        Ok(funded) => funded,
        Err(e) => {
            eprintln!("guest-rome build.rs: REFUSING — {genesis_path}: {e}");
            std::process::exit(1);
        }
    };
    println!("cargo:warning={}", genesis_balances::summary_line(&funded));

    println!(
        "cargo:warning=guest-rome embeds {} sha256={sha256_hex} chainId={chain_id}",
        Path::new(&genesis_path).display()
    );

    // Re-run if the env var's VALUE changes (a different genesis named) or the named FILE's own
    // contents change (the same path, edited in place) — either one silently re-embedding a different
    // chain's rules without this warning being re-printed is exactly what this build script exists to
    // surface.
    println!("cargo:rerun-if-env-changed=ROME_CHAIN_GENESIS");
    println!("cargo:rerun-if-changed=genesis_balances.rs");
    println!("cargo:rerun-if-changed={genesis_path}");
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
