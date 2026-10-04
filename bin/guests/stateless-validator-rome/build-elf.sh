#!/usr/bin/env bash
# Reproducible build of the zec-rome ELF.
#
# `--remap-path-prefix` alone is NOT enough (found while building this script, verified with `nm` on two
# real builds): it only rewrites what rustc itself embeds as debug-info/panic-location strings. Cargo
# separately computes a per-package `-C metadata` hash for every PATH dependency from that dependency's
# own absolute source path (its `SourceId`), to keep two same-named crates at different paths from
# colliding — and that hash is baked into every mangled symbol name (the `Cs<hash>_` component of a v0
# symbol, e.g. `Cs5ZwbW26hIEA_10guest_rome`), independent of `--remap-path-prefix` entirely. Two real
# builds of the identical source from two different checkout directories, WITH `--remap-path-prefix` set
# for every absolute path, still produced different sha256 ELF hashes; `nm` on both showed
# `guest_rome`/`rome_zk_channel`'s own `Cs..._` hash differing between them — the metadata hash, not a
# leaked string. The only fix that touches the actual root cause is to make Cargo SEE the identical
# absolute path both times: this script rsyncs this checkout's own two path-dependency roots (this
# fork and the parent workspace's `crates/`) into a fixed staging directory before invoking
# cargo, so `SourceId` — and therefore the metadata hash and the final ELF bytes — are identical
# regardless of which real directory this script itself is run from. `--remap-path-prefix` still runs on
# top of that (this script's own doc, below) so the staging path never leaks into panic-location strings
# either.
#
# Usage: build-elf.sh [--genesis PATH] [--expect-chain-id N]
#   --genesis PATH         the chain's genesis file to embed in the ELF (default: this repo's
#                          chains/tiber-200101.genesis.json, the same as before this option existed)
#   --expect-chain-id N    refuse to build unless the genesis' config.chainId is N
# The guest's build.rs also refuses a genesis that gives more than one account a non-zero balance, and
# prints the one allowed balance (address, wei, lamports at 1 lamport = 1e9 wei); the summary below repeats it
# as genesis_balance= so it can be checked against the chain's vault before a key is registered.
# The genesis is copied into the staging directory under a fixed name and the STAGED copy of
# `.cargo/config.toml` is pointed at it, so nothing in this checkout is edited and the build sees the same
# paths whatever the genesis file is called or wherever it lives. (`cargo-zisk build` takes no `--config`
# flag, and `ROME_CHAIN_GENESIS` is set with `force = true` in that file so a process environment variable
# cannot override it; a generated config in the staging tree is the one place left that stays
# reproducible.) At the end the script prints the ELF path and sha256 and the embedded genesis' sha256 and
# chainId, and checks that the genesis bytes really are inside the ELF.
#
# Run from anywhere; always builds `bin/guests/stateless-validator-rome` (wherever THIS script
# lives) in release mode, and copies the resulting ELF back to this script's own `target/` (so existing
# instructions pointing at that relative path keep working). `cargo-zisk` must be on PATH or reachable
# via `$ZISK_HOME/bin` (default `~/.zisk`) — this script only *runs* it, never `ziskup`, and never writes
# under `$ZISK_HOME`. Override the staging directory with `$ZEC_ROME_STAGING_ROOT` (default
# `/tmp/zec-rome-reproducible-build`) — it is wiped and recreated on every run.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# This checkout's own root (the fork, `rome-protocol/rome-zk-guest`) — computed from this script's own
# location (three levels up: bin/guests/stateless-validator-rome -> bin/guests -> bin -> fork root),
# without `git rev-parse`: copies of this checkout can omit every `.git` directory,
# including those in nested repositories.
# Deriving the root from this script's location also works in those copies.
FORK_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# The parent workspace this fork is nested under, per this fork's documented layout:
# clone it as `.fork/` under the workspace that supplies the path dependencies. The
# fork's path dependencies on `rome-zk-layouts`/`rome-zk-merkle`/`rome-zk-channel`/`rome-zk-executor-api`
# (`../../../../../crates/<name>` from `crates/clients/rome/guest`) only resolve when this holds, so a
# checkout that does not satisfy it cannot build this ELF at all — refuse by name rather than let cargo's
# own "path not found" error stand in for it.
if [ "$(basename "$FORK_ROOT")" != ".fork" ]; then
  echo "build-elf.sh: refusing — this checkout's root is '$FORK_ROOT', not a directory named '.fork'." >&2
  echo "This fork must be cloned as '.fork/' directly under a rome-zk-evm checkout for its path" >&2
  echo "dependencies (rome-zk-layouts, rome-zk-merkle, rome-zk-channel, rome-zk-executor-api) to resolve." >&2
  exit 1
fi
ROME_ZK_ROOT="$(dirname "$FORK_ROOT")"

DEFAULT_GENESIS_REL="chains/tiber-200101.genesis.json"
GENESIS_ARG=""
EXPECT_CHAIN_ID=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --genesis) [ "$#" -ge 2 ] || { echo "build-elf.sh: --genesis needs a path" >&2; exit 2; }; GENESIS_ARG="$2"; shift 2 ;;
    --genesis=*) GENESIS_ARG="${1#--genesis=}"; shift ;;
    --expect-chain-id) [ "$#" -ge 2 ] || { echo "build-elf.sh: --expect-chain-id needs a number" >&2; exit 2; }; EXPECT_CHAIN_ID="$2"; shift 2 ;;
    --expect-chain-id=*) EXPECT_CHAIN_ID="${1#--expect-chain-id=}"; shift ;;
    -h|--help) sed -n '/^# Usage:/,/^# chainId, and checks/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "build-elf.sh: unknown argument '$1' (try --help)" >&2; exit 2 ;;
  esac
done

if [ -n "$GENESIS_ARG" ]; then
  GENESIS_SRC="$GENESIS_ARG"
else
  GENESIS_SRC="$FORK_ROOT/$DEFAULT_GENESIS_REL"
fi
if [ ! -f "$GENESIS_SRC" ]; then
  echo "build-elf.sh: REFUSING — genesis file '$GENESIS_SRC' does not exist." >&2
  exit 1
fi
if [ -n "$EXPECT_CHAIN_ID" ] && ! [[ "$EXPECT_CHAIN_ID" =~ ^[0-9]+$ ]]; then
  echo "build-elf.sh: --expect-chain-id must be a plain decimal number, got '$EXPECT_CHAIN_ID'." >&2
  exit 2
fi
command -v python3 >/dev/null || { echo "build-elf.sh: python3 is needed to read the genesis file." >&2; exit 1; }

# The chain id the genesis itself carries (`config.chainId`) — the same field the guest's build.rs reads.
genesis_chain_id() {
  python3 -c 'import json,sys
g=json.load(open(sys.argv[1]))
v=g["config"]["chainId"]
assert isinstance(v,int) and not isinstance(v,bool) and v>0
print(v)' "$1"
}
if ! GENESIS_CHAIN_ID="$(genesis_chain_id "$GENESIS_SRC" 2>/dev/null)"; then
  echo "build-elf.sh: REFUSING — '$GENESIS_SRC' is not a genesis file with a numeric config.chainId." >&2
  exit 1
fi
if [ -n "$EXPECT_CHAIN_ID" ] && [ "$GENESIS_CHAIN_ID" != "$EXPECT_CHAIN_ID" ]; then
  echo "build-elf.sh: REFUSING — chain id mismatch: '$GENESIS_SRC' has config.chainId $GENESIS_CHAIN_ID but --expect-chain-id is $EXPECT_CHAIN_ID." >&2
  exit 1
fi

CARGO_HOME_RESOLVED="${CARGO_HOME:-$HOME/.cargo}"
ZISK_HOME_RESOLVED="${ZISK_HOME:-$HOME/.zisk}"

# Fixed (never random/mktemp) staging root: the whole point is that it is the SAME absolute path on
# every invocation, whatever directory this checkout itself lives at, so Cargo's path-derived metadata
# hash comes out identical every time. Wiped and rebuilt from this checkout on every run, never reused
# across a source change without being refreshed.
STAGING_ROOT="${ZEC_ROME_STAGING_ROOT:-/tmp/zec-rome-reproducible-build}"
STAGED_ROME_ZK="${STAGING_ROOT}/rome-zk"
STAGED_FORK="${STAGED_ROME_ZK}/.fork"

rm -rf "${STAGING_ROOT:?}"
mkdir -p "$STAGED_ROME_ZK"
# Copy the entire parent workspace: `rome-zk-channel`/`rome-zk-layouts`/etc.'s Cargo.toml
# declares `edition.workspace = true`, which needs that workspace's root `Cargo.toml` to be
# discoverable by Cargo's normal upward search from wherever a path dependency resolves to — a
# `crates/`-only copy fails that search ("failed to find a workspace root"), found on the first staged
# build attempt. `.fork/` itself is excluded here (nested under the parent workspace, staged separately
# below at its own fixed path) and never doubly copied.
rsync -a --exclude target --exclude .fork "$ROME_ZK_ROOT/" "$STAGED_ROME_ZK/"
rsync -a --exclude target "$FORK_ROOT/" "$STAGED_FORK/"

# Which genesis the staged build embeds. With no --genesis nothing is changed (the checked-in config names
# the Tiber file). With --genesis, the file is copied to one fixed name and the staged config is rewritten
# to name that copy; the original config in this checkout is never touched.
if [ -n "$GENESIS_ARG" ]; then
  EMBED_REL="chains/selected.genesis.json"
  cp "$GENESIS_SRC" "${STAGED_FORK}/${EMBED_REL}"
  cat > "${STAGED_FORK}/.cargo/config.toml" <<CFG
# Generated by bin/guests/stateless-validator-rome/build-elf.sh for this build only.
[env]
ROME_CHAIN_GENESIS = { value = "${EMBED_REL}", relative = true, force = true }
CFG
else
  EMBED_REL="$DEFAULT_GENESIS_REL"
  if ! grep -qF "value = \"${EMBED_REL}\"" "${STAGED_FORK}/.cargo/config.toml"; then
    echo "build-elf.sh: REFUSING — .cargo/config.toml no longer names ${EMBED_REL}; pass --genesis PATH." >&2
    exit 1
  fi
fi
EMBEDDED_GENESIS="${STAGED_FORK}/${EMBED_REL}"

# Every absolute path this build can embed a panic-location string under, remapped to a FIXED,
# checkout-independent name — most specific prefix first (rustc/Cargo applies the first matching
# `--remap-path-prefix` rule, and the staged fork root sits inside the staged parent workspace, so the
# fork's own rule must come first or its paths would be caught by the parent's rule instead, one
# level too shallow). These are the STAGED paths (always the same), not this invocation's real ones.
REMAP_FLAGS=(
  "--remap-path-prefix=${STAGED_FORK}=/build/rome-zk/.fork"
  "--remap-path-prefix=${STAGED_ROME_ZK}=/build/rome-zk"
  "--remap-path-prefix=${CARGO_HOME_RESOLVED}/registry=/build/cargo/registry"
  "--remap-path-prefix=${CARGO_HOME_RESOLVED}/git=/build/cargo/git"
  "--remap-path-prefix=${ZISK_HOME_RESOLVED}=/build/zisk"
)

# The fixed zisk-target flags this directory's own `.cargo/config.toml` declares — carried into
# `RUSTFLAGS` explicitly (this config lives at the STAGED location too, copied verbatim by the rsync
# above; RUSTFLAGS replaces, not merges with, a `[target.*] rustflags` config table, so it must be
# repeated here rather than relied upon from the config file alone).
ZISK_TARGET_FLAGS=(-Z share-generics=y -C llvm-args=--inline-threshold=2000)

export RUSTFLAGS="${ZISK_TARGET_FLAGS[*]} ${REMAP_FLAGS[*]}"

CARGO_ZISK="$(command -v cargo-zisk || echo "${ZISK_HOME_RESOLVED}/bin/cargo-zisk")"
if [ ! -x "$CARGO_ZISK" ]; then
  echo "build-elf.sh: cargo-zisk not found on PATH or at ${ZISK_HOME_RESOLVED}/bin/cargo-zisk" >&2
  exit 1
fi

# The build uses exactly the versions in this directory's committed Cargo.lock. `cargo-zisk build` has no
# `--locked` flag of its own, and without it cargo silently re-resolves whatever the lock does not cover to
# the newest versions crates.io holds that day, so the same source would give a different ELF from one week
# to the next. So the lock is checked first with `cargo metadata --locked` (which fails instead of
# updating), under the `zisk` toolchain `cargo-zisk` itself builds with, and compared again after the build.
STAGED_GUEST="${STAGED_FORK}/bin/guests/stateless-validator-rome"
LOCK_BEFORE="$(sha256sum "${STAGED_GUEST}/Cargo.lock" | awk '{print $1}')"
if ! ( cd "$STAGED_GUEST" && RUSTUP_TOOLCHAIN=zisk cargo metadata --locked --format-version 1 >/dev/null ); then
  echo "build-elf.sh: REFUSING — bin/guests/stateless-validator-rome/Cargo.lock is out of date for this tree" >&2
  echo "(a manifest or a path dependency changed since it was resolved). Cargo would re-resolve it to the" >&2
  echo "newest crates.io versions and the ELF would depend on the day it is built. Re-resolve on purpose:" >&2
  echo "run 'cargo metadata' (without --locked) in that directory under the zisk toolchain, which re-resolves" >&2
  echo "only what changed (not 'cargo update', which moves everything), review the diff, commit the new lock." >&2
  exit 1
fi

echo "build-elf.sh: building from staged ${STAGED_GUEST}" >&2
echo "build-elf.sh: RUSTFLAGS=${RUSTFLAGS}" >&2
# Cargo's own messages (the guest build.rs prints the genesis balance there) are kept in a log as well as
# shown. stdout stays on stdout, stderr goes to the log and back to stderr.
BUILD_LOG="${STAGING_ROOT}/cargo-build.log"
{ ( cd "$STAGED_GUEST" && "$CARGO_ZISK" build --release ) 2>&1 1>&3 | tee "$BUILD_LOG" >&2; } 3>&1

if [ "$(sha256sum "${STAGED_GUEST}/Cargo.lock" | awk '{print $1}')" != "$LOCK_BEFORE" ]; then
  echo "build-elf.sh: REFUSING — cargo changed Cargo.lock during the build, so the ELF was not built from the committed lock." >&2
  exit 1
fi

# The balance line the guest build.rs printed. A build without it did not run the check, so it is not trusted.
GENESIS_BALANCE="$(sed -n 's/.*genesis-balance: //p' "$BUILD_LOG" | head -n 1)"
if [ -z "$GENESIS_BALANCE" ]; then
  echo "build-elf.sh: REFUSING — the build did not print the genesis balance line, so the genesis balance check did not run." >&2
  exit 1
fi

STAGED_ELF="${STAGED_FORK}/bin/guests/stateless-validator-rome/target/elf/riscv64ima-zisk-zkvm-elf/release/zec-rome"
if [ ! -f "$STAGED_ELF" ]; then
  echo "build-elf.sh: expected ELF not found at $STAGED_ELF" >&2
  exit 1
fi

# Prove the remap + staging actually worked, not just that we asked for it: neither this invocation's
# real checkout paths, the staging root, nor $CARGO_HOME/$ZISK_HOME should appear anywhere in the built
# binary.
LEAKED=0
for prefix in "$FORK_ROOT" "$ROME_ZK_ROOT" "$STAGING_ROOT" "$CARGO_HOME_RESOLVED" "$ZISK_HOME_RESOLVED"; do
  if strings "$STAGED_ELF" | grep -qF "$prefix"; then
    echo "build-elf.sh: REFUSING — build path '$prefix' still present in $STAGED_ELF" >&2
    LEAKED=1
  fi
done
if [ "$LEAKED" -ne 0 ]; then
  exit 1
fi

# Copy back to this script's own (real) target dir so existing relative-path instructions keep working.
mkdir -p "$SCRIPT_DIR/target/elf/riscv64ima-zisk-zkvm-elf/release"
cp "$STAGED_ELF" "$SCRIPT_DIR/target/elf/riscv64ima-zisk-zkvm-elf/release/zec-rome"
ELF="$SCRIPT_DIR/target/elf/riscv64ima-zisk-zkvm-elf/release/zec-rome"

SHA256="$(sha256sum "$ELF" | awk '{print $1}')"

# The genesis bytes must really be inside the ELF — proves the config line took effect, not just that we
# wrote it.
if ! python3 -c 'import sys
elf=open(sys.argv[1],"rb").read(); g=open(sys.argv[2],"rb").read()
sys.exit(0 if g in elf else 1)' "$ELF" "$EMBEDDED_GENESIS"; then
  echo "build-elf.sh: REFUSING — the genesis file is not embedded in $ELF." >&2
  exit 1
fi
GENESIS_SHA256="$(sha256sum "$EMBEDDED_GENESIS" | awk '{print $1}')"

echo "build-elf.sh: built $ELF"
echo "build-elf.sh: sha256=${SHA256}"
echo "build-elf.sh: genesis_sha256=${GENESIS_SHA256}"
echo "build-elf.sh: chain_id=${GENESIS_CHAIN_ID}"
echo "build-elf.sh: genesis_balance=${GENESIS_BALANCE}"
