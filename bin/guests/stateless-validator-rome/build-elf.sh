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
# Usage: run from anywhere; always builds `bin/guests/stateless-validator-rome` (wherever THIS script
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

echo "build-elf.sh: building from staged ${STAGED_FORK}/bin/guests/stateless-validator-rome" >&2
echo "build-elf.sh: RUSTFLAGS=${RUSTFLAGS}" >&2
( cd "${STAGED_FORK}/bin/guests/stateless-validator-rome" && "$CARGO_ZISK" build --release )

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
echo "build-elf.sh: built $ELF"
echo "build-elf.sh: sha256=${SHA256}"
