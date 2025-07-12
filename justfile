# Every commit on the master branch is expected to have working `check` and `test-*` recipes.
#
# The recipes make heavy use of `rustup`'s toolchain syntax (e.g. `cargo +nightly`). `rustup` is
# required on the system in order to intercept the `cargo` commands and to install and use the appropriate toolchain with components. 

NIGHTLY_TOOLCHAIN := "nightly-2025-07-10"
STABLE_TOOLCHAIN := "1.87.0"

@_default:
  just --list

# Quick check including lints and formatting. Run "fix" mode for auto-fixes.
@check mode="verify":
  # Use nightly toolchain for modern format and lint rules.
  # Ensure the toolchain is installed and has the necessary components.
  rustup component add --toolchain {{NIGHTLY_TOOLCHAIN}} rustfmt clippy
  just _check-{{mode}}

# Verify check, fails if anything is off. Good for CI.
@_check-verify:
  # Cargo's wrapper for rustfmt predates workspaces, so uses the "--all" flag instead of "--workspaces".
  cargo +{{NIGHTLY_TOOLCHAIN}} fmt --check --all
  # Lint all workspace members. Enable all feature flags. Check all targets (tests, examples) along with library code. Turn warnings into errors.
  cargo +{{NIGHTLY_TOOLCHAIN}} clippy --workspace --all-features --all-targets -- -D warnings
  # Static analysis of types and lifetimes.
  # Nightly toolchain required by benches target.
  cargo +{{NIGHTLY_TOOLCHAIN}} check --workspace --all-features --all-targets

# Attempt any auto-fixes for format and lints.
@_check-fix:
  # No --check flag to actually apply formatting.
  cargo +{{NIGHTLY_TOOLCHAIN}} fmt --all
  # Adding --fix flag to apply suggestions with --allow-dirty.
  cargo +{{NIGHTLY_TOOLCHAIN}} clippy --workspace --all-features --all-targets --fix --allow-dirty -- -D warnings

# Run a test suite: features, msrv, constraints, or no-std.
@test suite="features":
  just _test-{{suite}}

# Test library with feature flag matrix compatability.
@_test-features:
  # Test the extremes: all features enabled as well as none. If features are additive, this should expose conflicts.
  # If non-additive features (mutually exclusive) are defined, more specific commands are required.
  # Run all targets except benches which needs the nightly toolchain.
  cargo +{{STABLE_TOOLCHAIN}} test --no-default-features --lib --bins --tests --examples
  cargo +{{STABLE_TOOLCHAIN}} test --all-features --lib --bins --tests --examples
  cargo +{{STABLE_TOOLCHAIN}} test --all-features --doc

# Check code with MSRV compiler.
@_test-msrv:
  # Handles creating sandboxed environments to ensure no newer binaries sneak in.
  cargo install cargo-msrv@0.18.4
  cargo msrv --manifest-path protocol/Cargo.toml verify --all-features

# Check minimum and maximum dependency contraints.
@_test-constraints:
  # Ensure that the workspace code works with dependency versions at both extremes. This checks
  # that we are not unintentionally using new feautures of a dependency or removed ones.
  # Skipping "--all-targets" for these checks since tests and examples are not relevant for a library consumer.
  # Enabling "--all-features" so all dependencies are checked.
  # Clear any previously resolved versions and re-resolve to the minimums.
  rm -f Cargo.lock
  cargo +{{NIGHTLY_TOOLCHAIN}} check --workspace --all-features -Z direct-minimal-versions
  # Clear again and check the maximums by ignoring any rust-version caps. 
  rm -f Cargo.lock
  cargo +{{NIGHTLY_TOOLCHAIN}} check --workspace --all-features --ignore-rust-version
  rm -f Cargo.lock

# Test no standard library support.
@_test-no-std:
  cargo install cross@0.2.5
  $HOME/.cargo/bin/cross build --package bip324 --target thumbv7m-none-eabi --no-default-features

# Run benchmarks.
@bench:
  cargo +{{NIGHTLY_TOOLCHAIN}} bench --package bip324 --bench cipher_session

# Run fuzz target: receive_key or receive_garbage.
@fuzz target seconds:
  rustup component add --toolchain {{NIGHTLY_TOOLCHAIN}} llvm-tools-preview
  cargo install cargo-fuzz@0.12.0
  # Generate new test cases and add to corpus. Bumping length for garbage.
  cd protocol && cargo +{{NIGHTLY_TOOLCHAIN}} fuzz run {{target}} -- -max_len=5120 -max_total_time={{seconds}}
  # Measure coverage of corpus against code.
  cd protocol && cargo +{{NIGHTLY_TOOLCHAIN}} fuzz coverage {{target}}
  # Generate HTML coverage report.
  protocol/fuzz/coverage.sh {{NIGHTLY_TOOLCHAIN}} {{target}}

# Add a release tag and publish to the upstream remote. Need write privileges on the repository.
@tag crate version remote="upstream":
  # Guardrails: on a clean main with updated changelog and manifest.
  if ! git diff --quiet || ! git diff --cached --quiet; then \
    echo "tag: Uncommitted changes"; exit 1; fi
  if [ "`git rev-parse --abbrev-ref HEAD`" != "main" ]; then \
    echo "tag: Not on main branch"; exit 1; fi
  if ! grep -q "## v{{version}}" {{crate}}/CHANGELOG.md; then \
    echo "tag: CHANGELOG.md entry missing for v{{version}}"; exit 1; fi
  if ! grep -q '^version = "{{version}}"' {{crate}}/Cargo.toml; then \
    echo "tag: Cargo.toml version mismatch"; exit 1; fi
  # An annotated release tag is specific to a crate following the convention crate-version.
  echo "Adding release tag {{crate}}-{{version}} and pushing to {{remote}}..."
  git tag -a {{crate}}-{{version}} -m "Release {{version}} for {{crate}}"
  git push {{remote}} {{crate}}-{{version}}
