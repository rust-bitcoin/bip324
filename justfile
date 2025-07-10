# Every commit on the master branch is expected to have working `check` and `test-*` recipes.
#
# The recipes make heavy use of `rustup`'s toolchain syntax (e.g. `cargo +nightly`). `rustup` is
# required on the system in order to intercept the `cargo` commands and to install and use the appropriate toolchain with components. 

NIGHTLY_TOOLCHAIN := "nightly-2025-07-10"
STABLE_TOOLCHAIN := "1.87.0"
FUZZ_VERSION := "0.12.0"

_default:
  @just --list

# Quick check of the code including lints and formatting.
@check:
  # Default to the nightly toolchain for modern format and lint rules.

  # Ensure the toolchain is installed and has the necessary components.
  rustup component add --toolchain {{NIGHTLY_TOOLCHAIN}} rustfmt clippy
  # Cargo's wrapper for rustfmt predates workspaces, so uses the "--all" flag instead of "--workspaces".
  cargo +{{NIGHTLY_TOOLCHAIN}} fmt --check --all
  # Lint all workspace members. Enable all feature flags. Check all targets (tests, examples) along with library code. Turn warnings into errors.
  cargo +{{NIGHTLY_TOOLCHAIN}} clippy --workspace --all-features --all-targets -- -D warnings

# Attempt any auto-fixes for format and lints.
@fix:
  # Ensure the toolchain is installed and has the necessary components.
  rustup component add --toolchain {{NIGHTLY_TOOLCHAIN}} rustfmt clippy
  # No --check flag to actually apply formatting.
  cargo +{{NIGHTLY_TOOLCHAIN}} fmt --all
  # Adding --fix flag to apply suggestions with --allow-dirty.
  cargo +{{NIGHTLY_TOOLCHAIN}} clippy --workspace --all-features --all-targets --fix --allow-dirty -- -D warnings

# Run a test suite: unit, features, msrv, constraints, no-std, or fuzz.
@test suite="unit":
  just _test-{{suite}}

# Unit test suite.
@_test-unit:
  # Run everything except benches which need the nightly toolchain.
  cargo +{{STABLE_TOOLCHAIN}} test --lib --bins --tests --examples
  cargo +{{STABLE_TOOLCHAIN}} test --doc

# Test feature flag matrix compatability.
@_test-features:
  # Build and test with all features, no features, and some combinations if required.
  cargo +{{STABLE_TOOLCHAIN}} test --package bip324 --lib --tests --all-features
  cargo +{{STABLE_TOOLCHAIN}} test --package bip324 --lib --tests --no-default-features

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

# Type check the fuzz targets.
@_test-fuzz:
  cargo install cargo-fuzz@{{FUZZ_VERSION}}
  cd protocol && cargo +{{NIGHTLY_TOOLCHAIN}} fuzz check

# Run benchmarks.
bench:
  cargo +{{NIGHTLY_TOOLCHAIN}} bench --package bip324 --bench cipher_session

# Run fuzz target: receive_key or receive_garbage.
@fuzz target seconds:
  rustup component add --toolchain {{NIGHTLY_TOOLCHAIN}} llvm-tools-preview
  cargo install cargo-fuzz@{{FUZZ_VERSION}}
  # Generate new test cases and add to corpus. Bumping length for garbage.
  cd protocol && cargo +{{NIGHTLY_TOOLCHAIN}} fuzz run {{target}} -- -max_len=5120 -max_total_time={{seconds}}
  # Measure coverage of corpus against code.
  cd protocol && cargo +{{NIGHTLY_TOOLCHAIN}} fuzz coverage {{target}}
  # Generate HTML coverage report.
  protocol/fuzz/coverage.sh {{NIGHTLY_TOOLCHAIN}} {{target}}

# Add a release tag and publish to the upstream remote. Need write privileges on the repository.
@tag crate version remote="upstream":
  # A release tag is specific to a crate so following the convention crate-version.
  echo "Adding release tag {{crate}}-{{version}} and pushing to {{remote}}..."
  # Annotated tag.
  git tag -a {{crate}}-{{version}} -m "Release {{version}} for {{crate}}"
  git push {{remote}} {{crate}}-{{version}}
