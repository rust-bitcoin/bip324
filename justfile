# Every commit on the master branch is expected to have working `check` and `test-*` recipes.
#
# The recipes make heavy use of `rustup`'s toolchain syntax (e.g. `cargo +nightly`). `rustup` is
# required on the system in order to intercept the `cargo` commands and to install and use the appropriate toolchain with components. 

NIGHTLY_TOOLCHAIN := "nightly-2025-06-19"
STABLE_TOOLCHAIN := "1.87.0"

@_default:
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

# Run a test suite: unit, features, msrv, constraints, or no-std.
@test suite="unit":
  just _test-{{suite}}

# Unit test suite.
@_test-unit:
  cargo +{{STABLE_TOOLCHAIN}} test --all-targets
  cargo +{{STABLE_TOOLCHAIN}} test --doc

# Test feature flag matrix compatability.
@_test-features:
  # Build and test with all features, no features, and some combinations.
  cargo +{{STABLE_TOOLCHAIN}} test --package bip324 --lib --all-features
  cargo +{{STABLE_TOOLCHAIN}} test --package bip324 --lib --no-default-features
  cargo +{{STABLE_TOOLCHAIN}} test --package bip324 --lib --no-default-features --features alloc 

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
  $HOME/.cargo/bin/cross build --package bip324 --target thumbv7m-none-eabi --no-default-features --features alloc

# Run fuzz test: handshake.
@fuzz target="handshake" time="60":
  cargo install cargo-fuzz@0.12.0
  cd protocol && cargo +{{NIGHTLY_TOOLCHAIN}} fuzz run {{target}} -- -max_total_time={{time}}

# Add a release tag and publish to the upstream remote. Need write privileges on the repository.
@tag crate version remote="upstream":
  # A release tag is specific to a crate so following the convention crate-version.
  echo "Adding release tag {{crate}}-{{version}} and pushing to {{remote}}..."
  # Annotated tag.
  git tag -a {{crate}}-{{version}} -m "Release {{version}} for {{crate}}"
  git push {{remote}} {{crate}}-{{version}}
