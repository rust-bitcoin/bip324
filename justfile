_default:
  @just --list

# Quick check of the code including lints and formatting.
check:
  cargo fmt --check
  # Turn warnings into errors.
  cargo clippy --workspace --all-targets -- -D warnings
  cargo check --workspace --all-features

# Run a test suite: unit, features, msrv, min-versions, or no-std.
test suite="unit":
  just _test-{{suite}}

# Unit test suite.
_test-unit:
  cargo test --workspace --all-targets
  cargo test --workspace --doc

# Test feature flag matrix compatability.
_test-features:
  # Build and test with all features, no features, and some combinations.
  cargo test --package bip324 --lib --all-features
  cargo test --package bip324 --lib --no-default-features
  cargo test --package bip324 --lib --no-default-features --features alloc 

# Check code with MSRV compiler.
_test-msrv:
  # Handles creating sandboxed environments to ensure no newer binaries sneak in.
  cargo install cargo-msrv@0.18.4
  cargo msrv --manifest-path protocol/Cargo.toml verify --all-features

# Test that minimum versions of dependency contraints are valid.
_test-min-versions:
  rm -f Cargo.lock
  cargo +nightly check --workspace --all-features -Z direct-minimal-versions

# Test no standard library support.
_test-no-std:
  cargo install cross@0.2.5
  $HOME/.cargo/bin/cross build --package bip324 --target thumbv7m-none-eabi --no-default-features --features alloc

# Add a release tag and publish to the upstream remote. Need write privileges on the repository.
tag crate version remote="upstream":
  # A release tag is specific to a crate so following the convention crate-version.
  echo "Adding release tag {{crate}}-{{version}} and pushing to {{remote}}..."
  # Annotated tag.
  git tag -a {{crate}}-{{version}} -m "Release {{version}} for {{crate}}"
  git push {{remote}} {{crate}}-{{version}}
