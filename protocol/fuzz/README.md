# Fuzz

Fuzzing targets for the BIP-324 implementation.

## Prerequisites

- Rust nightly toolchain (required for LibFuzzer support)
- `cargo-fuzz` for easy cargo integration of the libfuzzer engine

## Adding New Targets

To add a new fuzz target:

1. Create a new file in `fuzz_targets/` with the appropriate fuzzing logic
2. Add an entry to `Cargo.toml` in this directory
3. Run the fuzzer with `cargo +nightly fuzz run <target_name>`

## Handling Found Issues

When a bug is found, a test case will be saved to the `artifacts/` directory. You can reproduce the issue with:

```bash
cargo +nightly fuzz run <target_name> <path_to_test_case>
```
