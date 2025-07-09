#!/usr/bin/env bash

# Generate HTML coverage report
# Usage: ./coverage.sh <toolchain> <target>
# Example: ./coverage.sh nightly-2025-07-10 receive_key
#
# Grabbed from this blog: https://tweedegolf.nl/en/blog/154/what-is-my-fuzzer-doing
# Hopefully standardized soon: https://github.com/taiki-e/cargo-llvm-cov/pull/431

set -euo pipefail

if [ $# -ne 2 ]; then
    echo "Usage: $0 <toolchain> <target>"
    echo "Example: $0 nightly-2025-07-10 receive_key"
    exit 1
fi

TOOLCHAIN="$1"
TARGET="$2"

# Change to protocol directory.
cd "$(dirname "$0")/.."

# Install rustfilt for demangling.
cargo install rustfilt@0.2.1
RUSTFILT="$HOME/.cargo/bin/rustfilt"

# Get toolchain info
SYSROOT=$(rustc +${TOOLCHAIN} --print sysroot)
HOST_TUPLE=$(rustc +${TOOLCHAIN} --print host-tuple)

BINARY="target/$HOST_TUPLE/coverage/$HOST_TUPLE/release/$TARGET"

echo "Generating HTML coverage report for $TARGET..."
"$SYSROOT/lib/rustlib/$HOST_TUPLE/bin/llvm-cov" show \
    "$BINARY" \
    -instr-profile=fuzz/coverage/"$TARGET"/coverage.profdata \
    -Xdemangler="$RUSTFILT" \
    --format=html \
    -output-dir=fuzz/coverage/"$TARGET"/html \
    -ignore-filename-regex="\.cargo|\.rustup|fuzz_target|/rustc/"

REPORT_PATH="$(pwd)/fuzz/coverage/$TARGET/html/index.html"
echo "$REPORT_PATH"
