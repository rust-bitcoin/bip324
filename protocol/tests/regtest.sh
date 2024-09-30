#!/usr/bin/env bash
#
# Test a handshake with a running bitcoin daemon.

# Exit immediately if a command exits with a non-zero status.
set -e

BITCOIND_PID=""

cleanup() {
    echo "Cleaning up..."
    if [ -n "$BITCOIND_PID" ]; then
        bitcoin-cli --chain=regtest --rpcuser=test --rpcpassword=b324 stop
        # Wait for the bitcoind process to stop.
        wait $BITCOIND_PID
    fi
}

# Ensure the bitcoind process is cleaned up if this script is killed for any reason.
trap cleanup EXIT

start_bitcoind() {
    bitcoind --chain=regtest --txindex --blockfilterindex --peerblockfilters \
             --rpcport=18443 --rpcuser=test --rpcpassword=b324 --rest=1 \
             --server=1 --listen=1 --v2transport=1 &
    BITCOIND_PID=$!
    
    echo "Waiting for bitcoind to start..."
    until bitcoin-cli --chain=regtest --rpcuser=test --rpcpassword=b324 getblockchaininfo &>/dev/null
    do
        sleep 1
    done
    echo "bitcoind started."
}

run_tests() {
    cargo test regtest_handshake -- --ignored --nocapture
    TEST_EXIT_CODE=$?
    return $TEST_EXIT_CODE
}

main() {
    start_bitcoind
    run_tests
    return $?
}

main
