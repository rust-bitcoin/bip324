bitcoind --chain=regtest --txindex --blockfilterindex --peerblockfilters --rpcport=18443 --rpcuser=test --rpcpassword=b324 --rest=1 --server=1 --listen=1 --v2transport=1 &
sleep 1
cargo test regtest_handshake -- --nocapture
sleep 1
## In case of failure this will stop core anyway.
bitcoin-cli --chain=regtest --rpcuser=test --rpcpassword=b324 stop