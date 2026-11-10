#!/bin/sh
set -e

PORT="${PORT:-8545}"
echo "Starting Hardhat JSON-RPC node on port ${PORT}..."
npx hardhat node --hostname 0.0.0.0 --port "${PORT}" &
NODE_PID=$!

echo "Waiting for Hardhat node to accept connections..."
for i in $(seq 1 30); do
  if wget -qO- "http://127.0.0.1:${PORT}" >/dev/null 2>&1 || nc -z 127.0.0.1 "${PORT}" 2>/dev/null; then
    echo "Hardhat node is ready!"
    break
  fi
  sleep 1
done

echo "Deploying ThreatRegistry smart contract..."
HARDHAT_CHAIN_URL="http://127.0.0.1:${PORT}" npx hardhat run scripts/deploy.js --network localhost || true

echo "ThreatRegistry active on JSON-RPC."
wait $NODE_PID
