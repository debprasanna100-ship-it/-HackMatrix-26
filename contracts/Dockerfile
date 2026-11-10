# TrustLens contracts — Hardhat (chain node + deploy one-shot share this image)
FROM node:20-alpine
WORKDIR /work

COPY package.json ./
RUN npm install

COPY hardhat.config.js ./
COPY contracts ./contracts
COPY scripts ./scripts
COPY test ./test

# default startup: start JSON-RPC node and deploy ThreatRegistry
CMD ["sh", "./scripts/start.sh"]
