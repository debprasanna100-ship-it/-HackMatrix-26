require("@nomicfoundation/hardhat-toolbox");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: { enabled: true, runs: 200 },
    },
  },
  networks: {
    // In-process network used by `npx hardhat test`.
    hardhat: {},
    // External local node: `npx hardhat node` then deploy with --network localhost.
    // HARDHAT_CHAIN_URL lets containers reach the node by service name.
    localhost: {
      url: process.env.HARDHAT_CHAIN_URL || "http://127.0.0.1:8545",
      chainId: 31337,
    },
    // Sepolia (optional): set TRUSTLENS_SEPOLIA_RPC_URL and TRUSTLENS_SEPOLIA_PRIVATE_KEY env vars.
    sepolia: {
      url: process.env.TRUSTLENS_SEPOLIA_RPC_URL || "",
      accounts: process.env.TRUSTLENS_SEPOLIA_PRIVATE_KEY
        ? [process.env.TRUSTLENS_SEPOLIA_PRIVATE_KEY]
        : [],
    },
  },
};
