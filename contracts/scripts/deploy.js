/**
 * Deploy ThreatRegistry and record the deployment (address, tx hash, chain id)
 * to deployment.<network>.json so the backend/frontend can reference it.
 *
 * Usage:
 *   npx hardhat run scripts/deploy.js                      # in-process hardhat network
 *   npx hardhat run scripts/deploy.js --network localhost  # against `npx hardhat node`
 *   npx hardhat run scripts/deploy.js --network sepolia    # needs env vars in hardhat.config.js
 */
const { ethers, network } = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log(`Deploying ThreatRegistry on network '${network.name}' (chainId ${Number((await ethers.provider.getNetwork()).chainId)})`);
  console.log(`Deployer: ${deployer.address}`);

  const factory = await ethers.getContractFactory("ThreatRegistry");
  const contract = await factory.deploy();
  await contract.waitForDeployment();

  const address = await contract.getAddress();
  const tx = contract.deploymentTransaction();
  const receipt = tx ? await tx.wait() : null;

  const info = {
    contract: "ThreatRegistry",
    network: network.name,
    chainId: Number((await ethers.provider.getNetwork()).chainId),
    address: address,
    deployer: deployer.address,
    deploymentTxHash: tx ? tx.hash : null,
    blockNumber: receipt ? receipt.blockNumber : null,
    gasUsed: receipt ? receipt.gasUsed.toString() : null,
    deployedAt: new Date().toISOString(),
  };

  const outFile = path.join(__dirname, "..", `deployment.${network.name}.json`);
  fs.writeFileSync(outFile, JSON.stringify(info, null, 2));

  console.log("\nThreatRegistry deployed:");
  console.log(JSON.stringify(info, null, 2));
  console.log(`\nSaved deployment info to ${outFile}`);
  console.log(`\nSet for the backend:  TRUSTLENS_REGISTRY_ADDRESS=${address}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
