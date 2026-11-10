const { expect } = require("chai");
const { ethers } = require("hardhat");

/**
 * Test hashes. In production these are SHA-256 of a report's canonical JSON;
 * any 32-byte value exercises the same contract logic.
 */
const HASH_A = ethers.id("trustlens://report/canonical-json-a");
const HASH_B = ethers.id("trustlens://report/canonical-json-b");
const ZERO_HASH = ethers.ZeroHash;

describe("ThreatRegistry", function () {
  async function deployFixture() {
    const factory = await ethers.getContractFactory("ThreatRegistry");
    const registry = await factory.deploy();
    await registry.waitForDeployment();
    const [reporter, other, third] = await ethers.getSigners();
    return { registry, reporter, other, third };
  }

  describe("submitReport", function () {
    it("stores reporter, timestamp, category, and initial status", async function () {
      const { registry, reporter } = await deployFixture();
      await registry.connect(reporter).submitReport(HASH_A, "url-analysis");

      const [rHashReporter, rHashSubmittedAt, rHashCategory, rHashStatus] =
        await registry.getReport(HASH_A);
      expect(rHashReporter).to.equal(reporter.address);
      expect(rHashCategory).to.equal("url-analysis");
      expect(rHashStatus).to.equal(0n); // Status.Submitted
      expect(rHashSubmittedAt).to.be.gt(0n);

      const block = await ethers.provider.getBlock("latest");
      expect(rHashSubmittedAt).to.equal(BigInt(block.timestamp));
    });

    it("emits ReportSubmitted with the committed hash and category", async function () {
      const { registry, reporter } = await deployFixture();
      await expect(registry.connect(reporter).submitReport(HASH_A, "url-analysis"))
        .to.emit(registry, "ReportSubmitted")
        .withArgs(HASH_A, reporter.address, "url-analysis", anyUint());
    });

    it("reverts on duplicate hash submission", async function () {
      const { registry, reporter, other } = await deployFixture();
      await registry.connect(reporter).submitReport(HASH_A, "url-analysis");
      await expect(
        registry.connect(other).submitReport(HASH_A, "url-analysis")
      ).to.be.revertedWithCustomError(registry, "AlreadySubmitted");
    });

    it("reverts on empty category", async function () {
      const { registry, reporter } = await deployFixture();
      await expect(
        registry.connect(reporter).submitReport(HASH_A, "")
      ).to.be.revertedWithCustomError(registry, "EmptyCategory");
    });

    it("reverts on zero hash", async function () {
      const { registry, reporter } = await deployFixture();
      await expect(
        registry.connect(reporter).submitReport(ZERO_HASH, "url-analysis")
      ).to.be.revertedWithCustomError(registry, "ZeroHash");
    });

    it("accepts distinct hashes from different reporters", async function () {
      const { registry, reporter, other } = await deployFixture();
      await registry.connect(reporter).submitReport(HASH_A, "url-analysis");
      await registry.connect(other).submitReport(HASH_B, "message-analysis");
      expect(await registry.verify(HASH_A)).to.equal(true);
      expect(await registry.verify(HASH_B)).to.equal(true);
      const [bReporter] = await registry.getReport(HASH_B);
      expect(bReporter).to.equal(other.address);
    });
  });

  describe("verify", function () {
    it("returns false for unknown hashes", async function () {
      const { registry } = await deployFixture();
      expect(await registry.verify(HASH_A)).to.equal(false);
    });

    it("returns true after submission", async function () {
      const { registry, reporter } = await deployFixture();
      await registry.connect(reporter).submitReport(HASH_A, "url-analysis");
      expect(await registry.verify(HASH_A)).to.equal(true);
    });

    it("getReport returns zero reporter for unknown hashes", async function () {
      const { registry } = await deployFixture();
      const [reporter, submittedAt, category, status] = await registry.getReport(HASH_A);
      expect(reporter).to.equal(ethers.ZeroAddress);
      expect(submittedAt).to.equal(0n);
      expect(category).to.equal("");
      expect(status).to.equal(0n);
    });
  });

  describe("updateStatus", function () {
    it("reporter can set Validated; revision is tracked", async function () {
      const { registry, reporter } = await deployFixture();
      await registry.connect(reporter).submitReport(HASH_A, "url-analysis");

      await expect(registry.connect(reporter).updateStatus(HASH_A, 1)) // Validated
        .to.emit(registry, "ReportStatusUpdated")
        .withArgs(HASH_A, 1, reporter.address, 0, anyUint());

      const [, , , status] = await registry.getReport(HASH_A);
      expect(status).to.equal(1n);
      expect(await registry.getRevisionCount(HASH_A)).to.equal(1n);

      const [revStatus, revBy] = await registry.getRevision(HASH_A, 0);
      expect(revStatus).to.equal(1n);
      expect(revBy).to.equal(reporter.address);
    });

    it("reporter can set Disputed", async function () {
      const { registry, reporter } = await deployFixture();
      await registry.connect(reporter).submitReport(HASH_A, "url-analysis");
      await registry.connect(reporter).updateStatus(HASH_A, 2); // Disputed
      const [, , , status] = await registry.getReport(HASH_A);
      expect(status).to.equal(2n);
    });

    it("tracks multiple revisions in order", async function () {
      const { registry, reporter } = await deployFixture();
      await registry.connect(reporter).submitReport(HASH_A, "url-analysis");
      await registry.connect(reporter).updateStatus(HASH_A, 1); // Validated
      await registry.connect(reporter).updateStatus(HASH_A, 2); // Disputed
      await registry.connect(reporter).updateStatus(HASH_A, 1); // Validated again

      expect(await registry.getRevisionCount(HASH_A)).to.equal(3n);
      expect(await registry.revisionHistoryLength(HASH_A)).to.equal(3n);

      const [s0] = await registry.getRevision(HASH_A, 0);
      const [s1] = await registry.getRevision(HASH_A, 1);
      const [s2] = await registry.getRevision(HASH_A, 2);
      expect([s0, s1, s2].map(Number)).to.deep.equal([1, 2, 1]);
    });

    it("reverts when a non-reporter updates the status", async function () {
      const { registry, reporter, other } = await deployFixture();
      await registry.connect(reporter).submitReport(HASH_A, "url-analysis");
      await expect(
        registry.connect(other).updateStatus(HASH_A, 1)
      ).to.be.revertedWithCustomError(registry, "NotReporter");
    });

    it("reverts on unknown report hash", async function () {
      const { registry, reporter } = await deployFixture();
      await expect(
        registry.connect(reporter).updateStatus(HASH_A, 1)
      ).to.be.revertedWithCustomError(registry, "UnknownReport");
    });

    it("reverts when setting the same status again", async function () {
      const { registry, reporter } = await deployFixture();
      await registry.connect(reporter).submitReport(HASH_A, "url-analysis");
      await registry.connect(reporter).updateStatus(HASH_A, 1);
      await expect(
        registry.connect(reporter).updateStatus(HASH_A, 1)
      ).to.be.revertedWithCustomError(registry, "UnchangedStatus");
    });

    it("reverts on invalid status value (0=Submitted or out of range)", async function () {
      const { registry, reporter } = await deployFixture();
      await registry.connect(reporter).submitReport(HASH_A, "url-analysis");
      // 0 = Submitted is rejected by the explicit status check.
      await expect(
        registry.connect(reporter).updateStatus(HASH_A, 0)
      ).to.be.revertedWithCustomError(registry, "InvalidStatus");
      // 3 is outside the enum's range: the EVM reverts during ABI decoding,
      // before the contract body runs, so there is no custom error.
      await expect(
        registry.connect(reporter).updateStatus(HASH_A, 3)
      ).to.be.reverted;
    });

    it("reverts getRevision on out-of-range index", async function () {
      const { registry, reporter } = await deployFixture();
      await registry.connect(reporter).submitReport(HASH_A, "url-analysis");
      await expect(registry.getRevision(HASH_A, 0)).to.be.revertedWith(
        "revision index out of range"
      );
    });
  });
});

/** Match any uint (Solidity timestamps differ per block). */
function anyUint() {
  return (value) => typeof value === "bigint" && value >= 0n;
}
