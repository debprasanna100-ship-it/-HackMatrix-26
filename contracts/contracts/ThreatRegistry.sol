// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title ThreatRegistry
/// @notice Tamper-evident commitments of TrustLens threat reports.
///
/// ONLY the SHA-256 hash of a report's canonical JSON and a coarse category
/// tag are stored on-chain. Raw URLs, message text, evidence contents, and
/// any personal data MUST NEVER be sent to this contract. Anyone holding the
/// original report JSON can recompute its canonical hash and check it here,
/// proving the report existed, unmodified, at a specific block time.
contract ThreatRegistry {
    enum Status {
        Submitted, // 0
        Validated, // 1
        Disputed   // 2
    }

    struct Report {
        address reporter;      // original submitter
        uint64 submittedAt;    // block timestamp of submission
        string category;       // coarse tag, e.g. "url-analysis" (never raw content)
        Status status;
        uint32 revisionCount;  // number of status updates applied
    }

    struct Revision {
        Status status;
        address updatedBy;
        uint64 updatedAt;
    }

    mapping(bytes32 => Report) private _reports;
    mapping(bytes32 => Revision[]) private _revisions;

    event ReportSubmitted(
        bytes32 indexed reportHash,
        address indexed reporter,
        string category,
        uint64 submittedAt
    );

    event ReportStatusUpdated(
        bytes32 indexed reportHash,
        Status newStatus,
        address indexed updatedBy,
        uint32 revisionIndex,
        uint64 updatedAt
    );

    error ZeroHash();
    error EmptyCategory();
    error AlreadySubmitted();
    error UnknownReport();
    error NotReporter();
    error InvalidStatus();
    error UnchangedStatus();

    /// @notice Commit a report hash. Reverts if the hash was already submitted.
    /// @param reportHash SHA-256 (32 bytes) of the report's canonical JSON.
    /// @param category   Coarse category tag; MUST NOT contain report content.
    function submitReport(bytes32 reportHash, string calldata category) external {
        if (reportHash == bytes32(0)) revert ZeroHash();
        if (bytes(category).length == 0) revert EmptyCategory();
        if (_reports[reportHash].reporter != address(0)) revert AlreadySubmitted();

        _reports[reportHash] = Report({
            reporter: msg.sender,
            submittedAt: uint64(block.timestamp),
            category: category,
            status: Status.Submitted,
            revisionCount: 0
        });

        emit ReportSubmitted(reportHash, msg.sender, category, uint64(block.timestamp));
    }

    /// @notice Change a report's status to Validated or Disputed.
    /// @dev Only the original reporter may update the status (documented MVP
    ///      governance assumption). Every change appends a revision entry.
    function updateStatus(bytes32 reportHash, Status newStatus) external {
        Report storage report = _reports[reportHash];
        if (report.reporter == address(0)) revert UnknownReport();
        if (msg.sender != report.reporter) revert NotReporter();
        if (newStatus != Status.Validated && newStatus != Status.Disputed) revert InvalidStatus();
        if (newStatus == report.status) revert UnchangedStatus();

        report.status = newStatus;
        report.revisionCount += 1;
        _revisions[reportHash].push(
            Revision({status: newStatus, updatedBy: msg.sender, updatedAt: uint64(block.timestamp)})
        );

        emit ReportStatusUpdated(
            reportHash, newStatus, msg.sender, report.revisionCount - 1, uint64(block.timestamp)
        );
    }

    /// @notice Read a report. status: 0=Submitted, 1=Validated, 2=Disputed.
    /// @return reporter address(0) when the hash is unknown.
    function getReport(bytes32 reportHash)
        external
        view
        returns (address reporter, uint64 submittedAt, string memory category, Status status)
    {
        Report storage report = _reports[reportHash];
        return (report.reporter, report.submittedAt, report.category, report.status);
    }

    /// @notice True when a report with this hash exists on-chain.
    function verify(bytes32 reportHash) external view returns (bool) {
        return _reports[reportHash].reporter != address(0);
    }

    /// @notice Number of status revisions recorded for a report.
    function getRevisionCount(bytes32 reportHash) external view returns (uint32) {
        return _reports[reportHash].revisionCount;
    }

    /// @notice One status revision. status: 1=Validated, 2=Disputed.
    function getRevision(bytes32 reportHash, uint32 index)
        external
        view
        returns (Status status, address updatedBy, uint64 updatedAt)
    {
        require(index < _revisions[reportHash].length, "revision index out of range");
        Revision storage revision = _revisions[reportHash][index];
        return (revision.status, revision.updatedBy, revision.updatedAt);
    }

    /// @notice Length of the stored revision array (equals getRevisionCount for this design).
    function revisionHistoryLength(bytes32 reportHash) external view returns (uint256) {
        return _revisions[reportHash].length;
    }
}
