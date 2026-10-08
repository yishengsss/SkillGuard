// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @notice SkillLicense 中供 SkillRegistry 调用的最小接口
interface ISkillLicense {
    function mint(address to, string calldata skillId, string calldata version, bytes32 reportHash)
        external
        returns (uint256 tokenId);
}

/// @title SkillRegistry
/// @notice 第三方 MCP 技能版本的注册、审计请求、审计报告、押金结算与许可证铸造。
///         每个版本独立审计，新版本必须重新审计（防「先良性后投毒」）。
contract SkillRegistry is Ownable, ReentrancyGuard {
    enum Status {
        None,
        Registered,
        AuditRequested,
        Verified,
        Malicious,
        ArbitrationPending,
        ArbitrationExpired
    }

    struct SkillVersion {
        address publisher;
        string repo; // 来源仓库 URL
        bytes32 codeHash; // 技能代码包哈希
        bytes32 metadataHash; // 工具描述（manifest）哈希
        uint256 deposit; // 技能方押金
        Status status;
        bytes32 reportHash; // 审计报告 keccak256
        address auditor;
    }

    uint256 public constant MIN_DEPOSIT = 0.01 ether;
    uint256 public constant AUDITOR_STAKE = 0.01 ether;

    /// @notice key = keccak256(abi.encode(skillId, version))
    mapping(bytes32 => SkillVersion) public skills;

    /// @notice 审计者地址 => 累计质押额（可累加）
    mapping(address => uint256) public auditorStake;

    /// @notice 唯一被授权铸造许可证的 SkillLicense 地址；由 owner 设置以解决部署顺序
    address public skillLicense;
    address public arbiter;
    address public treasury;
    bool public arbitrationConfigured;
    uint256 public constant ARBITRATION_PERIOD = 7 days;
    struct Arbitration {
        address reporter;
        bytes32 originalReportHash;
        uint256 openedAt;
        uint256 deadline;
        bytes32 finalReportHash;
    }
    mapping(bytes32 => Arbitration) public arbitrations;
    error ArbitrationNotConfigured();
    error InvalidArbitrationRole();
    error ConfigurationLocked();
    error EmptyReportHash();
    error NotArbiter();
    error ArbitrationExpiredError();
    error ArbitrationStillOpen();
    error NoFunds();
    mapping(address => uint256) public credits;
    event ArbitrationResolved(bytes32 indexed key, address indexed arbiter, bool confirmedMalicious, bytes32 finalReportHash);
    event ArbitrationTimedOut(bytes32 indexed key);
    event FundsCredited(address indexed recipient, bytes32 indexed key, uint256 amount);
    event FundsWithdrawn(address indexed recipient, uint256 amount);
    event ArbitrationConfigured(address indexed arbiter, address indexed treasury);
    event ArbitrationOpened(bytes32 indexed key, address indexed reporter, bytes32 reportHash, uint256 deadline);

    function protocolVersion() external pure returns (uint256) { return 2; }

    function configureArbitration(address arbiter_, address treasury_) external onlyOwner {
        if (arbitrationConfigured) revert ConfigurationLocked();
        if (arbiter_ == address(0) || treasury_ == address(0) || arbiter_ == treasury_
            || arbiter_ == owner() || treasury_ == owner()) revert InvalidArbitrationRole();
        arbiter = arbiter_; treasury = treasury_; arbitrationConfigured = true;
        emit ArbitrationConfigured(arbiter_, treasury_);
    }

    function transferOwnership(address newOwner) public override onlyOwner {
        if (arbitrationConfigured && (newOwner == arbiter || newOwner == treasury)) revert InvalidArbitrationRole();
        super.transferOwnership(newOwner);
    }

    function _checkParticipant(address participant) private view {
        if (!arbitrationConfigured) revert ArbitrationNotConfigured();
        if (participant == arbiter || participant == treasury) revert InvalidArbitrationRole();
    }


    event SkillRegistered(
        bytes32 indexed key,
        address indexed publisher,
        string skillId,
        string version,
        string repo,
        bytes32 codeHash,
        bytes32 metadataHash
    );
    event AuditRequested(bytes32 indexed key, address indexed publisher, uint256 deposit);
    event ReportSubmitted(bytes32 indexed key, address indexed auditor, bool isMalicious, bytes32 reportHash);
    event DepositSlashed(bytes32 indexed key, address indexed publisher, address indexed auditor, uint256 amount);
    event AuditorSlashed(address indexed auditor, uint256 amount);
    event SkillLicenseUpdated(address indexed previousLicense, address indexed newLicense);
    event LicenseMinted(bytes32 indexed key, address indexed to, uint256 tokenId);

    error KeyAlreadyExists(bytes32 key);
    error UnknownKey(bytes32 key);
    error NotPublisher(address caller, address publisher);
    error InvalidStatus(Status current, Status required);
    error InsufficientDeposit(uint256 sent, uint256 required);
    error InsufficientStake(uint256 staked, uint256 required);
    error NotStakedAuditor(address caller);
    error SelfAuditForbidden(address publisher);
    error NothingToSlash(address auditor);
    error TransferFailed();
    error SkillLicenseNotSet();
    error ZeroAddress();

    constructor(address initialOwner) Ownable(initialOwner) {}

    /// @notice owner 设置/更新 SkillLicense 地址（部署顺序：两个合约都部署后再互相接线）
    function setSkillLicense(address newSkillLicense) external onlyOwner {
        if (newSkillLicense == address(0)) revert ZeroAddress();

        address previous = skillLicense;
        skillLicense = newSkillLicense;

        emit SkillLicenseUpdated(previous, newSkillLicense);
    }

    /// @notice 供 SkillLicense 回读真实审计者；许可证不通过 mint 参数接收该值
    function auditorOf(bytes32 key) external view returns (address) {
        return skills[key].auditor;
    }

    /// @notice 计算版本登记键
    function keyOf(string memory skillId, string memory version) public pure returns (bytes32) {
        return keccak256(abi.encode(skillId, version));
    }

    /// @notice 注册技能版本，status=Registered；同 key 已存在则 revert
    function register(
        string calldata skillId,
        string calldata version,
        string calldata repo,
        bytes32 codeHash,
        bytes32 metadataHash
    ) external returns (bytes32 key) {
        key = keyOf(skillId, version);
        if (skills[key].status != Status.None) revert KeyAlreadyExists(key);

        skills[key] = SkillVersion({
            publisher: msg.sender,
            repo: repo,
            codeHash: codeHash,
            metadataHash: metadataHash,
            deposit: 0,
            status: Status.Registered,
            reportHash: bytes32(0),
            auditor: address(0)
        });

        emit SkillRegistered(key, msg.sender, skillId, version, repo, codeHash, metadataHash);
    }

    /// @notice 技能方请求审计并锁入押金，status: Registered -> AuditRequested
    function requestAudit(string calldata skillId, string calldata version) external payable {
        _checkParticipant(msg.sender);
        bytes32 key = keyOf(skillId, version);
        SkillVersion storage s = skills[key];

        if (s.status == Status.None) revert UnknownKey(key);
        if (s.status != Status.Registered) revert InvalidStatus(s.status, Status.Registered);
        if (msg.sender != s.publisher) revert NotPublisher(msg.sender, s.publisher);
        if (msg.value < MIN_DEPOSIT) revert InsufficientDeposit(msg.value, MIN_DEPOSIT);

        s.deposit += msg.value;
        s.status = Status.AuditRequested;

        emit AuditRequested(key, msg.sender, msg.value);
    }

    /// @notice 质押成为审计者；可重复调用累加质押额（SPEC: msg.value >= AUDITOR_STAKE）
    function stakeAsAuditor() external payable {
        _checkParticipant(msg.sender);
        if (msg.value < AUDITOR_STAKE) revert InsufficientStake(msg.value, AUDITOR_STAKE);

        auditorStake[msg.sender] += msg.value;
    }

    /// @notice 已质押审计者提交审计结论
    ///         安全：status=Verified，押金计入 publisher 可领取余额
    ///         恶意：status=ArbitrationPending，押金冻结等待独立仲裁
    function submitReport(string calldata skillId, string calldata version, bool isMalicious, bytes32 reportHash)
        external
        nonReentrant
    {
        bytes32 key = keyOf(skillId, version);
        SkillVersion storage s = skills[key];

        if (s.status == Status.None) revert UnknownKey(key);
        if (s.status != Status.AuditRequested) revert InvalidStatus(s.status, Status.AuditRequested);
        if (auditorStake[msg.sender] < AUDITOR_STAKE) revert NotStakedAuditor(msg.sender);
        // 禁止 publisher 用同一地址审计自己的技能（自审自过）
        if (msg.sender == s.publisher) revert SelfAuditForbidden(msg.sender);
        _checkParticipant(msg.sender);
        if (reportHash == bytes32(0)) revert EmptyReportHash();

        bool mintLicense = !isMalicious;
        // 安全结论必须铸证；未接线时在改动任何状态之前失败
        if (mintLicense && skillLicense == address(0)) revert SkillLicenseNotSet();

        uint256 deposit = s.deposit;
        address publisher = s.publisher;

        s.auditor = msg.sender;
        s.reportHash = reportHash;
        if (!isMalicious) s.deposit = 0;

        // effects -> events -> interactions
        if (isMalicious) {
            s.status = Status.ArbitrationPending;
            arbitrations[key] = Arbitration(msg.sender, reportHash, block.timestamp, block.timestamp + ARBITRATION_PERIOD, bytes32(0));
            emit ArbitrationOpened(key, msg.sender, reportHash, block.timestamp + ARBITRATION_PERIOD);
        } else {
            s.status = Status.Verified;
        }

        emit ReportSubmitted(key, msg.sender, isMalicious, reportHash);

        if (mintLicense) {
            // 恶意结论不铸造；许可证的 auditor 由 SkillLicense 回读本合约取得
            uint256 tokenId = ISkillLicense(skillLicense).mint(publisher, skillId, version, reportHash);
            emit LicenseMinted(key, publisher, tokenId);
            _credit(publisher, key, deposit);
        }
    }

    /// @notice Finalize a provisional malicious report; funds never reward its reporter.
    function resolveArbitration(string calldata skillId, string calldata version, bool confirmedMalicious, bytes32 arbitrationReportHash)
        external nonReentrant
    {
        if (msg.sender != arbiter) revert NotArbiter();
        bytes32 key = keyOf(skillId, version);
        SkillVersion storage s = skills[key];
        if (s.status != Status.ArbitrationPending) revert InvalidStatus(s.status, Status.ArbitrationPending);
        if (block.timestamp >= arbitrations[key].deadline) revert ArbitrationExpiredError();
        if (arbitrationReportHash == bytes32(0)) revert EmptyReportHash();
        if (!confirmedMalicious && skillLicense == address(0)) revert SkillLicenseNotSet();
        uint256 amount = s.deposit;
        s.deposit = 0;
        s.reportHash = arbitrationReportHash;
        arbitrations[key].finalReportHash = arbitrationReportHash;
        s.status = confirmedMalicious ? Status.Malicious : Status.Verified;
        _credit(confirmedMalicious ? treasury : s.publisher, key, amount);
        emit ArbitrationResolved(key, msg.sender, confirmedMalicious, arbitrationReportHash);
        if (!confirmedMalicious) {
            uint256 tokenId = ISkillLicense(skillLicense).mint(s.publisher, skillId, version, arbitrationReportHash);
            emit LicenseMinted(key, s.publisher, tokenId);
        }
    }

    function expireArbitration(string calldata skillId, string calldata version) external nonReentrant {
        bytes32 key = keyOf(skillId, version);
        SkillVersion storage s = skills[key];
        if (s.status != Status.ArbitrationPending) revert InvalidStatus(s.status, Status.ArbitrationPending);
        if (block.timestamp < arbitrations[key].deadline) revert ArbitrationStillOpen();
        uint256 amount = s.deposit;
        s.deposit = 0;
        s.status = Status.ArbitrationExpired;
        _credit(s.publisher, key, amount);
        emit ArbitrationTimedOut(key);
    }

    function _credit(address recipient, bytes32 key, uint256 amount) private {
        credits[recipient] += amount;
        emit FundsCredited(recipient, key, amount);
    }

    function withdrawFunds() external nonReentrant {
        uint256 amount = credits[msg.sender];
        if (amount == 0) revert NoFunds();
        credits[msg.sender] = 0;
        emit FundsWithdrawn(msg.sender, amount);
        _sendValue(msg.sender, amount);
    }

    /// @notice owner 罚没审计者全部质押并转给 owner（演示用简化仲裁）
    function slashAuditor(address auditor) external onlyOwner {
        uint256 amount = auditorStake[auditor];
        if (amount == 0) revert NothingToSlash(auditor);

        auditorStake[auditor] = 0;
        emit AuditorSlashed(auditor, amount);

        _sendValue(owner(), amount);
    }

    /// @notice 查询版本状态
    function getStatus(string calldata skillId, string calldata version) external view returns (Status) {
        return skills[keyOf(skillId, version)].status;
    }

    function _sendValue(address to, uint256 amount) private {
        if (amount == 0) return;
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }
}
