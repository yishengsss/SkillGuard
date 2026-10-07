// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title SkillRegistry
/// @notice 第三方 MCP 技能版本的注册、审计请求、审计报告与押金结算登记表。
///         每个版本独立审计，新版本必须重新审计（防「先良性后投毒」）。
/// @dev 本阶段只做登记与押金结算，不接入 SkillLicense(NFT)。
contract SkillRegistry is Ownable, ReentrancyGuard {
    enum Status {
        None,
        Registered,
        AuditRequested,
        Verified,
        Malicious
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

    constructor(address initialOwner) Ownable(initialOwner) {}

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
        if (msg.value < AUDITOR_STAKE) revert InsufficientStake(msg.value, AUDITOR_STAKE);

        auditorStake[msg.sender] += msg.value;
    }

    /// @notice 已质押审计者提交审计结论
    ///         安全：status=Verified，押金退还 publisher
    ///         恶意：status=Malicious，押金转给审计者
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

        uint256 deposit = s.deposit;
        address publisher = s.publisher;

        s.auditor = msg.sender;
        s.reportHash = reportHash;
        s.deposit = 0;

        // effects -> events -> interactions
        if (isMalicious) {
            s.status = Status.Malicious;
            emit DepositSlashed(key, publisher, msg.sender, deposit);
        } else {
            s.status = Status.Verified;
        }

        emit ReportSubmitted(key, msg.sender, isMalicious, reportHash);

        _sendValue(isMalicious ? msg.sender : publisher, deposit);
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
