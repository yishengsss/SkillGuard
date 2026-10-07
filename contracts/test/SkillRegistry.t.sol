// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {SkillRegistry} from "../src/SkillRegistry.sol";

/// @notice 恶意 publisher：收到退款时尝试重入 submitReport
contract ReenteringAuditor {
    SkillRegistry private immutable registry;
    string public secondSkillId;
    string public secondVersion;
    bool public reentryAttempted;
    bool public reentrySucceeded;

    constructor(SkillRegistry registry_) {
        registry = registry_;
    }

    function stake() external payable {
        registry.stakeAsAuditor{value: msg.value}();
    }

    function setReentryTarget(string calldata skillId, string calldata version) external {
        secondSkillId = skillId;
        secondVersion = version;
    }

    function beginAudit(string calldata skillId, string calldata version) external {
        registry.submitReport(skillId, version, true, bytes32(uint256(0xA11CE)));
    }

    receive() external payable {
        if (bytes(secondSkillId).length == 0 || reentryAttempted) return;
        reentryAttempted = true;
        try registry.submitReport(secondSkillId, secondVersion, true, bytes32(uint256(0xB0B))) {
            reentrySucceeded = true;
        } catch {
            reentrySucceeded = false;
        }
    }
}

/// @notice 拒收 ETH 的 publisher：用于覆盖 TransferFailed 分支
contract NoReceivePublisher {
    SkillRegistry private immutable registry;

    constructor(SkillRegistry registry_) {
        registry = registry_;
    }

    function registerAndRequest(string calldata skillId, string calldata version) external payable {
        registry.register(skillId, version, "https://example.org/repo", bytes32(uint256(1)), bytes32(uint256(2)));
        registry.requestAudit{value: msg.value}(skillId, version);
    }
}

contract SkillRegistryTest is Test {
    SkillRegistry internal registry;

    address internal owner = makeAddr("owner");
    address internal publisher = makeAddr("publisher");
    address internal auditor = makeAddr("auditor");
    address internal other = makeAddr("other");

    string internal constant SKILL_ID = "mail-helper";
    string internal constant VERSION = "1.0.0";
    string internal constant REPO = "https://example.com/mail-helper";
    bytes32 internal constant CODE_HASH = keccak256("code-v1");
    bytes32 internal constant META_HASH = keccak256("metadata-v1");
    bytes32 internal constant REPORT_HASH = keccak256("report-v1");

    uint256 internal constant MIN_DEPOSIT = 0.01 ether;
    uint256 internal constant AUDITOR_STAKE = 0.01 ether;

    function setUp() public {
        registry = new SkillRegistry(owner);

        vm.deal(publisher, 100 ether);
        vm.deal(auditor, 100 ether);
        vm.deal(other, 100 ether);
    }

    /* ------------------------------------------------------------ 辅助 */

    function _register(address who, string memory skillId, string memory version) internal returns (bytes32 key) {
        vm.prank(who);
        key = registry.register(skillId, version, REPO, CODE_HASH, META_HASH);
    }

    function _registerAndRequest(address who, string memory skillId, string memory version)
        internal
        returns (bytes32 key)
    {
        key = _register(who, skillId, version);
        vm.prank(who);
        registry.requestAudit{value: MIN_DEPOSIT}(skillId, version);
    }

    function _stake(address who) internal {
        vm.prank(who);
        registry.stakeAsAuditor{value: AUDITOR_STAKE}();
    }

    /* ------------------------------------------------- register */

    function test_Register_WritesRecordAndEmits() public {
        bytes32 expectedKey = keccak256(abi.encode(SKILL_ID, VERSION));

        vm.expectEmit(true, true, true, true, address(registry));
        emit SkillRegistry.SkillRegistered(expectedKey, publisher, SKILL_ID, VERSION, REPO, CODE_HASH, META_HASH);

        vm.prank(publisher);
        bytes32 key = registry.register(SKILL_ID, VERSION, REPO, CODE_HASH, META_HASH);

        assertEq(key, expectedKey, "key should be keccak256(abi.encode(skillId, version))");

        (
            address pub,
            string memory repo,
            bytes32 codeHash,
            bytes32 metadataHash,
            uint256 deposit,
            SkillRegistry.Status status,
            bytes32 reportHash,
            address aud
        ) = registry.skills(key);

        assertEq(pub, publisher);
        assertEq(repo, REPO);
        assertEq(codeHash, CODE_HASH);
        assertEq(metadataHash, META_HASH);
        assertEq(deposit, 0);
        assertEq(uint8(status), uint8(SkillRegistry.Status.Registered));
        assertEq(reportHash, bytes32(0));
        assertEq(aud, address(0));
    }

    function test_Register_KeyOfMatchesAbiEncode() public view {
        assertEq(registry.keyOf(SKILL_ID, VERSION), keccak256(abi.encode(SKILL_ID, VERSION)));
    }

    function test_Register_RevertsOnDuplicateKey() public {
        bytes32 key = _register(publisher, SKILL_ID, VERSION);

        vm.prank(other);
        vm.expectRevert(abi.encodeWithSelector(SkillRegistry.KeyAlreadyExists.selector, key));
        registry.register(SKILL_ID, VERSION, REPO, CODE_HASH, META_HASH);
    }

    function test_Register_RevertsOnDuplicateEvenAfterAudit() public {
        bytes32 key = _registerAndRequest(publisher, SKILL_ID, VERSION);
        _stake(auditor);
        vm.prank(auditor);
        registry.submitReport(SKILL_ID, VERSION, false, REPORT_HASH);

        vm.prank(other);
        vm.expectRevert(abi.encodeWithSelector(SkillRegistry.KeyAlreadyExists.selector, key));
        registry.register(SKILL_ID, VERSION, REPO, CODE_HASH, META_HASH);
    }

    function test_Register_DifferentVersionsAreIndependent() public {
        bytes32 k1 = _register(publisher, SKILL_ID, "1.0.0");
        bytes32 k2 = _register(publisher, SKILL_ID, "2.0.0");

        assertTrue(k1 != k2);
        assertEq(uint8(registry.getStatus(SKILL_ID, "1.0.0")), uint8(SkillRegistry.Status.Registered));
        assertEq(uint8(registry.getStatus(SKILL_ID, "2.0.0")), uint8(SkillRegistry.Status.Registered));
    }

    function test_Register_DifferentSkillIdsAreIndependent() public {
        bytes32 k1 = _register(publisher, "mail-helper", VERSION);
        bytes32 k2 = _register(publisher, "weather", VERSION);
        assertTrue(k1 != k2);
    }

    function test_Register_AnyoneCanRegister() public {
        bytes32 key = _register(other, SKILL_ID, VERSION);
        (address pub,,,,,,,) = registry.skills(key);
        assertEq(pub, other);
    }

    /* ------------------------------------------------- requestAudit */

    function test_RequestAudit_HappyPath() public {
        bytes32 key = _register(publisher, SKILL_ID, VERSION);

        vm.expectEmit(true, true, true, true, address(registry));
        emit SkillRegistry.AuditRequested(key, publisher, MIN_DEPOSIT);

        vm.prank(publisher);
        registry.requestAudit{value: MIN_DEPOSIT}(SKILL_ID, VERSION);

        (,,,, uint256 deposit, SkillRegistry.Status status,,) = registry.skills(key);
        assertEq(deposit, MIN_DEPOSIT);
        assertEq(uint8(status), uint8(SkillRegistry.Status.AuditRequested));
        assertEq(address(registry).balance, MIN_DEPOSIT);
    }

    function test_RequestAudit_RevertsWhenValueBelowMin() public {
        _register(publisher, SKILL_ID, VERSION);

        vm.prank(publisher);
        vm.expectRevert(
            abi.encodeWithSelector(SkillRegistry.InsufficientDeposit.selector, MIN_DEPOSIT - 1, MIN_DEPOSIT)
        );
        registry.requestAudit{value: MIN_DEPOSIT - 1}(SKILL_ID, VERSION);
    }

    function test_RequestAudit_RevertsForNonPublisher() public {
        _register(publisher, SKILL_ID, VERSION);

        vm.prank(other);
        vm.expectRevert(abi.encodeWithSelector(SkillRegistry.NotPublisher.selector, other, publisher));
        registry.requestAudit{value: MIN_DEPOSIT}(SKILL_ID, VERSION);
    }

    function test_RequestAudit_RevertsOnUnknownKey() public {
        bytes32 key = registry.keyOf("ghost", "1.0.0");

        vm.prank(publisher);
        vm.expectRevert(abi.encodeWithSelector(SkillRegistry.UnknownKey.selector, key));
        registry.requestAudit{value: MIN_DEPOSIT}("ghost", "1.0.0");
    }

    function test_RequestAudit_RevertsWhenAlreadyRequested() public {
        _registerAndRequest(publisher, SKILL_ID, VERSION);

        vm.prank(publisher);
        vm.expectRevert(
            abi.encodeWithSelector(
                SkillRegistry.InvalidStatus.selector,
                SkillRegistry.Status.AuditRequested,
                SkillRegistry.Status.Registered
            )
        );
        registry.requestAudit{value: MIN_DEPOSIT}(SKILL_ID, VERSION);
    }

    function testFuzz_RequestAudit_AcceptsAnyValueAtLeastMin(uint96 rawAmount) public {
        uint256 amount = bound(uint256(rawAmount), MIN_DEPOSIT, 50 ether);
        bytes32 key = _register(publisher, SKILL_ID, VERSION);

        vm.deal(publisher, amount);
        vm.prank(publisher);
        registry.requestAudit{value: amount}(SKILL_ID, VERSION);

        (,,,, uint256 deposit, SkillRegistry.Status status,,) = registry.skills(key);
        assertEq(deposit, amount);
        assertEq(uint8(status), uint8(SkillRegistry.Status.AuditRequested));
    }

    /* ------------------------------------------------- stakeAsAuditor */

    function test_Stake_ExactMinimumWorks() public {
        vm.prank(auditor);
        registry.stakeAsAuditor{value: AUDITOR_STAKE}();
        assertEq(registry.auditorStake(auditor), AUDITOR_STAKE);
    }

    function test_Stake_AccumulatesAcrossCalls() public {
        vm.startPrank(auditor);
        registry.stakeAsAuditor{value: AUDITOR_STAKE}();
        assertEq(registry.auditorStake(auditor), AUDITOR_STAKE);
        registry.stakeAsAuditor{value: 2 * AUDITOR_STAKE}();
        vm.stopPrank();

        assertEq(registry.auditorStake(auditor), 3 * AUDITOR_STAKE);
    }

    function test_Stake_RevertsWhenValueBelowMinimum() public {
        vm.prank(auditor);
        vm.expectRevert(abi.encodeWithSelector(SkillRegistry.InsufficientStake.selector, 0.009 ether, AUDITOR_STAKE));
        registry.stakeAsAuditor{value: 0.009 ether}();
        assertEq(registry.auditorStake(auditor), 0);
    }

    function test_Stake_EachCallMustMeetMinimumOnItsOwn() public {
        vm.startPrank(auditor);
        registry.stakeAsAuditor{value: AUDITOR_STAKE}();

        // 第二次只补 0.002，低于门槛 -> revert，已质押的部分不受影响
        vm.expectRevert(abi.encodeWithSelector(SkillRegistry.InsufficientStake.selector, 0.002 ether, AUDITOR_STAKE));
        registry.stakeAsAuditor{value: 0.002 ether}();
        vm.stopPrank();

        assertEq(registry.auditorStake(auditor), AUDITOR_STAKE);
    }

    function test_Stake_AnyoneCanStake() public {
        vm.prank(other);
        registry.stakeAsAuditor{value: 1 ether}();
        assertEq(registry.auditorStake(other), 1 ether);
    }

    /* ------------------------------------------------- submitReport */

    function test_SubmitReport_SafeRefundsPublisherAndVerifies() public {
        bytes32 key = _registerAndRequest(publisher, SKILL_ID, VERSION);
        _stake(auditor);

        uint256 publisherBefore = publisher.balance;
        uint256 auditorBefore = auditor.balance;

        vm.expectEmit(true, true, true, true, address(registry));
        emit SkillRegistry.ReportSubmitted(key, auditor, false, REPORT_HASH);

        vm.prank(auditor);
        registry.submitReport(SKILL_ID, VERSION, false, REPORT_HASH);

        (address pub,,,, uint256 deposit, SkillRegistry.Status status, bytes32 reportHash, address aud) =
            registry.skills(key);

        assertEq(uint8(status), uint8(SkillRegistry.Status.Verified));
        assertEq(deposit, 0);
        assertEq(reportHash, REPORT_HASH);
        assertEq(aud, auditor);
        assertEq(pub, publisher);
        assertEq(publisher.balance, publisherBefore + MIN_DEPOSIT, "deposit refunded to publisher");
        assertEq(auditor.balance, auditorBefore, "auditor gets nothing on safe verdict");
        assertEq(
            address(registry).balance,
            registry.auditorStake(auditor),
            "registry holds only the auditor stake, deposit fully refunded"
        );
    }

    function test_SubmitReport_MaliciousPaysAuditor() public {
        bytes32 key = _registerAndRequest(publisher, SKILL_ID, VERSION);
        _stake(auditor);

        uint256 publisherBefore = publisher.balance;
        uint256 auditorBefore = auditor.balance;

        vm.expectEmit(true, true, true, true, address(registry));
        emit SkillRegistry.DepositSlashed(key, publisher, auditor, MIN_DEPOSIT);
        vm.expectEmit(true, true, true, true, address(registry));
        emit SkillRegistry.ReportSubmitted(key, auditor, true, REPORT_HASH);

        vm.prank(auditor);
        registry.submitReport(SKILL_ID, VERSION, true, REPORT_HASH);

        (,,,, uint256 deposit, SkillRegistry.Status status, bytes32 reportHash, address aud) = registry.skills(key);

        assertEq(uint8(status), uint8(SkillRegistry.Status.Malicious));
        assertEq(deposit, 0);
        assertEq(reportHash, REPORT_HASH);
        assertEq(aud, auditor);
        assertEq(auditor.balance, auditorBefore + MIN_DEPOSIT, "deposit slashed to auditor");
        assertEq(publisher.balance, publisherBefore, "publisher gets nothing on malicious verdict");
        assertEq(
            address(registry).balance,
            registry.auditorStake(auditor),
            "registry holds only the auditor stake, deposit fully slashed out"
        );
    }

    function test_SubmitReport_AuditorStakeIsNotConsumed() public {
        _registerAndRequest(publisher, SKILL_ID, VERSION);
        _stake(auditor);

        vm.prank(auditor);
        registry.submitReport(SKILL_ID, VERSION, false, REPORT_HASH);

        assertEq(registry.auditorStake(auditor), AUDITOR_STAKE, "stake stays locked as collateral");
    }

    function test_SubmitReport_RevertsForUnstakedCaller() public {
        _registerAndRequest(publisher, SKILL_ID, VERSION);

        vm.prank(other);
        vm.expectRevert(abi.encodeWithSelector(SkillRegistry.NotStakedAuditor.selector, other));
        registry.submitReport(SKILL_ID, VERSION, false, REPORT_HASH);
    }

    function test_SubmitReport_RevertsOnSelfAudit() public {
        _registerAndRequest(publisher, SKILL_ID, VERSION);
        _stake(publisher);

        vm.prank(publisher);
        vm.expectRevert(abi.encodeWithSelector(SkillRegistry.SelfAuditForbidden.selector, publisher));
        registry.submitReport(SKILL_ID, VERSION, false, REPORT_HASH);
    }

    function test_SubmitReport_RevertsWhenNotRequested() public {
        _register(publisher, SKILL_ID, VERSION);
        _stake(auditor);

        vm.prank(auditor);
        vm.expectRevert(
            abi.encodeWithSelector(
                SkillRegistry.InvalidStatus.selector,
                SkillRegistry.Status.Registered,
                SkillRegistry.Status.AuditRequested
            )
        );
        registry.submitReport(SKILL_ID, VERSION, false, REPORT_HASH);
    }

    function test_SubmitReport_RevertsOnUnknownKey() public {
        _stake(auditor);
        bytes32 key = registry.keyOf("ghost", "9.9.9");

        vm.prank(auditor);
        vm.expectRevert(abi.encodeWithSelector(SkillRegistry.UnknownKey.selector, key));
        registry.submitReport("ghost", "9.9.9", false, REPORT_HASH);
    }

    function test_SubmitReport_RevertsOnSecondCall() public {
        _registerAndRequest(publisher, SKILL_ID, VERSION);
        _stake(auditor);

        vm.prank(auditor);
        registry.submitReport(SKILL_ID, VERSION, false, REPORT_HASH);

        vm.prank(auditor);
        vm.expectRevert(
            abi.encodeWithSelector(
                SkillRegistry.InvalidStatus.selector, SkillRegistry.Status.Verified, SkillRegistry.Status.AuditRequested
            )
        );
        registry.submitReport(SKILL_ID, VERSION, true, REPORT_HASH);
    }

    function test_SubmitReport_RevertsWhenPublisherRejectsRefund() public {
        NoReceivePublisher stub = new NoReceivePublisher(registry);
        stub.registerAndRequest{value: MIN_DEPOSIT}(SKILL_ID, VERSION);
        _stake(auditor);

        vm.prank(auditor);
        vm.expectRevert(SkillRegistry.TransferFailed.selector);
        registry.submitReport(SKILL_ID, VERSION, false, REPORT_HASH);

        // 整笔交易回滚，状态与押金保持原样
        (,,,, uint256 deposit, SkillRegistry.Status status,,) = registry.skills(registry.keyOf(SKILL_ID, VERSION));
        assertEq(uint8(status), uint8(SkillRegistry.Status.AuditRequested));
        assertEq(deposit, MIN_DEPOSIT);
    }

    function test_SubmitReport_ReentrancyBlocked() public {
        ReenteringAuditor reentrant = new ReenteringAuditor(registry);

        // 目标一：重入的受害者
        _registerAndRequest(publisher, "skill-a", VERSION);
        // 目标二：重入者要打的第二个版本
        _registerAndRequest(publisher, "skill-b", VERSION);

        vm.deal(address(reentrant), 1 ether);
        reentrant.stake{value: AUDITOR_STAKE}();
        reentrant.setReentryTarget("skill-b", VERSION);

        reentrant.beginAudit("skill-a", VERSION);

        assertTrue(reentrant.reentryAttempted(), "receive() should have tried to re-enter");
        assertFalse(reentrant.reentrySucceeded(), "ReentrancyGuard must block the nested call");
        assertEq(
            uint8(registry.getStatus("skill-a", VERSION)),
            uint8(SkillRegistry.Status.Malicious),
            "outer call still settles"
        );
        assertEq(
            uint8(registry.getStatus("skill-b", VERSION)),
            uint8(SkillRegistry.Status.AuditRequested),
            "nested call had no effect"
        );
    }

    function testFuzz_SubmitReport_SafeRoutesDepositToPublisher(uint96 rawDeposit) public {
        uint256 deposit = bound(uint256(rawDeposit), MIN_DEPOSIT, 10 ether);
        vm.deal(publisher, deposit);

        _register(publisher, SKILL_ID, VERSION);
        vm.prank(publisher);
        registry.requestAudit{value: deposit}(SKILL_ID, VERSION);
        _stake(auditor);

        uint256 before = publisher.balance;
        vm.prank(auditor);
        registry.submitReport(SKILL_ID, VERSION, false, REPORT_HASH);

        assertEq(publisher.balance, before + deposit);
        assertEq(address(registry).balance, registry.auditorStake(auditor));
    }

    function testFuzz_SubmitReport_MaliciousRoutesDepositToAuditor(uint96 rawDeposit) public {
        uint256 deposit = bound(uint256(rawDeposit), MIN_DEPOSIT, 10 ether);
        vm.deal(publisher, deposit);

        _register(publisher, SKILL_ID, VERSION);
        vm.prank(publisher);
        registry.requestAudit{value: deposit}(SKILL_ID, VERSION);
        _stake(auditor);

        uint256 before = auditor.balance;
        vm.prank(auditor);
        registry.submitReport(SKILL_ID, VERSION, true, REPORT_HASH);

        assertEq(auditor.balance, before + deposit);
        assertEq(address(registry).balance, registry.auditorStake(auditor));
    }

    /* ------------------------------------------------- slashAuditor */

    function test_SlashAuditor_ConfiscatesFullAccumulatedStakeToOwner() public {
        vm.startPrank(auditor);
        registry.stakeAsAuditor{value: AUDITOR_STAKE}();
        registry.stakeAsAuditor{value: 2 * AUDITOR_STAKE}();
        vm.stopPrank();

        uint256 staked = registry.auditorStake(auditor);
        assertEq(staked, 3 * AUDITOR_STAKE);
        uint256 ownerBefore = owner.balance;

        vm.expectEmit(true, true, true, true, address(registry));
        emit SkillRegistry.AuditorSlashed(auditor, staked);

        vm.prank(owner);
        registry.slashAuditor(auditor);

        assertEq(registry.auditorStake(auditor), 0);
        assertEq(owner.balance, ownerBefore + staked, "full accumulated stake goes to owner");
        assertEq(address(registry).balance, 0, "registry drained after slashing");
    }

    function test_SlashAuditor_ConfiscatesAboveMinimumStake() public {
        vm.prank(auditor);
        registry.stakeAsAuditor{value: 1 ether}();

        uint256 ownerBefore = owner.balance;
        vm.prank(owner);
        registry.slashAuditor(auditor);

        assertEq(registry.auditorStake(auditor), 0);
        assertEq(owner.balance, ownerBefore + 1 ether);
    }

    function test_SlashAuditor_RevertsForNonOwner() public {
        vm.prank(auditor);
        registry.stakeAsAuditor{value: AUDITOR_STAKE}();

        vm.prank(other);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, other));
        registry.slashAuditor(auditor);
    }

    function test_SlashAuditor_RevertsWhenNothingStaked() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(SkillRegistry.NothingToSlash.selector, auditor));
        registry.slashAuditor(auditor);
    }

    function test_SlashAuditor_RevertsOnSecondCall() public {
        vm.prank(auditor);
        registry.stakeAsAuditor{value: AUDITOR_STAKE}();

        vm.prank(owner);
        registry.slashAuditor(auditor);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(SkillRegistry.NothingToSlash.selector, auditor));
        registry.slashAuditor(auditor);
    }

    function test_SlashAuditor_BlocksFormerAuditorFromSubmitting() public {
        _registerAndRequest(publisher, SKILL_ID, VERSION);
        _stake(auditor);

        vm.prank(owner);
        registry.slashAuditor(auditor);

        vm.prank(auditor);
        vm.expectRevert(abi.encodeWithSelector(SkillRegistry.NotStakedAuditor.selector, auditor));
        registry.submitReport(SKILL_ID, VERSION, false, REPORT_HASH);
    }

    function test_SlashAuditor_RestakingRestoresAuditorRights() public {
        _registerAndRequest(publisher, SKILL_ID, VERSION);
        _stake(auditor);

        vm.prank(owner);
        registry.slashAuditor(auditor);

        _stake(auditor);
        vm.prank(auditor);
        registry.submitReport(SKILL_ID, VERSION, false, REPORT_HASH);

        assertEq(uint8(registry.getStatus(SKILL_ID, VERSION)), uint8(SkillRegistry.Status.Verified));
    }

    /* ------------------------------------------------- getStatus */

    function test_GetStatus_UnknownKeyIsNone() public view {
        assertEq(uint8(registry.getStatus("nope", "0.0.1")), uint8(SkillRegistry.Status.None));
    }

    function test_GetStatus_TracksFullLifecycle() public {
        assertEq(uint8(registry.getStatus(SKILL_ID, VERSION)), uint8(SkillRegistry.Status.None));

        _register(publisher, SKILL_ID, VERSION);
        assertEq(uint8(registry.getStatus(SKILL_ID, VERSION)), uint8(SkillRegistry.Status.Registered));

        vm.prank(publisher);
        registry.requestAudit{value: MIN_DEPOSIT}(SKILL_ID, VERSION);
        assertEq(uint8(registry.getStatus(SKILL_ID, VERSION)), uint8(SkillRegistry.Status.AuditRequested));

        _stake(auditor);
        vm.prank(auditor);
        registry.submitReport(SKILL_ID, VERSION, true, REPORT_HASH);
        assertEq(uint8(registry.getStatus(SKILL_ID, VERSION)), uint8(SkillRegistry.Status.Malicious));
    }

    function test_MaliciousVerdictDoesNotAffectOtherVersion() public {
        _registerAndRequest(publisher, SKILL_ID, "1.0.0");
        _register(publisher, SKILL_ID, "2.0.0");
        _stake(auditor);

        vm.prank(auditor);
        registry.submitReport(SKILL_ID, "1.0.0", true, REPORT_HASH);

        assertEq(uint8(registry.getStatus(SKILL_ID, "1.0.0")), uint8(SkillRegistry.Status.Malicious));
        assertEq(
            uint8(registry.getStatus(SKILL_ID, "2.0.0")),
            uint8(SkillRegistry.Status.Registered),
            "new version must be re-audited (anti rug-pull)"
        );
    }

    /* ------------------------------------------------- 常量 / 构造 */

    function test_Constants() public view {
        assertEq(registry.MIN_DEPOSIT(), 0.01 ether);
        assertEq(registry.AUDITOR_STAKE(), 0.01 ether);
    }

    function test_Constructor_SetsOwner() public view {
        assertEq(registry.owner(), owner);
    }

    function test_Constructor_RevertsOnZeroOwner() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableInvalidOwner.selector, address(0)));
        new SkillRegistry(address(0));
    }
}
