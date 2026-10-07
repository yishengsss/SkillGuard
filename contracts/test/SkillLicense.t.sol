// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC721Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {SkillLicense} from "../src/SkillLicense.sol";

/// @notice 直接冒充 registry 调用 mint 的攻击者
contract FakeRegistry {
    SkillLicense private immutable license;

    constructor(SkillLicense license_) {
        license = license_;
    }

    function callMint(address to, string calldata skillId, string calldata version, bytes32 reportHash)
        external
        returns (uint256)
    {
        return license.mint(to, skillId, version, reportHash);
    }
}

/// @notice 不实现 onERC721Received 的接收方，触发 _safeMint 回滚
contract NonReceiver {}

/// @notice 提供任意 auditorOf 返回值的桩 registry，用于覆盖 NoAuditor 分支
contract StubRegistry {
    mapping(bytes32 => address) public auditorOfValue;

    function setAuditor(bytes32 key, address who) external {
        auditorOfValue[key] = who;
    }

    function auditorOf(bytes32 key) external view returns (address) {
        return auditorOfValue[key];
    }

    function callMint(
        SkillLicense license,
        address to,
        string calldata skillId,
        string calldata version,
        bytes32 reportHash
    ) external returns (uint256) {
        return license.mint(to, skillId, version, reportHash);
    }

    /// @dev 让桩 registry 尝试自己发角色，验证 minter 无法自我提权
    function callGrantRole(SkillLicense license, bytes32 role, address account) external {
        license.grantRole(role, account);
    }
}

contract SkillLicenseTest is Test {
    SkillLicense internal license;

    address internal owner = makeAddr("owner");
    address internal publisher = makeAddr("publisher");
    address internal auditor = makeAddr("auditor");
    address internal other = makeAddr("other");

    string internal constant SKILL_ID = "mail-helper";
    string internal constant VERSION = "1.0.0";
    string internal constant REPO = "https://example.com/mail-helper";
    bytes32 internal constant REPORT_HASH = keccak256("report-v1");

    bytes32 internal key = keccak256(abi.encode(SKILL_ID, VERSION));
    bytes32 internal minterRole;

    /// @dev DEFAULT_ADMIN_ROLE 是常量 0x00，缓存下来以免在 expectRevert 后触发额外外部调用
    bytes32 internal constant DEFAULT_ADMIN = bytes32(0);

    function setUp() public {
        license = new SkillLicense(owner);
        minterRole = license.MINTER_ROLE();
        assertEq(license.DEFAULT_ADMIN_ROLE(), DEFAULT_ADMIN);
    }

    /// @dev AccessControl 的拒绝是 AccessControlUnauthorizedAccount(account, MINTER_ROLE)
    /// @dev 不查询 license（外部调用会吃掉 vm.prank 的目标）
    function _unauthorized(address account) internal view returns (bytes memory) {
        return abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, account, minterRole);
    }

    /// @dev grantRole/revokeRole 由 DEFAULT_ADMIN_ROLE(0x00) 把关，而它从未授予任何地址
    function _unauthorizedAdmin(address account) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, account, bytes32(0));
    }

    /* ------------------------------------------------------------ 构造 / 元数据 */

    function test_Constructor_SetsNameSymbolOwner() public view {
        assertEq(license.name(), "SkillGuard Verified License");
        assertEq(license.symbol(), "SGVL");
        assertEq(license.owner(), owner);
        assertEq(license.registry(), address(0), "registry unset until owner wires it");
        assertEq(license.totalMinted(), 0);
    }

    function test_Constructor_RevertsOnZeroOwner() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableInvalidOwner.selector, address(0)));
        new SkillLicense(address(0));
    }

    function test_KeyOf_MatchesRegistryFormula() public view {
        assertEq(license.keyOf(SKILL_ID, VERSION), keccak256(abi.encode(SKILL_ID, VERSION)));
    }

    /* ------------------------------------------------------------ 未授权铸造 */

    function test_Mint_RevertsWhenRegistryUnset() public {
        vm.prank(other);
        vm.expectRevert(_unauthorized(other));
        license.mint(publisher, SKILL_ID, VERSION, REPORT_HASH);
    }

    function test_Mint_RevertsForArbitraryCaller() public {
        vm.prank(owner);
        license.setRegistry(other);

        // 只有持有 MINTER_ROLE 的 registry 能铸造，owner 自己也不行
        vm.prank(owner);
        vm.expectRevert(_unauthorized(owner));
        license.mint(publisher, SKILL_ID, VERSION, REPORT_HASH);

        vm.prank(auditor);
        vm.expectRevert(_unauthorized(auditor));
        license.mint(publisher, SKILL_ID, VERSION, REPORT_HASH);
    }

    function test_Mint_RevertsForImpersonatingContract() public {
        vm.prank(owner);
        license.setRegistry(other);

        FakeRegistry fake = new FakeRegistry(license);
        vm.expectRevert(_unauthorized(address(fake)));
        fake.callMint(publisher, SKILL_ID, VERSION, REPORT_HASH);
    }

    function test_SetRegistry_OnlyOwnerAndEmits() public {
        vm.expectEmit(true, true, true, true, address(license));
        emit SkillLicense.RegistryUpdated(address(0), other);

        vm.prank(owner);
        license.setRegistry(other);
        assertEq(license.registry(), other);

        vm.prank(owner);
        license.setRegistry(auditor);
        assertEq(license.registry(), auditor);

        vm.prank(other);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, other));
        license.setRegistry(other);
    }

    function test_SetRegistry_RevertsOnZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(SkillLicense.ZeroAddress.selector);
        license.setRegistry(address(0));
    }

    /* ------------------------------------------------------------ MINTER_ROLE */

    function test_SetRegistry_GrantsMinterRoleToNewRegistry() public {
        StubRegistry stub = new StubRegistry();
        vm.prank(owner);
        license.setRegistry(address(stub));

        assertTrue(license.hasRole(minterRole, address(stub)));
    }

    function test_SetRegistry_RevokesMinterRoleFromOldRegistry() public {
        StubRegistry first = new StubRegistry();
        StubRegistry second = new StubRegistry();

        vm.startPrank(owner);
        license.setRegistry(address(first));
        assertTrue(license.hasRole(minterRole, address(first)));

        license.setRegistry(address(second));
        vm.stopPrank();

        assertFalse(license.hasRole(minterRole, address(first)), "old registry must lose mint rights");
        assertTrue(license.hasRole(minterRole, address(second)), "new registry gains mint rights");
        assertEq(license.registry(), address(second));
    }

    function test_SetRegistry_OldRegistryCannotMintAfterRotation() public {
        StubRegistry first = new StubRegistry();
        StubRegistry second = new StubRegistry();
        bytes32 firstKey = keccak256(abi.encode("skill-a", VERSION));
        bytes32 secondKey = keccak256(abi.encode("skill-b", VERSION));
        first.setAuditor(firstKey, auditor);
        second.setAuditor(secondKey, auditor);

        vm.startPrank(owner);
        license.setRegistry(address(first));
        license.setRegistry(address(second));
        vm.stopPrank();

        // 旧地址即使 auditorOf 仍可用，也不再持有 MINTER_ROLE
        vm.expectRevert(_unauthorized(address(first)));
        first.callMint(license, publisher, "skill-a", VERSION, REPORT_HASH);

        assertEq(license.totalMinted(), 0);
        assertEq(license.registry(), address(second), "registry pointer still points at the new one");
    }

    function test_SetRegistry_NewRegistryCanMintAfterRotation() public {
        StubRegistry first = new StubRegistry();
        StubRegistry second = new StubRegistry();
        bytes32 secondKey = keccak256(abi.encode("skill-b", VERSION));
        second.setAuditor(secondKey, auditor);

        vm.startPrank(owner);
        license.setRegistry(address(first));
        license.setRegistry(address(second));
        vm.stopPrank();

        uint256 tokenId = second.callMint(license, publisher, "skill-b", VERSION, REPORT_HASH);

        assertEq(tokenId, 1);
        assertEq(license.ownerOf(tokenId), publisher);
        assertTrue(license.isVerified("skill-b", VERSION));
        (,,, address aud,) = license.licenses(tokenId);
        assertEq(aud, auditor);
    }

    function test_SetRegistry_AtMostOneMinterAcrossRotations() public {
        StubRegistry a = new StubRegistry();
        StubRegistry b = new StubRegistry();

        vm.startPrank(owner);
        license.setRegistry(address(a));
        license.setRegistry(address(b));
        license.setRegistry(address(a));
        vm.stopPrank();

        assertTrue(license.hasRole(minterRole, address(a)));
        assertFalse(license.hasRole(minterRole, address(b)), "rotating back must revoke the other minter");
    }

    /* ------------------------------------------------------------ grantRole 不能扩大 minter */

    function test_GrantRole_NoDefaultAdminSoNobodyCanGrantMinter() public {
        assertEq(license.getRoleAdmin(minterRole), license.DEFAULT_ADMIN_ROLE());
        assertEq(license.DEFAULT_ADMIN_ROLE(), bytes32(0));

        // DEFAULT_ADMIN_ROLE 从未授予任何地址，包括 owner
        assertFalse(license.hasRole(license.DEFAULT_ADMIN_ROLE(), owner));
        assertFalse(license.hasRole(license.DEFAULT_ADMIN_ROLE(), address(this)));
        assertFalse(license.hasRole(license.DEFAULT_ADMIN_ROLE(), other));
    }

    function test_GrantRole_OwnerCannotEscalate() public {
        vm.prank(owner);
        vm.expectRevert(_unauthorizedAdmin(owner));
        license.grantRole(minterRole, other);

        assertFalse(license.hasRole(minterRole, other));
    }

    function test_GrantRole_OtherCannotEscalate() public {
        vm.prank(other);
        vm.expectRevert(_unauthorizedAdmin(other));
        license.grantRole(minterRole, other);

        vm.prank(other);
        vm.expectRevert(_unauthorizedAdmin(other));
        license.grantRole(DEFAULT_ADMIN, other);

        assertFalse(license.hasRole(minterRole, other));
        assertFalse(license.hasRole(DEFAULT_ADMIN, other));
    }

    function test_GrantRole_RevokeRoleAlsoUnreachable() public {
        StubRegistry stub = new StubRegistry();
        vm.prank(owner);
        license.setRegistry(address(stub));

        vm.prank(owner);
        vm.expectRevert(_unauthorizedAdmin(owner));
        license.revokeRole(minterRole, address(stub));

        assertTrue(license.hasRole(minterRole, address(stub)), "only setRegistry manages the minter role");
    }

    function test_GrantRole_RegistryItselfCannotSelfEscalate() public {
        // 当前 minter 想把自己升级成 admin，从而再给别人发角色 —— 也应该失败
        StubRegistry stub = new StubRegistry();
        vm.prank(owner);
        license.setRegistry(address(stub));

        vm.expectRevert(_unauthorizedAdmin(address(stub)));
        stub.callGrantRole(license, minterRole, address(stub));

        vm.expectRevert(_unauthorizedAdmin(address(stub)));
        stub.callGrantRole(license, DEFAULT_ADMIN, address(stub));

        assertFalse(license.hasRole(DEFAULT_ADMIN, address(stub)));
    }

    function test_ERC165_SupportsERC721AndAccessControl() public view {
        // ERC165 self
        assertTrue(license.supportsInterface(0x01ffc9a7));
        // ERC721
        assertTrue(license.supportsInterface(0x80ac58cd));
        // IAccessControl
        assertTrue(license.supportsInterface(0x7965db0b));
        // 不支持的接口
        assertFalse(license.supportsInterface(0xffffffff));
    }

    /* ------------------------------------------------------------ 正常路径 */

    function test_Mint_HappyPathWritesMetadata() public {
        StubRegistry stub = new StubRegistry();
        stub.setAuditor(key, auditor);
        vm.prank(owner);
        license.setRegistry(address(stub));

        vm.warp(1_760_000_000);

        vm.expectEmit(true, true, true, true, address(license));
        emit SkillLicense.LicenseMinted(1, key, publisher, auditor, REPORT_HASH);

        uint256 tokenId = stub.callMint(license, publisher, SKILL_ID, VERSION, REPORT_HASH);

        assertEq(tokenId, 1, "token ids start at 1");
        assertEq(license.ownerOf(tokenId), publisher);
        assertTrue(license.isVerified(SKILL_ID, VERSION));
        assertEq(license.tokenOfKey(key), tokenId);
        assertEq(license.totalMinted(), 1);

        (string memory skillId, string memory version, bytes32 reportHash, address aud, uint256 ts) =
            license.licenses(tokenId);

        assertEq(skillId, SKILL_ID);
        assertEq(version, VERSION);
        assertEq(reportHash, REPORT_HASH);
        assertEq(aud, auditor, "auditor read from registry, not supplied by caller");
        assertEq(ts, 1_760_000_000, "timestamp is block.timestamp");
    }

    function test_Mint_UsesAuditorFromRegistryContext() public {
        // 即使调用方是 registry，auditor 也只能来自 registry 的视图
        StubRegistry stub = new StubRegistry();
        stub.setAuditor(key, other);
        vm.prank(owner);
        license.setRegistry(address(stub));

        uint256 tokenId = stub.callMint(license, publisher, SKILL_ID, VERSION, REPORT_HASH);
        (,,, address aud,) = license.licenses(tokenId);

        assertEq(aud, other, "ignores any caller-supplied identity");
    }

    function test_Mint_TokenIdsIncrementPerVersion() public {
        StubRegistry stub = new StubRegistry();
        vm.prank(owner);
        license.setRegistry(address(stub));

        bytes32 keyA = keccak256(abi.encode("weather", "1.0.0"));
        bytes32 keyB = keccak256(abi.encode("weather", "2.0.0"));
        stub.setAuditor(keyA, auditor);
        stub.setAuditor(keyB, auditor);

        uint256 t1 = stub.callMint(license, publisher, "weather", "1.0.0", REPORT_HASH);
        uint256 t2 = stub.callMint(license, publisher, "weather", "2.0.0", REPORT_HASH);

        assertEq(t1, 1);
        assertEq(t2, 2);
        assertEq(license.totalMinted(), 2);
    }

    function test_Mint_EachVersionGetsItsOwnToken() public {
        StubRegistry stub = new StubRegistry();
        vm.prank(owner);
        license.setRegistry(address(stub));

        bytes32 keyV1 = keccak256(abi.encode(SKILL_ID, "1.0.0"));
        bytes32 keyV2 = keccak256(abi.encode(SKILL_ID, "2.0.0"));
        stub.setAuditor(keyV1, auditor);
        stub.setAuditor(keyV2, auditor);

        stub.callMint(license, publisher, SKILL_ID, "1.0.0", REPORT_HASH);
        stub.callMint(license, publisher, SKILL_ID, "2.0.0", REPORT_HASH);

        assertTrue(license.isVerified(SKILL_ID, "1.0.0"));
        assertTrue(license.isVerified(SKILL_ID, "2.0.0"));
    }

    /* ------------------------------------------------------------ 重复版本 */

    function test_Mint_RevertsOnDuplicateVersion() public {
        StubRegistry stub = new StubRegistry();
        stub.setAuditor(key, auditor);
        vm.prank(owner);
        license.setRegistry(address(stub));

        stub.callMint(license, publisher, SKILL_ID, VERSION, REPORT_HASH);

        vm.expectRevert(abi.encodeWithSelector(SkillLicense.AlreadyLicensed.selector, key));
        stub.callMint(license, publisher, SKILL_ID, VERSION, REPORT_HASH);

        assertEq(license.totalMinted(), 1);
    }

    function test_Mint_DuplicateStillRevertsWhenMetadataDiffers() public {
        // 同一版本即使换了报告哈希也仍然只能有一张证
        StubRegistry stub = new StubRegistry();
        stub.setAuditor(key, auditor);
        vm.prank(owner);
        license.setRegistry(address(stub));

        stub.callMint(license, publisher, SKILL_ID, VERSION, REPORT_HASH);

        vm.expectRevert(abi.encodeWithSelector(SkillLicense.AlreadyLicensed.selector, key));
        stub.callMint(license, publisher, SKILL_ID, VERSION, keccak256("other-report"));
    }

    function test_Mint_DifferentSkillSameVersionIsAllowed() public {
        StubRegistry stub = new StubRegistry();
        bytes32 weatherKey = keccak256(abi.encode("weather", VERSION));
        stub.setAuditor(key, auditor);
        stub.setAuditor(weatherKey, auditor);
        vm.prank(owner);
        license.setRegistry(address(stub));

        stub.callMint(license, publisher, SKILL_ID, VERSION, REPORT_HASH);
        stub.callMint(license, publisher, "weather", VERSION, REPORT_HASH);

        assertEq(license.totalMinted(), 2);
    }

    /* ------------------------------------------------------------ 缺少审计者 */

    function test_Mint_RevertsWhenRegistryReportsNoAuditor() public {
        StubRegistry stub = new StubRegistry();
        // 未设置 auditor：模拟 registry 与 license 的 key 公式分歧
        vm.prank(owner);
        license.setRegistry(address(stub));

        vm.expectRevert(abi.encodeWithSelector(SkillLicense.NoAuditor.selector, key));
        stub.callMint(license, publisher, SKILL_ID, VERSION, REPORT_HASH);

        assertEq(license.totalMinted(), 0);
    }

    /* ------------------------------------------------------------ 铸造失败回滚 */

    function test_Mint_RevertsWhenReceiverRejectsNFT() public {
        StubRegistry stub = new StubRegistry();
        stub.setAuditor(key, auditor);
        vm.prank(owner);
        license.setRegistry(address(stub));

        NonReceiver bad = new NonReceiver();

        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721InvalidReceiver.selector, address(bad)));
        stub.callMint(license, address(bad), SKILL_ID, VERSION, REPORT_HASH);

        assertEq(license.totalMinted(), 0, "failed mint leaves no token");
        assertEq(license.tokenOfKey(key), 0, "key stays unmapped after rollback");
        assertFalse(license.isVerified(SKILL_ID, VERSION));
    }

    /* ------------------------------------------------------------ isVerified / 转让 */

    function test_IsVerified_FalseForUnknownVersion() public view {
        assertFalse(license.isVerified(SKILL_ID, VERSION));
        assertFalse(license.isVerified("ghost", "9.9.9"));
    }

    function test_IsVerified_SurvivesTransfer() public {
        StubRegistry stub = new StubRegistry();
        stub.setAuditor(key, auditor);
        vm.prank(owner);
        license.setRegistry(address(stub));

        uint256 tokenId = stub.callMint(license, publisher, SKILL_ID, VERSION, REPORT_HASH);

        vm.prank(publisher);
        license.transferFrom(publisher, other, tokenId);

        assertEq(license.ownerOf(tokenId), other);
        assertTrue(license.isVerified(SKILL_ID, VERSION), "verification is per-version, not per-holder");
    }

    /* ------------------------------------------------------------ ERC721 基本行为 */

    function test_TokenOfKey_ZeroForUnminted() public view {
        assertEq(license.tokenOfKey(key), 0);
    }

    function test_Licenses_EmptyForUnmintedToken() public view {
        (string memory skillId, string memory version, bytes32 reportHash, address aud, uint256 ts) =
            license.licenses(99);
        assertEq(bytes(skillId).length, 0);
        assertEq(bytes(version).length, 0);
        assertEq(reportHash, bytes32(0));
        assertEq(aud, address(0));
        assertEq(ts, 0);
    }

    function test_OwnerOf_RevertsForNonexistentToken() public {
        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721NonexistentToken.selector, 1));
        license.ownerOf(1);
    }

    function testFuzz_Mint_TokenIdIncrementsMonotonically(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 20);

        StubRegistry stub = new StubRegistry();
        vm.prank(owner);
        license.setRegistry(address(stub));

        for (uint256 i = 1; i <= n; ++i) {
            string memory version = vm.toString(i);
            bytes32 k = keccak256(abi.encode(SKILL_ID, version));
            stub.setAuditor(k, auditor);

            uint256 tokenId = stub.callMint(license, publisher, SKILL_ID, version, REPORT_HASH);
            assertEq(tokenId, i);
            assertEq(license.tokenOfKey(k), i);
        }

        assertEq(license.totalMinted(), n);
    }

    function testFuzz_Mint_TimestampMatchesBlockTime(uint64 rawTime) public {
        vm.warp(bound(uint256(rawTime), 1, type(uint64).max));

        StubRegistry stub = new StubRegistry();
        stub.setAuditor(key, auditor);
        vm.prank(owner);
        license.setRegistry(address(stub));

        uint256 tokenId = stub.callMint(license, publisher, SKILL_ID, VERSION, REPORT_HASH);
        (,,,, uint256 ts) = license.licenses(tokenId);

        assertEq(ts, block.timestamp);
    }
}
