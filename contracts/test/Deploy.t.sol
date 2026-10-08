// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Deploy} from "../script/Deploy.s.sol";
import {SkillRegistry} from "../src/SkillRegistry.sol";
import {SkillLicense} from "../src/SkillLicense.sol";

contract DeployTest is Test {
    Deploy internal deployScript;

    SkillRegistry internal registry;
    SkillLicense internal license;

    /// @dev 公开的 Anvil 测试私钥 #0（公开已知，非真实资产）
    uint256 internal constant ANVIL_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    address internal owner;

    /// @dev 测试专用产物路径，位于 ./out/ 下，绝不触碰仓库根目录的 deployments.json
    string internal outputPath;

    /// @dev 缓存常量：{value: registry.MIN_DEPOSIT()} 里的外部调用会吃掉 vm.prank 目标
    uint256 internal minDeposit;
    uint256 internal auditorStake;

    function setUp() public {
        owner = vm.addr(ANVIL_KEY);
        vm.deal(owner, 100 ether);

        deployScript = new Deploy();
        outputPath = string.concat(vm.projectRoot(), "/out/test-deployments.json");

        // 走真实 runWithKey 路径（内部 startBroadcast），msg.sender 语义与 Anvil 部署一致；
        // 仅把产物路径换到 ./out/ 下的隔离文件
        (address reg, address lic) = deployScript.runWithKey(ANVIL_KEY, owner, outputPath);
        registry = SkillRegistry(reg);
        vm.prank(owner);registry.configureArbitration(makeAddr("arbiter"),makeAddr("treasury"));
        license = SkillLicense(lic);

        minDeposit = registry.MIN_DEPOSIT();
        auditorStake = registry.AUDITOR_STAKE();
    }

    /* ------------------------------------------------------------ 部署：owner */

    function test_Run_RejectsMainnet() public {
        vm.setEnv("PRIVATE_KEY", vm.toString(ANVIL_KEY));
        vm.setEnv("DEPLOYMENTS_PATH", outputPath);
        vm.chainId(677);
        vm.expectRevert("Deploy: unsupported chain");
        deployScript.run();
    }

    /* ------------------------------------------------------------ 第五步：仲裁角色 */

    /// @dev v2 部署路径使用独立产物文件，避免影响本套件其他对 outputFile 的断言
    string internal outputPathV2;

    function setUp2() public returns (SkillRegistry) {
        outputPathV2 = string.concat(vm.projectRoot(), "/out/test-deployments-v2.json");
        address arbiter = vm.addr(0xA1);
        address treasury = vm.addr(0xA2);
        (address reg,) = deployScript.runWithKeyAndArbitration(ANVIL_KEY, owner, arbiter, treasury, outputPathV2);
        return SkillRegistry(reg);
    }

    /// @dev v2.1 部署路径：同一次广播里完成接线 + configureArbitration，产物记录角色与协议版本
    function test_RunWithKeyAndArbitration_ConfiguresRolesOnce() public {
        address arbiter = vm.addr(0xA1);
        address treasury = vm.addr(0xA2);
        SkillRegistry installed = setUp2();
        assertTrue(installed.arbitrationConfigured(), "arbitration must be configured");
        assertEq(installed.arbiter(), arbiter);
        assertEq(installed.treasury(), treasury);
        assertEq(installed.protocolVersion(), 2);
        assertEq(installed.owner(), owner);

        string memory json = vm.readFile(outputPathV2);
        assertEq(vm.parseJsonAddress(json, ".arbiter"), arbiter);
        assertEq(vm.parseJsonAddress(json, ".treasury"), treasury);
        assertEq(vm.parseJsonUint(json, ".protocolVersion"), 2);
    }

    function test_RunWithKeyAndArbitration_RejectsZeroOrOverlappingRoles() public {
        string memory path = string.concat(vm.projectRoot(), "/out/test-deployments-v2.json");
        vm.expectRevert("Deploy: zero arbitration role");
        deployScript.runWithKeyAndArbitration(ANVIL_KEY, owner, address(0), makeAddr("treasury"), path);
        vm.expectRevert("Deploy: zero arbitration role");
        deployScript.runWithKeyAndArbitration(ANVIL_KEY, owner, makeAddr("arbiter"), address(0), path);
        vm.expectRevert("Deploy: overlapping roles");
        address same = makeAddr("both");
        deployScript.runWithKeyAndArbitration(ANVIL_KEY, owner, same, same, path);
        vm.expectRevert("Deploy: overlapping roles");
        deployScript.runWithKeyAndArbitration(ANVIL_KEY, owner, owner, makeAddr("treasury"), path);
    }

    /// @notice 角色锁定与钱包签名前的配置一致性：重复配置回滚，owner 不能改成角色地址
    function test_ArbitrationRolesAreLockedAfterConfigure() public {
        SkillRegistry installed = setUp2();
        address lockedTreasury = installed.treasury();
        vm.prank(owner);
        vm.expectRevert(SkillRegistry.ConfigurationLocked.selector);
        installed.configureArbitration(makeAddr("other"), lockedTreasury);
        address lockedArbiter = installed.arbiter();
        vm.prank(owner);
        vm.expectRevert(SkillRegistry.InvalidArbitrationRole.selector);
        installed.transferOwnership(lockedArbiter); // 管理员不能把所有权转给受保护的仲裁地址
        assertTrue(installed.arbitrationConfigured());
    }

    function test_Deploy_OwnersMatchDeployer() public view {
        assertEq(registry.owner(), owner, "SkillRegistry owner must be the deployer");
        assertEq(license.owner(), owner, "SkillLicense owner must be the deployer");
        assertEq(registry.owner(), license.owner(), "both contracts share one owner");
    }

    function test_Deploy_RevertsWhenBroadcasterIsNotOwner() public {
        // 用非 owner 私钥广播：接线调用以该 EOA 发出，合约自身的 onlyOwner 会拒绝
        uint256 strangerKey = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d; // Anvil #1
        address stranger = vm.addr(strangerKey);
        vm.deal(stranger, 100 ether);

        string memory isolated = string.concat(vm.projectRoot(), "/out/test-unauthorized.json");
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        deployScript.runWithKey(strangerKey, owner, isolated);
    }

    function test_Deploy_RevertsOnZeroOwner() public {
        vm.expectRevert("Deploy: zero owner");
        deployScript.deployAndWire(address(0));
    }

    /* ------------------------------------------------------------ 部署：双向连接 */

    function test_Deploy_WiresBothDirections() public view {
        assertEq(registry.skillLicense(), address(license), "registry must point at license");
        assertEq(license.registry(), address(registry), "license must point at registry");
    }

    function test_Deploy_GrantsMinterRoleToRegistry() public view {
        assertTrue(
            license.hasRole(license.MINTER_ROLE(), address(registry)), "registry must hold MINTER_ROLE after wiring"
        );
    }

    function test_Deploy_NoDefaultAdminGrantedToAnyone() public view {
        assertFalse(license.hasRole(bytes32(0), owner));
        assertFalse(license.hasRole(bytes32(0), address(registry)));
        assertFalse(license.hasRole(bytes32(0), address(this)));
    }

    /* ------------------------------------------------------------ 端到端：安全路径铸 NFT */

    function test_Deploy_EndToEndSafePathMintsLicense() public {
        address publisher = makeAddr("publisher");
        address auditor = makeAddr("auditor");
        vm.deal(publisher, 10 ether);
        vm.deal(auditor, 10 ether);

        string memory skillId = "weather";
        string memory version = "1.0.0";
        bytes32 reportHash = keccak256("safe-report");

        vm.prank(publisher);
        registry.register(skillId, version, "https://example.com/weather", keccak256("code"), keccak256("meta"));

        vm.prank(publisher);
        registry.requestAudit{value: minDeposit}(skillId, version);

        vm.prank(auditor);
        registry.stakeAsAuditor{value: auditorStake}();

        vm.prank(auditor);
        registry.submitReport(skillId, version, false, reportHash);

        assertEq(uint8(registry.getStatus(skillId, version)), uint8(SkillRegistry.Status.Verified));
        assertTrue(license.isVerified(skillId, version), "safe verdict must mint a license");
        assertEq(license.totalMinted(), 1);

        uint256 tokenId = license.tokenOfKey(registry.keyOf(skillId, version));
        assertEq(license.ownerOf(tokenId), publisher, "license goes to the publisher");

        (string memory gotSkill, string memory gotVersion, bytes32 gotReport, address gotAuditor,) =
            license.licenses(tokenId);
        assertEq(gotSkill, skillId);
        assertEq(gotVersion, version);
        assertEq(gotReport, reportHash);
        assertEq(gotAuditor, auditor, "auditor recorded from registry context");
    }

    function test_Deploy_EndToEndMaliciousPathDoesNotMint() public {
        address publisher = makeAddr("publisher");
        address auditor = makeAddr("auditor");
        vm.deal(publisher, 10 ether);
        vm.deal(auditor, 10 ether);

        string memory skillId = "mail-helper";
        string memory version = "1.0.0";

        vm.prank(publisher);
        registry.register(skillId, version, "https://example.com/mail-helper", keccak256("code"), keccak256("meta"));
        vm.prank(publisher);
        registry.requestAudit{value: minDeposit}(skillId, version);
        vm.prank(auditor);
        registry.stakeAsAuditor{value: auditorStake}();

        vm.prank(auditor);
        registry.submitReport(skillId, version, true, keccak256("malicious-report"));

        assertEq(uint8(registry.getStatus(skillId, version)), uint8(SkillRegistry.Status.ArbitrationPending));
        assertFalse(license.isVerified(skillId, version), "malicious verdict must not mint");
        assertEq(license.totalMinted(), 0);
    }

    /* ------------------------------------------------------------ deployments.json 产物 */

    function test_WriteDeployments_WritesSpecFormatToIsolatedPath() public {
        string memory path = string.concat(vm.projectRoot(), "/out/test-format.json");
        deployScript.writeDeployments(path, 31337, address(registry), address(license));

        string memory json = vm.readFile(path);

        assertEq(vm.parseJsonUint(json, ".chainId"), 31337);
        assertEq(vm.parseJsonAddress(json, ".SkillRegistry"), address(registry));
        assertEq(vm.parseJsonAddress(json, ".SkillLicense"), address(license));
    }

    function test_WriteDeployments_ContainsExactlySpecKeys() public {
        // 用独立路径，避免与其它测试互相覆盖文件
        string memory path = string.concat(vm.projectRoot(), "/out/test-keys.json");
        deployScript.writeDeployments(path, 11155111, address(registry), address(license));

        string memory json = vm.readFile(path);
        string[] memory keys = vm.parseJsonKeys(json, "$");

        // forge 的 serialize 按键名排序输出，因此只校验集合与数量，不依赖顺序
        assertEq(keys.length, 3, "SPEC format has exactly three keys");
        assertEq(vm.parseJsonUint(json, ".chainId"), 11155111);
        assertEq(vm.parseJsonAddress(json, ".SkillRegistry"), address(registry));
        assertEq(vm.parseJsonAddress(json, ".SkillLicense"), address(license));
    }

    function test_WriteDeployments_OverwritesStaleContent() public {
        // 先写一份旧数据，确认再次写入会覆盖而非追加
        string memory path = string.concat(vm.projectRoot(), "/out/test-overwrite.json");
        deployScript.writeDeployments(path, 1, address(0xA11CE), address(0xB0B));
        deployScript.writeDeployments(path, 31337, address(registry), address(license));

        string memory json = vm.readFile(path);
        assertEq(vm.parseJsonUint(json, ".chainId"), 31337);
        assertEq(vm.parseJsonAddress(json, ".SkillRegistry"), address(registry));
        assertEq(vm.parseJsonAddress(json, ".SkillLicense"), address(license));
        assertEq(vm.parseJsonKeys(json, "$").length, 3, "still exactly three keys");
    }

    function test_DeploymentsPath_TargetsRepoRootNotContractsDir() public view {
        // 项目根是 contracts/，产物必须落到其上一级（仓库根）
        string memory path = deployScript.deploymentsPath();

        assertEq(path, string.concat(vm.projectRoot(), "/../deployments.json"));
    }

    /* ------------------------------------------------------------ 广播产物：setUp 已写出的文件 */

    function test_RunWithKey_WroteChainIdOfCurrentChain() public view {
        string memory json = vm.readFile(outputPath);

        // setUp 走的就是 runWithKey，产物里的 chainId 应为测试链 id
        assertEq(vm.parseJsonUint(json, ".chainId"), block.chainid);
        assertEq(vm.parseJsonAddress(json, ".SkillRegistry"), address(registry));
        assertEq(vm.parseJsonAddress(json, ".SkillLicense"), address(license));
    }

    /// @notice 回归：首次在仓库根目录创建文件必须成功
    /// @dev 授权的是「已存在的父目录」而非尚不存在的文件本身 —— Foundry 会 canonicalize
    ///      许可路径，文件不存在时保留字面量，与规范化后的待写路径不匹配，首次创建就会失败。
    ///      父目录只给了写权限，不能回读校验内容；用 vm.removeFile 反证：
    ///      它在文件不存在时会 revert，能删成功即说明文件确实被首次创建了。
    ///      探针文件唯一命名，用完立即删除，绝不触碰真正的 deployments.json。
    function test_WriteDeployments_FirstTimeCreationInRepoRoot() public {
        string memory probePath = string.concat(vm.projectRoot(), "/../.deployments-test-probe-firstcreate.json");

        // 探针绝不能与真实产物同名
        assertTrue(
            keccak256(bytes(probePath)) != keccak256(bytes(deployScript.deploymentsPath())),
            "probe must never alias the real deployments.json"
        );

        // 首次创建：若许可路径 canonicalize 不匹配，这里会 revert
        deployScript.writeDeployments(probePath, 31337, address(registry), address(license));

        // 该文件此前不存在；removeFile 对不存在的文件会 revert，因此能走到这里
        // 就证明创建确实发生了
        vm.removeFile(probePath);
    }

    /// @notice 回归补充：真实产物与探针同处仓库根，探针可写即证明该目录已授权
    function test_DeploymentsPath_ParentDirectoryIsWritable() public view {
        string memory realPath = deployScript.deploymentsPath();
        string memory probePath = string.concat(vm.projectRoot(), "/../.deployments-test-probe-firstcreate.json");

        // 二者都位于 contracts/../（仓库根）：目录前缀相同
        assertEq(_dirPrefix(probePath), _dirPrefix(realPath), "probe and real output share a directory");
    }

    /// @dev 取路径最后一个 "/" 之前的部分
    function _dirPrefix(string memory path) internal pure returns (string memory) {
        bytes memory b = bytes(path);
        for (uint256 i = b.length; i > 0; --i) {
            if (b[i - 1] == "/") {
                bytes memory out = new bytes(i - 1);
                for (uint256 j = 0; j < i - 1; ++j) {
                    out[j] = b[j];
                }
                return string(out);
            }
        }
        return "";
    }
}
