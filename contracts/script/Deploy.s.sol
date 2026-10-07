// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {SkillRegistry} from "../src/SkillRegistry.sol";
import {SkillLicense} from "../src/SkillLicense.sol";

/// @title Deploy
/// @notice 部署 SkillRegistry 与 SkillLicense，完成双向接线，并把地址写入仓库根目录 deployments.json。
/// @dev 关键约束：registry.setSkillLicense / license.setRegistry 都是 onlyOwner。
///      因此接线调用必须在「签名密钥对应的地址」这一层发出 —— 广播时即 EOA 本身，
///      绝不能经中间合约转发，否则 msg.sender 会变成合约地址而被 onlyOwner 拒绝。
///      测试用 runWithKey（内部 startBroadcast）复现同一语义，仅替换产物路径。
///
///      本地 Anvil 运行：
///        forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 --broadcast
contract Deploy is Script {
    /// @dev deployments.json 位于仓库根目录，而 Foundry 项目根是 contracts/
    string internal constant DEPLOYMENTS_RELATIVE_PATH = "../deployments.json";

    /// @notice 从 PRIVATE_KEY 读取签名密钥，广播部署，写产物
    /// @return registry 已部署的 SkillRegistry 地址
    /// @return license 已部署的 SkillLicense 地址
    function run() external returns (address registry, address license) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);
        (registry, license) = deployAndWire(vm.addr(deployerPrivateKey));
        vm.stopBroadcast();

        writeDeployments(deploymentsPath(), block.chainid, registry, license);

        console2.log("chainId      :", block.chainid);
        console2.log("SkillRegistry:", registry);
        console2.log("SkillLicense :", license);
        console2.log("deployments  :", deploymentsPath());
    }

    /// @notice 用指定私钥广播部署并写产物；测试复用此入口，路径换成隔离文件
    /// @param deployerPrivateKey 广播私钥，其地址必须等于 owner
    /// @param owner 两个合约共同的 owner
    /// @param outputPath deployments.json 的绝对路径
    function runWithKey(uint256 deployerPrivateKey, address owner, string memory outputPath)
        public
        returns (address registry, address license)
    {
        vm.startBroadcast(deployerPrivateKey);
        (registry, license) = deployAndWire(owner);
        vm.stopBroadcast();

        writeDeployments(outputPath, block.chainid, registry, license);
    }

    /// @notice 部署两个合约并双向接线
    /// @dev 不做 msg.sender 自检：接线调用会以广播者身份发出，若广播私钥不是 owner，
    ///      合约自身的 onlyOwner 会以 OwnableUnauthorizedAccount 直接拒绝，无需重复判断。
    /// @param owner 两个合约共同的 owner
    function deployAndWire(address owner) public returns (address registry, address license) {
        require(owner != address(0), "Deploy: zero owner");

        SkillRegistry registryContract = new SkillRegistry(owner);
        SkillLicense licenseContract = new SkillLicense(owner);

        // 两合约 owner 相同，因此同一次广播即可完成双向接线
        registryContract.setSkillLicense(address(licenseContract));
        licenseContract.setRegistry(address(registryContract));

        return (address(registryContract), address(licenseContract));
    }

    /// @notice 仓库根目录 deployments.json 的绝对路径
    function deploymentsPath() public view returns (string memory) {
        return string.concat(vm.projectRoot(), "/", DEPLOYMENTS_RELATIVE_PATH);
    }

    /// @notice 按 SPEC 第 7 节格式写出 {chainId, SkillRegistry, SkillLicense}
    /// @dev writeJson 自身会覆盖已存在文件，无需先删除
    function writeDeployments(string memory outputPath, uint256 chainId, address registry, address license) public {
        string memory obj = "deployments";

        vm.serializeUint(obj, "chainId", chainId);
        vm.serializeAddress(obj, "SkillRegistry", registry);
        string memory json = vm.serializeAddress(obj, "SkillLicense", license);

        vm.writeJson(json, outputPath);
    }
}
