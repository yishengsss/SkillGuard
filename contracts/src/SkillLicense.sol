// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @notice SkillRegistry 中供 SkillLicense 读取的可信视图（仅 auditorOf 是必需的）
interface ISkillRegistry {
    function auditorOf(bytes32 key) external view returns (address);
}

/// @title SkillLicense
/// @notice 审计通过后由 SkillRegistry 铸造的 VERIFIED 许可证（ERC-721）。
///         每个技能版本最多一张；恶意结论不铸造。
/// @dev 审计者地址不在 mint 参数里（SPEC 3.2 签名固定）。许可证只信任持有 MINTER_ROLE
///      的 registry，并回读 registry.auditorOf(key) 取得真实审计者 —— 既不用 tx.origin，
///      也不接受调用方自报的审计者。
///      铸造权限用 OZ AccessControl 表达：角色只能由本合约内部（setRegistry）授予，
///      且 DEFAULT_ADMIN_ROLE 从未授予任何地址，因此 grantRole 无法被用来扩大 minter 集合。
contract SkillLicense is ERC721, Ownable, AccessControl {
    struct License {
        string skillId;
        string version;
        bytes32 reportHash;
        address auditor;
        uint256 timestamp;
    }

    /// @notice 唯一可铸造许可证的角色；由 setRegistry 内部授予当前 registry
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    /// @notice 唯一被授权铸造的 SkillRegistry 地址
    address public registry;

    /// @notice tokenId => 许可证元数据
    mapping(uint256 => License) public licenses;

    /// @notice 版本键 => tokenId（0 表示未铸造）
    mapping(bytes32 => uint256) public tokenOfKey;

    uint256 private _nextTokenId = 1;

    event RegistryUpdated(address indexed previousRegistry, address indexed newRegistry);
    event LicenseMinted(
        uint256 indexed tokenId, bytes32 indexed key, address indexed to, address auditor, bytes32 reportHash
    );

    error AlreadyLicensed(bytes32 key);
    error NoAuditor(bytes32 key);
    error ZeroAddress();

    constructor(address initialOwner) ERC721("SkillGuard Verified License", "SGVL") Ownable(initialOwner) {}

    /// @notice ERC-165：ERC721 与 AccessControl 的接口都要暴露
    function supportsInterface(bytes4 interfaceId) public view override(ERC721, AccessControl) returns (bool) {
        return ERC721.supportsInterface(interfaceId) || AccessControl.supportsInterface(interfaceId);
    }

    /// @notice owner 设置可信 registry；用于解决部署顺序（先部署两个合约，再互相接线）
    /// @dev 更换地址时先撤销旧 registry 的 MINTER_ROLE 再授予新的，任一时刻至多一个 minter
    function setRegistry(address newRegistry) external onlyOwner {
        if (newRegistry == address(0)) revert ZeroAddress();

        address previous = registry;
        registry = newRegistry;

        if (previous != address(0)) _revokeRole(MINTER_ROLE, previous);
        _grantRole(MINTER_ROLE, newRegistry);

        emit RegistryUpdated(previous, newRegistry);
    }

    /// @notice 版本键，与 SPEC 3.1 的 key 公式一致
    function keyOf(string memory skillId, string memory version) public pure returns (bytes32) {
        return keccak256(abi.encode(skillId, version));
    }

    /// @notice 铸造许可证，只有持有 MINTER_ROLE 的 SkillRegistry 可调
    /// @dev 若两个合约的 key 公式出现分歧，auditorOf 会返回 0 并在此 revert（失败安全）
    function mint(address to, string calldata skillId, string calldata version, bytes32 reportHash)
        external
        onlyRole(MINTER_ROLE)
        returns (uint256 tokenId)
    {
        bytes32 key = keyOf(skillId, version);
        if (tokenOfKey[key] != 0) revert AlreadyLicensed(key);

        // 审计者来自可信 registry 的调用上下文，而非调用方传入
        address auditor = ISkillRegistry(registry).auditorOf(key);
        if (auditor == address(0)) revert NoAuditor(key);

        tokenId = _nextTokenId++;
        tokenOfKey[key] = tokenId;
        licenses[tokenId] = License({
            skillId: skillId, version: version, reportHash: reportHash, auditor: auditor, timestamp: block.timestamp
        });

        // effects -> events -> interactions
        emit LicenseMinted(tokenId, key, to, auditor, reportHash);
        _safeMint(to, tokenId);
    }

    /// @notice 该版本是否持有 VERIFIED 许可证（gate 安装门禁读取）
    /// @dev 只看是否铸造过，与当前持有人无关；转让不会使其失效
    function isVerified(string calldata skillId, string calldata version) external view returns (bool) {
        return tokenOfKey[keyOf(skillId, version)] != 0;
    }

    /// @notice 已铸造的许可证总数
    function totalMinted() external view returns (uint256) {
        return _nextTokenId - 1;
    }
}
