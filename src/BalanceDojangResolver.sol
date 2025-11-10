// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {UUPSUpgradeable} from "@openzeppelin-contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin-contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {SchemaResolverUpgradeable} from "./abstract/SchemaResolverUpgradeable.sol";
import {BalanceValidationResolverUpgradeable} from "./abstract/BalanceValidationResolverUpgradeable.sol";
import {AllowlistResolverUpgradeable} from "./abstract/AllowlistResolverUpgradeable.sol";
import {BalanceIndexingResolverUpgradeable} from "./abstract/BalanceIndexingResolverUpgradeable.sol";
import {ZeroAddress} from "./libraries/Common.sol";
import {Attestation} from "@eas-contracts/contracts/IEAS.sol";

contract BalanceDojangResolver is
    UUPSUpgradeable,
    AccessControlUpgradeable,
    SchemaResolverUpgradeable,
    BalanceValidationResolverUpgradeable,
    AllowlistResolverUpgradeable,
    BalanceIndexingResolverUpgradeable
{
    // 0x8421c86537ca8724814af8dd9a3536c8129b6f4ebed2c873a3cb4c7f1ef851b1
    bytes32 public constant UPGRADER_ROLE = keccak256("dojang.balancedojangresolver.upgrader");

    /**
     * @dev Locks the contract, preventing any future reinitialization. This
     * implementation contract was designed to be called through proxies.
     * @custom:oz-upgrades-unsafe-allow constructor
     */
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Allows a new attester.
     * @param attester The address of the attester to be added to allowlist.
     */
    function allowAttester(address attester) external onlyRole(AccessControlUpgradeable.DEFAULT_ADMIN_ROLE) {
        _allowAttester(attester);
    }

    /**
     * @notice Removes an existing allowed attester.
     * @param attester The address of the attester to be removed from allowlist.
     */
    function removeAttester(address attester) external onlyRole(AccessControlUpgradeable.DEFAULT_ADMIN_ROLE) {
        _removeAttester(attester);
    }

    /**
     * @notice Updates the indexer contract used to index attestations
     * @param indexer The address of the new IAttestationIndexer
     */
    function setIndexer(address indexer) external onlyRole(AccessControlUpgradeable.DEFAULT_ADMIN_ROLE) {
        _setIndexer(indexer);
    }

    /**
     * @dev Initializes the contract
     * @param admin The address to be granted with the default admin Role
     */
    function initialize(address admin) public initializer {
        if (admin == address(0)) {
            revert ZeroAddress();
        }

        __UUPSUpgradeable_init();
        __AccessControl_init();

        __SchemaResolver_init();
        __BalanceValidationResolver_init();
        __AllowlistResolver_init();
        __BalanceIndexingResolver_init();

        _grantRole(AccessControlUpgradeable.DEFAULT_ADMIN_ROLE, admin);
    }

    /// @notice Semantic version.
    /// @custom:semver 0.3.0
    function version() public pure virtual returns (string memory) {
        return "0.3.0";
    }

    /// @inheritdoc SchemaResolverUpgradeable
    /// @dev See {BalanceValidationResolverUpgradeable-onAttest}, {AllowlistResolverUpgradeable-onAttest}, and
    /// {BalanceIndexingResolverUpgradeable-onAttest}.
    function onAttest(
        Attestation calldata attestation,
        uint256 value
    )
        internal
        override(
            SchemaResolverUpgradeable,
            BalanceValidationResolverUpgradeable,
            AllowlistResolverUpgradeable,
            BalanceIndexingResolverUpgradeable
        )
        returns (bool)
    {
        return BalanceValidationResolverUpgradeable.onAttest(attestation, value)
            && AllowlistResolverUpgradeable.onAttest(attestation, value)
            && BalanceIndexingResolverUpgradeable.onAttest(attestation, value);
    }

    /// @inheritdoc SchemaResolverUpgradeable
    /// @dev See {BalanceValidationResolverUpgradeable-onRevoke}, {AllowlistResolverUpgradeable-onRevoke}, and
    /// {BalanceIndexingResolverUpgradeable-onRevoke}.
    function onRevoke(
        Attestation calldata attestation,
        uint256 value
    )
        internal
        override(
            SchemaResolverUpgradeable,
            BalanceValidationResolverUpgradeable,
            AllowlistResolverUpgradeable,
            BalanceIndexingResolverUpgradeable
        )
        returns (bool)
    {
        return BalanceValidationResolverUpgradeable.onRevoke(attestation, value)
            && AllowlistResolverUpgradeable.onRevoke(attestation, value)
            && BalanceIndexingResolverUpgradeable.onRevoke(attestation, value);
    }

    /**
     * @notice Authorizes the upgrade of the contract.
     * @dev Only those with the UPGRADER_ROLE can call this.
     * @inheritdoc UUPSUpgradeable
     */
    // solhint-disable-next-line no-empty-blocks
    function _authorizeUpgrade(address) internal override onlyRole(UPGRADER_ROLE) {}
}
