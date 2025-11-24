// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {UUPSUpgradeable} from "@openzeppelin-contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin-contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {SchemaResolverUpgradeable} from "./abstract/SchemaResolverUpgradeable.sol";
import {BalanceRootValidationResolverUpgradeable} from "./abstract/BalanceRootValidationResolverUpgradeable.sol";
import {AllowlistResolverUpgradeable} from "./abstract/AllowlistResolverUpgradeable.sol";
import {BalanceRootIndexingResolverUpgradeable} from "./abstract/BalanceRootIndexingResolverUpgradeable.sol";
import {ZeroAddress} from "./libraries/Common.sol";
import {Attestation} from "@eas-contracts/contracts/IEAS.sol";

contract BalanceRootDojangResolver is
    UUPSUpgradeable,
    AccessControlUpgradeable,
    SchemaResolverUpgradeable,
    BalanceRootValidationResolverUpgradeable,
    AllowlistResolverUpgradeable,
    BalanceRootIndexingResolverUpgradeable
{
    // 0x5b437c77573c20c7ba441302748381a65e029cf6e602320d44b325b937c3dd9c
    bytes32 public constant UPGRADER_ROLE = keccak256("dojang.balancerootdojangresolver.upgrader");

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
        __BalanceRootValidationResolver_init();
        __AllowlistResolver_init();
        __BalanceRootIndexingResolver_init();

        _grantRole(AccessControlUpgradeable.DEFAULT_ADMIN_ROLE, admin);
    }

    /// @notice Semantic version.
    /// @custom:semver 0.4.0
    function version() public pure virtual returns (string memory) {
        return "0.4.0";
    }

    /// @inheritdoc SchemaResolverUpgradeable
    /// @dev See {BalanceRootValidationResolverUpgradeable-onAttest}, {AllowlistResolverUpgradeable-onAttest}, and
    /// {BalanceRootIndexingResolverUpgradeable-onAttest}.
    function onAttest(
        Attestation calldata attestation,
        uint256 value
    )
        internal
        override(
            SchemaResolverUpgradeable,
            BalanceRootValidationResolverUpgradeable,
            AllowlistResolverUpgradeable,
            BalanceRootIndexingResolverUpgradeable
        )
        returns (bool)
    {
        return BalanceRootValidationResolverUpgradeable.onAttest(attestation, value)
            && AllowlistResolverUpgradeable.onAttest(attestation, value)
            && BalanceRootIndexingResolverUpgradeable.onAttest(attestation, value);
    }

    /// @inheritdoc SchemaResolverUpgradeable
    /// @dev See {BalanceRootValidationResolverUpgradeable-onRevoke}, {AllowlistResolverUpgradeable-onRevoke}, and
    /// {BalanceRootIndexingResolverUpgradeable-onRevoke}.
    function onRevoke(
        Attestation calldata attestation,
        uint256 value
    )
        internal
        override(
            SchemaResolverUpgradeable,
            BalanceRootValidationResolverUpgradeable,
            AllowlistResolverUpgradeable,
            BalanceRootIndexingResolverUpgradeable
        )
        returns (bool)
    {
        return BalanceRootValidationResolverUpgradeable.onRevoke(attestation, value)
            && AllowlistResolverUpgradeable.onRevoke(attestation, value)
            && BalanceRootIndexingResolverUpgradeable.onRevoke(attestation, value);
    }

    /**
     * @notice Authorizes the upgrade of the contract.
     * @dev Only those with the UPGRADER_ROLE can call this.
     * @inheritdoc UUPSUpgradeable
     */
    // solhint-disable-next-line no-empty-blocks
    function _authorizeUpgrade(address) internal override onlyRole(UPGRADER_ROLE) {}
}
