// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Initializable} from "@openzeppelin-contracts-upgradeable/proxy/utils/Initializable.sol";
import {SchemaResolverUpgradeable} from "./SchemaResolverUpgradeable.sol";
import {Attestation} from "@eas-contracts/contracts/IEAS.sol";

/**
 * @title Allowlist Schema Resolver for EAS
 * @dev A base contract for creating an EAS Schema Resolver that can guard
 * a schema's usage based on the attester. Only attester(s) on the allowlist
 * can create attestations when this base contract is used for a schema's resolver.
 */
abstract contract AllowlistResolverUpgradeable is Initializable, SchemaResolverUpgradeable {
    /// @custom:storage-location erc7201:dojang.storage.AllowlistResolverUpgradeable
    struct AllowlistResolverStorage {
        /**
         * @dev Addresses that are allowed to attest using the schema this resolver
         * is
         * associated with.
         */
        mapping(address => bool) allowedAttester;
    }

    /// @notice
    /// keccak256(abi.encode(uint256(keccak256("dojang.storage.AllowlistResolverUpgradeable"))
    /// - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ALLOWLIST_RESOLVER_STORAGE_LOCATION =
        0xd852276f09be10fac28953842991572f8a5e8e0a6613bca011479db2d659a500;

    /// @notice Emitted when an attester is allowed.
    event AttesterAllowed(address indexed attester);

    /// @notice Emitted when an attester is removed.
    event AttesterRemoved(address indexed attester);

    /// @dev Attester already in allowlist.
    error AttesterAlreadyAllowed(address attester);

    /// @dev Attester not in allowlist.
    error AttesterAlreadyNotAllowed(address attester);

    function __AllowlistResolver_init() internal onlyInitializing {
        __AllowlistResolver_init_unchained();
    }

    // solhint-disable-next-line no-empty-blocks
    function __AllowlistResolver_init_unchained() internal onlyInitializing {}

    /**
     * @dev Adds a new allowed attester.
     *
     * If this function were to be made public or external,
     * it should be protected to only allow authorized callers.
     *
     * @param attester The address of the attester to be added to allowlist.
     */
    function _allowAttester(address attester) internal {
        AllowlistResolverStorage storage $ = _getAllowlistResolverStorage();

        if ($.allowedAttester[attester]) {
            revert AttesterAlreadyAllowed(attester);
        }
        $.allowedAttester[attester] = true;
        emit AttesterAllowed(attester);
    }

    /**
     * @dev Removes an existing allowed attester.
     *
     * If this function were to be made public or external,
     * it should be protected to only allow authorized callers.
     *
     * @param attester The address of the attester to be removed from allowlist.
     */
    function _removeAttester(address attester) internal {
        AllowlistResolverStorage storage $ = _getAllowlistResolverStorage();

        if (!$.allowedAttester[attester]) {
            revert AttesterAlreadyNotAllowed(attester);
        }
        $.allowedAttester[attester] = false;
        emit AttesterRemoved(attester);
    }

    /**
     * @dev Processes a new attestation, and checks if the attester is in the
     * allowlist.
     * See {SchemaResolverUpgradeable-onAttest}.
     *
     * @param attestation The new attestation.
     * @return bool True if the attestation is allowed based on the attester.
     */
    function onAttest(Attestation calldata attestation, uint256) internal virtual override returns (bool) {
        AllowlistResolverStorage storage $ = _getAllowlistResolverStorage();
        return $.allowedAttester[attestation.attester];
    }

    /**
     * @dev Not implemented as EAS already ensures that only the attester
     * who created an attestation can revoke it. We do not need an additional
     * allowlist.
     * See {SchemaResolverUpgradeable-onRevoke}.
     *
     * @return bool Always true as EAS already ensures that only the attester can
     * revoke.
     */
    function onRevoke(Attestation calldata, uint256) internal virtual override returns (bool) {
        return true;
    }

    function _getAllowlistResolverStorage() private pure returns (AllowlistResolverStorage storage $) {
        assembly {
            $.slot := ALLOWLIST_RESOLVER_STORAGE_LOCATION
        }
    }
}
