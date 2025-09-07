// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Initializable} from "@openzeppelin-contracts-upgradeable/proxy/utils/Initializable.sol";
import {SchemaResolverUpgradeable} from "./SchemaResolverUpgradeable.sol";
import {Attestation} from "@eas-contracts/contracts/IEAS.sol";
import {IAttestationIndexer} from "../interfaces/IAttestationIndexer.sol";
import {IndexerUpdated, InvalidIndexer} from "../libraries/Common.sol";

/**
 * @title Address Dojang Indexing Resolver for EAS
 * @dev A base contract for creating an EAS Schema Resolver than indexes attestations
 * for address dojang.
 */
abstract contract AddressIndexingResolverUpgradeable is Initializable, SchemaResolverUpgradeable {
    /// @custom:storage-location erc7201:dojang.storage.AddressIndexingResolverUpgradeable
    struct AddressIndexingResolverStorage {
        /// @notice Address of the attestation indexer contract
        IAttestationIndexer indexer;
    }

    /// @notice
    /// keccak256(abi.encode(uint256(keccak256("dojang.storage.AddressIndexingResolverUpgradeable"))
    /// - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ADDRESS_INDEXING_RESOLVER_STORAGE_LOCATION =
        0x865ef45a81b5ea8104b3058e4b7c920da617ffc76b0f193f84980e2e5fb3cf00;

    function __AddressIndexingResolver_init() internal onlyInitializing {
        __AddressIndexingResolver_init_unchained();
    }

    function __AddressIndexingResolver_init_unchained() internal onlyInitializing 
    // solhint-disable-next-line no-empty-blocks
    {}

    /**
     * @dev Indexes the given attestation via the external indexer.
     * See {SchemaResolverUpgradeable-onAttest}.
     *
     * @param attestation The new attestation to be indexed.
     * @return bool True if the attestation was indexed successfully without
     * reverting.
     */
    function onAttest(Attestation calldata attestation, uint256) internal virtual override returns (bool) {
        AddressIndexingResolverStorage storage $ = _getAddressIndexingResolverStorage();
        $.indexer.index(attestation.uid);
        return true;
    }

    /**
     * @dev Not implemented as indexing on revocation is not necessary.
     * See {SchemaResolverUpgradeable-onRevoke}.
     *
     * Attestations should always be verified upon usage.
     * The indexer should not be relied upon as the source of truth or
     * for an attestation's liveness.
     *
     * @return bool Always true since this functionality is not implemented.
     */
    function onRevoke(Attestation calldata, uint256) internal virtual override returns (bool) {
        return true;
    }

    /**
     * @dev Updates the indexer contract
     * @param indexer The address of the new IAttestationIndexer
     */
    function _setIndexer(address indexer) internal {
        AddressIndexingResolverStorage storage $ = _getAddressIndexingResolverStorage();

        if (indexer == address(0) || indexer == address($.indexer)) {
            revert InvalidIndexer();
        }
        address prevIndexer = address($.indexer);
        $.indexer = IAttestationIndexer(indexer);
        emit IndexerUpdated(prevIndexer, address($.indexer));
    }

    function _getAddressIndexingResolverStorage() private pure returns (AddressIndexingResolverStorage storage $) {
        assembly {
            $.slot := ADDRESS_INDEXING_RESOLVER_STORAGE_LOCATION
        }
    }
}
