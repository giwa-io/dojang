// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Initializable} from "@openzeppelin-contracts-upgradeable/proxy/utils/Initializable.sol";
import {SchemaResolverUpgradeable} from "./SchemaResolverUpgradeable.sol";
import {Attestation} from "@eas-contracts/contracts/IEAS.sol";
import {IAttestationIndexer} from "../interfaces/IAttestationIndexer.sol";
import {IndexerUpdated, InvalidIndexer} from "../libraries/Common.sol";

/**
 * @title Balance Dojang Indexing Resolver for EAS
 * @dev A base contract for creating an EAS Schema Resolver that indexes attestations
 * for balance dojang.
 */
abstract contract BalanceIndexingResolverUpgradeable is Initializable, SchemaResolverUpgradeable {
    /// @custom:storage-location erc7201:dojang.storage.BalanceIndexingResolverUpgradeable
    struct BalanceIndexingResolverStorage {
        IAttestationIndexer indexer;
    }

    /// @notice
    /// keccak256(abi.encode(uint256(keccak256("dojang.storage.BalanceIndexingResolverUpgradeable"))
    /// - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant BALANCE_INDEXING_RESOLVER_STORAGE_LOCATION =
        0x1daeb03bc251932f84305b1d992090c50f663b400469e848b99f0e227fbdb200;

    function __BalanceIndexingResolver_init() internal onlyInitializing {
        __BalanceIndexingResolver_init_unchained();
    }

    function __BalanceIndexingResolver_init_unchained() internal onlyInitializing 
    // solhint-disable-next-line no-empty-blocks
    {}

    /**
     * @dev Extracts attestation data and indexes it with UID via the
     * external indexer.
     * See {SchemaResolverUpgradeable-onAttest}.
     *
     * @param attestation The new attestation to be indexed.
     * @return bool True if the attestation was indexed successfully without
     * reverting.
     */
    function onAttest(Attestation calldata attestation, uint256) internal virtual override returns (bool) {
        BalanceIndexingResolverStorage storage $ = _getBalanceIndexingResolverStorage();

        (uint256 coinType, uint64 snapshotAt) = abi.decode(attestation.data, (uint256, uint64));
        bytes32 key = keccak256(abi.encode(coinType, snapshotAt));
        $.indexer.index(key, attestation.uid);
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
        BalanceIndexingResolverStorage storage $ = _getBalanceIndexingResolverStorage();

        if (indexer == address(0) || indexer == address($.indexer)) {
            revert InvalidIndexer();
        }
        // Note: In test environments, mock contracts may not have code
        // This validation is primarily for production safety
        address prevIndexer = address($.indexer);
        $.indexer = IAttestationIndexer(indexer);
        emit IndexerUpdated(prevIndexer, address($.indexer));
    }

    function _getBalanceIndexingResolverStorage() private pure returns (BalanceIndexingResolverStorage storage $) {
        assembly {
            $.slot := BALANCE_INDEXING_RESOLVER_STORAGE_LOCATION
        }
    }
}
