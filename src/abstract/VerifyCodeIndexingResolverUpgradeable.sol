// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Initializable} from "@openzeppelin-contracts-upgradeable/proxy/utils/Initializable.sol";
import {SchemaResolverUpgradeable} from "./SchemaResolverUpgradeable.sol";
import {IAttestationIndexer} from "../interfaces/IAttestationIndexer.sol";
import {Attestation} from "@eas-contracts/contracts/IEAS.sol";
import {IndexerUpdated, InvalidIndexer} from "../libraries/Common.sol";

abstract contract VerifyCodeIndexingResolverUpgradeable is Initializable, SchemaResolverUpgradeable {
    /// @custom:storage-location erc7201:dojang.storage.VerifyCodeIndexingResolverUpgradeable
    struct VerifyCodeIndexingResolverStorage {
        /// @notice Address of the attestation indexer contract
        IAttestationIndexer indexer;
    }

    /// @notice
    /// keccak256(abi.encode(uint256(keccak256("dojang.storage.VerifyCodeIndexingResolverUpgradeable"))
    /// - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant VERIFY_CODE_INDEXING_RESOLVER_STORAGE_LOCATION =
        0x56479d54c8a270d052194a471b8a16cca9486bd3897b44aa281df9412faba700;

    function __VerifyCodeIndexingResolver_init() internal onlyInitializing {
        __VerifyCodeIndexingResolver_init_unchained();
    }

    // solhint-disable-next-line no-empty-blocks
    function __VerifyCodeIndexingResolver_init_unchained() internal onlyInitializing {}

    /**
     * @dev Indexes the given attestation via the external indexer.
     * See {SchemaResolverUpgradeable-onAttest}.
     *
     * @param attestation The new attestation to be indexed.
     * @return bool True if the attestation was indexed successfully without
     * reverting.
     */
    function onAttest(Attestation calldata attestation, uint256) internal virtual override returns (bool) {
        VerifyCodeIndexingResolverStorage storage $ = _getVerifyCodeIndexingResolverStorage();
        (bytes32 codeHash, string memory domain) = abi.decode(attestation.data, (bytes32, string));

        bytes32 key = keccak256(abi.encode(codeHash, domain));
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
        VerifyCodeIndexingResolverStorage storage $ = _getVerifyCodeIndexingResolverStorage();

        if (indexer == address(0) || indexer == address($.indexer)) {
            revert InvalidIndexer();
        }
        address prevIndexer = address($.indexer);
        $.indexer = IAttestationIndexer(indexer);
        emit IndexerUpdated(prevIndexer, address($.indexer));
    }

    function _getVerifyCodeIndexingResolverStorage()
        private
        pure
        returns (VerifyCodeIndexingResolverStorage storage $)
    {
        assembly {
            $.slot := VERIFY_CODE_INDEXING_RESOLVER_STORAGE_LOCATION
        }
    }
}
