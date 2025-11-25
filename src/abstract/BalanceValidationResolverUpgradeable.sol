// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Attestation} from "@eas-contracts/contracts/IEAS.sol";
import {Initializable} from "@openzeppelin-contracts-upgradeable/proxy/utils/Initializable.sol";
import {MerkleProof} from "@openzeppelin-contracts/utils/cryptography/MerkleProof.sol";
import {SchemaResolverUpgradeable} from "./SchemaResolverUpgradeable.sol";
import {AttestationVerifier} from "../libraries/AttestationVerifier.sol";

/**
 * @title Balance Dojang Validation Resolver for EAS
 * @dev A base contract for creating an EAS Schema Resolver that validate attestations
 * for balance dojang.
 */
abstract contract BalanceValidationResolverUpgradeable is Initializable, SchemaResolverUpgradeable {
    using AttestationVerifier for Attestation;

    /// @custom:storage-location erc7201:dojang.storage.BalanceValidationResolverUpgradeable
    struct BalanceValidationResolverStorage {
        bytes32 balanceRootSchemaUID;
    }

    /// @notice
    /// keccak256(abi.encode(uint256(keccak256("dojang.storage.BalanceValidationResolverUpgradeable"))
    /// - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant BALANCE_VALIDATION_RESOLVER_STORAGE_LOCATION =
        0x2a69b9ad7364f276a616f7187fc857f1063f993b4c2cf91bd2106690bff73100;

    /// @notice Emitted when the balance root schema UID is updated.
    event BalanceRootSchemaUIDUpdated(bytes32 indexed oldUID, bytes32 indexed newUID);

    function __BalanceValidationResolver_init() internal onlyInitializing {
        __BalanceValidationResolver_init_unchained();
    }

    // solhint-disable-next-line no-empty-blocks
    function __BalanceValidationResolver_init_unchained() internal onlyInitializing {}

    /**
     * @dev Extracts attestation data and validate it.
     * See {SchemaResolverUpgradeable-onAttest}.
     *
     * @param attestation The new attestation to be validated.
     * @return bool True if the attestation is valid.
     */
    function onAttest(Attestation calldata attestation, uint256) internal virtual override returns (bool) {
        Attestation memory root = _EAS.getAttestation(attestation.refUID);
        root.verify(address(0), _getBalanceValidationResolverStorage().balanceRootSchemaUID);

        (,,,, bytes32 treeRoot) = abi.decode(root.data, (uint256, uint64, uint192, uint256, bytes32));
        (uint256 amount, bytes32 salt, bytes32[] memory proofs) =
            abi.decode(attestation.data, (uint256, bytes32, bytes32[]));

        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(attestation.recipient, amount, salt))));

        return MerkleProof.verify(proofs, treeRoot, leaf);
    }

    /**
     * @return bool Always true since this functionality is not implemented.
     */
    function onRevoke(Attestation calldata, uint256) internal virtual override returns (bool) {
        return true;
    }

    function _setBalanceRootSchemaUID(bytes32 uid) internal {
        BalanceValidationResolverStorage storage $ = _getBalanceValidationResolverStorage();
        bytes32 oldUID = $.balanceRootSchemaUID;
        emit BalanceRootSchemaUIDUpdated(oldUID, uid);
        $.balanceRootSchemaUID = uid;
    }

    function _getBalanceValidationResolverStorage() private pure returns (BalanceValidationResolverStorage storage $) {
        assembly {
            $.slot := BALANCE_VALIDATION_RESOLVER_STORAGE_LOCATION
        }
    }
}
