// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title Attestation Indexer Interface
 * @notice Interface for indexing EAS attestations by arbitrary keys
 * @dev Enables efficient retrieval of attestation UIDs using indexing
 */
interface IAttestationIndexer {
    /**
     * @notice Emitted when an attestation is indexed
     * @param schema The schema UID used for the attestation
     * @param attester The attester address of the attestation
     * @param recipient The address that received the attestation
     * @param key The index key used
     * @param attestationUid The UID of the indexed attestation
     */
    event AttestationIndexed(
        bytes32 indexed schema, address indexed attester, address indexed recipient, bytes32 key, bytes32 attestationUid
    );

    /**
     * @notice Indexes a specific attestation
     * @dev This function associates a (recipient, schemaUid) with a specific
     * attestation UID
     * @param attestationUid The UID of the attestation to be indexed
     */
    function index(bytes32 attestationUid) external;

    /**
     * @notice Indexes a specific attestation under a given key
     * @dev This function associates a (recipient, schemaUid, key) with a specific
     * attestation UID
     * @param key Arbitrary index key (e.g., hashed identifier)
     * @param attestationUid The UID of the attestation to be indexed
     */
    function index(bytes32 key, bytes32 attestationUid) external;

    /**
     * @notice Retrieves an attestation UID indexed by schema, attester and recipient
     * @param schemaUid The UID of the EAS schema
     * @param attester The attester address of the attestation
     * @param recipient The recipient address of the attestation
     * @return attestationUid The UID of the indexed attestation
     */
    function getAttestationUid(
        bytes32 schemaUid,
        address attester,
        address recipient
    )
        external
        view
        returns (bytes32);

    /**
     * @notice Retrieves an attestation UID indexed by schema, attester, recipient and key
     * @param schemaUid The UID of the EAS schema
     * @param attester The attester address of the attestation
     * @param recipient The recipient address of the attestation
     * @param key The key under which the attestation was indexed
     * @return attestationUid The UID of the indexed attestation
     */
    function getAttestationUid(
        bytes32 schemaUid,
        address attester,
        address recipient,
        bytes32 key
    )
        external
        view
        returns (bytes32);
}
