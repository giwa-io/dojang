// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Attestation} from "@eas-contracts/contracts/IEAS.sol";

/**
 * @title EAS Attestation Verifier
 * @notice Utility library for verifying EAS attestations
 * @dev Provides reusable checks for UID presence, expiration, revocation, recipient
 * and schema matching
 */
library AttestationVerifier {
    /// @notice Emitted when the attestation UID is zero
    error ZeroUid();
    /// @notice Emitted when the attestation has expired
    error ExpiredAttestation(bytes32 attestationUid, uint256 expirationTime);
    /// @notice Emitted when the attestation has been revoked
    error RevokedAttestation(bytes32 attestationUid, uint256 revocationTime);
    /// @notice Emitted when the attestation's recipient does not match the expected
    /// address
    error MisMatchRecipient(address actual, address expect);
    /// @notice Emitted when the attestation's schema does not match the expected
    /// schema
    error MisMatchSchema(bytes32 actual, bytes32 expect);

    /**
     * @notice Verifies the basic validity of an attestation
     * @dev Checks UID presence, expiration, and revocation status
     * @param attestation The attestation to verify
     */
    function verify(Attestation memory attestation) internal view {
        if (attestation.uid == 0) {
            revert ZeroUid();
        }

        _verify(attestation);
    }

    /**
     * @notice Verifies the basic validity of an attestation
     * @dev Checks UID presence, expiration, and revocation status
     * @param attestation The attestation to verify
     * @return Whether the attestation is valid
     */
    function isVerified(Attestation memory attestation) internal view returns (bool) {
        if (attestation.uid == 0) {
            return false;
        }

        return _isVerified(attestation);
    }

    /**
     * @notice Verifies an attestation's validity along with recipient and schema
     * match
     * @dev Checks UID, expiration, revocation, recipient, and schema UID
     * @param attestation The attestation to verify
     * @param recipient The expected recipient address
     * @param schemaUid The expected schema UID
     */
    function verify(Attestation memory attestation, address recipient, bytes32 schemaUid) internal view {
        verify(attestation);

        if (attestation.recipient != recipient) {
            revert MisMatchRecipient(attestation.recipient, recipient);
        }

        if (attestation.schema != schemaUid) {
            revert MisMatchSchema(attestation.schema, schemaUid);
        }
    }

    /**
     * @notice Verifies an attestation's validity along with recipient and schema
     * match
     * @dev Checks UID, expiration, revocation, recipient, and schema UID
     * @param attestation The attestation to verify
     * @param recipient The expected recipient address
     * @param schemaUid The expected schema UID
     * @return Whether the attestation is valid
     */
    function isVerified(
        Attestation memory attestation,
        address recipient,
        bytes32 schemaUid
    )
        internal
        view
        returns (bool)
    {
        if (!isVerified(attestation)) {
            return false;
        }

        if (attestation.recipient != recipient) {
            return false;
        }

        if (attestation.schema != schemaUid) {
            return false;
        }

        return true;
    }

    /**
     * @dev Internal helper for verifying expiration and revocation
     * @param attestation The attestation to verify
     */
    function _verify(Attestation memory attestation) private view {
        if (attestation.expirationTime != 0 && attestation.expirationTime <= uint64(block.timestamp)) {
            revert ExpiredAttestation(attestation.uid, attestation.expirationTime);
        }

        if (attestation.revocationTime != 0) {
            revert RevokedAttestation(attestation.uid, attestation.revocationTime);
        }
    }

    /**
     * @dev Internal helper for verifying expiration and revocation
     * @param attestation The attestation to verify
     * @return Whether the attestation is valid
     */
    function _isVerified(Attestation memory attestation) private view returns (bool) {
        if (attestation.expirationTime != 0 && attestation.expirationTime <= uint64(block.timestamp)) {
            return false;
        }

        if (attestation.revocationTime != 0) {
            return false;
        }

        return true;
    }
}
