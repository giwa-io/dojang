// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {DojangAttesterId} from "../libraries/Types.sol";
import {Attestation} from "@eas-contracts/contracts/IEAS.sol";

interface IDojangScroll {
    /**
     * @notice Emitted when an address is not verified
     * @param addr The address of the user
     */
    error NotVerifiedAddress(address addr);

    /**
     * @notice Emitted when a balance root is not found
     * @param coinType The custom coin type (ticker encoded as uint256)
     * @param snapshotAt The timestamp representing when the balance snapshot was taken
     */
    error BalanceRootNotFound(uint256 coinType, uint64 snapshotAt);

    /**
     * @notice Emitted when a balance is not verified
     * @param recipient The recipient address
     * @param coinType The custom coin type (ticker encoded as uint256)
     * @param snapshotAt The timestamp representing when the balance snapshot was taken
     */
    error NotVerifiedBalance(address recipient, uint256 coinType, uint64 snapshotAt);

    /// @notice Thrown when the root attestation's attester does not match the expected attester.
    error MismatchRootAttester(address actual, address expected);

    /**
     * @notice Checks whether the given address has a verified attestation from the specified attester
     * @dev Returns true if a verified attestation exists for the address-attester pair
     * @param addr The address of the user
     * @param attesterId The attester identifier
     * @return Whether the address is verified by the given attester
     */
    function isVerified(address addr, DojangAttesterId attesterId) external view returns (bool);

    /**
     * @notice Returns the verified address attestation uid for the given recipient.
     * @dev Reverts if no verified attestation exists for the given combination
     * @param addr The address of the user
     * @param attesterId The attester identifier
     * @return The verified address attestation uid
     */
    function getVerifiedAddressAttestationUid(address addr, DojangAttesterId attesterId) external view returns (bytes32);

    /**
     * @notice Returns the balance root attestation uid for the given coin type and timestamp
     * @dev Reverts if no balance root attestation exists for the given combination
     * @param coinType The custom coin type (ticker encoded as uint256) of the asset
     * @param snapshotAt The timestamp representing when the balance snapshot was taken
     * @param attesterId The attester identifier
     */
    function getBalanceRootAttestationUid(
        uint256 coinType,
        uint64 snapshotAt,
        DojangAttesterId attesterId
    )
        external
        view
        returns (bytes32);

    /**
     * @notice Returns the verified balance for the given recipient, coin type and timestamp
     * @dev Reverts if no verified attestation exists for the given combination
     * @param recipient The address of the user
     * @param coinType The custom coin type (ticker encoded as uint256) of the asset
     * @param snapshotAt The timestamp representing when the balance snapshot was taken
     * @param attesterId The attester identifier
     * @return The balance amount, denominated in the smallest unit of the asset (i.e., according to the coinType's
     * decimals)
     */
    function getVerifiedBalance(
        address recipient,
        uint256 coinType,
        uint64 snapshotAt,
        DojangAttesterId attesterId
    )
        external
        view
        returns (uint256);

    /**
     * @notice Returns the verified balance attestation uid for the given recipient, coin type and timestamp
     * @dev Reverts if no verified attestation exists for the given combination
     * @param recipient The address of the user
     * @param coinType The custom coin type (ticker encoded as uint256) of the asset
     * @param snapshotAt The timestamp representing when the balance snapshot was taken
     * @param attesterId The attester identifier
     * @return The verified balance attestation uid
     */
    function getVerifiedBalanceAttestationUid(
        address recipient,
        uint256 coinType,
        uint64 snapshotAt,
        DojangAttesterId attesterId
    )
        external
        view
        returns (bytes32);

    /**
     * @notice Checks whether the given codeHash and domain pair has a verified attestation from the specified attester
     * @dev Returns true if a verified attestation exists for the (codeHash, domain, attester) combination.
     *      The codeHash and domain MUST be derived off-chain according to the VerifyCodeSpec
     *      (see `offchain-specs/verify-code/VerifyCodeSpec.sol`) so that issuers and verifiers
     *      use a consistent hashing and canonicalization rule.
     * @param codeHash The hashed verification code
     * @param domain The domain string associated with the verification code; should be canonicalized before lookup
     * @param attesterId The attester identifier
     * @return Whether the verification code-domain pair is verified by the given attester
     */
    function isVerifiedCode(
        bytes32 codeHash,
        string calldata domain,
        DojangAttesterId attesterId
    )
        external
        view
        returns (bool);

    /**
     * @notice Returns the verified code attestation uid for the given codeHash-domain pair and attester
     * @dev Reverts if no verified attestation exists for the given combination.
     *      The caller MUST derive codeHash and canonicalized domain off-chain according to the VerifyCodeSpec
     *      (see `offchain-specs/verify-code/VerifyCodeSpec.sol`) to ensure consistent lookup semantics.
     * @param codeHash The hashed verification code
     * @param domain The domain string associated with the verification code; should be canonicalized before lookup
     * @param attesterId The attester identifier
     * @return The verify-code attestation uid
     */
    function getVerifyCodeAttestationUid(
        bytes32 codeHash,
        string calldata domain,
        DojangAttesterId attesterId
    )
        external
        view
        returns (bytes32);

    /**
     * @notice Returns the address attestation record for the given user address and attester
     * @dev Returns the raw attestation without evaluating timestamps or reverting on expiration,
     *      enabling ERC-4337 validation (where TIMESTAMP opcode is banned under ERC-7562)
     *      to extract expirationTime as validUntil.
     * @param addr The address of the user
     * @param attesterId The attester identifier
     * @return The address attestation record
     */
    function getAddressAttestation(address addr, DojangAttesterId attesterId) external view returns (Attestation memory);

    /**
     * @notice Returns the balance root attestation record for the given coin type and timestamp
     * @dev Returns the raw attestation without evaluating timestamps or reverting on expiration.
     * @param coinType The custom coin type of the asset
     * @param snapshotAt The timestamp representing when the balance snapshot was taken
     * @param attesterId The attester identifier
     * @return The balance root attestation record
     */
    function getBalanceRootAttestation(
        uint256 coinType,
        uint64 snapshotAt,
        DojangAttesterId attesterId
    )
        external
        view
        returns (Attestation memory);

    /**
     * @notice Returns the balance attestation record for the given recipient, coin type and timestamp
     * @dev Returns the raw attestation without evaluating timestamps or reverting on expiration.
     * @param recipient The address of the user
     * @param coinType The custom coin type of the asset
     * @param snapshotAt The timestamp representing when the balance snapshot was taken
     * @param attesterId The attester identifier
     * @return The balance attestation record
     */
    function getBalanceAttestation(
        address recipient,
        uint256 coinType,
        uint64 snapshotAt,
        DojangAttesterId attesterId
    )
        external
        view
        returns (Attestation memory);

    /**
     * @notice Returns the verify-code attestation record for the given codeHash and domain
     * @dev Returns the raw attestation without evaluating timestamps or reverting on expiration.
     * @param codeHash The hashed verification code
     * @param domain The domain string associated with the verification code; should be canonicalized before lookup
     * @param attesterId The attester identifier
     * @return The verify-code attestation record
     */
    function getVerifyCodeAttestation(
        bytes32 codeHash,
        string calldata domain,
        DojangAttesterId attesterId
    )
        external
        view
        returns (Attestation memory);
}
