// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IDojangAttester {
    /// @notice Emitted when an address is attested
    event AddressAttested(address indexed addr);

    /// @notice Emitted when an address is revoked
    event AddressRevoked(address indexed addr);

    /// @notice Emitted when a balance is attested
    event BalanceAttested(address indexed recipient, uint256 indexed coinType, uint64 indexed snapshotAt);

    /// @notice Emitted when a balance is revoked
    event BalanceRevoked(address indexed recipient, uint256 indexed coinType, uint64 indexed snapshotAt);

    /**
     * @notice Issues an address attestation for the recipient
     * @dev This is a gas optimization to reduce calldata size when attesting by
     * templatizing the attestation request data.
     * @param recipient The address receiving the attestation
     * @param expirationTime The timestamp after which the address attestation becomes invalid.
     * @return UID of the created attestation
     */
    function attestAddress(address recipient, uint64 expirationTime) external returns (bytes32);

    /**
     * @notice Revokes an address attestation
     * @dev This is a gas optimization to reduce calldata size when revoking by
     * templatizing the revocation request data.
     * @param attestationUid UID of the attestation to revoke
     */
    function revokeAddress(bytes32 attestationUid) external;

    /**
     * @notice Issues the balance of a recipient for a specific coin type at a snapshotAt timestamp
     * @dev This is a gas optimization to reduce calldata size when attesting by
     * templatizing the attestation request data.
     * @param recipient The address to which the attestation will be issued
     * @param coinType The BIP-44 coin type of the asset
     * @param snapshotAt The timestamp representing when the balance snapshot was taken
     * @param balance The balance amount, denominated in the smallest unit of the asset (i.e., according to the
     * coinType's decimals)
     * @return UID of the created attestation
     */
    function attestBalance(
        address recipient,
        uint256 coinType,
        uint64 snapshotAt,
        uint256 balance
    )
        external
        returns (bytes32);

    /**
     * @notice Revokes a balance attestation
     * @dev This is a gas optimization to reduce calldata size when revoking by
     * templatizing the revocation request data.
     * @param attestationUid UID of the attestation to revoke
     */
    function revokeBalance(bytes32 attestationUid) external;
}
