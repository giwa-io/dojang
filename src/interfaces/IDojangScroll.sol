// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {DojangAttesterId} from "../libraries/Types.sol";

interface IDojangScroll {
    /**
     * @notice Emitted when an address is not verified
     * @param addr The address of the user
     */
    error NotVerifiedAddress(address addr);

    /**
     * @notice Emitted when a balance is not verified
     * @param recipient The recipient address
     * @param coinType The BIP-44 coin type
     * @param snapshotAt The timestamp representing when the balance snapshot was taken
     */
    error NotVerifiedBalance(address recipient, uint256 coinType, uint64 snapshotAt);

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
    function getVerifiedAddressAttestationUid(
        address addr,
        DojangAttesterId attesterId
    )
        external
        view
        returns (bytes32);

    /**
     * @notice Returns the verified balance for the given recipient, coin type and timestamp
     * @dev Reverts if no verified attestation exists for the given combination
     * @param recipient The address of the user
     * @param coinType The BIP-44 coin type of the asset
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
     * @param coinType The BIP-44 coin type of the asset
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
}
