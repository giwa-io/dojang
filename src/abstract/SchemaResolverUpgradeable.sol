// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Initializable} from "@openzeppelin-contracts-upgradeable/proxy/utils/Initializable.sol";
import {ISchemaResolver} from "@eas-contracts/contracts/resolver/ISchemaResolver.sol";
import {IEAS, Attestation} from "@eas-contracts/contracts/IEAS.sol";
import {Predeploys} from "../libraries/Types.sol";

/**
 * @title Schema Resolver for EAS
 * @dev Based on EAS `SchemaResolver`, but made upgradeable while still abiding by
 * the interface.
 */
abstract contract SchemaResolverUpgradeable is Initializable, ISchemaResolver {
    /// @dev Predeployed reference to the EAS contract
    IEAS private constant _EAS = IEAS(Predeploys.EAS);

    error AccessDenied();
    error NotPayable();
    error InvalidLength();
    error InsufficientValue();

    /**
     * @dev Ensures that only the EAS contract can make this call.
     */
    modifier onlyEAS() {
        _onlyEAS();

        _;
    }

    /**
     * @dev ETH callback.
     */
    receive() external payable virtual {
        if (!isPayable()) {
            revert NotPayable();
        }
    }

    /**
     * @inheritdoc ISchemaResolver
     */
    function attest(Attestation calldata attestation) external payable onlyEAS returns (bool) {
        return onAttest(attestation, msg.value);
    }

    /**
     * @inheritdoc ISchemaResolver
     */
    function multiAttest(
        Attestation[] calldata attestations,
        uint256[] calldata values
    )
        external
        payable
        onlyEAS
        returns (bool)
    {
        uint256 length = attestations.length;
        if (length != values.length) {
            revert InvalidLength();
        }

        // We are keeping track of the remaining ETH amount that can be sent to
        // resolvers and will keep deducting
        // from it to verify that there isn't any attempt to send too much ETH to
        // resolvers. Please note that unless
        // some ETH was stuck in the contract by accident (which shouldn't happen in
        // normal conditions), it won't be
        // possible to send too much ETH anyway.
        uint256 remainingValue = msg.value;

        for (uint256 i = 0; i < length; i = uncheckedInc(i)) {
            // Ensure that the attester/revoker doesn't try to spend more than
            // available.
            uint256 value = values[i];
            if (value > remainingValue) {
                revert InsufficientValue();
            }

            // Forward the attestation to the underlying resolver and return false in
            // case it isn't approved.
            if (!onAttest(attestations[i], value)) {
                return false;
            }

            unchecked {
                // Subtract the ETH amount, that was provided to this attestation,
                // from the global remaining ETH amount.
                remainingValue -= value;
            }
        }

        return true;
    }

    /**
     * @inheritdoc ISchemaResolver
     */
    function revoke(Attestation calldata attestation) external payable onlyEAS returns (bool) {
        return onRevoke(attestation, msg.value);
    }

    /**
     * @inheritdoc ISchemaResolver
     */
    function multiRevoke(
        Attestation[] calldata attestations,
        uint256[] calldata values
    )
        external
        payable
        onlyEAS
        returns (bool)
    {
        uint256 length = attestations.length;
        if (length != values.length) {
            revert InvalidLength();
        }

        // We are keeping track of the remaining ETH amount that can be sent to
        // resolvers and will keep deducting
        // from it to verify that there isn't any attempt to send too much ETH to
        // resolvers. Please note that unless
        // some ETH was stuck in the contract by accident (which shouldn't happen in
        // normal conditions), it won't be
        // possible to send too much ETH anyway.
        uint256 remainingValue = msg.value;

        for (uint256 i = 0; i < length; i = uncheckedInc(i)) {
            // Ensure that the attester/revoker doesn't try to spend more than
            // available.
            uint256 value = values[i];
            if (value > remainingValue) {
                revert InsufficientValue();
            }

            // Forward the revocation to the underlying resolver and return false in
            // case it isn't approved.
            if (!onRevoke(attestations[i], value)) {
                return false;
            }

            unchecked {
                // Subtract the ETH amount, that was provided to this attestation,
                // from the global remaining ETH amount.
                remainingValue -= value;
            }
        }

        return true;
    }

    /**
     * @inheritdoc ISchemaResolver
     */
    function isPayable() public pure virtual returns (bool) {
        return false;
    }

    // solhint-disable-next-line no-empty-blocks
    function __SchemaResolver_init() internal onlyInitializing {}

    // solhint-disable-next-line no-empty-blocks
    function __SchemaResolver_init_unchained() internal onlyInitializing {}

    /**
     * @notice A resolver callback that should be implemented by child contracts.
     * @param attestation The new attestation.
     * @param value An explicit ETH amount that was sent to the resolver. Please note
     * that this value is verified in
     *        both attest() and multiAttest() callbacks EAS-only callbacks and that
     * in case of multi attestations,
     *        it'll usually hold that msg.value != value, since msg.value aggregated
     * the sent ETH amounts for all
     *        the attestations in the batch.
     * @return Whether the attestation is valid.
     */
    function onAttest(Attestation calldata attestation, uint256 value) internal virtual returns (bool);

    /**
     * @notice Processes an attestation revocation and verifies if it can be revoked.
     * @param attestation The existing attestation to be revoked.
     * @param value An explicit ETH amount that was sent to the resolver. Please note
     * that this value is verified in
     *        both revoke() and multiRevoke() callbacks EAS-only callbacks and that
     * in case of multi attestations,
     *        it'll usually hold that msg.value != value, since msg.value aggregated
     * the sent ETH amounts for all
     *        the attestations in the batch.
     * @return Whether the attestation can be revoked.
     */
    function onRevoke(Attestation calldata attestation, uint256 value) internal virtual returns (bool);

    /// @dev A helper function to work with unchecked iterators in loops.
    /// @param i The index to increment.
    /// @return j The incremented index.
    function uncheckedInc(uint256 i) internal pure returns (uint256 j) {
        unchecked {
            j = i + 1;
        }
    }

    /**
     * @dev Ensures that only the EAS contract can make this call.
     */
    function _onlyEAS() private view {
        if (msg.sender != address(_EAS)) {
            revert AccessDenied();
        }
    }
}
