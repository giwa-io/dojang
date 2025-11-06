// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Initializable} from "@openzeppelin-contracts-upgradeable/proxy/utils/Initializable.sol";
import {SchemaResolverUpgradeable} from "./SchemaResolverUpgradeable.sol";
import {Attestation} from "@eas-contracts/contracts/IEAS.sol";
import {CustomCoinTypes} from "../libraries/Types.sol";

/**
 * @title Balance Dojang Validation Resolver for EAS
 * @dev A base contract for creating an EAS Schema Resolver that validate attestations
 * for balance dojang.
 */
abstract contract BalanceValidationResolverUpgradeable is Initializable, SchemaResolverUpgradeable {
    using CustomCoinTypes for uint256;

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
        (uint256 coinType, uint64 snapshotAt) = abi.decode(attestation.data, (uint256, uint64));
        return coinType.isValid() && snapshotAt <= uint64(block.timestamp);
    }

    /**
     * @return bool Always true since this functionality is not implemented.
     */
    function onRevoke(Attestation calldata, uint256) internal virtual override returns (bool) {
        return true;
    }
}
