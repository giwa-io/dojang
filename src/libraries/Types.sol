// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title Predeploys
 * @notice Contains constant addresses for contracts that are pre-deployed to the L2
 * system.
 * @dev These addresses are assumed to be fixed and immutable at the protocol level
 */
library Predeploys {
    /// @notice Address of the SchemaRegistry predeploy.
    address internal constant SCHEMA_REGISTRY = 0x4200000000000000000000000000000000000020;

    /// @notice Address of the EAS predeploy.
    address internal constant EAS = 0x4200000000000000000000000000000000000021;
}

/**
 * @dev BIP-44 coin type validation utilities.
 *
 * This library provides functions to verify whether a given uint256 value
 * is a valid BIP-44 coin type.
 */
library BIP44CoinTypes {
    /**
     * @notice Emitted when an invalid coin type is provided
     * @param coinType The invalid coin type that triggered the error
     */
    error InvalidCoinType(uint256 coinType);

    /**
     * @notice Checks if a given coin type is valid according to BIP-44 coin type
     * @dev A valid coin type must be less than 2^31
     * @param coinType The coin type to validate
     * @return True if valid (i.e., less than 2^31), false otherwise
     */
    function isValid(uint256 coinType) internal pure returns (bool) {
        return (coinType >> 31) == 0;
    }

    /**
     * @notice Reverts if the given coin type is invalid
     * @param coinType The coin type to validate
     */
    function requireValid(uint256 coinType) internal pure {
        if (!isValid(coinType)) {
            revert InvalidCoinType(coinType);
        }
    }
}

/**
 * @dev Dojang EAS schema identifiers
 *
 * This library defines canonical schema IDs used by the Dojang service.
 * Each schema ID is derived using keccak256 over a unique, namespaced string.
 */
library DojangSchemaIds {
    // 0x568eb581cdf80b03d3bdfa414f3203bfdcc4bba4e66355612bd0e879da812f06
    bytes32 public constant ADDRESS_DOJANG = keccak256("dojang.dojangschemaids.address");

    // 0x06c3bd846f5ea60b0b6f5a835ef85fd8253b53f67917d6c690be628d032f841b
    bytes32 public constant BALANCE_DOJANG = keccak256("dojang.dojangschemaids.balance");
}

/**
 * @dev DojangAttesterId is a strongly-typed alias for bytes32
 *
 * This user-defined value type is used to explicitly mark and handle
 * attester identifiers within the Dojang system.
 */
type DojangAttesterId is bytes32;

/**
 * @dev Canonical attester types for Dojang service
 *
 * This library defines predefined attester identifiers that are used
 * within Dojang to distinguish trusted attestation issuers.
 */
library DojangAttesterIds {
    // 0xd99b42e778498aa3c9c1f6a012359130252780511687a35982e8e52735453034
    DojangAttesterId public constant UPBIT_KOREA =
        DojangAttesterId.wrap(keccak256("dojang.dojangattesterids.upbitkorea"));
}
