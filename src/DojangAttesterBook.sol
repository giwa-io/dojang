// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {UUPSUpgradeable} from "@openzeppelin-contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin-contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ZeroAddress} from "./libraries/Common.sol";
import {DojangAttesterId} from "./libraries/Types.sol";

contract DojangAttesterBook is UUPSUpgradeable, AccessControlUpgradeable {
    // 0x635a0c1689ad5a7df2dedc643572aeaf20ebc2ba3151b047c687dd08ef00e591
    bytes32 public constant UPGRADER_ROLE = keccak256("dojang.dojangattesterbook.upgrader");

    /// @dev Mapping of internal attester IDs to attester address
    mapping(DojangAttesterId attesterId => address attester) private _attesters;

    /// @notice Emitted when an attester is registered
    event AttesterRegistered(DojangAttesterId indexed attesterId, address indexed attester);

    /// @notice Emitted when an attester is unregistered
    event AttesterUnregistered(DojangAttesterId indexed attesterId);

    /**
     * @dev Locks the contract, preventing any future reinitialization. This
     * implementation contract was designed to be called through proxies.
     * @custom:oz-upgrades-unsafe-allow constructor
     */
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Registers a attester identifier to a specific attester address
     * @param attesterId An internal identifier
     * @param attester The actual attester address to associate
     */
    function register(
        DojangAttesterId attesterId,
        address attester
    )
        external
        onlyRole(AccessControlUpgradeable.DEFAULT_ADMIN_ROLE)
    {
        if (attester == address(0)) {
            revert ZeroAddress();
        }

        _attesters[attesterId] = attester;
        emit AttesterRegistered(attesterId, attester);
    }

    /**
     * @notice Unregisters a attester identifier from the book
     * @param attesterId An internal identifier
     */
    function unregister(DojangAttesterId attesterId) external onlyRole(AccessControlUpgradeable.DEFAULT_ADMIN_ROLE) {
        delete _attesters[attesterId];
        emit AttesterUnregistered(attesterId);
    }

    /**
     * @notice Returns the attester address for a given attester identifier
     * @param attesterId An internal identifier
     * @return The actual attester address to associate
     */
    function getAttester(DojangAttesterId attesterId) external view returns (address) {
        return _attesters[attesterId];
    }

    /**
     * @dev Initializes the contract
     * @param admin The address to be granted with the default admin Role
     */
    function initialize(address admin) public initializer {
        if (admin == address(0)) {
            revert ZeroAddress();
        }

        __UUPSUpgradeable_init();
        __AccessControl_init();

        _grantRole(AccessControlUpgradeable.DEFAULT_ADMIN_ROLE, admin);
    }

    /**
     * @notice Authorizes the upgrade of the contract.
     * @dev Only those with the UPGRADER_ROLE can call this.
     * @inheritdoc UUPSUpgradeable
     */
    // solhint-disable-next-line no-empty-blocks
    function _authorizeUpgrade(address) internal override onlyRole(UPGRADER_ROLE) {}
}
