// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {UUPSUpgradeable} from "@openzeppelin-contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin-contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ZeroAddress} from "./libraries/Common.sol";
import {ISchemaRegistry} from "@eas-contracts/contracts/ISchemaRegistry.sol";
import {Predeploys} from "./libraries/Types.sol";

contract SchemaBook is UUPSUpgradeable, AccessControlUpgradeable {
    /// @dev Predeployed reference to the SchemaRegistry contract
    ISchemaRegistry private constant _SCHEMA_REGISTRY = ISchemaRegistry(Predeploys.SCHEMA_REGISTRY);

    // 0x94128ea7f74a449ce658791007e32321f49a24a085ab70669bc3d744a5146add
    bytes32 public constant UPGRADER_ROLE = keccak256("dojang.schemabook.upgrader");

    /// @dev Mapping of internal schema IDs to EAS schema UIDs
    mapping(bytes32 schemaId => bytes32 easSchemaUid) private _schemas;

    /// @notice Emitted when a schema is registered
    event SchemaRegistered(bytes32 indexed schemaId, bytes32 indexed easSchemaUid);

    /// @notice Emitted when a schema is unregistered
    event SchemaUnregistered(bytes32 indexed schemaId);

    /// @notice Thrown when trying to set invalid schema id
    error InvalidSchemaId();

    /// @notice Thrown when trying to set invalid eas schema uid
    error InvalidEasSchemaUid();

    /// @notice Thrown when trying to register a schema that is already registered
    error SchemaAlreadyRegistered();

    /**
     * @dev Locks the contract, preventing any future reinitialization. This
     * implementation contract was designed to be called through proxies.
     * @custom:oz-upgrades-unsafe-allow constructor
     */
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Registers a schema identifier to a specific EAS schema UID
     * @param schemaId An internal identifier
     * @param easSchemaUid The actual EAS schema UID to associate
     */
    function register(
        bytes32 schemaId,
        bytes32 easSchemaUid
    )
        external
        onlyRole(AccessControlUpgradeable.DEFAULT_ADMIN_ROLE)
    {
        if (_schemas[schemaId] != bytes32(0)) {
            revert SchemaAlreadyRegistered();
        }
        if (schemaId == bytes32(0)) {
            revert InvalidSchemaId();
        }
        if (easSchemaUid == bytes32(0) || _SCHEMA_REGISTRY.getSchema(easSchemaUid).uid == bytes32(0)) {
            revert InvalidEasSchemaUid();
        }

        _schemas[schemaId] = easSchemaUid;
        emit SchemaRegistered(schemaId, easSchemaUid);
    }

    /**
     * @notice Unregisters a schema identifier from the book
     * @param schemaId An internal identifier
     */
    function unregister(bytes32 schemaId) external onlyRole(AccessControlUpgradeable.DEFAULT_ADMIN_ROLE) {
        if (_schemas[schemaId] == bytes32(0)) {
            revert InvalidSchemaId();
        }

        delete _schemas[schemaId];
        emit SchemaUnregistered(schemaId);
    }

    /**
     * @notice Returns the EAS schema UID for a given schema identifier
     * @param schemaId An internal identifier
     * @return The actual EAS schema UID to associate
     */
    function getSchemaUid(bytes32 schemaId) external view returns (bytes32) {
        return _schemas[schemaId];
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
