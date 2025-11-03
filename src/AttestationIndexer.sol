// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {UUPSUpgradeable} from "@openzeppelin-contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin-contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin-contracts-upgradeable/utils/PausableUpgradeable.sol";
import {IEAS, Attestation} from "@eas-contracts/contracts/IEAS.sol";
import {IAttestationIndexer} from "./interfaces/IAttestationIndexer.sol";
import {Predeploys} from "./libraries/Types.sol";
import {ZeroAddress} from "./libraries/Common.sol";
import {AttestationVerifier} from "./libraries/AttestationVerifier.sol";

/**
 * @title Attestation Indexer
 * @notice An indexer for EAS attestation.
 */
contract AttestationIndexer is UUPSUpgradeable, AccessControlUpgradeable, PausableUpgradeable, IAttestationIndexer {
    using AttestationVerifier for Attestation;

    /// @dev Predeployed reference to the EAS contract
    IEAS private constant _EAS = IEAS(Predeploys.EAS);

    // 0xa4771738a4a8d7cf0668efc96ce25cca50d013312cf387bac358f7392cc4d905
    bytes32 public constant PAUSER_ROLE = keccak256("dojang.attestationindexer.pauser");
    // 0x3916eed0902929784feb1e46ad4564b96fa109b7abea862fab5e29b1799b2e5f
    bytes32 public constant UPGRADER_ROLE = keccak256("dojang.attestationindexer.upgrader");
    // 0x12871cff13e82f1629feba448a7c66e21bef7c90d20deb75fea29020b75d749a
    bytes32 public constant INDEXER_ROLE = keccak256("dojang.attestationindexer.indexer");

    /// @notice Default key value used for keyless indexing
    bytes32 public constant DEFAULT_KEY = bytes32(0);

    /// @dev Internal mapping: schema UID => attester => recipient => key => attestation UID
    mapping(
        bytes32 schemaUid
            => mapping(address attester => mapping(address recipient => mapping(bytes32 key => bytes32 attestationUid)))
    ) private _rawDB;

    /// @dev Internal mapping: schema UID => attester => key => attestation UIDs
    mapping(bytes32 schemaUid => mapping(address attester => mapping(bytes32 key => bytes32[] attestationUids))) private
        _keyedDB;

    /**
     * @dev Locks the contract, preventing any future reinitialization. This
     * implementation contract was designed to be called through proxies.
     * @custom:oz-upgrades-unsafe-allow constructor
     */
    constructor() {
        _disableInitializers();
    }

    /**
     * @inheritdoc IAttestationIndexer
     */
    function index(bytes32 attestationUid) external whenNotPaused onlyRole(INDEXER_ROLE) {
        _index(DEFAULT_KEY, attestationUid);
    }

    /**
     * @inheritdoc IAttestationIndexer
     */
    function index(bytes32 key, bytes32 attestationUid) external whenNotPaused onlyRole(INDEXER_ROLE) {
        _index(key, attestationUid);
    }

    /**
     * @notice Pause the contract, halting attestation indexing.
     * @dev Only callable by accounts with PAUSER_ROLE
     */
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /**
     * @notice Resumes the contract, resuming attestation indexing.
     * @dev Only callable by accounts with PAUSER_ROLE
     */
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /**
     * @inheritdoc IAttestationIndexer
     */
    function getAttestationUid(
        bytes32 schemaUid,
        address attester,
        address recipient
    )
        external
        view
        returns (bytes32)
    {
        return _rawDB[schemaUid][attester][recipient][DEFAULT_KEY];
    }

    /**
     * @inheritdoc IAttestationIndexer
     */
    function getAttestationUid(
        bytes32 schemaUid,
        address attester,
        address recipient,
        bytes32 key
    )
        external
        view
        returns (bytes32)
    {
        return _rawDB[schemaUid][attester][recipient][key];
    }

    /**
     * @inheritdoc IAttestationIndexer
     */
    function getAttestationUids(
        bytes32 schemaUid,
        address attester,
        bytes32 key
    )
        external
        view
        returns (bytes32[] memory)
    {
        return _keyedDB[schemaUid][attester][key];
    }

    /**
     * @dev Initializes the contract.
     * @param admin The address to be granted with the default admin Role.
     */
    function initialize(address admin) public initializer {
        if (admin == address(0)) {
            revert ZeroAddress();
        }

        __UUPSUpgradeable_init();
        __AccessControl_init();
        __Pausable_init();

        _grantRole(AccessControlUpgradeable.DEFAULT_ADMIN_ROLE, admin);
    }

    /**
     * @notice Authorizes the upgrade of the contract.
     * @dev Only those with the UPGRADER_ROLE can call this.
     * @inheritdoc UUPSUpgradeable
     */
    // solhint-disable-next-line no-empty-blocks
    function _authorizeUpgrade(address) internal override onlyRole(UPGRADER_ROLE) {}

    /**
     * @dev Internal function to validate and index an attestation
     * @param key Index key under which the attestation will be stored
     * @param attestationUid UID of the attestation to index
     */
    function _index(bytes32 key, bytes32 attestationUid) private {
        Attestation memory attestation = _EAS.getAttestation(attestationUid);
        attestation.verify();

        _rawDB[attestation.schema][attestation.attester][attestation.recipient][key] = attestationUid;
        _keyedDB[attestation.schema][attestation.attester][key].push(attestationUid);
        emit AttestationIndexed(attestation.schema, attestation.attester, attestation.recipient, key, attestation.uid);
    }
}
