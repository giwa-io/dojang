// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {UUPSUpgradeable} from "@openzeppelin-contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin-contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {IDojangScroll} from "./interfaces/IDojangScroll.sol";
import {IAttestationIndexer} from "./interfaces/IAttestationIndexer.sol";
import {
    IndexerUpdated,
    SchemaBookUpdated,
    DojangAttesterBookUpdated,
    ZeroAddress,
    InvalidIndexer,
    InvalidSchemaBook,
    InvalidDojangAttesterBook
} from "./libraries/Common.sol";
import {IEAS, Attestation} from "@eas-contracts/contracts/IEAS.sol";
import {AttestationVerifier} from "./libraries/AttestationVerifier.sol";
import {Predeploys, DojangAttesterId, DojangSchemaIds} from "./libraries/Types.sol";
import {SchemaBook} from "./SchemaBook.sol";
import {DojangAttesterBook} from "./DojangAttesterBook.sol";
import {ISemver} from "./interfaces/ISemver.sol";

/**
 * @title Dojang Scroll
 * @notice Provides view access to issued "dojang" via EAS
 * attestations
 */
contract DojangScroll is UUPSUpgradeable, AccessControlUpgradeable, IDojangScroll, ISemver {
    using AttestationVerifier for Attestation;

    /// @dev Predeployed reference to the EAS contract
    IEAS private constant _EAS = IEAS(Predeploys.EAS);

    // 0x780d9af2547ff489e27e4d081cfe787295973a1c8d1b8ee9585d9bfa2fb9258f
    bytes32 public constant UPGRADER_ROLE = keccak256("dojang.dojangscroll.upgrader");

    /// @notice Address of the schema book contract
    SchemaBook public _schemaBook;

    /// @notice Address of the dojang attester book contract
    DojangAttesterBook public _dojangAttesterBook;

    /// @notice Address of the attestation indexer contract
    IAttestationIndexer public _indexer;

    /**
     * @dev Locks the contract, preventing any future reinitialization. This
     * implementation contract was designed to be called through proxies.
     * @custom:oz-upgrades-unsafe-allow constructor
     */
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Updates the schema book contract used to find dojang schema
     * @param schemaBook The address of the new SchemaBook
     */
    function setSchemaBook(address schemaBook) external onlyRole(AccessControlUpgradeable.DEFAULT_ADMIN_ROLE) {
        if (schemaBook == address(0) || schemaBook == address(_schemaBook)) {
            revert InvalidSchemaBook();
        }
        address prevSchemaBook = address(_schemaBook);
        _schemaBook = SchemaBook(schemaBook);
        emit SchemaBookUpdated(prevSchemaBook, address(_schemaBook));
    }

    function setDojangAttesterBook(address dojangAttesterBook)
        external
        onlyRole(AccessControlUpgradeable.DEFAULT_ADMIN_ROLE)
    {
        if (dojangAttesterBook == address(0) || dojangAttesterBook == address(_dojangAttesterBook)) {
            revert InvalidDojangAttesterBook();
        }
        address prevDojangAttesterBook = address(_dojangAttesterBook);
        _dojangAttesterBook = DojangAttesterBook(dojangAttesterBook);
        emit DojangAttesterBookUpdated(prevDojangAttesterBook, address(_dojangAttesterBook));
    }

    /**
     * @notice Updates the indexer contract used to find attestations
     * @param indexer The address of the new IAttestationIndexer
     * @dev Reverts with InvalidIndexer if the address is zero or unchanged
     */
    function setIndexer(address indexer) external onlyRole(AccessControlUpgradeable.DEFAULT_ADMIN_ROLE) {
        if (indexer == address(0) || indexer == address(_indexer)) {
            revert InvalidIndexer();
        }
        address prevIndexer = address(_indexer);
        _indexer = IAttestationIndexer(indexer);
        emit IndexerUpdated(prevIndexer, address(_indexer));
    }

    /**
     * @inheritdoc IDojangScroll
     */
    function isVerified(address addr, DojangAttesterId attesterId) external view returns (bool) {
        return _getAddressAttestation(addr, attesterId).isVerified();
    }

    /**
     * @inheritdoc IDojangScroll
     */
    function getVerifiedAddressAttestationUid(
        address addr,
        DojangAttesterId attesterId
    )
        external
        view
        returns (bytes32)
    {
        Attestation memory attestation = _getAddressAttestation(addr, attesterId);
        attestation.verify();
        return attestation.uid;
    }

    /**
     * @inheritdoc IDojangScroll
     */
    function getVerifiedBalance(
        address recipient,
        uint256 coinType,
        uint64 snapshotAt,
        DojangAttesterId attesterId
    )
        external
        view
        returns (uint256)
    {
        Attestation memory attestation = _getBalanceAttestation(recipient, coinType, snapshotAt, attesterId);
        attestation.verify();

        uint256 decodedCoinType;
        uint64 decodedSnapshotAt;
        uint256 decodedBalance;
        (decodedCoinType, decodedSnapshotAt, decodedBalance) = abi.decode(attestation.data, (uint256, uint64, uint256));

        if (decodedCoinType != coinType || decodedSnapshotAt != snapshotAt) {
            revert NotVerifiedBalance(recipient, coinType, snapshotAt);
        }

        return decodedBalance;
    }

    /**
     * @inheritdoc IDojangScroll
     */
    function getVerifiedBalanceAttestationUid(
        address recipient,
        uint256 coinType,
        uint64 snapshotAt,
        DojangAttesterId attesterId
    )
        external
        view
        returns (bytes32)
    {
        Attestation memory attestation = _getBalanceAttestation(recipient, coinType, snapshotAt, attesterId);
        attestation.verify();
        return attestation.uid;
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

    /// @notice Semantic version.
    /// @custom:semver 0.2.0
    function version() public pure virtual returns (string memory) {
        return "0.2.0";
    }

    /**
     * @notice Authorizes the upgrade of the contract.
     * @dev Only those with the UPGRADER_ROLE can call this.
     * @inheritdoc UUPSUpgradeable
     */
    // solhint-disable-next-line no-empty-blocks
    function _authorizeUpgrade(address) internal override onlyRole(UPGRADER_ROLE) {}

    /**
     * @notice Returns the address attestation for the given recipient.
     * @dev This function does not verify the existence or validity of the attestation.
     * @param addr The address of the user
     * @param attesterId The attester identifier
     * @return The address attestation
     */
    function _getAddressAttestation(
        address addr,
        DojangAttesterId attesterId
    )
        internal
        view
        returns (Attestation memory)
    {
        bytes32 easSchemaUid = _schemaBook.getSchemaUid(DojangSchemaIds.ADDRESS_DOJANG);
        address attesterAddress = _dojangAttesterBook.getAttester(attesterId);

        bytes32 attestationUid = _indexer.getAttestationUid(easSchemaUid, attesterAddress, addr);
        return _EAS.getAttestation(attestationUid);
    }

    /**
     * @notice Returns the address attestation for the given recipient, coin type and timestamp.
     * @dev This function does not verify the existence or validity of the attestation.
     * @param recipient The address of the user
     * @param coinType The BIP-44 coin type of the asset
     * @param snapshotAt The timestamp representing when the balance snapshot was taken
     * @param attesterId The attester identifier
     * @return The balance attestation
     */
    function _getBalanceAttestation(
        address recipient,
        uint256 coinType,
        uint64 snapshotAt,
        DojangAttesterId attesterId
    )
        internal
        view
        returns (Attestation memory)
    {
        bytes32 easSchemaUid = _schemaBook.getSchemaUid(DojangSchemaIds.BALANCE_DOJANG);
        address attesterAddress = _dojangAttesterBook.getAttester(attesterId);

        bytes32 key = keccak256(abi.encode(coinType, snapshotAt));
        bytes32 attestationUid = _indexer.getAttestationUid(easSchemaUid, attesterAddress, recipient, key);
        return _EAS.getAttestation(attestationUid);
    }
}
