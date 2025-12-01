// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {
    IndexerUpdated,
    SchemaBookUpdated,
    DojangAttesterBookUpdated,
    ZeroAddress,
    InvalidIndexer,
    InvalidSchemaBook,
    InvalidDojangAttesterBook
} from "../src/libraries/Common.sol";
import {AttestationVerifier} from "../src/libraries/AttestationVerifier.sol";
import {DojangScroll} from "../src/DojangScroll.sol";
import {IDojangScroll} from "../src/interfaces/IDojangScroll.sol";
import {ERC1967Proxy} from "@openzeppelin-contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IAccessControl} from "@openzeppelin-contracts/access/IAccessControl.sol";
import {Initializable} from "@openzeppelin-contracts-upgradeable/proxy/utils/Initializable.sol";
import {IEAS, Attestation} from "@eas-contracts/contracts/IEAS.sol";
import {Predeploys, DojangSchemaIds, DojangAttesterIds} from "../src/libraries/Types.sol";
import {SchemaBook} from "../src/SchemaBook.sol";
import {DojangAttesterBook} from "../src/DojangAttesterBook.sol";

contract DojangScroll_Base is Test {
    DojangScroll public dojangScroll;
    address internal admin;
    address internal upgrader;
    address internal alice;

    function setUp() public virtual {
        admin = makeAddr("admin");
        upgrader = makeAddr("upgrader");
        alice = makeAddr("alice");

        address impl = address(new DojangScroll());
        bytes memory initData = abi.encodeCall(DojangScroll.initialize, admin);
        address proxy = address(new ERC1967Proxy(impl, initData));

        dojangScroll = DojangScroll(proxy);

        vm.startPrank(admin);
        dojangScroll.grantRole(dojangScroll.UPGRADER_ROLE(), upgrader);
        vm.stopPrank();
    }
}

contract DojangScroll_Init is DojangScroll_Base {
    function test_initialize_revert_for_reinitialize() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        dojangScroll.initialize(alice);
    }

    function test_initialize_revert_for_invalidAdmin() public {
        address impl = address(new DojangScroll());
        bytes memory initData = abi.encodeCall(DojangScroll.initialize, address(0));

        vm.expectRevert(ZeroAddress.selector);
        new ERC1967Proxy(impl, initData);
    }
}

contract DojangScrollV2 is DojangScroll {
    function version() public pure override returns (string memory) {
        return "99.0.0";
    }
}

contract DojangScroll_Upgrade is DojangScroll_Base {
    function test_upgrade_revert_by_notUpgrader() public {
        address newImpl = address(new DojangScrollV2());

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, alice, dojangScroll.UPGRADER_ROLE()
            )
        );
        vm.prank(alice);
        dojangScroll.upgradeToAndCall(newImpl, bytes(""));
    }

    function test_upgrade_succeeds_by_upgrader() public {
        assertEq(dojangScroll.version(), "0.5.0");

        address newImpl = address(new DojangScrollV2());

        vm.prank(upgrader);
        dojangScroll.upgradeToAndCall(newImpl, bytes(""));
        DojangScrollV2 newDojangScroll = DojangScrollV2(address(dojangScroll));

        assertEq(newDojangScroll.version(), "99.0.0");
    }
}

contract DojangScroll_Configure is DojangScroll_Base {
    function test_setSchemaBook_revert_when_zeroAddress() public {
        vm.expectRevert(InvalidSchemaBook.selector);

        vm.prank(admin);
        dojangScroll.setSchemaBook(address(0));
    }

    function test_setSchemaBook_revert_when_sameAddress() public {
        address schemaBook = vm.randomAddress();

        vm.prank(admin);
        dojangScroll.setSchemaBook(schemaBook);

        vm.expectRevert(InvalidSchemaBook.selector);
        vm.prank(admin);
        dojangScroll.setSchemaBook(schemaBook);
    }

    function test_setSchemaBook_succeeds() public {
        address schemaBook = vm.randomAddress();

        vm.expectEmit(true, true, true, true);
        emit SchemaBookUpdated(address(0), schemaBook);

        vm.prank(admin);
        dojangScroll.setSchemaBook(schemaBook);
    }

    function test_setDojangAttesterBook_revert_when_zeroAddress() public {
        vm.expectRevert(InvalidDojangAttesterBook.selector);

        vm.prank(admin);
        dojangScroll.setDojangAttesterBook(address(0));
    }

    function test_setDojangAttesterBook_revert_when_sameAddress() public {
        address dojangAttesterBook = vm.randomAddress();

        vm.prank(admin);
        dojangScroll.setDojangAttesterBook(dojangAttesterBook);

        vm.expectRevert(InvalidDojangAttesterBook.selector);
        vm.prank(admin);
        dojangScroll.setDojangAttesterBook(dojangAttesterBook);
    }

    function test_setDojangAttesterBook_succeeds() public {
        address dojangAttesterBook = vm.randomAddress();

        vm.expectEmit(true, true, true, true);
        emit DojangAttesterBookUpdated(address(0), dojangAttesterBook);

        vm.prank(admin);
        dojangScroll.setDojangAttesterBook(dojangAttesterBook);
    }

    function test_setIndexer_revert_when_zeroAddress() public {
        vm.expectRevert(InvalidIndexer.selector);

        vm.prank(admin);
        dojangScroll.setIndexer(address(0));
    }

    function test_setIndexer_revert_when_sameAddress() public {
        address indexer = vm.randomAddress();

        vm.prank(admin);
        dojangScroll.setIndexer(indexer);

        vm.expectRevert(InvalidIndexer.selector);
        vm.prank(admin);
        dojangScroll.setIndexer(indexer);
    }

    function test_setIndexer_succeeds() public {
        address indexer = vm.randomAddress();

        vm.expectEmit(true, true, true, true);
        emit IndexerUpdated(address(0), indexer);

        vm.prank(admin);
        dojangScroll.setIndexer(indexer);
    }
}

contract DojangScroll_Test is DojangScroll_Base {
    Attestation internal addressAttestation;
    Attestation internal balanceRootAttestation;
    Attestation internal balanceAttestation;
    Attestation internal verifyCodeAttestation;

    address internal constant SCHEMA_BOOK = address(0x0011);
    address internal constant DOJANG_ATTESTER_BOOK = address(0x0022);
    bytes32 internal constant ADDRESS_DOJANG_SCHEMA_UID = bytes32("address_dojang");
    bytes32 internal constant BALANCE_ROOT_DOJANG_SCHEMA_UID = bytes32("balance_root_dojang");
    bytes32 internal constant BALANCE_DOJANG_SCHEMA_UID = bytes32("balance_dojang");
    bytes32 internal constant VERIFY_CODE_DOJANG_SCHEMA_UID = bytes32("verify_code_dojang");

    address internal attester;

    address internal constant INDEXER = address(0x1234);

    address internal constant ADDRESS = 0x685933139dE0F4153D32247376e068E156bBA440;

    bytes32 internal constant ADDRESS_ATTESTATION_UID = bytes32("address");
    bytes32 internal constant BALANCE_ROOT_ATTESTATION_UID = bytes32("balance_root");
    bytes32 internal constant BALANCE_ATTESTATION_UID = bytes32("balance");
    bytes32 internal constant VERIFY_CODE_ATTESTATION_UID = bytes32("verify_code");

    uint256 internal constant SOLANA_COIN_TYPE = 0x3000000000000000000000000000000000000000000000000000000004c4f53;

    uint64 internal constant SNAPSHOT_AT = 1_700_000_000 - 5 minutes;
    uint256 internal constant BALANCE = 10_000_000_000_000_000_000;
    bytes32 internal constant CODE_HASH = keccak256(bytes("rawcode"));
    string internal constant DOMAIN = "foo.bar";

    function setUp() public override {
        super.setUp();
        vm.warp(1_700_000_000);

        vm.startPrank(admin);
        dojangScroll.setSchemaBook(SCHEMA_BOOK);
        dojangScroll.setDojangAttesterBook(DOJANG_ATTESTER_BOOK);
        dojangScroll.setIndexer(INDEXER);
        vm.stopPrank();

        attester = address(this);

        addressAttestation = Attestation({
            uid: ADDRESS_ATTESTATION_UID,
            schema: ADDRESS_DOJANG_SCHEMA_UID,
            recipient: ADDRESS,
            attester: attester,
            time: uint64(block.timestamp),
            expirationTime: uint64(block.timestamp) + 12,
            revocationTime: 0,
            refUID: bytes32(0),
            data: abi.encode(true),
            revocable: true
        });

        balanceRootAttestation = Attestation({
            uid: BALANCE_ROOT_ATTESTATION_UID,
            schema: BALANCE_ROOT_DOJANG_SCHEMA_UID,
            recipient: address(0),
            attester: attester,
            time: uint64(block.timestamp),
            expirationTime: uint64(block.timestamp) + 12,
            revocationTime: 0,
            refUID: bytes32(0),
            data: abi.encode(SOLANA_COIN_TYPE, SNAPSHOT_AT, uint192(1), uint256(1), bytes32(0)),
            revocable: true
        });

        bytes32[] memory proofs;
        balanceAttestation = Attestation({
            uid: BALANCE_ATTESTATION_UID,
            schema: BALANCE_DOJANG_SCHEMA_UID,
            recipient: ADDRESS,
            attester: address(this),
            time: uint64(block.timestamp),
            expirationTime: uint64(block.timestamp) + 12,
            revocationTime: 0,
            refUID: BALANCE_ROOT_ATTESTATION_UID,
            data: abi.encode(BALANCE, bytes32(0), proofs),
            revocable: true
        });

        verifyCodeAttestation = Attestation({
            uid: VERIFY_CODE_ATTESTATION_UID,
            schema: VERIFY_CODE_DOJANG_SCHEMA_UID,
            recipient: address(0),
            attester: attester,
            time: uint64(block.timestamp),
            expirationTime: uint64(block.timestamp) + 12,
            revocationTime: 0,
            refUID: bytes32(0),
            data: abi.encode(CODE_HASH, DOMAIN),
            revocable: true
        });
    }

    function mockGetAddressAttestation(Attestation memory attestation) internal {
        vm.mockCall(
            SCHEMA_BOOK,
            abi.encodeWithSelector(SchemaBook.getSchemaUid.selector, DojangSchemaIds.ADDRESS_DOJANG),
            abi.encode(ADDRESS_DOJANG_SCHEMA_UID)
        );
        vm.mockCall(
            DOJANG_ATTESTER_BOOK,
            abi.encodeWithSelector(DojangAttesterBook.getAttester.selector, DojangAttesterIds.UPBIT_KOREA),
            abi.encode(attester)
        );
        vm.mockCall(
            INDEXER,
            abi.encodeWithSelector(
                bytes4(keccak256("getAttestationUid(bytes32,address,address)")),
                ADDRESS_DOJANG_SCHEMA_UID,
                attester,
                ADDRESS
            ),
            abi.encode(attestation.uid)
        );
        vm.mockCall(
            Predeploys.EAS,
            abi.encodeWithSelector(IEAS.getAttestation.selector, attestation.uid),
            abi.encode(attestation)
        );
    }

    function mockGetBalanceRootAttestation(Attestation memory attestation) internal {
        vm.mockCall(
            SCHEMA_BOOK,
            abi.encodeWithSelector(SchemaBook.getSchemaUid.selector, DojangSchemaIds.BALANCE_ROOT_DOJANG),
            abi.encode(BALANCE_ROOT_DOJANG_SCHEMA_UID)
        );
        vm.mockCall(
            DOJANG_ATTESTER_BOOK,
            abi.encodeWithSelector(DojangAttesterBook.getAttester.selector, DojangAttesterIds.UPBIT_KOREA),
            abi.encode(attester)
        );
        vm.mockCall(
            INDEXER,
            abi.encodeWithSelector(
                bytes4(keccak256("getAttestationUid(bytes32,address,address,bytes32)")),
                BALANCE_ROOT_DOJANG_SCHEMA_UID,
                attester,
                address(0),
                keccak256(abi.encode(SOLANA_COIN_TYPE, SNAPSHOT_AT))
            ),
            abi.encode(attestation.uid)
        );
        vm.mockCall(
            Predeploys.EAS,
            abi.encodeWithSelector(IEAS.getAttestation.selector, attestation.uid),
            abi.encode(attestation)
        );
    }

    function mockGetBalanceAttestation(Attestation memory attestation) internal {
        vm.mockCall(
            SCHEMA_BOOK,
            abi.encodeWithSelector(SchemaBook.getSchemaUid.selector, DojangSchemaIds.BALANCE_DOJANG),
            abi.encode(BALANCE_DOJANG_SCHEMA_UID)
        );
        vm.mockCall(
            DOJANG_ATTESTER_BOOK,
            abi.encodeWithSelector(DojangAttesterBook.getAttester.selector, DojangAttesterIds.UPBIT_KOREA),
            abi.encode(attester)
        );
        vm.mockCall(
            INDEXER,
            abi.encodeWithSelector(
                bytes4(keccak256("getAttestationUid(bytes32,address,address,bytes32)")),
                BALANCE_DOJANG_SCHEMA_UID,
                attester,
                ADDRESS,
                keccak256(abi.encode(SOLANA_COIN_TYPE, SNAPSHOT_AT))
            ),
            abi.encode(attestation.uid)
        );
        vm.mockCall(
            Predeploys.EAS,
            abi.encodeWithSelector(IEAS.getAttestation.selector, attestation.uid),
            abi.encode(attestation)
        );
    }

    function mockGetVerifyCodeAttestation(Attestation memory attestation) internal {
        vm.mockCall(
            SCHEMA_BOOK,
            abi.encodeWithSelector(SchemaBook.getSchemaUid.selector, DojangSchemaIds.VERIFY_CODE_DOJANG),
            abi.encode(VERIFY_CODE_DOJANG_SCHEMA_UID)
        );
        vm.mockCall(
            DOJANG_ATTESTER_BOOK,
            abi.encodeWithSelector(DojangAttesterBook.getAttester.selector, DojangAttesterIds.UPBIT_KOREA),
            abi.encode(attester)
        );
        vm.mockCall(
            INDEXER,
            abi.encodeWithSelector(
                bytes4(keccak256("getAttestationUid(bytes32,address,address,bytes32)")),
                VERIFY_CODE_DOJANG_SCHEMA_UID,
                attester,
                address(0),
                keccak256(abi.encode(CODE_HASH, DOMAIN))
            ),
            abi.encode(attestation.uid)
        );
        vm.mockCall(
            Predeploys.EAS,
            abi.encodeWithSelector(IEAS.getAttestation.selector, attestation.uid),
            abi.encode(attestation)
        );
    }

    function test_isVerified_false_when_notExistAttestation() public {
        Attestation memory zeroAttestation;
        mockGetAddressAttestation(zeroAttestation);

        vm.assertFalse(dojangScroll.isVerified(ADDRESS, DojangAttesterIds.UPBIT_KOREA));
    }

    function test_isVerified_false_when_expiredAttestation() public {
        addressAttestation.expirationTime = uint64(block.timestamp) - 5 minutes;
        mockGetAddressAttestation(addressAttestation);

        vm.assertFalse(dojangScroll.isVerified(ADDRESS, DojangAttesterIds.UPBIT_KOREA));
    }

    function test_isVerified_false_when_revokedAttestation() public {
        addressAttestation.revocationTime = uint64(block.timestamp) - 5 minutes;
        mockGetAddressAttestation(addressAttestation);

        vm.assertFalse(dojangScroll.isVerified(ADDRESS, DojangAttesterIds.UPBIT_KOREA));
    }

    function test_isVerified_true() public {
        mockGetAddressAttestation(addressAttestation);

        vm.assertTrue(dojangScroll.isVerified(ADDRESS, DojangAttesterIds.UPBIT_KOREA));
    }

    function test_getVerifiedAddressAttestationUid_revert_when_notExistAttestation() public {
        Attestation memory zeroAttestation;
        mockGetAddressAttestation(zeroAttestation);

        vm.expectRevert(AttestationVerifier.ZeroUid.selector);
        dojangScroll.getVerifiedAddressAttestationUid(ADDRESS, DojangAttesterIds.UPBIT_KOREA);
    }

    function test_getVerifiedAddressAttestationUid_revert_when_expiredAttestation() public {
        addressAttestation.expirationTime = uint64(block.timestamp) - 5 minutes;
        mockGetAddressAttestation(addressAttestation);

        vm.expectRevert(
            abi.encodeWithSelector(
                AttestationVerifier.ExpiredAttestation.selector,
                ADDRESS_ATTESTATION_UID,
                uint64(block.timestamp) - 5 minutes
            )
        );
        dojangScroll.getVerifiedAddressAttestationUid(ADDRESS, DojangAttesterIds.UPBIT_KOREA);
    }

    function test_getVerifiedAddressAttestationUid_revert_when_revokedAttestation() public {
        addressAttestation.revocationTime = uint64(block.timestamp) - 5 minutes;
        mockGetAddressAttestation(addressAttestation);

        vm.expectRevert(
            abi.encodeWithSelector(
                AttestationVerifier.RevokedAttestation.selector,
                ADDRESS_ATTESTATION_UID,
                uint64(block.timestamp) - 5 minutes
            )
        );
        dojangScroll.getVerifiedAddressAttestationUid(ADDRESS, DojangAttesterIds.UPBIT_KOREA);
    }

    function test_getVerifiedAddressAttestationUid_succeeds() public {
        mockGetAddressAttestation(addressAttestation);

        bytes32 attestationUid = dojangScroll.getVerifiedAddressAttestationUid(ADDRESS, DojangAttesterIds.UPBIT_KOREA);
        assertEq(attestationUid, ADDRESS_ATTESTATION_UID);
    }

    function test_getBalanceRootAttestationUid_revert_when_notExistAttestation() public {
        Attestation memory zeroAttestation;
        mockGetBalanceRootAttestation(zeroAttestation);

        vm.expectRevert(AttestationVerifier.ZeroUid.selector);
        dojangScroll.getBalanceRootAttestationUid(SOLANA_COIN_TYPE, SNAPSHOT_AT, DojangAttesterIds.UPBIT_KOREA);
    }

    function test_getBalanceRootAttestationUid_revert_when_expiredAttestation() public {
        balanceRootAttestation.expirationTime = uint64(block.timestamp) - 5 minutes;
        mockGetBalanceRootAttestation(balanceRootAttestation);

        vm.expectRevert(
            abi.encodeWithSelector(
                AttestationVerifier.ExpiredAttestation.selector,
                BALANCE_ROOT_ATTESTATION_UID,
                uint64(block.timestamp) - 5 minutes
            )
        );
        dojangScroll.getBalanceRootAttestationUid(SOLANA_COIN_TYPE, SNAPSHOT_AT, DojangAttesterIds.UPBIT_KOREA);
    }

    function test_getBalanceRootAttestationUid_revert_when_revokedAttestation() public {
        balanceRootAttestation.revocationTime = uint64(block.timestamp) - 5 minutes;
        mockGetBalanceRootAttestation(balanceRootAttestation);

        vm.expectRevert(
            abi.encodeWithSelector(
                AttestationVerifier.RevokedAttestation.selector,
                BALANCE_ROOT_ATTESTATION_UID,
                uint64(block.timestamp) - 5 minutes
            )
        );
        dojangScroll.getBalanceRootAttestationUid(SOLANA_COIN_TYPE, SNAPSHOT_AT, DojangAttesterIds.UPBIT_KOREA);
    }

    function test_getBalanceRootAttestationUid_succeeds() public {
        mockGetBalanceRootAttestation(balanceRootAttestation);

        bytes32 attestationUid =
            dojangScroll.getBalanceRootAttestationUid(SOLANA_COIN_TYPE, SNAPSHOT_AT, DojangAttesterIds.UPBIT_KOREA);
        assertEq(attestationUid, BALANCE_ROOT_ATTESTATION_UID);
    }

    function test_getVerifiedBalance_revert_when_notExistAttestation() public {
        Attestation memory zeroAttestation;
        mockGetBalanceAttestation(zeroAttestation);

        vm.expectRevert(AttestationVerifier.ZeroUid.selector);
        dojangScroll.getVerifiedBalance(ADDRESS, SOLANA_COIN_TYPE, SNAPSHOT_AT, DojangAttesterIds.UPBIT_KOREA);
    }

    function test_getVerifiedBalance_revert_when_expiredAttestation() public {
        balanceAttestation.expirationTime = uint64(block.timestamp);
        mockGetBalanceAttestation(balanceAttestation);

        vm.expectRevert(
            abi.encodeWithSelector(
                AttestationVerifier.ExpiredAttestation.selector, BALANCE_ATTESTATION_UID, uint64(block.timestamp)
            )
        );
        dojangScroll.getVerifiedBalance(ADDRESS, SOLANA_COIN_TYPE, SNAPSHOT_AT, DojangAttesterIds.UPBIT_KOREA);
    }

    function test_getVerifiedBalance_revert_when_revokedAttestation() public {
        balanceAttestation.revocationTime = uint64(block.timestamp);
        mockGetBalanceAttestation(balanceAttestation);

        vm.expectRevert(
            abi.encodeWithSelector(
                AttestationVerifier.RevokedAttestation.selector, BALANCE_ATTESTATION_UID, uint64(block.timestamp)
            )
        );
        dojangScroll.getVerifiedBalance(ADDRESS, SOLANA_COIN_TYPE, SNAPSHOT_AT, DojangAttesterIds.UPBIT_KOREA);
    }

    function test_getVerifiedBalance_revert_when_notMatchData() public {
        uint256 otherSnapshotTime = block.timestamp - 100 minutes;
        balanceRootAttestation.data =
            abi.encode(SOLANA_COIN_TYPE, otherSnapshotTime, uint192(1), uint256(1), bytes32(0));
        mockGetBalanceAttestation(balanceAttestation);
        mockGetBalanceRootAttestation(balanceRootAttestation);

        vm.expectRevert(
            abi.encodeWithSelector(IDojangScroll.NotVerifiedBalance.selector, ADDRESS, SOLANA_COIN_TYPE, SNAPSHOT_AT)
        );
        dojangScroll.getVerifiedBalance(ADDRESS, SOLANA_COIN_TYPE, SNAPSHOT_AT, DojangAttesterIds.UPBIT_KOREA);
    }

    function test_getVerifiedBalance_succeeds() public {
        mockGetBalanceAttestation(balanceAttestation);
        mockGetBalanceRootAttestation(balanceRootAttestation);

        uint256 balance =
            dojangScroll.getVerifiedBalance(ADDRESS, SOLANA_COIN_TYPE, SNAPSHOT_AT, DojangAttesterIds.UPBIT_KOREA);
        assertEq(balance, BALANCE);
    }

    function test_getVerifiedBalanceAttestationUid_revert_when_notExistAttestation() public {
        Attestation memory zeroAttestation;
        mockGetBalanceAttestation(zeroAttestation);

        vm.expectRevert(AttestationVerifier.ZeroUid.selector);
        dojangScroll.getVerifiedBalanceAttestationUid(
            ADDRESS, SOLANA_COIN_TYPE, SNAPSHOT_AT, DojangAttesterIds.UPBIT_KOREA
        );
    }

    function test_getVerifiedBalanceAttestationUid_revert_when_expiredAttestation() public {
        balanceAttestation.expirationTime = uint64(block.timestamp) - 5 minutes;
        mockGetBalanceAttestation(balanceAttestation);

        vm.expectRevert(
            abi.encodeWithSelector(
                AttestationVerifier.ExpiredAttestation.selector,
                BALANCE_ATTESTATION_UID,
                uint64(block.timestamp) - 5 minutes
            )
        );
        dojangScroll.getVerifiedBalanceAttestationUid(
            ADDRESS, SOLANA_COIN_TYPE, SNAPSHOT_AT, DojangAttesterIds.UPBIT_KOREA
        );
    }

    function test_getVerifiedBalanceAttestationUid_revert_when_revokedAttestation() public {
        balanceAttestation.revocationTime = uint64(block.timestamp) - 5 minutes;
        mockGetBalanceAttestation(balanceAttestation);

        vm.expectRevert(
            abi.encodeWithSelector(
                AttestationVerifier.RevokedAttestation.selector,
                BALANCE_ATTESTATION_UID,
                uint64(block.timestamp) - 5 minutes
            )
        );
        dojangScroll.getVerifiedBalanceAttestationUid(
            ADDRESS, SOLANA_COIN_TYPE, SNAPSHOT_AT, DojangAttesterIds.UPBIT_KOREA
        );
    }

    function test_getVerifiedBalanceAttestationUid_succeeds() public {
        mockGetBalanceAttestation(balanceAttestation);

        bytes32 attestationUid = dojangScroll.getVerifiedBalanceAttestationUid(
            ADDRESS, SOLANA_COIN_TYPE, SNAPSHOT_AT, DojangAttesterIds.UPBIT_KOREA
        );
        assertEq(attestationUid, BALANCE_ATTESTATION_UID);
    }

    function test_isVerifiedCode_false_when_notExistAttestation() public {
        Attestation memory zeroAttestation;
        mockGetVerifyCodeAttestation(zeroAttestation);

        vm.assertFalse(dojangScroll.isVerifiedCode(CODE_HASH, DOMAIN, DojangAttesterIds.UPBIT_KOREA));
    }

    function test_isVerifiedCode_false_when_expiredAttestation() public {
        verifyCodeAttestation.expirationTime = uint64(block.timestamp) - 5 minutes;
        mockGetVerifyCodeAttestation(verifyCodeAttestation);

        vm.assertFalse(dojangScroll.isVerifiedCode(CODE_HASH, DOMAIN, DojangAttesterIds.UPBIT_KOREA));
    }

    function test_isVerifiedCode_false_when_revokedAttestation() public {
        verifyCodeAttestation.revocationTime = uint64(block.timestamp) - 5 minutes;
        mockGetVerifyCodeAttestation(verifyCodeAttestation);

        vm.assertFalse(dojangScroll.isVerifiedCode(CODE_HASH, DOMAIN, DojangAttesterIds.UPBIT_KOREA));
    }

    function test_isVerifiedCode_true() public {
        mockGetVerifyCodeAttestation(verifyCodeAttestation);

        vm.assertTrue(dojangScroll.isVerifiedCode(CODE_HASH, DOMAIN, DojangAttesterIds.UPBIT_KOREA));
    }

    function test_getVerifyCodeAttestationUid_revert_when_notExistAttestation() public {
        Attestation memory zeroAttestation;
        mockGetVerifyCodeAttestation(zeroAttestation);

        vm.expectRevert(AttestationVerifier.ZeroUid.selector);
        dojangScroll.getVerifyCodeAttestationUid(CODE_HASH, DOMAIN, DojangAttesterIds.UPBIT_KOREA);
    }

    function test_getVerifyCodeAttestationUid_revert_when_expiredAttestation() public {
        verifyCodeAttestation.expirationTime = uint64(block.timestamp) - 5 minutes;
        mockGetVerifyCodeAttestation(verifyCodeAttestation);

        vm.expectRevert(
            abi.encodeWithSelector(
                AttestationVerifier.ExpiredAttestation.selector,
                VERIFY_CODE_ATTESTATION_UID,
                uint64(block.timestamp) - 5 minutes
            )
        );
        dojangScroll.getVerifyCodeAttestationUid(CODE_HASH, DOMAIN, DojangAttesterIds.UPBIT_KOREA);
    }

    function test_getVerifyCodeAttestationUid_revert_when_revokedAttestation() public {
        verifyCodeAttestation.revocationTime = uint64(block.timestamp) - 5 minutes;
        mockGetVerifyCodeAttestation(verifyCodeAttestation);

        vm.expectRevert(
            abi.encodeWithSelector(
                AttestationVerifier.RevokedAttestation.selector,
                VERIFY_CODE_ATTESTATION_UID,
                uint64(block.timestamp) - 5 minutes
            )
        );
        dojangScroll.getVerifyCodeAttestationUid(CODE_HASH, DOMAIN, DojangAttesterIds.UPBIT_KOREA);
    }

    function test_getVerifyCodeAttestationUid_succeeds() public {
        mockGetVerifyCodeAttestation(verifyCodeAttestation);

        bytes32 attestationUid =
            dojangScroll.getVerifyCodeAttestationUid(CODE_HASH, DOMAIN, DojangAttesterIds.UPBIT_KOREA);
        assertEq(attestationUid, VERIFY_CODE_ATTESTATION_UID);
    }
}
