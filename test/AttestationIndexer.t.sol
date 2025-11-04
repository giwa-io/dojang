// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {AttestationIndexer} from "../src/AttestationIndexer.sol";
import {ZeroAddress} from "../src/libraries/Common.sol";
import {Predeploys} from "../src/libraries/Types.sol";
import {AttestationVerifier} from "../src/libraries/AttestationVerifier.sol";
import {IAttestationIndexer} from "../src/interfaces/IAttestationIndexer.sol";
import {IEAS, Attestation} from "@eas-contracts/contracts/IEAS.sol";
import {IAccessControl} from "@openzeppelin-contracts/access/IAccessControl.sol";
import {ERC1967Proxy} from "@openzeppelin-contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Initializable} from "@openzeppelin-contracts-upgradeable/proxy/utils/Initializable.sol";

contract AttestationIndexer_Base is Test {
    AttestationIndexer public attestationIndexer;
    address internal admin;
    address internal pauser;
    address internal upgrader;
    address internal indexer;
    address internal alice;

    function setUp() public virtual {
        admin = makeAddr("admin");
        pauser = makeAddr("pauser");
        upgrader = makeAddr("upgrader");
        indexer = makeAddr("indexer");
        alice = makeAddr("alice");

        address impl = address(new AttestationIndexer());
        bytes memory initData = abi.encodeCall(AttestationIndexer.initialize, admin);
        address proxy = address(new ERC1967Proxy(impl, initData));

        attestationIndexer = AttestationIndexer(proxy);

        vm.startPrank(admin);
        attestationIndexer.grantRole(attestationIndexer.PAUSER_ROLE(), pauser);
        attestationIndexer.grantRole(attestationIndexer.UPGRADER_ROLE(), upgrader);
        attestationIndexer.grantRole(attestationIndexer.INDEXER_ROLE(), indexer);
        vm.stopPrank();
    }
}

contract AttestationIndexer_Init is AttestationIndexer_Base {
    function test_initialize_revert_for_reinitialize() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        attestationIndexer.initialize(alice);
    }

    function test_initialize_revert_for_invalidAdmin() public {
        address impl = address(new AttestationIndexer());
        bytes memory initData = abi.encodeCall(AttestationIndexer.initialize, address(0));

        vm.expectRevert(ZeroAddress.selector);
        new ERC1967Proxy(impl, initData);
    }
}

contract AttestationIndexer_Pause is AttestationIndexer_Base {
    function test_pause_revert_by_notPauser() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, alice, attestationIndexer.PAUSER_ROLE()
            )
        );
        vm.prank(alice);
        attestationIndexer.pause();
    }

    function test_pause_succeeds_by_pauser() public {
        vm.prank(pauser);
        attestationIndexer.pause();
        assertTrue(attestationIndexer.paused());
    }

    function test_unpause_revert_by_notPauser() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, alice, attestationIndexer.PAUSER_ROLE()
            )
        );
        vm.prank(alice);
        attestationIndexer.unpause();
    }

    function test_unpause_succeeds_by_pauser() public {
        vm.startPrank(pauser);
        attestationIndexer.pause();
        attestationIndexer.unpause();
        vm.stopPrank();
        assertFalse(attestationIndexer.paused());
    }
}

contract AttestationIndexerV2 is AttestationIndexer {
    function version() public pure override returns (string memory) {
        return "99.0.0";
    }
}

contract AttestationIndexer_Upgrade is AttestationIndexer_Base {
    function test_upgrade_revert_by_notUpgrader() public {
        address newImpl = address(new AttestationIndexerV2());

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, alice, attestationIndexer.UPGRADER_ROLE()
            )
        );
        vm.prank(alice);
        attestationIndexer.upgradeToAndCall(newImpl, bytes(""));
    }

    function test_upgrade_succeeds_by_upgrader() public {
        assertEq(attestationIndexer.version(), "0.2.0");

        address newImpl = address(new AttestationIndexerV2());

        vm.prank(upgrader);
        attestationIndexer.upgradeToAndCall(newImpl, bytes(""));
        AttestationIndexerV2 newAttestationIndexer = AttestationIndexerV2(address(attestationIndexer));

        assertEq(newAttestationIndexer.version(), "99.0.0");
    }
}

contract AttestationIndexer_Test is AttestationIndexer_Base {
    Attestation internal attestation;

    address internal constant RECIPIENT = address(0x1234);
    bytes32 internal constant SCHEMA_UID = bytes32("schema");
    bytes32 internal constant ATTESTATION_UID = keccak256("attestation");

    address internal attester;

    function setUp() public override {
        super.setUp();
        vm.warp(1_700_000_000);

        attester = address(this);
        attestation = Attestation({
            uid: ATTESTATION_UID,
            schema: SCHEMA_UID,
            recipient: RECIPIENT,
            attester: attester,
            time: uint64(block.timestamp),
            expirationTime: uint64(block.timestamp) + 12,
            revocationTime: 0,
            refUID: bytes32(0),
            data: "",
            revocable: true
        });
    }

    function test_index_with_defaultKey() public {
        vm.mockCall(
            Predeploys.EAS,
            abi.encodeWithSelector(IEAS.getAttestation.selector, ATTESTATION_UID),
            abi.encode(attestation)
        );

        vm.expectEmit(true, true, true, true);
        emit IAttestationIndexer.AttestationIndexed(
            SCHEMA_UID, attester, RECIPIENT, attestationIndexer.DEFAULT_KEY(), ATTESTATION_UID
        );

        vm.prank(indexer);
        attestationIndexer.index(ATTESTATION_UID);

        assertEq(attestationIndexer.getAttestationUid(SCHEMA_UID, attester, RECIPIENT), ATTESTATION_UID);
        assertEq(
            attestationIndexer.getAttestationUids(SCHEMA_UID, attester, attestationIndexer.DEFAULT_KEY())[0],
            ATTESTATION_UID
        );
    }

    function test_index_with_customKey() public {
        bytes32 customKey = bytes32("custom-key");

        vm.mockCall(
            Predeploys.EAS,
            abi.encodeWithSelector(IEAS.getAttestation.selector, ATTESTATION_UID),
            abi.encode(attestation)
        );

        vm.expectEmit(true, true, true, true);
        emit IAttestationIndexer.AttestationIndexed(SCHEMA_UID, attester, RECIPIENT, customKey, ATTESTATION_UID);

        vm.prank(indexer);
        attestationIndexer.index(customKey, ATTESTATION_UID);

        assertEq(attestationIndexer.getAttestationUid(SCHEMA_UID, attester, RECIPIENT, customKey), ATTESTATION_UID);
        assertEq(attestationIndexer.getAttestationUids(SCHEMA_UID, attester, customKey)[0], ATTESTATION_UID);
    }

    function test_index_revert_when_attestation_invalid() public {
        attestation.expirationTime = uint64(block.timestamp);

        vm.mockCall(
            Predeploys.EAS,
            abi.encodeWithSelector(IEAS.getAttestation.selector, ATTESTATION_UID),
            abi.encode(attestation)
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                AttestationVerifier.ExpiredAttestation.selector, ATTESTATION_UID, uint64(block.timestamp)
            )
        );

        vm.prank(indexer);
        attestationIndexer.index(ATTESTATION_UID);
    }
}
