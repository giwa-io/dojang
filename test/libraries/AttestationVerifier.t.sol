// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Attestation} from "@eas-contracts/contracts/IEAS.sol";
import {AttestationVerifier} from "../../src/libraries/AttestationVerifier.sol";

contract AttestationVerifierHelperForRevertTest {
    using AttestationVerifier for Attestation;

    function verify(Attestation memory attestation) external view {
        attestation.verify();
    }

    function isVerified(Attestation memory attestation) external view returns (bool) {
        return attestation.isVerified();
    }

    function verify(Attestation memory attestation, address recipient, bytes32 schemaUid) external view {
        attestation.verify(recipient, schemaUid);
    }

    function isVerified(
        Attestation memory attestation,
        address recipient,
        bytes32 schemaUid
    )
        external
        view
        returns (bool)
    {
        return attestation.isVerified(recipient, schemaUid);
    }
}

contract AttestationVerifier_Test is Test {
    AttestationVerifierHelperForRevertTest public helper;
    Attestation internal mockAttestation;

    address internal constant RECIPIENT = address(0x1234);
    bytes32 internal constant SCHEMA_UID = bytes32("schema");

    function setUp() public {
        vm.warp(1_700_000_000);
        helper = new AttestationVerifierHelperForRevertTest();

        mockAttestation = Attestation({
            uid: keccak256("uid"),
            schema: SCHEMA_UID,
            recipient: RECIPIENT,
            attester: address(this),
            time: uint64(block.timestamp),
            expirationTime: uint64(block.timestamp) + 12,
            revocationTime: 0,
            refUID: bytes32(0),
            data: "",
            revocable: true
        });
    }

    function test_verify_revert_for_zeroUid() public {
        mockAttestation.uid = bytes32(0);

        vm.expectRevert(AttestationVerifier.ZeroUid.selector);
        helper.verify(mockAttestation);
    }

    function test_verify_revert_if_expired() public {
        mockAttestation.expirationTime = uint64(block.timestamp) - 1;

        vm.expectRevert(
            abi.encodeWithSelector(
                AttestationVerifier.ExpiredAttestation.selector, mockAttestation.uid, mockAttestation.expirationTime
            )
        );
        helper.verify(mockAttestation);
    }

    function test_verify_revert_if_revoked() public {
        mockAttestation.revocationTime = uint64(block.timestamp);

        vm.expectRevert(
            abi.encodeWithSelector(
                AttestationVerifier.RevokedAttestation.selector, mockAttestation.uid, mockAttestation.revocationTime
            )
        );
        helper.verify(mockAttestation);
    }

    function test_isVerified_false_for_zeroUid() public {
        mockAttestation.uid = bytes32(0);

        vm.assertFalse(helper.isVerified(mockAttestation));
    }

    function test_isVerified_false_if_expired() public {
        mockAttestation.expirationTime = uint64(block.timestamp) - 1;

        vm.assertFalse(helper.isVerified(mockAttestation));
    }

    function test_isVerified_false_if_revoked() public {
        mockAttestation.revocationTime = uint64(block.timestamp);

        vm.assertFalse(helper.isVerified(mockAttestation));
    }

    function test_verify_revert_if_recipientMisMatch() public {
        address expectedRecipient = address(0xBEEF);

        vm.expectRevert(
            abi.encodeWithSelector(AttestationVerifier.MisMatchRecipient.selector, RECIPIENT, expectedRecipient)
        );
        helper.verify(mockAttestation, expectedRecipient, SCHEMA_UID);
    }

    function test_verify_revert_if_schemaMisMatch() public {
        bytes32 expectedSchema = bytes32("weird-schema");

        vm.expectRevert(abi.encodeWithSelector(AttestationVerifier.MisMatchSchema.selector, SCHEMA_UID, expectedSchema));
        helper.verify(mockAttestation, RECIPIENT, expectedSchema);
    }

    function test_isVerified_false_if_precheck_failed() public {
        mockAttestation.uid = bytes32(0);
        vm.assertFalse(helper.isVerified(mockAttestation, RECIPIENT, SCHEMA_UID));
    }

    function test_isVerified_false_if_recipientMisMatch() public view {
        address expectedRecipient = address(0xBEEF);

        vm.assertFalse(helper.isVerified(mockAttestation, expectedRecipient, SCHEMA_UID));
    }

    function test_isVerified_false_if_schemaMisMatch() public view {
        bytes32 expectedSchema = bytes32("weird-schema");

        vm.assertFalse(helper.isVerified(mockAttestation, RECIPIENT, expectedSchema));
    }

    function test_verify_succeeds() public view {
        helper.verify(mockAttestation);
        helper.verify(mockAttestation, RECIPIENT, SCHEMA_UID);
    }

    function test_isVerified_true() public view {
        vm.assertTrue(helper.isVerified(mockAttestation));
        vm.assertTrue(helper.isVerified(mockAttestation, RECIPIENT, SCHEMA_UID));
    }
}
