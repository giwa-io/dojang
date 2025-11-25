// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Attestation} from "@eas-contracts/contracts/IEAS.sol";
import {BalanceValidationResolverUpgradeable} from "../../src/abstract/BalanceValidationResolverUpgradeable.sol";
import {Predeploys} from "src/libraries/Types.sol";
import {AttestationVerifier} from "src/libraries/AttestationVerifier.sol";

contract MockBalanceValidationResolver is BalanceValidationResolverUpgradeable {
    function initialize() public initializer {
        __SchemaResolver_init();
        __BalanceValidationResolver_init();
    }

    function version() external pure returns (string memory) {
        return "99.0.0";
    }

    function setBalanceRootSchemaUID(bytes32 schemaUID) external {
        _setBalanceRootSchemaUID(schemaUID);
    }

    function mockAttest(Attestation calldata attestation) external payable returns (bool) {
        return onAttest(attestation, msg.value);
    }

    function mockRevoke(Attestation calldata attestation) external payable returns (bool) {
        return onRevoke(attestation, msg.value);
    }
}

contract BalanceValidationResolver_Base is Test {
    MockBalanceValidationResolver public mockBalanceValidationResolver;

    bytes32 internal constant BALANCE_ROOT_SCHEMA_UID = bytes32("balanceRootSchemaUID");

    function setUp() public virtual {
        mockBalanceValidationResolver = new MockBalanceValidationResolver();
        mockBalanceValidationResolver.initialize();
    }
}

contract BalanceValidationResolver_Configure is BalanceValidationResolver_Base {
    function test_version() public view {
        assertEq(mockBalanceValidationResolver.version(), "99.0.0");
    }
}

contract BalanceValidationResolver_Test is BalanceValidationResolver_Base {
    bytes32 internal constant ROOT = 0xd4205e580ec0284840a0b5f7706fe1647965417a45d7a1d1a8d7a90ae40bdcce;
    bytes32 internal constant REF_UID = bytes32("refUID");

    address internal constant RECIPIENT = address(0x1234);
    uint256 internal constant BALANCE = 10_000_000_000_000_000_000;
    bytes32 internal constant SALT = keccak256("salt");
    bytes32[] internal PROOFS = new bytes32[](3);

    function setUp() public override {
        super.setUp();
        mockBalanceValidationResolver.setBalanceRootSchemaUID(BALANCE_ROOT_SCHEMA_UID);
        PROOFS[0] = bytes32(0x00ad81533b36a6fee8fd154f598637471c82c59e10d8f6c31d6661929fbd8f92);
        PROOFS[1] = bytes32(0xdea38148395b88e4c454154adc5a69242c8fe345e352ecbe1418078bfd119623);
        PROOFS[2] = bytes32(0x66b17509ac7c30cb130b3ec65dfc7cfb49a220b9a6aa00ec07002a6f732e9486);
    }

    function test_onAttest_false_for_invalid_referencing_schema() public {
        vm.mockCall(
            Predeploys.EAS,
            abi.encodeWithSelector(bytes4(keccak256("getAttestation(bytes32)")), REF_UID),
            abi.encode(
                Attestation({
                    uid: REF_UID,
                    schema: bytes32("invalidSchemaUID"),
                    time: 0,
                    expirationTime: 0,
                    revocationTime: 0,
                    refUID: bytes32(0),
                    data: abi.encode(uint256(0), uint64(0), uint192(0), uint256(0), ROOT),
                    attester: address(0),
                    revocable: true,
                    recipient: address(0)
                })
            )
        );

        Attestation memory attestation;
        attestation.uid = bytes32("uid");
        attestation.refUID = REF_UID;
        attestation.recipient = RECIPIENT;
        attestation.data = abi.encode(BALANCE, SALT, PROOFS);

        vm.expectRevert(
            abi.encodeWithSelector(
                AttestationVerifier.MisMatchSchema.selector, bytes32("invalidSchemaUID"), BALANCE_ROOT_SCHEMA_UID
            )
        );
        mockBalanceValidationResolver.mockAttest(attestation);
    }

    function test_onAttest_false_for_invalid_proof() public {
        vm.mockCall(
            Predeploys.EAS,
            abi.encodeWithSelector(bytes4(keccak256("getAttestation(bytes32)")), REF_UID),
            abi.encode(
                Attestation({
                    uid: REF_UID,
                    schema: BALANCE_ROOT_SCHEMA_UID,
                    time: 0,
                    expirationTime: 0,
                    revocationTime: 0,
                    refUID: bytes32(0),
                    data: abi.encode(uint256(0), uint64(0), uint192(0), uint256(0), keccak256("Invalid Proof")),
                    attester: address(0),
                    revocable: true,
                    recipient: address(0)
                })
            )
        );

        Attestation memory attestation;
        attestation.uid = bytes32("uid");
        attestation.refUID = REF_UID;
        attestation.recipient = RECIPIENT;
        attestation.data = abi.encode(BALANCE, SALT, PROOFS);

        assertFalse(mockBalanceValidationResolver.mockAttest(attestation));
    }

    function test_onAttest_false_for_mismatched_recipient() public {
        vm.mockCall(
            Predeploys.EAS,
            abi.encodeWithSelector(bytes4(keccak256("getAttestation(bytes32)")), REF_UID),
            abi.encode(
                Attestation({
                    uid: REF_UID,
                    schema: BALANCE_ROOT_SCHEMA_UID,
                    time: 0,
                    expirationTime: 0,
                    revocationTime: 0,
                    refUID: bytes32(0),
                    data: abi.encode(uint256(0), uint64(0), uint192(0), uint256(0), ROOT),
                    attester: address(0),
                    revocable: true,
                    recipient: address(0)
                })
            )
        );

        Attestation memory attestation;
        attestation.uid = bytes32("uid");
        attestation.refUID = REF_UID;
        attestation.recipient = address(0x5678);
        attestation.data = abi.encode(BALANCE, SALT, PROOFS);

        assertFalse(mockBalanceValidationResolver.mockAttest(attestation));
    }

    function test_onAttest_true() public {
        vm.mockCall(
            Predeploys.EAS,
            abi.encodeWithSelector(bytes4(keccak256("getAttestation(bytes32)")), REF_UID),
            abi.encode(
                Attestation({
                    uid: REF_UID,
                    schema: BALANCE_ROOT_SCHEMA_UID,
                    time: 0,
                    expirationTime: 0,
                    revocationTime: 0,
                    refUID: bytes32(0),
                    data: abi.encode(uint256(0), uint64(0), uint192(0), uint256(0), ROOT),
                    attester: address(0),
                    revocable: true,
                    recipient: address(0)
                })
            )
        );

        Attestation memory attestation;
        attestation.uid = bytes32("uid");
        attestation.refUID = REF_UID;
        attestation.recipient = RECIPIENT;
        attestation.data = abi.encode(BALANCE, SALT, PROOFS);

        assertTrue(mockBalanceValidationResolver.mockAttest(attestation));
    }

    function testFuzz_onRevoke_alwaysTrue(Attestation memory attestation) public {
        assertTrue(mockBalanceValidationResolver.mockRevoke(attestation));
    }
}
