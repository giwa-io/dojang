// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Attestation} from "@eas-contracts/contracts/IEAS.sol";
import {BalanceValidationResolverUpgradeable} from "../../src/abstract/BalanceValidationResolverUpgradeable.sol";

contract MockBalanceValidationResolver is BalanceValidationResolverUpgradeable {
    function initialize() public initializer {
        __SchemaResolver_init();
        __BalanceValidationResolver_init();
    }

    function version() external pure returns (string memory) {
        return "99.0.0";
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

contract BalanceIndexingResolver_Test is BalanceValidationResolver_Base {
    uint256 internal constant BITCOIN_COIN_TYPE = 0;
    uint256 internal constant BALANCE = 10_000_000_000_000_000_000;

    function setUp() public override {
        super.setUp();
        vm.warp(1_700_000_000);
    }

    function test_onAttest_false_for_snapshotAt_future() public {
        Attestation memory attestation;
        attestation.uid = bytes32("uid");
        attestation.data = abi.encode(BITCOIN_COIN_TYPE, 1_700_000_000 + 1, BALANCE);

        assertFalse(mockBalanceValidationResolver.mockAttest(attestation));
    }

    function test_onAttest_false_for_invalid_coinType() public {
        Attestation memory attestation;
        attestation.uid = bytes32("uid");
        attestation.data = abi.encode(1 + 1 << 31, 1_700_000_000 - 1, BALANCE);

        assertFalse(mockBalanceValidationResolver.mockAttest(attestation));
    }

    function test_onAttest_true() public {
        Attestation memory attestation;
        attestation.uid = bytes32("uid");
        attestation.data = abi.encode(BITCOIN_COIN_TYPE, 1_700_000_000 - 1, BALANCE);

        assertTrue(mockBalanceValidationResolver.mockAttest(attestation));
    }

    function testFuzz_onRevoke_alwaysTrue(Attestation memory attestation) public {
        assertTrue(mockBalanceValidationResolver.mockRevoke(attestation));
    }
}
