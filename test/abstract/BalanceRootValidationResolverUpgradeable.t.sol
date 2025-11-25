// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Attestation} from "@eas-contracts/contracts/IEAS.sol";
import {
    BalanceRootValidationResolverUpgradeable
} from "../../src/abstract/BalanceRootValidationResolverUpgradeable.sol";

contract MockBalanceRootValidationResolver is BalanceRootValidationResolverUpgradeable {
    function initialize() public initializer {
        __SchemaResolver_init();
        __BalanceRootValidationResolver_init();
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

contract BalanceRootValidationResolver_Base is Test {
    MockBalanceRootValidationResolver public mockBalanceRootValidationResolver;

    function setUp() public virtual {
        mockBalanceRootValidationResolver = new MockBalanceRootValidationResolver();
        mockBalanceRootValidationResolver.initialize();
    }
}

contract BalanceRootValidationResolver_Configure is BalanceRootValidationResolver_Base {
    function test_version() public view {
        assertEq(mockBalanceRootValidationResolver.version(), "99.0.0");
    }
}

contract BalanceIndexingResolver_Test is BalanceRootValidationResolver_Base {
    uint256 internal constant BTC_COIN_TYPE = 0x0300000000000000000000000000000000000000000000000000000000435442;
    uint192 internal constant LEAF_COUNT = 1_000_000;
    uint256 internal constant TOTAL_AMOUNT = 10_000_000_000_000_000_000;
    bytes32 internal constant ROOT = bytes32("root");

    function setUp() public override {
        super.setUp();
        vm.warp(1_700_000_000);
    }

    function test_onAttest_false_for_snapshotAt_future() public {
        Attestation memory attestation;
        attestation.uid = bytes32("uid");
        attestation.data = abi.encode(BTC_COIN_TYPE, 1_700_000_000 + 1, LEAF_COUNT, TOTAL_AMOUNT, ROOT);

        assertFalse(mockBalanceRootValidationResolver.mockAttest(attestation));
    }

    function test_onAttest_false_for_invalid_coinType() public {
        Attestation memory attestation;
        attestation.uid = bytes32("uid");
        attestation.data = abi.encode(1 << 31 + 1, 1_700_000_000 - 1, LEAF_COUNT, TOTAL_AMOUNT, ROOT);

        assertFalse(mockBalanceRootValidationResolver.mockAttest(attestation));
    }

    function test_onAttest_false_for_zero_leafCount() public {
        Attestation memory attestation;
        attestation.uid = bytes32("uid");
        attestation.data = abi.encode(BTC_COIN_TYPE, 1_700_000_000 - 1, 0, TOTAL_AMOUNT, ROOT);

        assertFalse(mockBalanceRootValidationResolver.mockAttest(attestation));
    }

    function test_onAttest_false_for_zero_totalAmount() public {
        Attestation memory attestation;
        attestation.uid = bytes32("uid");
        attestation.data = abi.encode(BTC_COIN_TYPE, 1_700_000_000 - 1, LEAF_COUNT, 0, ROOT);

        assertFalse(mockBalanceRootValidationResolver.mockAttest(attestation));
    }

    function test_onAttest_false_for_zero_root() public {
        Attestation memory attestation;
        attestation.uid = bytes32("uid");
        attestation.data = abi.encode(BTC_COIN_TYPE, 1_700_000_000 - 1, LEAF_COUNT, TOTAL_AMOUNT, bytes32(0));

        assertFalse(mockBalanceRootValidationResolver.mockAttest(attestation));
    }

    function test_onAttest_true() public {
        Attestation memory attestation;
        attestation.uid = bytes32("uid");
        attestation.data = abi.encode(BTC_COIN_TYPE, 1_700_000_000 - 1, LEAF_COUNT, TOTAL_AMOUNT, ROOT);

        assertTrue(mockBalanceRootValidationResolver.mockAttest(attestation));
    }

    function testFuzz_onRevoke_alwaysTrue(Attestation memory attestation) public {
        assertTrue(mockBalanceRootValidationResolver.mockRevoke(attestation));
    }
}
