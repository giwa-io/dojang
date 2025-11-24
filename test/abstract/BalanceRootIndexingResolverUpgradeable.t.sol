// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {IndexerUpdated, InvalidIndexer} from "../../src/libraries/Common.sol";
import {Attestation} from "@eas-contracts/contracts/IEAS.sol";
import {BalanceRootIndexingResolverUpgradeable} from "../../src/abstract/BalanceRootIndexingResolverUpgradeable.sol";

contract MockBalanceRootIndexingResolver is BalanceRootIndexingResolverUpgradeable {
    function initialize() public initializer {
        __SchemaResolver_init();
        __BalanceRootIndexingResolver_init();
    }

    function version() external pure returns (string memory) {
        return "99.0.0";
    }

    function setIndexer(address indexer) external {
        _setIndexer(indexer);
    }

    function mockAttest(Attestation calldata attestation) external payable returns (bool) {
        return onAttest(attestation, msg.value);
    }

    function mockRevoke(Attestation calldata attestation) external payable returns (bool) {
        return onRevoke(attestation, msg.value);
    }
}

contract BalanceRootIndexingResolver_Base is Test {
    MockBalanceRootIndexingResolver public mockBalanceRootIndexingResolver;

    address internal constant INDEXER = address(0x1234);

    function setUp() public virtual {
        mockBalanceRootIndexingResolver = new MockBalanceRootIndexingResolver();
        mockBalanceRootIndexingResolver.initialize();
    }
}

contract BalanceRootIndexingResolver_Configure is BalanceRootIndexingResolver_Base {
    function test_version() public view {
        assertEq(mockBalanceRootIndexingResolver.version(), "99.0.0");
    }

    function test_setIndexer_revert_when_zeroAddress() public {
        vm.expectRevert(InvalidIndexer.selector);
        mockBalanceRootIndexingResolver.setIndexer(address(0));
    }

    function test_setIndexer_revert_when_sameAddress() public {
        mockBalanceRootIndexingResolver.setIndexer(INDEXER);

        vm.expectRevert(InvalidIndexer.selector);
        mockBalanceRootIndexingResolver.setIndexer(INDEXER);
    }

    function test_setIndexer_succeeds() public {
        mockBalanceRootIndexingResolver.setIndexer(INDEXER);

        address newIndexer = vm.randomAddress();

        vm.expectEmit(true, true, true, true);
        emit IndexerUpdated(INDEXER, newIndexer);

        mockBalanceRootIndexingResolver.setIndexer(newIndexer);
    }
}

contract BalanceRootIndexingResolver_Test is BalanceRootIndexingResolver_Base {
    uint256 internal constant BITCOIN_COIN_TYPE = 0;
    uint64 internal constant SNAPSHOT_AT = 1_750_307_050;
    uint192 internal constant LEAF_COUNT = 1_000_000;
    uint256 internal constant TOTAL_AMOUNT = 10_000_000_000_000_000_000;
    bytes32 internal constant ROOT = bytes32("root");

    function setUp() public override {
        super.setUp();
        mockBalanceRootIndexingResolver.setIndexer(INDEXER);
    }

    function test_onAttest_true_for_balanceDojangAttestation() public {
        Attestation memory attestation;
        attestation.uid = bytes32("uid");
        attestation.data = abi.encode(BITCOIN_COIN_TYPE, SNAPSHOT_AT, LEAF_COUNT, TOTAL_AMOUNT, ROOT);

        bytes32 key = keccak256(abi.encode(BITCOIN_COIN_TYPE, SNAPSHOT_AT));
        vm.mockCall(
            INDEXER,
            abi.encodeWithSelector(bytes4(keccak256("index(bytes32,bytes32)")), key, attestation.uid),
            bytes("")
        );

        assertTrue(mockBalanceRootIndexingResolver.mockAttest(attestation));
    }

    function testFuzz_onRevoke_alwaysTrue(Attestation memory attestation) public {
        assertTrue(mockBalanceRootIndexingResolver.mockRevoke(attestation));
    }
}
