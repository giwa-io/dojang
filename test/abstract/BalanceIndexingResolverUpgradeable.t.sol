// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {IndexerUpdated, InvalidIndexer} from "../../src/libraries/Common.sol";
import {Attestation} from "@eas-contracts/contracts/IEAS.sol";
import {BalanceIndexingResolverUpgradeable} from "../../src/abstract/BalanceIndexingResolverUpgradeable.sol";

contract MockBalanceIndexingResolver is BalanceIndexingResolverUpgradeable {
    function initialize() public initializer {
        __SchemaResolver_init();
        __BalanceIndexingResolver_init();
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

contract BalanceIndexingResolver_Base is Test {
    MockBalanceIndexingResolver public mockBalanceIndexingResolver;

    address internal constant INDEXER = address(0x1234);

    function setUp() public virtual {
        mockBalanceIndexingResolver = new MockBalanceIndexingResolver();
        mockBalanceIndexingResolver.initialize();
    }
}

contract BalanceIndexingResolver_Configure is BalanceIndexingResolver_Base {
    function test_version() public view {
        assertEq(mockBalanceIndexingResolver.version(), "99.0.0");
    }

    function test_setIndexer_revert_when_zeroAddress() public {
        vm.expectRevert(InvalidIndexer.selector);
        mockBalanceIndexingResolver.setIndexer(address(0));
    }

    function test_setIndexer_revert_when_sameAddress() public {
        mockBalanceIndexingResolver.setIndexer(INDEXER);

        vm.expectRevert(InvalidIndexer.selector);
        mockBalanceIndexingResolver.setIndexer(INDEXER);
    }

    function test_setIndexer_succeeds() public {
        mockBalanceIndexingResolver.setIndexer(INDEXER);

        address newIndexer = vm.randomAddress();

        vm.expectEmit(true, true, true, true);
        emit IndexerUpdated(INDEXER, newIndexer);

        mockBalanceIndexingResolver.setIndexer(newIndexer);
    }
}

contract BalanceIndexingResolver_Test is BalanceIndexingResolver_Base {
    uint256 internal constant BITCOIN_COIN_TYPE = 0;
    uint64 internal constant SNAPSHOT_AT = 1_750_307_050;
    uint256 internal constant BALANCE = 10_000_000_000_000_000_000;

    function setUp() public override {
        super.setUp();
        mockBalanceIndexingResolver.setIndexer(INDEXER);
    }

    function test_onAttest_true_for_balanceDojangAttestation() public {
        Attestation memory attestation;
        attestation.uid = bytes32("uid");
        attestation.data = abi.encode(BITCOIN_COIN_TYPE, SNAPSHOT_AT, BALANCE);

        bytes32 key = keccak256(abi.encode(BITCOIN_COIN_TYPE, SNAPSHOT_AT));
        vm.mockCall(
            INDEXER,
            abi.encodeWithSelector(bytes4(keccak256("index(bytes32,bytes32)")), key, attestation.uid),
            bytes("")
        );

        assertTrue(mockBalanceIndexingResolver.mockAttest(attestation));
    }

    function testFuzz_onRevoke_alwaysTrue(Attestation memory attestation) public {
        assertTrue(mockBalanceIndexingResolver.mockRevoke(attestation));
    }
}
