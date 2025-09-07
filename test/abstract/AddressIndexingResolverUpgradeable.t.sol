// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {IndexerUpdated, ZeroAddress, InvalidIndexer} from "../../src/libraries/Common.sol";
import {Attestation} from "@eas-contracts/contracts/IEAS.sol";
import {AddressIndexingResolverUpgradeable} from "../../src/abstract/AddressIndexingResolverUpgradeable.sol";
import {Strings} from "@openzeppelin-contracts/utils/Strings.sol";

contract MockAddressIndexingResolver is AddressIndexingResolverUpgradeable {
    function initialize() public initializer {
        __SchemaResolver_init();
        __AddressIndexingResolver_init();
    }

    function version() external pure returns (string memory) {
        return "0.1.0";
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

contract AddressIndexingResolver_Base is Test {
    MockAddressIndexingResolver public mockAddressIndexingResolver;

    address internal constant INDEXER = address(0x1234);

    function setUp() public virtual {
        mockAddressIndexingResolver = new MockAddressIndexingResolver();
        mockAddressIndexingResolver.initialize();
    }
}

contract AddressIndexingResolver_Configure is AddressIndexingResolver_Base {
    function test_version() public view {
        assertEq(mockAddressIndexingResolver.version(), "0.1.0");
    }

    function test_setIndexer_revert_when_zeroAddress() public {
        vm.expectRevert(InvalidIndexer.selector);
        mockAddressIndexingResolver.setIndexer(address(0));
    }

    function test_setIndexer_revert_when_sameAddress() public {
        mockAddressIndexingResolver.setIndexer(INDEXER);

        vm.expectRevert(InvalidIndexer.selector);
        mockAddressIndexingResolver.setIndexer(INDEXER);
    }

    function test_setIndexer_succeeds() public {
        mockAddressIndexingResolver.setIndexer(INDEXER);

        address newIndexer = vm.randomAddress();

        vm.expectEmit(true, true, true, true);
        emit IndexerUpdated(INDEXER, newIndexer);

        mockAddressIndexingResolver.setIndexer(newIndexer);
    }
}

contract AddressIndexingResolver_Test is AddressIndexingResolver_Base {
    address internal constant ADDRESS = 0x685933139dE0F4153D32247376e068E156bBA440;

    function setUp() public override {
        super.setUp();
        mockAddressIndexingResolver.setIndexer(INDEXER);
    }

    function test_onAttest_true() public {
        Attestation memory attestation;
        attestation.uid = bytes32("uid");
        attestation.data = abi.encode(true);

        vm.mockCall(INDEXER, abi.encodeWithSelector(bytes4(keccak256("index(bytes32)")), attestation.uid), bytes(""));

        assertTrue(mockAddressIndexingResolver.mockAttest(attestation));
    }

    function testFuzz_onRevoke_alwaysTrue(Attestation memory attestation) public {
        assertTrue(mockAddressIndexingResolver.mockRevoke(attestation));
    }
}
