// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Attestation} from "@eas-contracts/contracts/IEAS.sol";
import {IndexerUpdated, InvalidIndexer} from "../../src/libraries/Common.sol";
import {VerifyCodeIndexingResolverUpgradeable} from "../../src/abstract/VerifyCodeIndexingResolverUpgradeable.sol";

contract MockVerifyCodeIndexingResolver is VerifyCodeIndexingResolverUpgradeable {
    function initialize() public initializer {
        __SchemaResolver_init();
        __VerifyCodeIndexingResolver_init();
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

contract VerifyCodeIndexingResolver_Base is Test {
    MockVerifyCodeIndexingResolver public mockVerifyCodeIndexingResolver;

    address internal constant INDEXER = address(0x1234);

    function setUp() public virtual {
        mockVerifyCodeIndexingResolver = new MockVerifyCodeIndexingResolver();
        mockVerifyCodeIndexingResolver.initialize();
    }
}

contract VerifyCodeIndexingResolver_Configure is VerifyCodeIndexingResolver_Base {
    function test_version() public view {
        assertEq(mockVerifyCodeIndexingResolver.version(), "99.0.0");
    }

    function test_setIndexer_revert_when_zeroAddress() public {
        vm.expectRevert(InvalidIndexer.selector);
        mockVerifyCodeIndexingResolver.setIndexer(address(0));
    }

    function test_setIndexer_revert_when_sameAddress() public {
        mockVerifyCodeIndexingResolver.setIndexer(INDEXER);

        vm.expectRevert(InvalidIndexer.selector);
        mockVerifyCodeIndexingResolver.setIndexer(INDEXER);
    }

    function test_setIndexer_succeeds() public {
        mockVerifyCodeIndexingResolver.setIndexer(INDEXER);

        address newIndexer = vm.randomAddress();

        vm.expectEmit(true, true, true, true);
        emit IndexerUpdated(INDEXER, newIndexer);

        mockVerifyCodeIndexingResolver.setIndexer(newIndexer);
    }
}

contract VerifyCodeIndexingResolver_Test is VerifyCodeIndexingResolver_Base {
    function setUp() public override {
        super.setUp();
        mockVerifyCodeIndexingResolver.setIndexer(INDEXER);
    }

    function test_onAttest_true_and_indexesWithExpectedKey() public {
        bytes32 uid = bytes32("uid");
        bytes32 codeHash = keccak256(bytes("rawcode"));
        string memory domain = "foo.bar";

        Attestation memory attestation;
        attestation.uid = uid;
        attestation.data = abi.encode(codeHash, domain);

        bytes32 expectedKey = keccak256(abi.encode(codeHash, domain));
        bytes memory expectedCalldata =
            abi.encodeWithSelector(bytes4(keccak256("index(bytes32,bytes32)")), expectedKey, uid);

        vm.mockCall(INDEXER, expectedCalldata, bytes(""));

        assertTrue(mockVerifyCodeIndexingResolver.mockAttest(attestation));
    }

    function testFuzz_onRevoke_alwaysTrue(Attestation memory attestation) public {
        assertTrue(mockVerifyCodeIndexingResolver.mockRevoke(attestation));
    }
}
