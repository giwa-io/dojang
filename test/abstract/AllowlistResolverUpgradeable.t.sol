// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {AllowlistResolverUpgradeable} from "../../src/abstract/AllowlistResolverUpgradeable.sol";
import {Attestation} from "@eas-contracts/contracts/IEAS.sol";

contract MockAllowlistResolver is AllowlistResolverUpgradeable {
    function initialize() public initializer {
        __SchemaResolver_init();
        __AllowlistResolver_init();
    }

    function version() external pure returns (string memory) {
        return "0.1.0";
    }

    function allowAttester(address attester) external {
        _allowAttester(attester);
    }

    function removeAttester(address attester) external {
        _removeAttester(attester);
    }

    function mockAttest(Attestation calldata attestation) external payable returns (bool) {
        return onAttest(attestation, msg.value);
    }

    function mockRevoke(Attestation calldata attestation) external payable returns (bool) {
        return onRevoke(attestation, msg.value);
    }
}

contract AllowlistResolver_Base is Test {
    MockAllowlistResolver public mockAllowlistResolver;
    address internal attester;
    address internal alice;

    function setUp() public {
        attester = makeAddr("attester");
        alice = makeAddr("alice");

        mockAllowlistResolver = new MockAllowlistResolver();
        mockAllowlistResolver.initialize();
    }
}

contract AllowlistResolver_Configure is AllowlistResolver_Base {
    function test_version() public view {
        assertEq(mockAllowlistResolver.version(), "0.1.0");
    }

    function test_allowAttester_succeeds() public {
        vm.expectEmit(true, true, true, true);
        emit AllowlistResolverUpgradeable.AttesterAllowed(attester);

        mockAllowlistResolver.allowAttester(attester);
    }

    function test_allowAttester_revert_when_alreadyAllowed() public {
        mockAllowlistResolver.allowAttester(attester);

        vm.expectRevert(abi.encodeWithSelector(AllowlistResolverUpgradeable.AttesterAlreadyAllowed.selector, attester));
        mockAllowlistResolver.allowAttester(attester);
    }

    function test_removeAttester_revert_when_alreadyNotAllowed() public {
        vm.expectRevert(
            abi.encodeWithSelector(AllowlistResolverUpgradeable.AttesterAlreadyNotAllowed.selector, attester)
        );
        mockAllowlistResolver.removeAttester(attester);
    }

    function test_removeAttester_succeeds() public {
        mockAllowlistResolver.allowAttester(attester);

        vm.expectEmit(true, true, true, true);
        emit AllowlistResolverUpgradeable.AttesterRemoved(attester);

        mockAllowlistResolver.removeAttester(attester);
    }
}

contract AllowlistResolver_Test is AllowlistResolver_Base {
    function test_onAttest() public {
        Attestation memory attestation;
        attestation.attester = attester;

        assertFalse(mockAllowlistResolver.mockAttest(attestation));

        mockAllowlistResolver.allowAttester(attester);
        assertTrue(mockAllowlistResolver.mockAttest(attestation));

        attestation.attester = alice;
        assertFalse(mockAllowlistResolver.mockAttest(attestation));
    }

    function testFuzz_onRevoke_alwaysTrue(Attestation memory attestation) public {
        assertTrue(mockAllowlistResolver.mockRevoke(attestation));
    }
}
